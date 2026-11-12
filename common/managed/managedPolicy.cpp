#include "managedPolicy.h"

#include <QCryptographicHash>
#include <QDebug>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMessageAuthenticationCode>
#include <QMutex>
#include <QMutexLocker>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSet>
#include <QSettings>
#include <QStringList>
#include <QUrl>
#include <QUuid>

#include <algorithm>

#ifdef Q_OS_WIN
    #include <windows.h>
    #include <sddl.h>
#endif

namespace amnezia::managed
{
    namespace
    {
        const QString policyKey = QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\AmneziaVPN");
        const QString protectedKey = QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\AmneziaVPN\\Managed");
        const QString managedModeValue = QStringLiteral("ManagedMode");
        const QString serversValue = QStringLiteral("Servers");
        const QString saltValue = QStringLiteral("Salt");

        constexpr int minimumSecretLength = 6;

        const QSet<QString> directOutboundProtocols = { QStringLiteral("freedom"), QStringLiteral("blackhole"),
                                                        QStringLiteral("dns"), QStringLiteral("loopback") };

        const QSet<QString> secretKeyNames = { QStringLiteral("password"),        QStringLiteral("privateKey"),
                                               QStringLiteral("client_priv_key"), QStringLiteral("psk_key"),
                                               QStringLiteral("presharedKey"),    QStringLiteral("PrivateKey"),
                                               QStringLiteral("PresharedKey") };

        QMutex socksPortsMutex;
        QSet<int> approvedSocksPorts;

        QJsonValue parseJsonText(const QString &text)
        {
            const QString trimmed = text.trimmed();
            if (!trimmed.startsWith(QLatin1Char('{')) && !trimmed.startsWith(QLatin1Char('['))) {
                return {};
            }
            const QJsonDocument doc = QJsonDocument::fromJson(trimmed.toUtf8());
            if (doc.isObject()) {
                return doc.object();
            }
            if (doc.isArray()) {
                return doc.array();
            }
            return {};
        }

        QList<QPair<QString, QString>> outboundEndpoints(const QString &protocol, const QJsonObject &settings)
        {
            QList<QPair<QString, QString>> endpoints;
            const bool usesUserId = protocol == QLatin1String("vless") || protocol == QLatin1String("vmess");
            const QString credentialKey = usesUserId ? QStringLiteral("id") : QStringLiteral("password");

            if (usesUserId) {
                for (const QJsonValue &server : settings.value(QStringLiteral("vnext")).toArray()) {
                    const QJsonObject serverObject = server.toObject();
                    const QString address = serverObject.value(QStringLiteral("address")).toString();
                    for (const QJsonValue &user : serverObject.value(QStringLiteral("users")).toArray()) {
                        endpoints.append({ address, user.toObject().value(credentialKey).toString() });
                    }
                }
            } else {
                for (const QJsonValue &server : settings.value(QStringLiteral("servers")).toArray()) {
                    const QJsonObject serverObject = server.toObject();
                    endpoints.append({ serverObject.value(QStringLiteral("address")).toString(),
                                       serverObject.value(credentialKey).toString() });
                }
            }

            if (settings.contains(QStringLiteral("address"))) {
                endpoints.append({ settings.value(QStringLiteral("address")).toString(),
                                   settings.value(credentialKey).toString() });
            }

            return endpoints;
        }

        bool isProxyProtocol(const QString &protocol)
        {
            return protocol == QLatin1String("vless") || protocol == QLatin1String("vmess")
                    || protocol == QLatin1String("trojan") || protocol == QLatin1String("shadowsocks");
        }


        void collectApprovedValues(const QJsonValue &value, QSet<QString> &approved);

        void collectApprovedFromString(const QString &text, QSet<QString> &approved)
        {
            const QString trimmed = text.trimmed();
            if (trimmed.isEmpty()) {
                return;
            }
            approved.insert(trimmed);
            collectApprovedValues(parseJsonText(trimmed), approved);

            static const QRegularExpression linkPattern(
                    QStringLiteral(R"(([a-z0-9+.\-]+)://([^@\s/?#]+)@(\[[^\]\s]+\]|[^:/?#\s]+))"),
                    QRegularExpression::CaseInsensitiveOption);
            auto matches = linkPattern.globalMatch(trimmed);
            while (matches.hasNext()) {
                const auto match = matches.next();
                const QString userInfo = QUrl::fromPercentEncoding(match.captured(2).toUtf8());
                QString host = match.captured(3);
                host.remove(QLatin1Char('[')).remove(QLatin1Char(']'));
                approved.insert(userInfo);
                approved.insert(host);

                if (match.captured(1).compare(QLatin1String("ss"), Qt::CaseInsensitive) == 0) {
                    const QByteArray decoded = QByteArray::fromBase64(userInfo.toUtf8(), QByteArray::Base64UrlEncoding);
                    const QString methodAndPassword = QString::fromUtf8(decoded);
                    const int separator = methodAndPassword.indexOf(QLatin1Char(':'));
                    if (separator > 0) {
                        approved.insert(methodAndPassword.mid(separator + 1));
                    }
                }
            }

            static const QRegularExpression serverKeyPattern(QStringLiteral(R"(PublicKey\s*=\s*([A-Za-z0-9+/]{43}=))"));
            auto keyMatches = serverKeyPattern.globalMatch(trimmed);
            while (keyMatches.hasNext()) {
                approved.insert(keyMatches.next().captured(1));
            }
        }

        void collectApprovedValues(const QJsonValue &value, QSet<QString> &approved)
        {
            if (value.isString()) {
                collectApprovedFromString(value.toString(), approved);
            } else if (value.isObject()) {
                const QJsonObject object = value.toObject();
                for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
                    collectApprovedValues(it.value(), approved);
                }
            } else if (value.isArray()) {
                for (const QJsonValue &item : value.toArray()) {
                    collectApprovedValues(item, approved);
                }
            }
        }

        QSet<QString> approvedValuesOf(const QByteArray &serversJson)
        {
            QSet<QString> approved;
            collectApprovedValues(parseJsonText(QString::fromUtf8(serversJson)), approved);
            return approved;
        }


        void addSecret(const QString &secret, QStringList &secrets)
        {
            if (secret.size() >= minimumSecretLength && !secrets.contains(secret)) {
                secrets.append(secret);
            }
        }

        void collectSecrets(const QJsonValue &value, QStringList &secrets);

        void collectSecretsFromString(const QString &text, QStringList &secrets)
        {
            collectSecrets(parseJsonText(text), secrets);

            static const QRegularExpression linkPattern(
                    QStringLiteral(R"((?:vless|vmess|trojan|ss)://([^@\s/?#]+)@)"),
                    QRegularExpression::CaseInsensitiveOption);
            auto links = linkPattern.globalMatch(text);
            while (links.hasNext()) {
                const QString userInfo = links.next().captured(1);
                addSecret(userInfo, secrets);
                addSecret(QUrl::fromPercentEncoding(userInfo.toUtf8()), secrets);
            }

            static const QRegularExpression wireGuardSecretPattern(
                    QStringLiteral(R"((?:PrivateKey|PresharedKey)\s*=\s*([A-Za-z0-9+/]{43}=))"));
            auto keys = wireGuardSecretPattern.globalMatch(text);
            while (keys.hasNext()) {
                addSecret(keys.next().captured(1), secrets);
            }
        }

        void collectSecrets(const QJsonValue &value, QStringList &secrets)
        {
            if (value.isString()) {
                collectSecretsFromString(value.toString(), secrets);
            } else if (value.isArray()) {
                for (const QJsonValue &item : value.toArray()) {
                    collectSecrets(item, secrets);
                }
            } else if (value.isObject()) {
                const QJsonObject object = value.toObject();
                for (const QJsonValue &outbound : object.value(QStringLiteral("outbounds")).toArray()) {
                    const QString protocol = outbound.toObject().value(QStringLiteral("protocol")).toString().toLower();
                    if (isProxyProtocol(protocol)) {
                        const auto endpoints =
                                outboundEndpoints(protocol, outbound.toObject().value(QStringLiteral("settings")).toObject());
                        for (const auto &endpoint : endpoints) {
                            addSecret(endpoint.second, secrets);
                        }
                    }
                }
                for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
                    if (secretKeyNames.contains(it.key()) && it.value().isString()) {
                        addSecret(it.value().toString(), secrets);
                    }
                    collectSecrets(it.value(), secrets);
                }
            }
        }

        QStringList secretsOf(const QByteArray &serversJson)
        {
            QStringList secrets;
            collectSecrets(parseJsonText(QString::fromUtf8(serversJson)), secrets);
            std::sort(secrets.begin(), secrets.end(), [](const QString &a, const QString &b) { return a.size() > b.size(); });
            return secrets;
        }

        QString placeholderFor(const QString &secret, const QByteArray &salt)
        {
            const QByteArray mac = QMessageAuthenticationCode::hash(secret.toUtf8(), salt, QCryptographicHash::Sha256);

            static const QRegularExpression wireGuardKeyPattern(QStringLiteral("^[A-Za-z0-9+/]{43}=$"));
            if (wireGuardKeyPattern.match(secret).hasMatch()) {
                return QString::fromLatin1(mac.toBase64());
            }

            QByteArray uuidBytes = mac.left(16);
            uuidBytes[6] = char((uuidBytes[6] & 0x0F) | 0x40);
            uuidBytes[8] = char((uuidBytes[8] & 0x3F) | 0x80);
            return QUuid::fromRfc4122(uuidBytes).toString(QUuid::WithoutBraces);
        }

        QString jsonEscaped(const QString &text)
        {
            const QByteArray encoded = QJsonDocument(QJsonArray { text }).toJson(QJsonDocument::Compact);
            return QString::fromUtf8(encoded.mid(2, encoded.size() - 4));
        }

        QStringList encodedForms(const QString &secret)
        {
            QStringList forms { secret };
            for (int level = 0; level < 3; ++level) {
                const QString next = jsonEscaped(forms.last());
                if (forms.contains(next)) {
                    break;
                }
                forms.append(next);
            }
            return forms;
        }

        QString endpointKey(const QString &protocol, const QString &address, const QString &credential)
        {
            return protocol + QLatin1Char('|') + address + QLatin1Char('|') + credential;
        }

        void collectApprovedOutbounds(const QJsonValue &value, QHash<QString, QJsonObject> &outbounds)
        {
            if (value.isString()) {
                collectApprovedOutbounds(parseJsonText(value.toString()), outbounds);
            } else if (value.isArray()) {
                for (const QJsonValue &item : value.toArray()) {
                    collectApprovedOutbounds(item, outbounds);
                }
            } else if (value.isObject()) {
                const QJsonObject object = value.toObject();
                for (const QJsonValue &outboundValue : object.value(QStringLiteral("outbounds")).toArray()) {
                    const QJsonObject outbound = outboundValue.toObject();
                    const QString protocol = outbound.value(QStringLiteral("protocol")).toString().toLower();
                    if (!isProxyProtocol(protocol)) {
                        continue;
                    }
                    const auto endpoints = outboundEndpoints(protocol, outbound.value(QStringLiteral("settings")).toObject());
                    for (const auto &[address, credential] : endpoints) {
                        outbounds.insert(endpointKey(protocol, address, credential), outbound);
                    }
                }
                for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
                    collectApprovedOutbounds(it.value(), outbounds);
                }
            }
        }

        bool enforceXrayConfig(QString &xrayConfig, const QByteArray &serversJson, QSet<int> *socksPorts)
        {
            QJsonObject config = QJsonDocument::fromJson(xrayConfig.toUtf8()).object();
            QHash<QString, QJsonObject> approvedOutbounds;
            collectApprovedOutbounds(parseJsonText(QString::fromUtf8(serversJson)), approvedOutbounds);

            QJsonArray enforcedOutbounds;
            bool hasApprovedProxy = false;

            for (const QJsonValue &outboundValue : config.value(QStringLiteral("outbounds")).toArray()) {
                const QJsonObject outbound = outboundValue.toObject();
                const QString protocol = outbound.value(QStringLiteral("protocol")).toString().toLower();

                if (directOutboundProtocols.contains(protocol)) {
                    if (outbound.value(QStringLiteral("settings")).toObject().contains(QStringLiteral("redirect"))) {
                        return false;
                    }
                    enforcedOutbounds.append(outbound);
                    continue;
                }
                if (!isProxyProtocol(protocol)) {
                    return false;
                }

                const auto endpoints = outboundEndpoints(protocol, outbound.value(QStringLiteral("settings")).toObject());
                if (endpoints.size() != 1) {
                    return false;
                }
                const auto approved = approvedOutbounds.constFind(
                        endpointKey(protocol, endpoints.first().first, endpoints.first().second));
                if (approved == approvedOutbounds.constEnd()) {
                    return false;
                }

                QJsonObject enforced = approved.value();
                if (outbound.contains(QStringLiteral("tag"))) {
                    enforced.insert(QStringLiteral("tag"), outbound.value(QStringLiteral("tag")));
                }
                enforcedOutbounds.append(enforced);
                hasApprovedProxy = true;
            }

            if (!hasApprovedProxy) {
                return false;
            }

            config.insert(QStringLiteral("outbounds"), enforcedOutbounds);
            if (config.contains(QStringLiteral("dns"))) {
                QJsonObject dns = config.value(QStringLiteral("dns")).toObject();
                dns.remove(QStringLiteral("hosts"));
                config.insert(QStringLiteral("dns"), dns);
            }
            xrayConfig = QString::fromUtf8(QJsonDocument(config).toJson(QJsonDocument::Compact));

            if (socksPorts) {
                for (const QJsonValue &inboundValue : config.value(QStringLiteral("inbounds")).toArray()) {
                    const QJsonObject inbound = inboundValue.toObject();
                    if (inbound.value(QStringLiteral("protocol")).toString() == QLatin1String("socks")) {
                        socksPorts->insert(inbound.value(QStringLiteral("port")).toInt());
                    }
                }
            }
            return true;
        }

#ifdef Q_OS_WIN
        bool ensureProtectedKey()
        {
            PSECURITY_DESCRIPTOR descriptor = nullptr;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)",
                                                                      SDDL_REVISION_1, &descriptor, nullptr)) {
                return false;
            }

            SECURITY_ATTRIBUTES attributes { sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE };
            HKEY key = nullptr;
            bool ok = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AmneziaVPN\\Managed", 0, nullptr,
                                      REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &attributes, &key,
                                      nullptr)
                    == ERROR_SUCCESS;
            if (ok) {
                ok = RegSetKeySecurity(key, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, descriptor)
                        == ERROR_SUCCESS;
                RegCloseKey(key);
            }
            LocalFree(descriptor);
            return ok;
        }
#endif

        QByteArray protectedServersList()
        {
#ifdef Q_OS_WIN
            QSettings storage(protectedKey, QSettings::Registry64Format);
            return storage.value(serversValue).toString().toUtf8();
#else
            return {};
#endif
        }

        QByteArray protectedSalt(bool createIfMissing)
        {
#ifdef Q_OS_WIN
            QSettings storage(protectedKey, QSettings::Registry64Format);
            QByteArray salt = QByteArray::fromHex(storage.value(saltValue).toString().toLatin1());
            if (salt.isEmpty() && createIfMissing) {
                salt.resize(32);
                QRandomGenerator::system()->fillRange(reinterpret_cast<quint32 *>(salt.data()), salt.size() / 4);
                storage.setValue(saltValue, QString::fromLatin1(salt.toHex()));
                storage.sync();
            }
            return salt;
#else
            Q_UNUSED(createIfMissing)
            return {};
#endif
        }

        bool writePublicServersList(const QByteArray &serversJson, const QByteArray &salt)
        {
#ifdef Q_OS_WIN
            QSettings policy(policyKey, QSettings::Registry64Format);
            policy.setValue(serversValue, QString::fromUtf8(redactedServersList(serversJson, salt)));
            policy.sync();
            return policy.status() == QSettings::NoError;
#else
            Q_UNUSED(serversJson)
            Q_UNUSED(salt)
            return false;
#endif
        }
    }

    bool isEnabled()
    {
#ifdef Q_OS_WIN
        QSettings policy(policyKey, QSettings::Registry64Format);
        return policy.value(managedModeValue, 0).toInt() == 1;
#else
        return false;
#endif
    }

    bool isCurrentProcessAdmin()
    {
#ifdef Q_OS_WIN
        BOOL isMember = FALSE;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        PSID administratorsGroup = nullptr;
        if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0,
                                     0, 0, &administratorsGroup)) {
            if (!CheckTokenMembership(nullptr, administratorsGroup, &isMember)) {
                isMember = FALSE;
            }
            FreeSid(administratorsGroup);
        }
        return isMember == TRUE;
#else
        return false;
#endif
    }

    bool isLocked()
    {
        return isEnabled() && !isCurrentProcessAdmin();
    }

    QByteArray serversList()
    {
#ifdef Q_OS_WIN
        if (isCurrentProcessAdmin()) {
            return protectedServersList();
        }
        QSettings policy(policyKey, QSettings::Registry64Format);
        return policy.value(serversValue).toString().toUtf8();
#else
        return {};
#endif
    }

    bool setServersList(const QByteArray &serversJson)
    {
#ifdef Q_OS_WIN
        if (!isCurrentProcessAdmin() || !ensureProtectedKey()) {
            return false;
        }
        const QByteArray salt = protectedSalt(true);
        QSettings storage(protectedKey, QSettings::Registry64Format);
        storage.setValue(serversValue, QString::fromUtf8(serversJson));
        storage.sync();
        return storage.status() == QSettings::NoError && writePublicServersList(serversJson, salt);
#else
        Q_UNUSED(serversJson)
        return false;
#endif
    }

    void refreshPublicServersList()
    {
#ifdef Q_OS_WIN
        if (!isEnabled() || !isCurrentProcessAdmin() || !ensureProtectedKey()) {
            return;
        }
        if (!writePublicServersList(protectedServersList(), protectedSalt(true))) {
            qWarning() << "Managed mode: failed to publish the servers list";
        }
#endif
    }

    bool resolveXrayConfig(QString &xrayConfig)
    {
        if (!isEnabled()) {
            return true;
        }
#ifdef Q_OS_WIN
        ensureProtectedKey();
#endif
        const QByteArray serversJson = protectedServersList();
        xrayConfig = substituteSecrets(xrayConfig, serversJson, protectedSalt(false));

        QSet<int> socksPorts;
        if (!enforceXrayConfig(xrayConfig, serversJson, &socksPorts)) {
            return false;
        }

        QMutexLocker locker(&socksPortsMutex);
        approvedSocksPorts = socksPorts;
        return true;
    }

    void forgetApprovedXrayConfig()
    {
        QMutexLocker locker(&socksPortsMutex);
        approvedSocksPorts.clear();
    }

    bool isTun2SocksProxyApproved(const QString &proxyUrl)
    {
        if (!isEnabled()) {
            return true;
        }

        const QUrl url(proxyUrl);
        if (url.host() != QLatin1String("127.0.0.1")) {
            return false;
        }

        QMutexLocker locker(&socksPortsMutex);
        return approvedSocksPorts.contains(url.port());
    }

    bool resolveWireGuardConfig(QJsonObject &activateMessage)
    {
        if (!isEnabled()) {
            return true;
        }
#ifdef Q_OS_WIN
        ensureProtectedKey();
#endif
        const QByteArray serversJson = protectedServersList();
        const QString text = QString::fromUtf8(QJsonDocument(activateMessage).toJson(QJsonDocument::Compact));
        activateMessage = QJsonDocument::fromJson(substituteSecrets(text, serversJson, protectedSalt(false)).toUtf8()).object();
        return isWireGuardPeerApprovedBy(activateMessage.value(QStringLiteral("serverPublicKey")).toString(), serversJson);
    }

    QByteArray redactedServersList(const QByteArray &serversJson, const QByteArray &salt)
    {
        const QStringList secrets = secretsOf(serversJson);
        QString text = QString::fromUtf8(serversJson);

        for (const QString &secret : secrets) {
            const QString placeholder = placeholderFor(secret, salt);
            for (const QString &form : encodedForms(secret)) {
                text.replace(form, placeholder);
            }
        }

        static const QRegularExpression encodedLinkPattern(QStringLiteral(R"((?:vmess|ss)://([A-Za-z0-9+/=_\-]{8,}))"),
                                                           QRegularExpression::CaseInsensitiveOption);
        QString result;
        qsizetype last = 0;
        auto links = encodedLinkPattern.globalMatch(text);
        while (links.hasNext()) {
            const auto match = links.next();
            const QByteArray encoded = match.captured(1).toUtf8();
            const QString decoded = QString::fromUtf8(QByteArray::fromBase64(encoded, QByteArray::Base64UrlEncoding))
                    + QString::fromUtf8(QByteArray::fromBase64(encoded));
            const bool leaksSecret = std::any_of(secrets.cbegin(), secrets.cend(),
                                                 [&decoded](const QString &secret) { return decoded.contains(secret); });
            result += text.mid(last, match.capturedStart(1) - last);
            result += leaksSecret ? QStringLiteral("redacted") : match.captured(1);
            last = match.capturedEnd(1);
        }
        result += text.mid(last);

        for (const QString &secret : secrets) {
            for (const QString &form : encodedForms(secret)) {
                if (result.contains(form)) {
                    qWarning() << "Managed mode: a secret could not be hidden, the public servers list is left empty";
                    return QByteArrayLiteral("[]");
                }
            }
        }

        return result.toUtf8();
    }

    QString substituteSecrets(const QString &text, const QByteArray &serversJson, const QByteArray &salt)
    {
        QString result = text;
        for (const QString &secret : secretsOf(serversJson)) {
            result.replace(placeholderFor(secret, salt), jsonEscaped(secret));
        }
        return result;
    }

    bool enforceXrayConfigBy(QString &xrayConfig, const QByteArray &serversJson)
    {
        return enforceXrayConfig(xrayConfig, serversJson, nullptr);
    }

    bool isWireGuardPeerApprovedBy(const QString &serverPublicKey, const QByteArray &serversJson)
    {
        const QString key = serverPublicKey.trimmed();
        return !key.isEmpty() && approvedValuesOf(serversJson).contains(key);
    }
}
