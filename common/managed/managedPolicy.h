#ifndef MANAGEDPOLICY_H
#define MANAGEDPOLICY_H

#include <QByteArray>
#include <QJsonObject>
#include <QString>

namespace amnezia::managed
{
    bool isEnabled();
    bool isCurrentProcessAdmin();
    bool isLocked();

    QByteArray serversList();
    bool setServersList(const QByteArray &serversJson);
    void refreshPublicServersList();

    bool resolveXrayConfig(QString &xrayConfig);
    void forgetApprovedXrayConfig();
    bool isTun2SocksProxyApproved(const QString &proxyUrl);
    bool resolveWireGuardConfig(QJsonObject &activateMessage);

    QByteArray redactedServersList(const QByteArray &serversJson, const QByteArray &salt);
    QString substituteSecrets(const QString &text, const QByteArray &serversJson, const QByteArray &salt);
    bool enforceXrayConfigBy(QString &xrayConfig, const QByteArray &serversJson);
    bool isWireGuardPeerApprovedBy(const QString &serverPublicKey, const QByteArray &serversJson);
}

#endif // MANAGEDPOLICY_H
