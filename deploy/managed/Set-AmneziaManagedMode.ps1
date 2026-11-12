#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Включает управляемый режим AmneziaVPN, переносит подключения между компьютерами.

.DESCRIPTION
    В управляемом режиме:
      - обычный пользователь видит только кнопку подключения;
      - добавлять и менять подключения можно, только запустив AmneziaVPN от имени администратора;
      - ключи хранятся в разделе реестра, который пользователь не может прочитать;
      - служба AmneziaVPN подключается только к серверам администратора.

.EXAMPLE
    .\Set-AmneziaManagedMode.ps1 -Enable
    Включить режим на этом компьютере.

.EXAMPLE
    .\Set-AmneziaManagedMode.ps1 -Export C:\Secure\amnezia.reg
    Сохранить подключения в файл для других компьютеров. В файле есть ключи — храните его закрыто.

.EXAMPLE
    .\Set-AmneziaManagedMode.ps1 -Enable -Import \\server\vpn$\amnezia.reg
    Включить режим и поставить подключения из файла. Подходит для сценария автозагрузки компьютера (GPO).

.EXAMPLE
    .\Set-AmneziaManagedMode.ps1 -Disable
#>
[CmdletBinding(DefaultParameterSetName = 'Enable')]
param(
    [Parameter(ParameterSetName = 'Enable')][switch]$Enable,
    [Parameter(ParameterSetName = 'Enable')][string]$Import,
    [Parameter(ParameterSetName = 'Disable')][switch]$Disable,
    [Parameter(ParameterSetName = 'Disable')][switch]$RemoveServers,
    [Parameter(ParameterSetName = 'Export')][string]$Export
)

$ErrorActionPreference = 'Stop'
$policyKey     = 'HKLM:\SOFTWARE\Policies\AmneziaVPN'
$protectedKey  = 'HKLM:\SOFTWARE\AmneziaVPN\Managed'
$protectedSddl = 'D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)'

function Protect-SecretKey {
    New-Item -Path $protectedKey -Force | Out-Null
    $acl = New-Object System.Security.AccessControl.RegistrySecurity
    $acl.SetSecurityDescriptorSddlForm($protectedSddl)
    Set-Acl -Path $protectedKey -AclObject $acl
}

function Restart-AmneziaService {
    $svc = Get-Service -Name 'AmneziaVPN-service' -ErrorAction SilentlyContinue
    if ($svc) { Restart-Service -Name $svc.Name -Force }
}

switch ($PSCmdlet.ParameterSetName) {
    'Enable' {
        Protect-SecretKey
        if ($Import) {
            $content = Get-Content -LiteralPath $Import -Raw
            if ($content -notmatch '\[HKEY_LOCAL_MACHINE\\SOFTWARE\\AmneziaVPN\\Managed\]') {
                throw "В файле $Import нет подключений AmneziaVPN."
            }
            & reg.exe import $Import 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Не удалось импортировать $Import" }
            Protect-SecretKey
        }
        New-Item -Path $policyKey -Force | Out-Null
        New-ItemProperty -Path $policyKey -Name ManagedMode -Value 1 -PropertyType DWord -Force | Out-Null
        Get-Process -Name 'AmneziaVPN' -ErrorAction SilentlyContinue | Stop-Process -Force
        Restart-AmneziaService

        if ($Import) {
            Write-Host 'Управляемый режим включён, подключения установлены.' -ForegroundColor Green
        } else {
            Write-Host @'
Управляемый режим включён.

Дальше:
  1. Правой кнопкой по ярлыку AmneziaVPN → «Запуск от имени администратора».
  2. Добавьте подключение (ключ vless:// или vpn://).
  3. Закройте программу. Пользователь увидит только кнопку подключения.
'@ -ForegroundColor Green
        }
    }
    'Disable' {
        Remove-ItemProperty -Path $policyKey -Name ManagedMode -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $policyKey -Name Servers -ErrorAction SilentlyContinue
        if ($RemoveServers) { Remove-Item -Path $protectedKey -Recurse -Force -ErrorAction SilentlyContinue }
        Restart-AmneziaService
        Write-Host 'Управляемый режим выключен.' -ForegroundColor Yellow
    }
    'Export' {
        if (-not (Get-ItemProperty -Path $protectedKey -Name Servers -ErrorAction SilentlyContinue)) {
            throw 'Подключений нет. Сначала добавьте подключение под администратором.'
        }
        & reg.exe export 'HKLM\SOFTWARE\AmneziaVPN\Managed' $Export /y | Out-Null
        Write-Host "Сохранено в $Export. В файле есть ключи: не кладите его туда, где его могут прочитать пользователи." -ForegroundColor Yellow
    }
}
