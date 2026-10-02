#Requires -RunAsAdministrator
param(
    [ValidatePattern('^[A-Za-z0-9_-]{1,15}$')]
    [string]$Prefix = 'PurpleDis',

    [ValidateRange(1, 10)]
    [int]$UserCount = 10,

    [switch]$Cleanup
)

# Prérequis : Audit User Account Management doit être activé.

function Write-Timestamp {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
}

$accounts = 1..$UserCount | ForEach-Object { "$Prefix$_" }

if ($Cleanup) {
    Write-Timestamp 'Début du nettoyage.'
    $accounts | ForEach-Object {
        Remove-LocalUser -Name $_ -ErrorAction SilentlyContinue
    }
    Write-Timestamp 'Nettoyage terminé.'
    return
}

$startedAt = Get-Date
$password = ConvertTo-SecureString ("Purple!{0}" -f [guid]::NewGuid().ToString('N')) -AsPlainText -Force

Write-Timestamp "Début du test : $UserCount comptes à désactiver."
foreach ($account in $accounts) {
    if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) {
        throw "Le compte $account existe déjà. Lancez -Cleanup ou changez le préfixe."
    }

    New-LocalUser -Name $account -Password $password -PasswordNeverExpires | Out-Null
    Write-Timestamp "Compte créé : $account"

    Disable-LocalUser -Name $account
    Write-Timestamp "Compte désactivé : $account"
}

Write-Timestamp 'Événements 4725 observés :'
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4725; StartTime = $startedAt } |
    Where-Object Message -match $Prefix |
    Select-Object TimeCreated, Id, Message
