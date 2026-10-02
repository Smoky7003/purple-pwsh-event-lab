#Requires -RunAsAdministrator
param(
    [ValidatePattern('^[A-Za-z0-9_-]{1,17}$')]
    [string]$Prefix = 'PurpleUsr',

    [ValidateRange(1, 100)]
    [int]$UserCount = 40,

    [switch]$Cleanup
)

# Prérequis : Audit User Account Management doit être activé.

function Write-Timestamp {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
}

$accounts = 1..$UserCount | ForEach-Object { "$Prefix$_" }
$startedAt = Get-Date

if ($Cleanup) {
    Write-Timestamp "Début de la suppression de $UserCount comptes."
    foreach ($account in $accounts) {
        Remove-LocalUser -Name $account -ErrorAction SilentlyContinue
        Write-Timestamp "Suppression demandée : $account"
    }

    Write-Timestamp 'Événements 4726 observés :'
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4726; StartTime = $startedAt } |
        Where-Object Message -match $Prefix |
        Select-Object TimeCreated, Id, Message
    return
}

$password = ConvertTo-SecureString ("Purple!{0}" -f [guid]::NewGuid().ToString('N')) -AsPlainText -Force
Write-Timestamp "Début de la création de $UserCount comptes."

foreach ($account in $accounts) {
    if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) {
        throw "Le compte $account existe déjà. Lancez -Cleanup ou changez le préfixe."
    }

    New-LocalUser -Name $account -Password $password -PasswordNeverExpires | Out-Null
    Write-Timestamp "Compte créé : $account"
}

Write-Timestamp 'Événements 4720 observés :'
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720; StartTime = $startedAt } |
    Where-Object Message -match $Prefix |
    Select-Object TimeCreated, Id, Message
