#Requires -RunAsAdministrator
param(
    [ValidatePattern('^[A-Za-z0-9_-]{1,20}$')]
    [string]$AccountName = 'PurpleRepeat',

    [ValidateRange(1, 2000)]
    [int]$Attempts = 2000,

    [switch]$Cleanup
)

# Prérequis : Audit Logon doit enregistrer les échecs pour obtenir les 4625.

function Write-Timestamp {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
}

if ($Cleanup) {
    Remove-LocalUser -Name $AccountName -ErrorAction SilentlyContinue
    Write-Timestamp "Suppression demandée : $AccountName"
    return
}

if (Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue) {
    throw "Le compte $AccountName existe déjà. Lancez -Cleanup ou choisissez un autre nom."
}

$startedAt = Get-Date
$validPassword = ConvertTo-SecureString ("Purple!{0}" -f [guid]::NewGuid().ToString('N')) -AsPlainText -Force
$invalidPassword = ConvertTo-SecureString ("Invalid!{0}" -f [guid]::NewGuid().ToString('N')) -AsPlainText -Force

New-LocalUser -Name $AccountName -Password $validPassword -PasswordNeverExpires | Out-Null
Write-Timestamp "Compte créé : $AccountName — début de $Attempts échecs de connexion."

$credential = [pscredential]::new(".\$AccountName", $invalidPassword)
1..$Attempts | ForEach-Object {
    try {
        Start-Process cmd.exe -ArgumentList '/c exit 0' -Credential $credential -WindowStyle Hidden -ErrorAction Stop
    }
    catch {
        # L'échec d'ouverture de session est attendu.
    }

    if ($_ % 100 -eq 0 -or $_ -eq $Attempts) {
        Write-Timestamp "Tentatives effectuées : $_/$Attempts"
    }
}

Write-Timestamp 'Test terminé. Événements 4625 et 4740 observés :'
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; StartTime = $startedAt } |
    Where-Object { $_.Id -in 4625, 4740 -and $_.Message -match $AccountName } |
    Select-Object TimeCreated, Id, Message
