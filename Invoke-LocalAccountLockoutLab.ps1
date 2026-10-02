#Requires -RunAsAdministrator
param(
    [ValidatePattern('^[A-Za-z0-9_-]{1,15}$')]
    [string]$Prefix = 'PurpleLk',

    [ValidateRange(1, 10)]
    [int]$UserCount = 10,

    [switch]$Cleanup
)

# Prérequis : la stratégie locale doit déjà verrouiller après 5 échecs.

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

$validPassword = ConvertTo-SecureString ("Purple!{0}" -f [guid]::NewGuid().ToString('N')) -AsPlainText -Force
$invalidPassword = ConvertTo-SecureString ("Invalid!{0}" -f [guid]::NewGuid().ToString('N')) -AsPlainText -Force

Write-Timestamp "Début du test : $UserCount comptes, 5 échecs par compte."
foreach ($account in $accounts) {
    if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) {
        throw "Le compte $account existe déjà. Lancez -Cleanup ou changez le préfixe."
    }
    New-LocalUser -Name $account -Password $validPassword -PasswordNeverExpires | Out-Null
    Write-Timestamp "Compte créé : $account"
    1..5 | ForEach-Object {
        Write-Timestamp "$account — tentative $_/5"
        try {
            Start-Process cmd.exe -ArgumentList '/c exit 0' -Credential ([pscredential]::new(".\$account", $invalidPassword)) -WindowStyle Hidden -ErrorAction Stop
        }
        catch {
            # Les cinq échecs d'ouverture de session sont attendus.
        }
    }
    Write-Timestamp "Fin des tentatives : $account"
}
Write-Timestamp 'Test terminé.'
