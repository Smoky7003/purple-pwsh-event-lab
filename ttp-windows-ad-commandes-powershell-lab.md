# TTP Windows et Active Directory — commandes PowerShell de labo

Ce guide est réservé à un environnement Windows/AD isolé, explicitement autorisé et restaurable. Il fournit des tests unitaires : exécuter **un seul test à la fois**, vérifier l'état obtenu sur le bon hôte, puis nettoyer avant de continuer.

Le guide ne modifie ni les règles de détection ni la stratégie d'audit. Il ne contient aucun contournement de Tamper Protection, aucune demande de ticket Kerberos, aucune usurpation d'identité et aucune authentification au moyen de la clé ajoutée à `msDS-KeyCredentialLink`.

## Valeurs de labo à adapter

| Valeur | Rôle |
|---|---|
| `LAB-DC01.lab.local` | Contrôleur de domaine interrogé et hôte où rechercher les événements AD |
| `DC=lab,DC=local` | Base DN LDAP autorisée |
| `LAB-SRV01` | Compte ordinateur cible jetable pour le test RBCD |
| `LAB-RBCD01` | Compte ordinateur contrôlé et jetable autorisé dans le test RBCD |
| `LAB-KeyCred-User` | Utilisateur désactivé et sans privilège, réservé au test Key Credential |
| `LAB-FS01`, `LAB-APP01` | Cibles explicitement autorisées pour les tests SMB/RPC |

## Prérequis communs

- Utiliser uniquement des machines et objets AD de labo dédiés, avec snapshot ou autre méthode de restauration.
- Ouvrir Windows PowerShell 5.1 avec le niveau de privilège requis par le test. Garder une seconde console d'administration disponible pour le nettoyage.
- Vérifier l'heure, le DNS, la connectivité et l'identité réellement utilisée avant de conclure à un problème de détection.
- Ne jamais placer de mot de passe, certificat exporté ou clé privée dans ce fichier ou dans la ligne de commande.
- Les événements AD sont à chercher sur le contrôleur de domaine qui a traité l'écriture. Le paramètre `-Server 'LAB-DC01.lab.local'` fixe ce point pour les tests AD.
- L'événement 5136 nécessite `Audit Directory Service Changes` et une SACL adaptée sur l'objet ou l'attribut. L'absence de 5136 ne prouve donc pas que l'écriture a échoué.

### Interprétation des résultats

| Observation | Conclusion |
|---|---|
| Erreur de commande et état cible inchangé | Commande lancée, mais action non réalisée : le problème vient de la commande ou d'un prérequis. |
| État cible modifié, mais aucune télémétrie attendue | Action exécutée ; détection, audit ou collecte à investiguer. |
| Preuve uniquement sur la source | Preuve partielle ; il manque la confirmation de la cible ou du DC. |
| Ni lecture d'état fiable ni preuve cible | Résultat indéterminé ; ne pas déclarer un échec de détection. |

---

## 1 — Désactivation temporaire de la protection temps réel Microsoft Defender

**Portée du test :** ce test reproduit une altération temporaire de la protection temps réel. Il ne désinstalle pas Defender, n'arrête pas `WinDefend`, ne crée pas d'exclusion et ne contourne pas Tamper Protection.

### Prérequis

- VM Windows de labo isolée ; ne pas utiliser un poste de production.
- Microsoft Defender Antivirus doit être le moteur actif.
- Console PowerShell élevée avec droits administrateur local.
- Si l'appareil est administré par Defender for Endpoint, activer préalablement le **mode troubleshooting** approuvé. Si Tamper Protection bloque le changement, arrêter le test au lieu de tenter un contournement.

### État initial et commande TTP

```powershell
Get-MpComputerStatus | Select-Object AMRunningMode, IsTamperProtected, RealTimeProtectionEnabled
Set-MpPreference -DisableRealtimeMonitoring $true
Get-MpComputerStatus | Select-Object AMRunningMode, IsTamperProtected, RealTimeProtectionEnabled
```

La preuve d'exécution est `RealTimeProtectionEnabled = False`. Une commande sans erreur ne suffit pas : une stratégie centrale ou Tamper Protection peut la bloquer ou l'annuler.

### Nettoyage immédiat

```powershell
Set-MpPreference -DisableRealtimeMonitoring $false
Get-MpComputerStatus | Select-Object AMRunningMode, IsTamperProtected, RealTimeProtectionEnabled
```

Le nettoyage est validé uniquement lorsque `RealTimeProtectionEnabled = True`.

### Preuves attendues

- **Hôte cible :** changement réel de `RealTimeProtectionEnabled`, puis retour à `True`.
- **Télémétrie :** processus PowerShell et, selon la configuration, événements Microsoft Defender/Operational 5001 et/ou 5007.
- Si la valeur reste `True`, la commande n'a pas réalisé le TTP : vérifier élévation, moteur actif, politique effective et Tamper Protection avant d'évaluer la détection.

---

## 2 — Modification RBCD de `msDS-AllowedToActOnBehalfOfOtherIdentity`

**Portée du test :** écrit la configuration Resource-Based Constrained Delegation sur un compte ordinateur jetable, puis la retire. Le test s'arrête après la modification de l'attribut : aucun ticket de service n'est demandé et aucune identité n'est usurpée.

### Prérequis

- RSAT et module PowerShell `ActiveDirectory` disponibles sur un poste d'administration.
- `LAB-SRV01` et `LAB-RBCD01` sont des comptes ordinateurs de labo dédiés.
- L'attribut de `LAB-SRV01` doit être vide avant le test. Le garde-fou ci-dessous arrête l'exécution s'il existe déjà une délégation.
- L'identité courante dispose du droit d'écriture sur la propriété concernée de `LAB-SRV01` (`WriteProperty` ou contrôle équivalent).
- Le DC `LAB-DC01.lab.local` est joignable.

### Garde-fou et commande TTP

```powershell
Import-Module ActiveDirectory

$DomainController = 'LAB-DC01.lab.local'
$RBCDTarget = 'LAB-SRV01'
$RBCDPrincipal = 'LAB-RBCD01'

$RBCDInitial = (Get-ADComputer -Server $DomainController -Identity $RBCDTarget -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity').'msDS-AllowedToActOnBehalfOfOtherIdentity'
if ($null -ne $RBCDInitial) {
    throw 'Attribut déjà renseigné : arrêt pour ne pas écraser une délégation légitime.'
}

Set-ADComputer -Server $DomainController -Identity $RBCDTarget -PrincipalsAllowedToDelegateToAccount (Get-ADComputer -Server $DomainController -Identity $RBCDPrincipal)
```

### Validation

```powershell
Get-ADComputer -Server $DomainController -Identity $RBCDTarget -Properties PrincipalsAllowedToDelegateToAccount |
    Select-Object Name, PrincipalsAllowedToDelegateToAccount
```

La sortie doit contenir le DN de `LAB-RBCD01`.

### Nettoyage

```powershell
Set-ADComputer -Server $DomainController -Identity $RBCDTarget -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'

Get-ADComputer -Server $DomainController -Identity $RBCDTarget -Properties PrincipalsAllowedToDelegateToAccount |
    Select-Object Name, PrincipalsAllowedToDelegateToAccount
```

Ce nettoyage par `-Clear` est acceptable uniquement parce que le garde-fou impose une valeur initialement vide.

### Preuves attendues

- **DC fixé par `-Server` :** Security 5136 avec `LDAP Display Name: msDS-AllowedToActOnBehalfOfOtherIdentity`, si l'audit et la SACL le permettent.
- **État AD :** lecture positive de `PrincipalsAllowedToDelegateToAccount`, puis valeur vide après nettoyage.
- Une erreur `Access is denied` ou `Insufficient access rights` signifie que l'écriture n'a pas été réalisée ; ce n'est pas un défaut de détection.

---

## 3 — Ajout contrôlé à `msDS-KeyCredentialLink`

**Portée du test :** génère une valeur Key Credential valide pour un utilisateur de labo désactivé, l'ajoute à l'attribut, puis retire exactement cette valeur. Aucune authentification PKINIT n'est effectuée et la clé privée n'est pas exportée.

### Prérequis

- Utilisateur `LAB-KeyCred-User` dédié, **désactivé**, sans groupe privilégié, sans clé Windows Hello/FIDO légitime et sans droit d'ouverture de session.
- Modules `ActiveDirectory` et `DSInternals` disponibles sur un poste d'administration, pas installés directement sur un DC. Le module DSInternals doit provenir d'une source approuvée et avoir été contrôlé avant le test.
- Schéma AD prenant en charge `msDS-KeyCredentialLink`.
- Droit d'écriture sur cet attribut ou contrôle équivalent sur l'objet utilisateur.
- Conserver la même console jusqu'au nettoyage. Le bloc affiche le `DeviceId` et le thumbprint nécessaires à une récupération ciblée.

### Garde-fou et commande TTP

```powershell
Import-Module ActiveDirectory
Import-Module DSInternals

$DomainController = 'LAB-DC01.lab.local'
$KeyCredTarget = Get-ADUser -Server $DomainController -Identity 'LAB-KeyCred-User' -Properties Enabled, MemberOf, 'msDS-KeyCredentialLink'

if ($KeyCredTarget.Enabled) {
    throw 'Le compte de test doit être désactivé.'
}
if ($null -ne $KeyCredTarget.'msDS-KeyCredentialLink') {
    throw 'Attribut déjà renseigné : utiliser un compte de labo sans credential légitime.'
}

$DeviceId = New-Guid
$Certificate = New-SelfSignedCertificate `
    -Subject 'CN=LAB-KeyCredentialLink-Test' `
    -KeyLength 2048 `
    -Provider 'Microsoft Strong Cryptographic Provider' `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -NotAfter (Get-Date).AddHours(2) `
    -TextExtension '2.5.29.19={text}false', '2.5.29.37={text}1.3.6.1.4.1.311.20.2.2' `
    -SuppressOid '2.5.29.14' `
    -KeyUsage None `
    -KeyExportPolicy NonExportable

$KeyCredential = Get-ADKeyCredential -Certificate $Certificate -DeviceId $DeviceId -OwnerDN $KeyCredTarget.DistinguishedName
$KeyCredentialValue = $KeyCredential.ToDNWithBinary()

Set-ADObject -Server $DomainController -Identity $KeyCredTarget.DistinguishedName -Add @{
    'msDS-KeyCredentialLink' = $KeyCredentialValue
}

[pscustomobject]@{
    DeviceId              = $DeviceId
    CertificateThumbprint = $Certificate.Thumbprint
    ValuePresent          = (Get-ADUser -Server $DomainController -Identity $KeyCredTarget -Properties 'msDS-KeyCredentialLink').'msDS-KeyCredentialLink' -contains $KeyCredentialValue
}
```

La preuve d'exécution est `ValuePresent = True`.

### Nettoyage dans la même console

```powershell
Set-ADObject -Server $DomainController -Identity $KeyCredTarget.DistinguishedName -Remove @{
    'msDS-KeyCredentialLink' = $KeyCredentialValue
}

Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($Certificate.Thumbprint)" -Force

(Get-ADUser -Server $DomainController -Identity $KeyCredTarget -Properties 'msDS-KeyCredentialLink').'msDS-KeyCredentialLink' -contains $KeyCredentialValue
```

Le dernier résultat doit être `False`. Ne pas utiliser `-Clear` sur un objet pouvant contenir une clé légitime.

### Récupération ciblée si la console a été perdue

Remplacer `<DEVICE-ID-NOTE>` par le GUID affiché pendant le test. Cette procédure retrouve puis retire uniquement la valeur créée par ce test.

```powershell
Import-Module ActiveDirectory
Import-Module DSInternals

$DomainController = 'LAB-DC01.lab.local'
$KeyCredTarget = Get-ADUser -Server $DomainController -Identity 'LAB-KeyCred-User' -Properties 'msDS-KeyCredentialLink'
$KeyCredentialValue = @($KeyCredTarget.'msDS-KeyCredentialLink') | Where-Object {
    (Get-ADKeyCredential -DNWithBinaryData $_).DeviceId -eq [guid]'<DEVICE-ID-NOTE>'
}

if (@($KeyCredentialValue).Count -ne 1) {
    throw 'Valeur exacte introuvable ou ambiguë : ne pas effacer l''attribut en bloc.'
}

Set-ADObject -Server $DomainController -Identity $KeyCredTarget.DistinguishedName -Remove @{
    'msDS-KeyCredentialLink' = $KeyCredentialValue
}
```

Supprimer ensuite uniquement le certificat ayant le thumbprint affiché pendant le test, s'il existe encore dans `Cert:\CurrentUser\My`.

### Preuves attendues

- **DC fixé par `-Server` :** Security 5136 avec `LDAP Display Name: msDS-KeyCredentialLink`, si l'audit et la SACL le permettent.
- **État AD :** `ValuePresent = True`, puis absence exacte de la valeur après nettoyage.
- **Poste d'administration :** création puis suppression du certificat local non exportable.
- Une écriture refusée prouve une tentative seulement. Sans lecture positive de l'attribut, la modification n'est pas confirmée ; ne pas déclarer le TTP exécuté.

---

## 4 — Scan borné des partages réseau

**Portée du test :** énumère les partages publiés de deux hôtes explicitement autorisés. La liste statique évite un balayage accidentel du domaine ou d'un sous-réseau entier.

### Prérequis

- Cibles `LAB-FS01` et `LAB-APP01` incluses dans le périmètre autorisé.
- Résolution DNS, TCP/445 et service Server/SMB disponibles.
- Identité Windows courante autorisée à énumérer les partages visibles.
- Audit de partage déjà configuré sur les cibles si des événements 5140/5145 sont attendus.

### Commande TTP

```powershell
$Targets = 'LAB-FS01', 'LAB-APP01'

foreach ($Target in $Targets) {
    if (Test-NetConnection -ComputerName $Target -Port 445 -InformationLevel Quiet -WarningAction SilentlyContinue) {
        Write-Host "Partages visibles sur $Target"
        net.exe view "\\$Target"
    }
    else {
        Write-Warning "$Target : TCP/445 indisponible"
    }
}
```

### Nettoyage

Aucun état persistant n'est créé par `Test-NetConnection` ou `net view`. Ne pas lancer un large `net use * /delete`, qui pourrait couper des connexions légitimes de l'utilisateur.

### Preuves attendues

- **Source :** `powershell.exe`, `net.exe` et connexions vers TCP/445 des deux cibles.
- **Cible :** selon la politique d'audit et l'état des connexions SMB, peuvent apparaître un 4624 type 3 lors d'une nouvelle authentification, ainsi que des 5140/5145 relatifs à `IPC$` et `srvsvc`.
- `Access is denied` ou une liste vide ne prouve pas une énumération réussie. Conserver séparément la tentative réseau et le résultat retourné.

---

## 5 — Énumération des sessions SMB via RPC named pipe `srvsvc`

**Portée du test :** appelle directement l'API Windows `NetSessionEnum` contre `LAB-FS01`. Elle retourne les sessions réseau du service Server/SMB ; elle n'énumère pas toutes les sessions interactives, RDP ou console. Le transport MS-SRVS utilise habituellement RPC sur SMB avec l'endpoint nommé `\PIPE\srvsvc`, visible comme `srvsvc` sous le partage `IPC$` ; confirmer ce transport avec la télémétrie cible ou une capture réseau.

### Prérequis

- `LAB-FS01` explicitement autorisé, résolvable et joignable sur TCP/445.
- Service Server actif sur la cible et authentification Windows valide.
- Les droits dépendent du niveau demandé et du durcissement. Un hôte durci peut retourner `ERROR_ACCESS_DENIED` ; cela signifie que l'énumération n'a pas abouti.
- Named Pipe/File Share auditing déjà configuré si une preuve 5145 est attendue.

### Commande TTP

```powershell
$TypeDefinition = @'
using System;
using System.Runtime.InteropServices;

public static class LabNetSession
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SESSION_INFO_10
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string sesi10_cname;
        [MarshalAs(UnmanagedType.LPWStr)] public string sesi10_username;
        public uint sesi10_time;
        public uint sesi10_idle_time;
    }

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int NetSessionEnum(
        string servername,
        string uncClientName,
        string username,
        int level,
        out IntPtr buffer,
        int preferredMaximumLength,
        out int entriesRead,
        out int totalEntries,
        ref int resumeHandle);

    [DllImport("Netapi32.dll")]
    public static extern int NetApiBufferFree(IntPtr buffer);
}
'@

if (-not ('LabNetSession' -as [type])) {
    Add-Type -TypeDefinition $TypeDefinition
}

$Buffer = [IntPtr]::Zero
$EntriesRead = 0
$TotalEntries = 0
$ResumeHandle = 0

$Status = [LabNetSession]::NetSessionEnum(
    '\\LAB-FS01',
    $null,
    $null,
    10,
    [ref]$Buffer,
    -1,
    [ref]$EntriesRead,
    [ref]$TotalEntries,
    [ref]$ResumeHandle
)

try {
    if ($Status -notin 0, 234) {
        throw "NetSessionEnum a échoué avec le statut Win32 $Status"
    }

    if ($Status -eq 234) {
        Write-Warning 'ERROR_MORE_DATA : les résultats affichés peuvent être partiels.'
    }

    [pscustomobject]@{
        Status       = $Status
        EntriesRead  = $EntriesRead
        TotalEntries = $TotalEntries
    }

    $EntrySize = [Runtime.InteropServices.Marshal]::SizeOf([type][LabNetSession+SESSION_INFO_10])

    for ($Index = 0; $Index -lt $EntriesRead; $Index++) {
        $Pointer = [IntPtr]::Add($Buffer, $Index * $EntrySize)
        $Session = [Runtime.InteropServices.Marshal]::PtrToStructure(
            $Pointer,
            [type][LabNetSession+SESSION_INFO_10]
        )

        [pscustomobject]@{
            Client           = $Session.sesi10_cname
            User             = $Session.sesi10_username
            ConnectedSeconds = $Session.sesi10_time
            IdleSeconds      = $Session.sesi10_idle_time
        }
    }
}
finally {
    if ($Buffer -ne [IntPtr]::Zero) {
        [void][LabNetSession]::NetApiBufferFree($Buffer)
    }
}
```

### Nettoyage

Aucun état distant n'est créé. Le buffer natif est libéré dans `finally`. Le type .NET `LabNetSession` reste chargé uniquement jusqu'à la fermeture de la console PowerShell.

### Preuves attendues

- **Résultat fonctionnel :** `Status = 0` confirme une réponse complète ; `Status = 234` indique une réponse partielle. Les objets suivants exposent `Client`, `User`, `ConnectedSeconds` et `IdleSeconds`. Zéro session peut être un résultat légitime.
- **Source/réseau :** `powershell.exe` vers TCP/445 de `LAB-FS01`.
- **Cible :** un 4624 type 3 peut apparaître si une nouvelle authentification SMB est créée ; avec l'audit approprié, un 5145 peut viser le partage `IPC$` avec `srvsvc` comme chemin relatif.
- Une capture réseau ou une télémétrie named pipe est nécessaire pour affirmer le transport exact ; le code source seul ne constitue pas une preuve réseau.

---

## 6 — Énumération LDAP bornée

**Portée du test :** utilise `System.DirectoryServices.DirectorySearcher` afin d'effectuer une vraie recherche LDAP limitée à 50 comptes ordinateurs sous la base DN autorisée. Le test utilise l'identité Windows courante et ne contient aucun secret.

### Prérequis

- DC `LAB-DC01.lab.local` et base `DC=lab,DC=local` explicitement autorisés.
- Résolution DNS et LDAP disponibles selon la politique du domaine.
- Compte de domaine disposant des droits de lecture ordinaires sur la base recherchée.
- Si le domaine impose LDAPS ou des exigences particulières de signature/channel binding, adapter la connexion conformément à la politique ; ne pas réduire le durcissement du DC pour faire réussir le test.

### Commande TTP

```powershell
$Root = [System.DirectoryServices.DirectoryEntry]::new(
    'LDAP://LAB-DC01.lab.local/DC=lab,DC=local'
)

$Searcher = [System.DirectoryServices.DirectorySearcher]::new($Root)
$Searcher.Filter = '(&(objectCategory=computer)(dNSHostName=*))'
$Searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
$Searcher.PageSize = 50
$Searcher.SizeLimit = 50
$Searcher.ServerTimeLimit = [TimeSpan]::FromSeconds(10)

[void]$Searcher.PropertiesToLoad.Add('distinguishedName')
[void]$Searcher.PropertiesToLoad.Add('dNSHostName')

$Results = $null

try {
    $Results = $Searcher.FindAll()

    $Results | ForEach-Object {
        [pscustomobject]@{
            DistinguishedName = [string]$_.Properties['distinguishedname'][0]
            DNSHostName       = [string]$_.Properties['dnshostname'][0]
        }
    }
}
finally {
    if ($null -ne $Results) {
        $Results.Dispose()
    }
    $Searcher.Dispose()
    $Root.Dispose()
}
```

### Nettoyage

Aucune modification AD n'est effectuée. Les objets LDAP clients sont libérés dans `finally`.

### Preuves attendues

- **Résultat fonctionnel :** au plus 50 objets avec DN et `dNSHostName`.
- **Source/réseau :** connexion LDAP de `powershell.exe` vers le DC indiqué.
- **DC :** l'événement 1644 dépend de la journalisation LDAP et des seuils configurés ; 4662 dépend d'une SACL. Leur absence ne prouve pas que la recherche n'a pas été exécutée.
- Une erreur de bind, de certificat ou de signature indique un prérequis de connexion non satisfait. Ne pas désactiver la signature LDAP ou le channel binding pour contourner l'erreur.

---

## Sources primaires

- [Microsoft Learn — Set-MpPreference](https://learn.microsoft.com/powershell/module/defender/set-mppreference)
- [Microsoft Learn — scénarios du mode troubleshooting Defender](https://learn.microsoft.com/defender-endpoint/troubleshooting-mode-scenarios)
- [Microsoft Learn — Set-ADComputer et PrincipalsAllowedToDelegateToAccount](https://learn.microsoft.com/powershell/module/activedirectory/set-adcomputer)
- [Microsoft Open Specifications — msDS-KeyCredentialLink](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/f70afbcc-780e-4d91-850c-cfadce5bb15c)
- [DSInternals — Get-ADKeyCredential](https://github.com/MichaelGrafnetter/DSInternals/blob/master/Documentation/PowerShell/Get-ADKeyCredential.md)
- [Microsoft Learn — NetSessionEnum](https://learn.microsoft.com/windows/win32/api/lmshare/nf-lmshare-netsessionenum)
- [Microsoft Open Specifications — NetrSessionEnum / MS-SRVS](https://learn.microsoft.com/openspecs/windows_protocols/ms-srvs/02b1f559-fda2-4ba3-94c2-806eb2777183)
- [Microsoft Learn — DirectorySearcher](https://learn.microsoft.com/dotnet/api/system.directoryservices.directorysearcher)
- [Microsoft Learn — événement 5136](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136)
- [Microsoft Learn — LDAP signing](https://learn.microsoft.com/windows-server/identity/ad-ds/ldap-signing)

