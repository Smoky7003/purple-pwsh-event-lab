<#
.SYNOPSIS
Effectue une enumeration LDAP Active Directory en lecture seule.

.DESCRIPTION
Interroge un controleur de domaine avec l'identite Windows courante ou un
PSCredential fourni. La recherche est bornee, paginee et limitee au Base DN
indique. Aucun objet Active Directory n'est modifie.

LastLogonTimestampUtc est une valeur repliquee et approximative. MemberOf
contient uniquement les groupes directs renvoyes par LDAP, sans transitivite
ni groupe principal.

.NOTES
Prerequis : Windows PowerShell 5.1 ou PowerShell 7 sous Windows, acces TCP/389
ou TCP/636, et droits LDAP de lecture. LDAPS exige un certificat serveur valide.

.EXAMPLE
.\Invoke-LdapEnumeration.ps1 -Server LAB-DC01.lab.local -Type Computers

.EXAMPLE
.\Invoke-LdapEnumeration.ps1 -Server LAB-DC01.lab.local -Type Users `
    -MaxResults 500 -CsvPath .\ldap-users.csv

.EXAMPLE
.\Invoke-LdapEnumeration.ps1 -Server LAB-DC01.lab.local -UseLdaps `
    -Type Custom -LdapFilter '(&(objectCategory=person)(mail=*))'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [string]$BaseDN,

    [ValidateSet('Users', 'Groups', 'Computers', 'DomainControllers', 'All', 'Custom')]
    [string]$Type = 'Computers',

    [string]$LdapFilter,

    [ValidateRange(1, 5000)]
    [int]$MaxResults = 200,

    [ValidateRange(1, 1000)]
    [int]$PageSize = 200,

    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 15,

    [ValidateRange(1, 65535)]
    [int]$Port = 389,

    [switch]$UseLdaps,

    [PSCredential]$Credential,

    [string]$CsvPath,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.DirectoryServices.Protocols

if ($UseLdaps -and -not $PSBoundParameters.ContainsKey('Port')) {
    $Port = 636
}

if ($Server -match '^[a-z]+://' -or $Server.Contains('/') -or $Server.Contains(':')) {
    throw "-Server attend un nom DNS ou une adresse IPv4, sans schema, port ni chemin LDAP. Utilisez -Port pour definir le port."
}

if ($Type -eq 'Custom' -and [string]::IsNullOrWhiteSpace($LdapFilter)) {
    throw "-LdapFilter est obligatoire avec -Type Custom."
}

if (-not [string]::IsNullOrWhiteSpace($LdapFilter) -and
    ($LdapFilter[0] -ne '(' -or $LdapFilter[$LdapFilter.Length - 1] -ne ')')) {
    throw "Le filtre LDAP doit etre entoure de parentheses."
}

if (-not [string]::IsNullOrWhiteSpace($CsvPath)) {
    $CsvPath = [IO.Path]::GetFullPath($CsvPath)
    $CsvDirectory = Split-Path -Parent $CsvPath

    if (-not (Test-Path -LiteralPath $CsvDirectory -PathType Container)) {
        throw "Le dossier d'export n'existe pas : $CsvDirectory"
    }

    if ((Test-Path -LiteralPath $CsvPath) -and -not $Force) {
        throw "Le fichier existe deja : $CsvPath. Utilisez -Force pour le remplacer."
    }
}

function Get-LdapValues {
    param(
        [Parameter(Mandatory)]
        [DirectoryServices.Protocols.SearchResultAttributeCollection]$Attributes,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $Attributes.Contains($Name)) {
        return @()
    }

    $Attribute = $Attributes[$Name]
    $Values = [Collections.Generic.List[object]]::new()

    for ($Index = 0; $Index -lt $Attribute.Count; $Index++) {
        $Values.Add($Attribute[$Index])
    }

    return $Values.ToArray()
}

function Get-LdapFirstValue {
    param(
        [Parameter(Mandatory)]
        [DirectoryServices.Protocols.SearchResultAttributeCollection]$Attributes,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $Attributes.Contains($Name) -or $Attributes[$Name].Count -eq 0) {
        return $null
    }

    Write-Output -NoEnumerate $Attributes[$Name][0]
}

function ConvertFrom-LdapFileTime {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    try {
        $FileTime = [Int64]$Value

        if ($FileTime -le 0 -or $FileTime -eq [Int64]::MaxValue) {
            return $null
        }

        return [DateTime]::FromFileTimeUtc($FileTime)
    }
    catch {
        return $null
    }
}

$PresetFilters = @{
    Users             = '(&(objectCategory=person)(objectClass=user))'
    Groups            = '(objectCategory=group)'
    Computers         = '(objectCategory=computer)'
    DomainControllers = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
    All               = '(objectClass=*)'
}

if ([string]::IsNullOrWhiteSpace($LdapFilter)) {
    $EffectiveFilter = $PresetFilters[$Type]
}
else {
    $EffectiveFilter = $LdapFilter
}

[string[]]$PropertiesToLoad = @(
    'objectClass',
    'objectGUID',
    'objectSid',
    'name',
    'displayName',
    'sAMAccountName',
    'userPrincipalName',
    'mail',
    'dNSHostName',
    'operatingSystem',
    'operatingSystemVersion',
    'description',
    'userAccountControl',
    'lastLogonTimestamp',
    'pwdLastSet',
    'whenCreated',
    'whenChanged',
    'memberOf'
)

$Endpoint = "$Server`:$Port"
$Connection = $null
$Rows = [Collections.Generic.List[object]]::new()
$Stage = 'initialisation'

try {
    $Identifier = [DirectoryServices.Protocols.LdapDirectoryIdentifier]::new(
        $Server,
        $Port
    )

    $Connection = [DirectoryServices.Protocols.LdapConnection]::new($Identifier)
    $Connection.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
    $Connection.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    $Connection.SessionOptions.ProtocolVersion = 3
    $Connection.SessionOptions.ReferralChasing = [DirectoryServices.Protocols.ReferralChasingOptions]::None

    if ($null -ne $Credential) {
        $Connection.Credential = $Credential.GetNetworkCredential()
    }

    if ($UseLdaps) {
        $Connection.SessionOptions.SecureSocketLayer = $true
    }
    else {
        $Connection.SessionOptions.Signing = $true
        $Connection.SessionOptions.Sealing = $true
    }

    $Stage = 'bind'
    $Connection.Bind()

    if ([string]::IsNullOrWhiteSpace($BaseDN)) {
        $Stage = 'lecture RootDSE'
        $RootRequest = [DirectoryServices.Protocols.SearchRequest]::new(
            '',
            '(objectClass=*)',
            [DirectoryServices.Protocols.SearchScope]::Base,
            [string[]]@('defaultNamingContext')
        )
        $RootRequest.TimeLimit = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $RootResponse = [DirectoryServices.Protocols.SearchResponse]$Connection.SendRequest($RootRequest)

        if ($RootResponse.Entries.Count -eq 0 -or
            -not $RootResponse.Entries[0].Attributes.Contains('defaultNamingContext')) {
            throw "RootDSE n'a retourne aucun defaultNamingContext."
        }

        $BaseDN = [string]$RootResponse.Entries[0].Attributes['defaultNamingContext'][0]

        if ([string]::IsNullOrWhiteSpace($BaseDN)) {
            throw "RootDSE a retourne un defaultNamingContext vide."
        }
    }

    $Stage = 'recherche'
    $SearchRequest = [DirectoryServices.Protocols.SearchRequest]::new(
        $BaseDN,
        $EffectiveFilter,
        [DirectoryServices.Protocols.SearchScope]::Subtree,
        $PropertiesToLoad
    )
    $SearchRequest.TimeLimit = [TimeSpan]::FromSeconds($TimeoutSeconds)

    $PageControl = [DirectoryServices.Protocols.PageResultRequestControl]::new(
        [Math]::Min($PageSize, $MaxResults)
    )
    [void]$SearchRequest.Controls.Add($PageControl)

    Write-Verbose "Recherche LDAP sur $Endpoint, BaseDN='$BaseDN', filtre='$EffectiveFilter'."

    while ($Rows.Count -lt $MaxResults) {
        $Remaining = $MaxResults - $Rows.Count
        $PageControl.PageSize = [Math]::Min($PageSize, $Remaining)
        $SearchResponse = [DirectoryServices.Protocols.SearchResponse]$Connection.SendRequest($SearchRequest)

        foreach ($Entry in $SearchResponse.Entries) {
            if ($Rows.Count -ge $MaxResults) {
                break
            }

            $Attributes = $Entry.Attributes
            $ObjectClasses = @(Get-LdapValues -Attributes $Attributes -Name 'objectClass')
            $UserAccountControl = Get-LdapFirstValue -Attributes $Attributes -Name 'userAccountControl'
            $PasswordLastSetRaw = Get-LdapFirstValue -Attributes $Attributes -Name 'pwdLastSet'
            $RawGuid = Get-LdapFirstValue -Attributes $Attributes -Name 'objectGUID'
            $RawSid = Get-LdapFirstValue -Attributes $Attributes -Name 'objectSid'
            $ObjectGuid = $null
            $ObjectSid = $null
            $Enabled = $null
            $PasswordChangeRequired = $null

            if ($RawGuid -is [byte[]]) {
                $ObjectGuid = [Guid]::new($RawGuid)
            }

            if ($RawSid -is [byte[]]) {
                $ObjectSid = [Security.Principal.SecurityIdentifier]::new($RawSid, 0).Value
            }

            if ($null -ne $UserAccountControl) {
                $Enabled = (([Int64]$UserAccountControl -band 2) -eq 0)
            }

            if ($null -ne $PasswordLastSetRaw) {
                $PasswordChangeRequired = ([Int64]$PasswordLastSetRaw -eq 0)
            }

            $Rows.Add([pscustomobject][ordered]@{
                ObjectClass             = if ($ObjectClasses.Count -gt 0) { [string]$ObjectClasses[-1] } else { $null }
                Name                    = [string](Get-LdapFirstValue -Attributes $Attributes -Name 'name')
                DisplayName             = [string](Get-LdapFirstValue -Attributes $Attributes -Name 'displayName')
                SamAccountName          = [string](Get-LdapFirstValue -Attributes $Attributes -Name 'sAMAccountName')
                UserPrincipalName       = [string](Get-LdapFirstValue -Attributes $Attributes -Name 'userPrincipalName')
                Mail                    = [string](Get-LdapFirstValue -Attributes $Attributes -Name 'mail')
                Enabled                 = $Enabled
                DNSHostName             = [string](Get-LdapFirstValue -Attributes $Attributes -Name 'dNSHostName')
                OperatingSystem         = [string](Get-LdapFirstValue -Attributes $Attributes -Name 'operatingSystem')
                OperatingSystemVersion  = [string](Get-LdapFirstValue -Attributes $Attributes -Name 'operatingSystemVersion')
                Description             = [string](Get-LdapFirstValue -Attributes $Attributes -Name 'description')
                LastLogonTimestampUtc   = ConvertFrom-LdapFileTime (Get-LdapFirstValue -Attributes $Attributes -Name 'lastLogonTimestamp')
                PasswordLastSetUtc      = ConvertFrom-LdapFileTime $PasswordLastSetRaw
                PasswordChangeRequired  = $PasswordChangeRequired
                WhenCreated             = [string](Get-LdapFirstValue -Attributes $Attributes -Name 'whenCreated')
                WhenChanged             = [string](Get-LdapFirstValue -Attributes $Attributes -Name 'whenChanged')
                MemberOf                = (@(Get-LdapValues -Attributes $Attributes -Name 'memberOf') -join '; ')
                DistinguishedName       = $Entry.DistinguishedName
                ObjectGuid              = $ObjectGuid
                ObjectSid               = $ObjectSid
            })
        }

        if ($Rows.Count -ge $MaxResults) {
            break
        }

        $PageResponseControl = $null

        foreach ($Control in $SearchResponse.Controls) {
            if ($Control -is [DirectoryServices.Protocols.PageResultResponseControl]) {
                $PageResponseControl = $Control
                break
            }
        }

        if ($null -eq $PageResponseControl -or
            $null -eq $PageResponseControl.Cookie -or
            $PageResponseControl.Cookie.Length -eq 0) {
            break
        }

        $PageControl.Cookie = $PageResponseControl.Cookie
    }
}
catch [DirectoryServices.Protocols.LdapException] {
    throw "Echec LDAP pendant '$Stage' sur $Endpoint (code $($_.Exception.ErrorCode)) : $($_.Exception.Message)"
}
catch {
    throw "Echec pendant '$Stage' sur $Endpoint (BaseDN='$BaseDN') : $($_.Exception.Message)"
}
finally {
    if ($null -ne $Connection) {
        $Connection.Dispose()
    }
}

if (-not [string]::IsNullOrWhiteSpace($CsvPath)) {
    $Rows | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8 -Force:$Force
    Write-Verbose "Export CSV cree : $CsvPath"
}

$Rows
