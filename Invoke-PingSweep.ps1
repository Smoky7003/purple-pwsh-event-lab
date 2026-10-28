[CmdletBinding(DefaultParameterSetName = 'Host')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Host')]
    [string]$Target,
    [Parameter(Mandatory, ParameterSetName = 'Network')]
    [string]$Network,
    [ValidateRange(1, 5000)]
    [int]$TimeoutMs = 200
)

$Address = $null

if ($PSCmdlet.ParameterSetName -eq 'Network') {
    $Parts = $Network.Split('/')

    if ($Parts.Count -ne 2 -or
        $Parts[1] -ne '24' -or
        -not [Net.IPAddress]::TryParse($Parts[0], [ref]$Address) -or
        $Address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $Address.GetAddressBytes()[3] -ne 0) {
        throw 'Réseau invalide. Format attendu : 192.168.1.0/24'
    }

    $Bytes = $Address.GetAddressBytes()
    $Prefix = $Bytes[0..2] -join '.'
    $Targets = 1..254 | ForEach-Object { "$Prefix.$_" }
}
else {
    if (-not [Net.IPAddress]::TryParse($Target, [ref]$Address) -or
        $Address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'Adresse IPv4 invalide.'
    }

    $Targets = @($Address.IPAddressToString)
}

$Ping = [Net.NetworkInformation.Ping]::new()

try {
    foreach ($CurrentTarget in $Targets) {
        try {
            $Reply = $Ping.Send($CurrentTarget, $TimeoutMs)

            if ($Reply.Status -eq [Net.NetworkInformation.IPStatus]::Success) {
                [pscustomobject]@{
                    IP        = $CurrentTarget
                    LatencyMs = $Reply.RoundtripTime
                }
            }
        }
        catch {}
    }
}
finally {
    $Ping.Dispose()
}
