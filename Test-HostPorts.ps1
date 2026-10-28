[CmdletBinding(DefaultParameterSetName = 'Host')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Host')]
    [string]$Target,
    [Parameter(Mandatory, ParameterSetName = 'Network')]
    [string]$Network,
    [int[]]$Ports = @(22, 80, 443, 445, 3389),
    [int]$TimeoutMs = 300
)

if ($PSCmdlet.ParameterSetName -eq 'Network') {
    try {
        $Address = [Net.IPAddress]::Parse(($Network -split '/')[0])
    }
    catch {
        throw 'Réseau invalide. Format attendu : 192.168.1.0/24'
    }

    if ($Network -notmatch '^[^/]+/24$' -or
        $Address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $Address.GetAddressBytes()[3] -ne 0) {
        throw 'Réseau invalide. Format attendu : 192.168.1.0/24'
    }

    $Bytes = $Address.GetAddressBytes()
    $Targets = 1..254 | ForEach-Object { "$($Bytes[0]).$($Bytes[1]).$($Bytes[2]).$_" }
}
else {
    $Targets = @($Target)
}

foreach ($CurrentTarget in $Targets) {
    foreach ($Port in $Ports) {
        $Client = [Net.Sockets.TcpClient]::new()

        try {
            if ($Client.ConnectAsync($CurrentTarget, $Port).Wait($TimeoutMs) -and $Client.Connected) {
                "$CurrentTarget`:$Port ouvert"
            }
        }
        catch {}
        finally {
            $Client.Dispose()
        }
    }
}
