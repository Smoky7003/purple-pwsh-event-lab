param(
    [Parameter(Mandatory)]
    [string]$Target,
    [int[]]$Ports = @(22, 80, 443, 445, 3389),
    [int]$TimeoutMs = 300
)

foreach ($Port in $Ports) {
    $Client = [Net.Sockets.TcpClient]::new()

    try {
        if ($Client.ConnectAsync($Target, $Port).Wait($TimeoutMs) -and $Client.Connected) {
            "$Target`:$Port ouvert"
        }
    }
    catch {}
    finally {
        $Client.Dispose()
    }
}
