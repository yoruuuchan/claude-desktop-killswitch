<#
    Optional, read-only Windows network diagnostic for Claude Kill-Switch.
    DNS configuration is descriptive. Raw UDP STUN is NOT a browser WebRTC test.
    Exit codes: 0 = compared exits match; 1 = compared exits differ;
                2 = comparison unavailable/incomplete.
#>
[CmdletBinding()]
param(
    [switch]$ProbeStun,
    [string]$ProxyUrl,
    [string]$StunServer = 'stun.l.google.com',
    [ValidateRange(1, 65535)][int]$StunPort = 19302
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ks-stun.ps1')

Write-Host ''
Write-Host '  Claude Kill-Switch - Network Audit (read-only)' -ForegroundColor Cyan

# Show routing and DNS evidence without treating it as proof of encrypted DNS.
try {
    $physical = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' })
    $route = Find-NetRoute -RemoteIPAddress '1.1.1.1' | Select-Object -First 1
    $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex
    $routeKind = if ($adapter.Name -in @($physical.Name)) { 'physical' } else { 'virtual / tunnel candidate' }
    Write-Host ("  IPv4 default egress: {0} ({1})" -f $adapter.Name, $routeKind)
} catch {
    Write-Host ("  IPv4 default egress: UNVERIFIED ({0})" -f $_.Exception.Message) -ForegroundColor Yellow
}

try {
    $upAliases = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name)
    $dns = @(Get-DnsClientServerAddress | Where-Object {
        $_.InterfaceAlias -in $upAliases -and
        @($_.ServerAddresses | Where-Object { $_ -notlike 'fec0:0:0:ffff::*' }).Count -gt 0
    })
    if ($dns.Count -eq 0) {
        Write-Host '  DNS servers: no configured entries found'
    } else {
        foreach ($entry in $dns) {
            Write-Host ("  DNS {0} / {1}: {2}" -f $entry.InterfaceAlias, $entry.AddressFamily,
                (@($entry.ServerAddresses | Where-Object { $_ -notlike 'fec0:0:0:ffff::*' }) -join ', '))
        }
    }
} catch {
    Write-Host ("  DNS servers: UNVERIFIED ({0})" -f $_.Exception.Message) -ForegroundColor Yellow
}
Write-Host '  DNS server entries do not prove whether applications use DoH, remote DNS, or plaintext DNS.'
Write-Host '  This script never changes the system time zone or proxy/firewall settings.'

$httpIp = $null
if ($ProxyUrl) {
    try {
        $uri = [Uri]$ProxyUrl
        if ($uri.Scheme -notin @('http', 'https') -or -not $uri.Host) {
            throw 'ProxyUrl must be an HTTP(S) proxy URL'
        }
        $response = Invoke-WebRequest -UseBasicParsing -Uri 'https://api4.ipify.org' -Proxy $ProxyUrl -TimeoutSec 12
        $httpIp = ([string]$response.Content).Trim()
        $parsed = $null
        if (-not [System.Net.IPAddress]::TryParse($httpIp, [ref]$parsed) -or
            $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            throw 'Unexpected IP echo response'
        }
        Write-Host ("  Explicit HTTP proxy IPv4: {0}" -f $httpIp)
    } catch {
        Write-Host ("  Explicit HTTP proxy IPv4: UNVERIFIED ({0})" -f $_.Exception.Message) -ForegroundColor Yellow
    }
} else {
    Write-Host '  Explicit HTTP proxy IPv4: NOT TESTED (pass -ProxyUrl)'
}

$stunIp = $null
if ($ProbeStun) {
    $udp = $null
    try {
        $serverIp = @([System.Net.Dns]::GetHostAddresses($StunServer) |
            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
            Select-Object -First 1)[0]
        if (-not $serverIp) { throw 'STUN host has no IPv4 address' }

        $tid = New-Object byte[] 12
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($tid) } finally { $rng.Dispose() }

        $request = [byte[]]@(0, 1, 0, 0, 0x21, 0x12, 0xA4, 0x42) + $tid
        $udp = [System.Net.Sockets.UdpClient]::new([System.Net.Sockets.AddressFamily]::InterNetwork)
        $udp.Client.ReceiveTimeout = 6000
        [void]$udp.Send($request, $request.Length, $serverIp.ToString(), $StunPort)
        $peer = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $reply = $udp.Receive([ref]$peer)
        if ($peer.Address.ToString() -ne $serverIp.ToString() -or $peer.Port -ne $StunPort) {
            throw 'STUN reply came from an unexpected endpoint'
        }
        $stunIp = ConvertFrom-KSStunResponse -Packet $reply -TransactionID $tid
        if (-not $stunIp) { throw 'Malformed or unmatched STUN response' }
        Write-Host ("  Raw UDP/STUN observed IPv4: {0}" -f $stunIp)
    } catch {
        Write-Host ("  Raw UDP/STUN: UNVERIFIED ({0})" -f $_.Exception.Message) -ForegroundColor Yellow
    } finally {
        if ($udp) { $udp.Close(); $udp.Dispose() }
    }
} else {
    Write-Host '  Raw UDP/STUN: NOT TESTED (pass -ProbeStun)'
}

Write-Host '  The UDP probe is not a browser WebRTC test and cannot establish browser leak safety.'
Write-Host '  STUN requests may expose the real public IP to the named STUN server.'

if ($httpIp -and $stunIp) {
    if ($httpIp -eq $stunIp) {
        Write-Host '  RESULT: compared HTTP-proxy and raw-UDP IPv4 exits MATCH. Other paths remain untested.' -ForegroundColor Green
        exit 0
    }
    Write-Host '  RESULT: compared HTTP-proxy and raw-UDP IPv4 exits DIFFER. Investigate UDP routing.' -ForegroundColor Red
    exit 1
}

Write-Host '  RESULT: UNVERIFIED. Need both -ProxyUrl and -ProbeStun with successful responses.' -ForegroundColor Yellow
exit 2
