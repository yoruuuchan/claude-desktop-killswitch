# Offline tests for STUN response parsing. No real UDP sockets or external endpoints.
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\ks-stun.ps1')

$tid = [byte[]]@(1,2,3,4,5,6,7,8,9,10,11,12)
$header = [byte[]]@(0x01,0x01,0x00,0x0C,0x21,0x12,0xA4,0x42) + $tid

# XOR-MAPPED-ADDRESS for 198.51.100.42, XORed with the magic cookie.
$xorAttr = [byte[]]@(0,0x20,0,8,0,1,0,0,0xE7,0x21,0xC0,0x68)
$packet = $header + $xorAttr
Assert-True ((ConvertFrom-KSStunResponse -Packet $packet -TransactionID $tid) -eq '198.51.100.42') 'stun: XOR-MAPPED-ADDRESS IPv4 decoded'

$plain = $header + [byte[]]@(0,1,0,8,0,1,0,0,203,0,113,7)
Assert-True ((ConvertFrom-KSStunResponse -Packet $plain -TransactionID $tid) -eq '203.0.113.7') 'stun: MAPPED-ADDRESS IPv4 decoded'

$badTid = [byte[]]@(0,2,3,4,5,6,7,8,9,10,11,12)
Assert-True ($null -eq (ConvertFrom-KSStunResponse -Packet $packet -TransactionID $badTid)) 'stun: wrong transaction ID rejected'
Assert-True ($null -eq (ConvertFrom-KSStunResponse -Packet ([byte[]]@(1,1,0)) -TransactionID $tid)) 'stun: short header rejected'

$badLength = [byte[]]@($packet.Clone())
$badLength[3] = 16
Assert-True ($null -eq (ConvertFrom-KSStunResponse -Packet $badLength -TransactionID $tid)) 'stun: truncated body rejected'

$badAttr = [byte[]]@($packet.Clone())
$badAttr[23] = 16
Assert-True ($null -eq (ConvertFrom-KSStunResponse -Packet $badAttr -TransactionID $tid)) 'stun: truncated attribute rejected'

$badCookie = [byte[]]@($packet.Clone())
$badCookie[4] = 0
Assert-True ($null -eq (ConvertFrom-KSStunResponse -Packet $badCookie -TransactionID $tid)) 'stun: bad cookie rejected'

$badResponseType = [byte[]]@($packet.Clone())
$badResponseType[0] = 0
Assert-True ($null -eq (ConvertFrom-KSStunResponse -Packet $badResponseType -TransactionID $tid)) 'stun: non-success response rejected'

# IPv6 XOR-MAPPED-ADDRESS, RFC 5389: first 4 octets use cookie, remainder use transaction ID.
$raw6 = [System.Net.IPAddress]::Parse('2001:db8::1').GetAddressBytes()
$xor6 = New-Object byte[] 16
$mask = [byte[]]@(0x21,0x12,0xA4,0x42) + $tid
for ($i = 0; $i -lt 16; $i++) { $xor6[$i] = [byte]([int]$raw6[$i] -bxor [int]$mask[$i]) }
$packet6 = [byte[]]@(1,1,0,24,0x21,0x12,0xA4,0x42) + $tid +
           [byte[]]@(0,0x20,0,20,0,2,0,0) + $xor6
Assert-True ((ConvertFrom-KSStunResponse -Packet $packet6 -TransactionID $tid) -eq '2001:db8::1') 'stun: XOR-MAPPED-ADDRESS IPv6 decoded'
