# STUN parser shared by the optional network audit and its offline regression tests.
# A missing, invalid, or unrecognized response is never evidence of a safe route.

function ConvertFrom-KSStunResponse {
    param(
        [byte[]]$Packet,
        [byte[]]$TransactionID
    )
    if ($null -eq $Packet -or $Packet.Length -lt 20 -or
        $null -eq $TransactionID -or $TransactionID.Length -ne 12) { return $null }

    $type = ([int]$Packet[0] -shl 8) -bor [int]$Packet[1]
    $bodyLength = ([int]$Packet[2] -shl 8) -bor [int]$Packet[3]
    if ($type -ne 0x0101 -or ($bodyLength % 4) -ne 0 -or
        $Packet.Length -lt (20 + $bodyLength)) { return $null }

    $cookie = [byte[]]@(0x21, 0x12, 0xA4, 0x42)
    for ($i = 0; $i -lt 4; $i++) {
        if ($Packet[4 + $i] -ne $cookie[$i]) { return $null }
    }
    for ($i = 0; $i -lt 12; $i++) {
        if ($Packet[8 + $i] -ne $TransactionID[$i]) { return $null }
    }

    $end = 20 + $bodyLength
    $position = 20
    while ($position + 4 -le $end) {
        $attributeType = ([int]$Packet[$position] -shl 8) -bor [int]$Packet[$position + 1]
        $attributeLength = ([int]$Packet[$position + 2] -shl 8) -bor [int]$Packet[$position + 3]
        $valueStart = $position + 4
        if (($valueStart + $attributeLength) -gt $end) { return $null }

        if ($attributeType -eq 0x0020 -or $attributeType -eq 0x0001) {
            if ($attributeLength -lt 8) { return $null }
            $family = $Packet[$valueStart + 1]
            if ($family -eq 0x01) {
                if ($attributeLength -ne 8) { return $null }
                $size = 4
            } elseif ($family -eq 0x02) {
                if ($attributeLength -ne 20) { return $null }
                $size = 16
            } else {
                return $null
            }

            $addressBytes = New-Object byte[] $size
            for ($i = 0; $i -lt $size; $i++) {
                $value = [int]$Packet[$valueStart + 4 + $i]
                if ($attributeType -eq 0x0020) {
                    if ($i -lt 4) {
                        $value = $value -bxor [int]$cookie[$i]
                    } else {
                        $value = $value -bxor [int]$TransactionID[$i - 4]
                    }
                }
                $addressBytes[$i] = [byte]$value
            }
            return ([System.Net.IPAddress]::new($addressBytes)).ToString()
        }
        $position = $valueStart + (($attributeLength + 3) -band (-bnot 3))
    }
    return $null
}
