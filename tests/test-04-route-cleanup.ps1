# P2-5: route cleanup by full identity, each route handled independently.

# ---- New-KSRouteRef ----
$ref = New-KSRouteRef -Prefix '1.2.3.4/32' -IfIndex 12 -NextHop '192.168.1.1'
Assert-True ($ref.Prefix -eq '1.2.3.4/32' -and $ref.IfIndex -eq 12 -and $ref.NextHop -eq '192.168.1.1') 'route ref: full identity recorded (prefix + ifIndex + nextHop)'

# ---- Remove-KSTestRoute: removed ----
$script:MockRoutes = @()
$script:MockRemoveThrows = $false
$script:MockLastRemove = $null
$status = Remove-KSTestRoute -RouteRef $ref
Assert-True ($status -eq 'removed') 'route cleanup: successful removal -> removed'
Assert-True ($script:MockLastRemove.Prefix -eq '1.2.3.4/32' -and $script:MockLastRemove.IfIndex -eq 12 -and $script:MockLastRemove.NextHop -eq '192.168.1.1') 'route cleanup: Remove-NetRoute receives the full identity, not a bare prefix'

# ---- not-found ----
$script:MockRoutes = @()
$script:MockRemoveThrows = $true    # Remove-NetRoute throws when the route is absent
$status = Remove-KSTestRoute -RouteRef $ref
Assert-True ($status -eq 'not-found') 'route cleanup: already gone -> not-found (read-back proves removal)'

# ---- failed: still present after a failed removal attempt ----
$script:MockRoutes = @([pscustomobject]@{ DestinationPrefix = '1.2.3.4/32'; InterfaceIndex = 12 })
$script:MockRemoveThrows = $true
$status = Remove-KSTestRoute -RouteRef $ref
Assert-True ($status -eq 'failed') 'route cleanup: still present after failed removal -> failed (reported, never swallowed)'

# ---- same prefix on ANOTHER interface is neither deleted nor "left" ----
$script:MockRoutes = @([pscustomobject]@{ DestinationPrefix = '1.2.3.4/32'; InterfaceIndex = 99 })
$script:MockRemoveThrows = $true
$script:MockLastRemove = $null
$status = Remove-KSTestRoute -RouteRef $ref
Assert-True ($status -eq 'not-found') 'route cleanup: same prefix on another interface is untouched and not reported as left'
Assert-True ($script:MockLastRemove.IfIndex -eq 12) 'route cleanup: removal targets only the recorded interface'
