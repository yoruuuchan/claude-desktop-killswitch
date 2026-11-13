<#
    claude-desktop-killswitch regression tests (runner)

    Pure in-memory mocks only. This suite NEVER dot-sources the main
    scripts (they contain admin checks and real firewall calls); it loads
    scripts/ks-lib.ps1 and mocks every Net* / Get-WinEvent cmdlet the
    library touches. Safety-net mocks are defined here so no test can
    accidentally reach the real system.

    Usage (Windows PowerShell 5.1):
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\run-tests.ps1
#>

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repoRoot 'scripts\ks-lib.ps1')

$script:PassCount = 0
$script:FailCount = 0

function Assert-True {
    param([bool]$Condition, [string]$Name)
    if ($Condition) {
        $script:PassCount++
        Write-Host "  [PASS] $Name" -ForegroundColor Green
    } else {
        $script:FailCount++
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
    }
}

# --------------------------------------------------------------------------
# Safety-net mocks. Individual test files override these with scenario
# behavior; the defaults exist so that no code path can ever fall through
# to the real NetSecurity / NetTCPIP / event-log cmdlets.
# --------------------------------------------------------------------------
$script:MockCalls = @()
$script:MockRules = @()
$script:MockRoutes = @()
$script:MockRemoveThrows = $false
$script:MockLastRemove = $null
$script:MockWinEvents = @()
$script:MockWinEventThrows = $false

function Get-NetFirewallRule {
    [CmdletBinding()] param($DisplayName, $Group, $PolicyStore, $Name)
    @($script:MockRules)
}
function New-NetFirewallRule {
    [CmdletBinding()] param($DisplayName, $Group, $Direction, $Action, $Profile, $RemoteAddress, $InterfaceAlias, $Program)
    $script:MockCalls += 'New-NetFirewallRule'
}
function Set-NetFirewallRule {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline = $true)]$InputObject,
          $Enabled, $Direction, $Action, $Profile, $RemoteAddress, $InterfaceAlias, $Program)
    process { $script:MockCalls += 'Set-NetFirewallRule' }
}
function Set-NetFirewallAddressFilter {
    [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)]$InputObject, $RemoteAddress)
    process { $script:MockCalls += 'Set-NetFirewallAddressFilter' }
}
function Set-NetFirewallInterfaceFilter {
    [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)]$InputObject, $InterfaceAlias)
    process { $script:MockCalls += 'Set-NetFirewallInterfaceFilter' }
}
function Set-NetFirewallApplicationFilter {
    [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)]$InputObject, $Program)
    process { $script:MockCalls += 'Set-NetFirewallApplicationFilter' }
}
function Get-NetFirewallAddressFilter {
    [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)]$InputObject)
    process { [pscustomobject]@{ RemoteAddress = $InputObject._RemoteAddress } }
}
function Get-NetFirewallApplicationFilter {
    [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)]$InputObject)
    process { [pscustomobject]@{ Program = $InputObject._Program } }
}
function Get-NetFirewallInterfaceFilter {
    [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)]$InputObject)
    process { [pscustomobject]@{ InterfaceAlias = $InputObject._InterfaceAlias } }
}
function Get-NetRoute {
    [CmdletBinding()] param($DestinationPrefix, $InterfaceIndex, $NextHop, $PolicyStore)
    # Respect the filters like the real cmdlet does, so read-back checks
    # only see routes matching the full identity.
    @($script:MockRoutes | Where-Object {
        ($null -eq $DestinationPrefix -or $_.DestinationPrefix -eq $DestinationPrefix) -and
        ($null -eq $InterfaceIndex -or $_.InterfaceIndex -eq $InterfaceIndex)
    })
}
function Remove-NetRoute {
    [CmdletBinding()] param($DestinationPrefix, $InterfaceIndex, $NextHop, $PolicyStore, [switch]$Confirm)
    $script:MockLastRemove = @{ Prefix = $DestinationPrefix; IfIndex = $InterfaceIndex; NextHop = $NextHop }
    if ($script:MockRemoveThrows) { throw 'mock Remove-NetRoute failed' }
}
function New-NetRoute {
    [CmdletBinding()] param($DestinationPrefix, $InterfaceIndex, $NextHop, $RouteMetric, $PolicyStore, [switch]$Confirm)
    $script:MockCalls += 'New-NetRoute'
}
function Get-WinEvent {
    [CmdletBinding()] param($FilterHashtable, $MaxEvents)
    if ($script:MockWinEventThrows) { throw 'mock Get-WinEvent failed (audit not enabled)' }
    @($script:MockWinEvents)
}

# Mock firewall rule object. Filter data travels on the object itself
# (_RemoteAddress / _Program / _InterfaceAlias) so the filter mocks above
# can serve any scenario without global state.
function New-MockRule {
    param([string]$Name, [string]$DisplayName,
          [string]$Enabled = 'True', [string]$Direction = 'Outbound',
          [string]$Action = 'Block', [string]$Profile = 'Any',
          [string[]]$RemoteAddress = @(), [string]$Program = '',
          [string[]]$InterfaceAlias = @())
    [pscustomobject]@{
        Name             = $Name
        DisplayName      = $DisplayName
        Enabled          = $Enabled
        Direction        = $Direction
        Action           = $Action
        Profile          = $Profile
        _RemoteAddress   = $RemoteAddress
        _Program         = $Program
        _InterfaceAlias  = $InterfaceAlias
    }
}

function New-MockWinEvent {
    param([string]$XmlText)
    $e = [pscustomobject]@{ XmlText = $XmlText }
    $e | Add-Member -MemberType ScriptMethod -Name ToXml -Value { return $this.XmlText }
    return $e
}

# --------------------------------------------------------------------------
Write-Host ''
Write-Host 'claude-desktop-killswitch regression tests' -ForegroundColor White
Write-Host ''

$testFiles = @(Get-ChildItem -Path $PSScriptRoot -Filter 'test-*.ps1' | Sort-Object Name)
foreach ($f in $testFiles) {
    Write-Host "> $($f.Name)" -ForegroundColor Cyan
    . $f.FullName
    Write-Host ''
}

Write-Host ("passed: {0}   failed: {1}" -f $script:PassCount, $script:FailCount) -ForegroundColor $(if ($script:FailCount -eq 0) { 'Green' } else { 'Red' })
Write-Host ''
if ($script:FailCount -gt 0) { exit 1 }
exit 0
