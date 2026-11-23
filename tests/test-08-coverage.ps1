# P1-5: read-only coverage audit - CIDR containment, endpoint catalog,
# per-process coverage, and honest exit codes.

$phys = @('Ethernet', 'Wi-Fi')
$public = Get-KSPublicAddressSets
$anthro = Get-KSAnthropicRanges

# ---- shared ranges and rule specs ----
Assert-True ($anthro.V4 -contains '160.79.104.0/23' -and $anthro.V4 -contains '153.61.224.0/22') 'ranges: official IPv4 ranges present'
Assert-True ($anthro.V6 -contains '2607:6bc0::/48' -and $anthro.V6 -contains '2607:6bc0:11::/48') 'ranges: official IPv6 ranges present'
Assert-True (@($public.V4).Count -eq 7) 'ranges: public IPv4 set has 7 ranges'
Assert-True ($public.V6 -contains '2000::/3') 'ranges: public IPv6 set includes global unicast'
$specs = @(Get-KSBasicRuleSpecs)
Assert-True ($specs.Count -eq 3) 'specs: three required basic rules'
Assert-True (@($specs | Where-Object { $_.Name -like '*153.61.224.0-22*' }).Count -eq 1) 'specs: separate 153.61.224.0/22 rule preserved'
Assert-True (@(Get-KSBasicRuleSpecs -BlockAllIPv6).Count -eq 4) 'specs: -BlockAllIPv6 adds the optional fourth rule'
$ipv4Spec = @($specs | Where-Object { $_.Name -eq 'KS - Block Anthropic IPv4 on physical' })[0]
Assert-True ($ipv4Spec.Remote -contains '160.79.104.0/23') 'specs: original 160.79.104.0/23 rule name and range preserved'
$ipv6Spec = @($specs | Where-Object { $_.Name -eq 'KS - Block Anthropic IPv6 on physical' })[0]
$all6Spec = @((Get-KSBasicRuleSpecs -BlockAllIPv6) | Where-Object { $_.Name -eq 'KS - Block all IPv6 on physical' })[0]
Assert-True ($ipv6Spec.Remote -contains '2607:6bc0::/48' -and $ipv6Spec.Remote -contains '2607:6bc0:11::/48' -and $all6Spec.Remote -contains '2000::/3') 'specs: IPv6 ranges and optional all-IPv6 rule preserved'

# ---- Test-KSIPInCIDR ----
Assert-True (Test-KSIPInCIDR -IP '160.79.104.10' -CIDR '160.79.104.0/23') 'cidr: IPv4 inside /23'
Assert-True (Test-KSIPInCIDR -IP '160.79.104.10' -CIDR '160.79.104.0/255.255.254.0') 'cidr: dotted mask is normalized before matching'
Assert-True (-not (Test-KSIPInCIDR -IP '160.79.106.10' -CIDR '160.79.104.0/23')) 'cidr: IPv4 outside /23'
Assert-True (Test-KSIPInCIDR -IP '2607:6bc0::10' -CIDR '2607:6bc0::/48') 'cidr: IPv6 inside /48'
Assert-True (-not (Test-KSIPInCIDR -IP '2607:6bc1::10' -CIDR '2607:6bc0::/48')) 'cidr: IPv6 outside /48'
Assert-True (-not (Test-KSIPInCIDR -IP '160.79.104.10' -CIDR '2607:6bc0::/48')) 'cidr: mixed families do not match'
Assert-True (-not (Test-KSIPInCIDR -IP 'not-an-ip' -CIDR '160.79.104.0/23')) 'cidr: invalid IP rejected'
Assert-True (-not (Test-KSIPInCIDR -IP '160.79.104.10' -CIDR '160.79.104.0/33')) 'cidr: invalid prefix length rejected'

# ---- Get-KSAddressSetCoverage ----
Assert-True ((Get-KSAddressSetCoverage -IPAddresses @('160.79.104.10') -Prefixes @('160.79.104.0/23')) -eq 'covered') 'address coverage: single IP inside'
Assert-True ((Get-KSAddressSetCoverage -IPAddresses @('34.54.194.141') -Prefixes @('160.79.104.0/23')) -eq 'not-covered') 'address coverage: Sift CDN IP outside official ranges'
Assert-True ((Get-KSAddressSetCoverage -IPAddresses @('160.79.104.10', '34.54.194.141') -Prefixes @('160.79.104.0/23')) -eq 'partial') 'address coverage: mixed result -> partial'
Assert-True ((Get-KSAddressSetCoverage -IPAddresses @() -Prefixes @('160.79.104.0/23')) -eq 'unresolved') 'address coverage: no DNS answers -> unresolved'
Assert-True ((Get-KSAddressSetCoverage -IPAddresses @('160.79.104.10') -Prefixes @()) -eq 'not-covered') 'address coverage: empty prefix list never counts as covered'

# ---- Get-KSAppRuleCoverage ----
function New-TestRuleView($rule, $remote, $program, $ifa) {
    [pscustomobject]@{ Rule = $rule; RemoteAddress = $remote; Program = $program; InterfaceAlias = $ifa }
}

$v4Rule = New-MockRule -Name 'cov-v4' -DisplayName 'cov-v4' -Program 'C:\Claude\claude.exe' -RemoteAddress $public.V4 -InterfaceAlias $phys
$v6Rule = New-MockRule -Name 'cov-v6' -DisplayName 'cov-v6' -Program 'C:\Claude\claude.exe' -RemoteAddress $public.V6 -InterfaceAlias $phys
$views = @(
    (New-TestRuleView $v4Rule $public.V4 'C:\Claude\claude.exe' $phys),
    (New-TestRuleView $v6Rule $public.V6 'C:\Claude\claude.exe' $phys)
)

$c = Get-KSAppRuleCoverage -Targets @('C:\Claude\claude.exe') -RuleViews $views `
    -ExpectedRemote4 $public.V4 -ExpectedRemote6 $public.V6 -ExpectedInterfaceAlias $phys
Assert-True ($c.Covered.Count -eq 1 -and $c.Uncovered.Count -eq 0) 'app coverage: healthy IPv4 + IPv6 rules cover the target'

$c = Get-KSAppRuleCoverage -Targets @('C:\Claude\claude.exe') -RuleViews @($views[0]) `
    -ExpectedRemote4 $public.V4 -ExpectedRemote6 $public.V6 -ExpectedInterfaceAlias $phys
Assert-True ($c.Uncovered.Count -eq 1) 'app coverage: missing IPv6 rule -> uncovered'

$v4OnlyOldAdapter = New-MockRule -Name 'cov-v4-old' -DisplayName 'cov-v4-old' -Program 'C:\Claude\claude.exe' -RemoteAddress $public.V4 -InterfaceAlias @('Ethernet')
$viewsOldAdapter = @(
    (New-TestRuleView $v4OnlyOldAdapter $public.V4 'C:\Claude\claude.exe' @('Ethernet')),
    (New-TestRuleView $v6Rule $public.V6 'C:\Claude\claude.exe' $phys)
)
$c = Get-KSAppRuleCoverage -Targets @('C:\Claude\claude.exe') -RuleViews $viewsOldAdapter `
    -ExpectedRemote4 $public.V4 -ExpectedRemote6 $public.V6 -ExpectedInterfaceAlias $phys
Assert-True ($c.Uncovered.Count -eq 1) 'app coverage: rule missing a new physical adapter -> uncovered'

$c = Get-KSAppRuleCoverage -Targets @('C:\Claude\claude.exe', 'C:\Claude\other.exe') -RuleViews $views `
    -ExpectedRemote4 $public.V4 -ExpectedRemote6 $public.V6 -ExpectedInterfaceAlias $phys
Assert-True ($c.Covered.Count -eq 1 -and $c.Uncovered.Count -eq 1) 'app coverage: an unruled target is reported separately'

$c = Get-KSAppRuleCoverage -Targets @('C:\Claude\claude.exe') -RuleViews @() `
    -ExpectedRemote4 $public.V4 -ExpectedRemote6 $public.V6 -ExpectedInterfaceAlias $phys
Assert-True ($c.Uncovered.Count -eq 1) 'app coverage: no rules -> uncovered'

# ---- Get-KSCoverageExitCode ----
Assert-True ((Get-KSCoverageExitCode -GapCount 0 -UnverifiedCount 0) -eq 0) 'coverage exit: clean -> 0'
Assert-True ((Get-KSCoverageExitCode -GapCount 1 -UnverifiedCount 0) -eq 1) 'coverage exit: concrete gap -> 1'
Assert-True ((Get-KSCoverageExitCode -GapCount 0 -UnverifiedCount 1) -eq 2) 'coverage exit: unverified -> 2'
Assert-True ((Get-KSCoverageExitCode -GapCount 1 -UnverifiedCount 1) -eq 1) 'coverage exit: gap takes precedence over unverified'

# ---- endpoint catalog ----
$endpoints = @(Get-KSKnownEndpoints)
Assert-True (@($endpoints | Where-Object { $_.Name -eq 's-cdn.anthropic.com' }).Count -eq 1) 'endpoints: Sift host present'
$sift = @($endpoints | Where-Object { $_.Name -eq 's-cdn.anthropic.com' })[0]
Assert-True ($sift.Role -match 'Sift' -and $sift.Category -eq 'ThirdParty') 'endpoints: Sift host marked third-party'
$statsig = @($endpoints | Where-Object { $_.Name -eq 'statsig.anthropic.com' })[0]
Assert-True ($statsig.Category -eq 'Historical') 'endpoints: statsig kept as historical, not current'
Assert-True (@($endpoints | Group-Object Name | Where-Object { $_.Count -gt 1 }).Count -eq 0) 'endpoints: names are unique'

# ---- Get-KSEndpointDnsRecords (mocked, no real DNS) ----
$script:MockDnsThrows = $false
$script:MockDnsRecords = @{
    's-cdn.anthropic.com' = @(
        [pscustomobject]@{ Type = 'CNAME'; NameHost = 'b-0.hexagon-cdn.com' },
        [pscustomobject]@{ Type = 'A'; IPAddress = '34.54.194.141' }
    )
}
$dns = Get-KSEndpointDnsRecords -Name 's-cdn.anthropic.com'
Assert-True ($dns.Resolved) 'dns: resolved endpoint reported as resolved'
Assert-True ($dns.CNAME -contains 'b-0.hexagon-cdn.com') 'dns: CNAME target collected'
Assert-True ($dns.IPAddresses -contains '34.54.194.141') 'dns: IPv4 answer collected'
Assert-True ((Get-KSAddressSetCoverage -IPAddresses $dns.IPAddresses -Prefixes $anthro.V4) -eq 'not-covered') 'dns: Sift CDN address is outside official IPv4 ranges'

$script:MockDnsThrows = $true
$dns = Get-KSEndpointDnsRecords -Name 'statsig.anthropic.com'
Assert-True (-not $dns.Resolved) 'dns: NXDOMAIN/unreadable name is not treated as resolved'
Assert-True ($dns.Error -match 'mock DNS failure') 'dns: failure reason retained for reporting'

# Reset mocks for any later test file.
$script:MockDnsThrows = $false
$script:MockDnsRecords = @{}
