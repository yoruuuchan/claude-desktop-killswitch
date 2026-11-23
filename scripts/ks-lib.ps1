<#
    Claude 防直连 —— 共享判断与只读查询函数库

    供 00-check.ps1 / 01-basic.ps1 / 02-full-rebuild.ps1 / 02-full-install.ps1 /
    03-verify.ps1 / 05-coverage.ps1 dot-source。本文件只定义函数，加载时不做
    任何系统查询或修改；DNS 解析和防火墙过滤器读取只在函数被调用时发生。
    tests/ 下的单元测试也只 dot-source 这个文件（配合 mock 函数），绝不加载
    主脚本（那会触发管理员检查和真实防火墙调用）。

    规则健康的定义（同名 ≠ 有效）：
      Enabled=True、Direction=Outbound、Action=Block、Profile=Any、
      RemoteAddress 覆盖期望集合（同时接受 CIDR 与点分掩码两种表示）、
      Program 精确相等（按进程的规则）、InterfaceAlias 覆盖当前全部物理网卡。
#>

# ---------------------------------------------------------------------------
# Shared address sets and rule specs. Install, rebuild and coverage checks all
# read these from one place so the three copies cannot drift apart.
# ---------------------------------------------------------------------------
function Get-KSAnthropicRanges {
    [pscustomobject]@{
        V4 = @('160.79.104.0/23', '153.61.224.0/22')
        V6 = @('2607:6bc0::/48', '2607:6bc0:11::/48')
    }
}

function Get-KSPublicAddressSets {
    # Public IPv4. Loopback, RFC1918, CGNAT 100.64/10 (Tailscale) and
    # link-local 169.254/16 stay outside the block on purpose.
    [pscustomobject]@{
        V4 = @(
            '1.0.0.0-9.255.255.255'
            '11.0.0.0-100.63.255.255'
            '100.128.0.0-126.255.255.255'
            '128.0.0.0-169.253.255.255'
            '169.255.0.0-172.15.255.255'
            '172.32.0.0-192.167.255.255'
            '192.169.0.0-223.255.255.255'
        )
        V6 = @('2000::/3', '64:ff9b::/96', '64:ff9b:1::/48')
    }
}

function Get-KSBasicRuleSpecs {
    param([switch]$BlockAllIPv6)
    $anthro = Get-KSAnthropicRanges
    $specs = @(
        [pscustomobject]@{ Name = 'KS - Block Anthropic IPv4 on physical';                 Remote = @('160.79.104.0/23') }
        [pscustomobject]@{ Name = 'KS - Block Anthropic IPv4 153.61.224.0-22 on physical'; Remote = @('153.61.224.0/22') }
        [pscustomobject]@{ Name = 'KS - Block Anthropic IPv6 on physical';                 Remote = $anthro.V6 }
    )
    if ($BlockAllIPv6) {
        $specs += [pscustomobject]@{ Name = 'KS - Block all IPv6 on physical'; Remote = (Get-KSPublicAddressSets).V6 }
    }
    return $specs
}

<#
    Known endpoints used by the read-only diagnostics. Category is deliberately
    narrow:
      Anthropic  = first-party names that should resolve into the official ranges
      ThirdParty = third-party hosting observed in current DNS or the 2026-11
                   research (Sift's browser beacon)
      Historical = a name kept only to correct stale documentation; its failure
                   to resolve is expected and is not a verification gap.
    This is a diagnostic catalog, not a blocking list. Resolved addresses are
    shared/dynamic infrastructure and must not be turned into firewall rules.
#>
function Get-KSKnownEndpoints {
    @(
        [pscustomobject]@{ Name = 'api.anthropic.com';        Role = 'Claude API';                              Category = 'Anthropic';  Note = '官方网段内' }
        [pscustomobject]@{ Name = 'claude.ai';                Role = 'Web app';                                 Category = 'Anthropic';  Note = '官方网段内' }
        [pscustomobject]@{ Name = 'platform.claude.com';      Role = 'Developer platform';                      Category = 'Anthropic';  Note = '官方网段内' }
        [pscustomobject]@{ Name = 's-cdn.anthropic.com';      Role = 'Sift browser beacon (web pages)';         Category = 'ThirdParty'; Note = 'CNAME 到 Sift CDN，非 Anthropic 自有网段' }
        [pscustomobject]@{ Name = 'b-0.hexagon-cdn.com';      Role = 'Sift CDN host (CNAME target)';            Category = 'ThirdParty'; Note = 'Sift 托管的共享 CDN' }
        [pscustomobject]@{ Name = 'statsig.anthropic.com';    Role = 'Historical client telemetry / flags';     Category = 'Historical'; Note = '2026-11-23 曾 NXDOMAIN；以本次解析为准' }
    )
}

# Resolve CNAME/A/AAAA through the system resolver. Read-only; never opens a
# TCP connection to the endpoint. CNAME flattening by a local resolver is
# possible, so callers must not treat an empty CNAME list as proof of no CNAME.
function Get-KSEndpointDnsRecords {
    param([string]$Name)
    $ips = [System.Collections.Generic.List[string]]::new()
    $cnames = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($type in @('CNAME', 'A', 'AAAA')) {
        try {
            foreach ($answer in @(Resolve-DnsName -Name $Name -Type $type -ErrorAction Stop)) {
                if ($answer.Type -eq 'CNAME' -and $answer.NameHost) {
                    $cnames.Add(([string]$answer.NameHost).TrimEnd('.'))
                }
                if ($answer.IPAddress) { $ips.Add([string]$answer.IPAddress) }
            }
        } catch {
            $errors.Add(('{0}: {1}' -f $type, $_.Exception.Message))
        }
    }
    [pscustomobject]@{
        Name        = $Name
        CNAME       = @($cnames | Sort-Object -Unique)
        IPAddresses = @($ips | Sort-Object -Unique)
        Resolved    = ($ips.Count -gt 0)
        Error       = $(if ($ips.Count -eq 0) { $errors -join '; ' } else { '' })
    }
}

# Exact CIDR containment for IPv4 and IPv6. Returns false for malformed input
# or mixed address families; a false negative is safe here because callers
# report "not covered" / "unverified", never "safe".
function Test-KSIPInCIDR {
    param([string]$IP, [string]$CIDR)
    $address = $null
    if (-not [System.Net.IPAddress]::TryParse($IP, [ref]$address)) { return $false }
    # Windows returns IPv4 prefixes with dotted masks; normalize before parsing.
    $parts = @((ConvertTo-KSNormalizedAddress $CIDR) -split '/')
    if ($parts.Count -ne 2) { return $false }
    $network = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$network)) { return $false }
    $prefixLength = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefixLength)) { return $false }

    $addressBytes = $address.GetAddressBytes()
    $networkBytes = $network.GetAddressBytes()
    if ($addressBytes.Length -ne $networkBytes.Length) { return $false }
    if ($prefixLength -lt 0 -or $prefixLength -gt ($addressBytes.Length * 8)) { return $false }

    $fullBytes = [int][math]::Floor($prefixLength / 8)
    $remainder = $prefixLength % 8
    for ($i = 0; $i -lt $fullBytes; $i++) {
        if ($addressBytes[$i] -ne $networkBytes[$i]) { return $false }
    }
    if ($remainder -eq 0) { return $true }
    $mask = (0xFF -shl (8 - $remainder)) -band 0xFF
    return (([int]$addressBytes[$fullBytes] -band $mask) -eq ([int]$networkBytes[$fullBytes] -band $mask))
}

# covered / partial / not-covered / unresolved. Empty prefixes never count as
# coverage: that is how "basic protection not installed" stays honest.
function Get-KSAddressSetCoverage {
    param([string[]]$IPAddresses, [string[]]$Prefixes)
    $ips = @($IPAddresses | Where-Object { $_ })
    if ($ips.Count -eq 0) { return 'unresolved' }
    $covered = 0
    foreach ($ip in $ips) {
        $hit = $false
        foreach ($prefix in @($Prefixes)) {
            if ($prefix -and (Test-KSIPInCIDR -IP $ip -CIDR $prefix)) { $hit = $true; break }
        }
        if ($hit) { $covered++ }
    }
    if ($covered -eq $ips.Count) { return 'covered' }
    if ($covered -eq 0) { return 'not-covered' }
    return 'partial'
}

# Batch filter lookup used by diagnostics: one -All pass first, then a
# per-rule pipeline only for entries -All missed. Keyed by InstanceID (the
# rule Name GUID). This mirrors the proven approach in 00-check.
function Get-KSFilterIndex {
    param([string]$FilterCommand, [object[]]$Rules)
    $idx = @{}
    & $FilterCommand -All -ErrorAction SilentlyContinue |
        ForEach-Object { $idx[$_.InstanceID] = $_ }
    foreach ($r in @($Rules)) {
        if (-not $idx.ContainsKey($r.Name)) {
            $f = @($r | & $FilterCommand -ErrorAction SilentlyContinue | Select-Object -First 1)
            if ($f) { $idx[$r.Name] = $f[0] }
        }
    }
    return $idx
}

# Health check over already-fetched filter data, so coverage checks can batch
# filter reads instead of invoking three filter cmdlets per rule per target.
function Test-KSRuleHealthData {
    param(
        $Rule,
        [string[]]$RemoteAddress,
        [string]$Program,
        [string[]]$InterfaceAlias,
        [string[]]$ExpectedRemoteAddress,
        [string]$ExpectedProgram = '',
        [string[]]$ExpectedInterfaceAlias
    )
    if (-not $Rule) { return $false }
    if ("$($Rule.Enabled)"   -ne 'True')     { return $false }
    if ("$($Rule.Direction)" -ne 'Outbound') { return $false }
    if ("$($Rule.Action)"    -ne 'Block')    { return $false }
    if ("$($Rule.Profile)"   -ne 'Any')      { return $false }
    if (-not (Test-KSAddressCoverage -Expected $ExpectedRemoteAddress -Actual $RemoteAddress)) { return $false }
    if ($ExpectedProgram -and "$Program" -ne $ExpectedProgram) { return $false }
    foreach ($i in @($ExpectedInterfaceAlias)) {
        if (@($InterfaceAlias) -notcontains $i) { return $false }
    }
    return $true
}

# Rule view: rule identity plus the three filters, fetched once.
function New-KSRuleView {
    param($Rule, [string[]]$RemoteAddress, [string]$Program, [string[]]$InterfaceAlias)
    [pscustomobject]@{
        Rule           = $Rule
        RemoteAddress  = @($RemoteAddress)
        Program        = "$Program"
        InterfaceAlias = @($InterfaceAlias)
    }
}

# Per-target coverage by the per-process layer: a target is covered only when
# a healthy IPv4 rule AND a healthy IPv6 rule exist for its exact path.
function Get-KSAppRuleCoverage {
    param(
        [string[]]$Targets,
        $RuleViews,
        [string[]]$ExpectedRemote4,
        [string[]]$ExpectedRemote6,
        [string[]]$ExpectedInterfaceAlias
    )
    $covered = [System.Collections.Generic.List[string]]::new()
    $uncovered = [System.Collections.Generic.List[string]]::new()
    foreach ($target in @($Targets | Sort-Object -Unique)) {
        $v4 = @($RuleViews | Where-Object {
            Test-KSRuleHealthData -Rule $_.Rule -RemoteAddress $_.RemoteAddress -Program $_.Program `
                -InterfaceAlias $_.InterfaceAlias -ExpectedRemoteAddress $ExpectedRemote4 `
                -ExpectedProgram $target -ExpectedInterfaceAlias $ExpectedInterfaceAlias })
        $v6 = @($RuleViews | Where-Object {
            Test-KSRuleHealthData -Rule $_.Rule -RemoteAddress $_.RemoteAddress -Program $_.Program `
                -InterfaceAlias $_.InterfaceAlias -ExpectedRemoteAddress $ExpectedRemote6 `
                -ExpectedProgram $target -ExpectedInterfaceAlias $ExpectedInterfaceAlias })
        if ($v4.Count -gt 0 -and $v6.Count -gt 0) { $covered.Add($target) }
        else { $uncovered.Add($target) }
    }
    [pscustomobject]@{ Covered = @($covered); Uncovered = @($uncovered) }
}

# 0 = no gap and no unverified item; 1 = concrete gap; 2 = incomplete audit.
function Get-KSCoverageExitCode {
    param([int]$GapCount, [int]$UnverifiedCount)
    if ($GapCount -gt 0) { return 1 }
    if ($UnverifiedCount -gt 0) { return 2 }
    return 0
}

# Convert 'a.b.c.d/255.255.252.0' to 'a.b.c.d/22'; pass everything else through
# unchanged (ranges like '1.0.0.0-9.255.255.255' and IPv6 prefixes compare literally).
function ConvertTo-KSNormalizedAddress {
    param([string]$Address)
    $a = $Address.Trim()
    if ($a -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$') {
        # Capture the groups immediately: any later -match would overwrite $Matches.
        $net = $Matches[1]
        $mask = $Matches[2]
        $bits = ''
        foreach ($octet in ($mask.Split('.'))) {
            $bits += [Convert]::ToString([int]$octet, 2).PadLeft(8, '0')
        }
        # Non-contiguous masks are not valid prefix lengths; leave them as-is.
        if ($bits -match '^1*0*$') {
            return ('{0}/{1}' -f $net, $bits.TrimEnd('0').Length)
        }
    }
    return $a.ToLower()
}

# Every expected address must be present in the actual list. Subset semantics:
# extra addresses on the rule are fine (old installs keep wider lists), missing
# ones mean the rule no longer blocks what it was created to block.
function Test-KSAddressCoverage {
    param([string[]]$Expected, [string[]]$Actual)
    $actualNorm = @($Actual | ForEach-Object { ConvertTo-KSNormalizedAddress $_ } | Where-Object { $_ })
    foreach ($e in @($Expected)) {
        if ($actualNorm -notcontains (ConvertTo-KSNormalizedAddress $e)) { return $false }
    }
    return $true
}

# Full "rule health" check. A rule that exists but is disabled, retargeted,
# or no longer bound to every current physical adapter is NOT protection.
function Test-KSRuleHealth {
    param(
        $Rule,
        [string[]]$ExpectedRemoteAddress,
        [string]$ExpectedProgram = '',
        [string[]]$ExpectedInterfaceAlias
    )
    if (-not $Rule) { return $false }
    $addr = @(($Rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).RemoteAddress)
    $prog = ''
    if ($ExpectedProgram) {
        $prog = ($Rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program
    }
    $ifa = @(($Rule | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue).InterfaceAlias)
    return (Test-KSRuleHealthData -Rule $Rule -RemoteAddress $addr -Program "$prog" -InterfaceAlias $ifa `
        -ExpectedRemoteAddress $ExpectedRemoteAddress -ExpectedProgram $ExpectedProgram `
        -ExpectedInterfaceAlias $ExpectedInterfaceAlias)
}

<#
    Create / skip / in-place-repair one block rule so that "same name" means
    "actually healthy". Returns @{ Action = 'created' | 'repaired' | 'skipped' }.

    Repair uses Set-NetFirewallRule on the existing rule: nothing is ever
    deleted, so there is no unprotected window (add-before-remove semantics
    are preserved trivially because there is no remove at all).
#>
function Update-KSBlockRule {
    param(
        [string]$Name,
        [string]$Group,
        [string[]]$RemoteAddress,
        [string[]]$InterfaceAlias,
        [string]$Program = '',
        $ExistingRules
    )
    $sameName = @($ExistingRules | Where-Object { $_.DisplayName -eq $Name })
    if ($sameName.Count -gt 0) {
        $unhealthy = @($sameName | Where-Object {
            -not (Test-KSRuleHealth -Rule $_ -ExpectedRemoteAddress $RemoteAddress `
                                      -ExpectedProgram $Program -ExpectedInterfaceAlias $InterfaceAlias) })
        if ($unhealthy.Count -eq 0) { return @{ Action = 'skipped' } }
        foreach ($r in $unhealthy) {
            $setParams = @{
                Enabled       = 'True'
                Direction     = 'Outbound'
                Action        = 'Block'
                Profile       = 'Any'
                RemoteAddress = $RemoteAddress
                InterfaceAlias = $InterfaceAlias
            }
            if ($Program) { $setParams.Program = $Program }
            $r | Set-NetFirewallRule @setParams
        }
        return @{ Action = 'repaired' }
    }
    $newParams = @{
        DisplayName   = $Name
        Group         = $Group
        Direction     = 'Outbound'
        Action        = 'Block'
        Profile       = 'Any'
        RemoteAddress = $RemoteAddress
        InterfaceAlias = $InterfaceAlias
    }
    if ($Program) { $newParams.Program = $Program }
    New-NetFirewallRule @newParams | Out-Null
    return @{ Action = 'created' }
}

<#
    Gate for 03-verify.ps1 -TestAnthropic. The step must be skipped when
    earlier tests already failed, when the Claude-KS rules are not installed
    (proceeding would just create a real direct connection), and refused when
    any Claude-related process is still alive (the /32 host route affects
    every process on the machine, not just the probe).

    Returns @{ Run; Category = 'run' | 'skip' | 'refuse'; Reason; SkipItem }.
#>
function Get-KSAnthropicGateDecision {
    param([int]$FailedCount, [bool]$HasClaudeKS, [string[]]$ClaudeProcessNames)
    if ($FailedCount -gt 0) {
        return @{ Run = $false; Category = 'skip'
                  Reason = '前面的测试有失败项，-TestAnthropic 已跳过：先弄清失败原因，再测正式规则。'
                  SkipItem = 'Anthropic 规则（前序测试失败）' }
    }
    if (-not $HasClaudeKS) {
        return @{ Run = $false; Category = 'skip'
                  Reason = '还没装基础防护（Claude-KS），这一项无法验证 —— 直接测只会产生一次真实直连。'
                  SkipItem = 'Anthropic 规则（未安装基础防护）' }
    }
    if (@($ClaudeProcessNames).Count -gt 0) {
        return @{ Run = $false; Category = 'refuse'
                  Reason = ("检测到 Claude 相关进程还在运行：{0}。这条 /32 主机路由影响整机所有进程，" -f ($ClaudeProcessNames -join '、')) +
                           '请先完全退出所有 Claude 相关进程（含托盘和 CLI），再跑这一步。'
                  SkipItem = 'Anthropic 规则（Claude 进程未退出）' }
    }
    return @{ Run = $true; Category = 'run'; Reason = ''; SkipItem = '' }
}

<#
    Look for a WFP 5157 (blocked connection) audit event matching the probe
    destination and return its FilterOrigin (the firewall rule ID that did
    the blocking). Language-neutral: reads the event XML data fields, not the
    localized message. Returns $null when auditing is off, the Security log
    is unreadable, or the matching event carries no FilterOrigin — callers
    must treat that as "cannot prove", never as "blocked by our rule".
#>
function Find-KSWfpBlockOrigin {
    param([string]$DestinationIP, [datetime]$Since)
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5157; StartTime = $Since } `
            -MaxEvents 200 -ErrorAction Stop
    } catch {
        return $null
    }
    foreach ($e in $events) {
        try { $xmlDoc = [xml]$e.ToXml() } catch { continue }
        $ns = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable)
        $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
        $dest = $xmlDoc.SelectSingleNode('//e:EventData/e:Data[@Name="DestAddress"]', $ns)
        if (-not $dest -or $dest.'#text' -ne $DestinationIP) { continue }
        $origin = $xmlDoc.SelectSingleNode('//e:EventData/e:Data[@Name="FilterOrigin"]', $ns)
        if ($origin) { return $origin.'#text' }
        return $null
    }
    return $null
}

<#
    Return identities holding write-ish Allow ACEs on an ACL object that are
    not SYSTEM (S-1-5-18) or BUILTIN\Administrators (S-1-5-32-544). A non-empty
    result means the directory is writable by non-admins — for a directory a
    HighestAvailable scheduled task executes scripts from, that is a
    privilege-escalation path and installation must be refused.
#>
function Get-KSUnsafeAclIdentities {
    param($Acl)
    $safeSids = @('S-1-5-18', 'S-1-5-32-544')
    # Only bits that actually enable code replacement: modify/append content,
    # delete, rewrite the DACL, or take ownership. Composites like FullControl
    # include READ bits, so banding against them would flag read-only ACEs.
    $dangerBits = [int][System.Security.AccessControl.FileSystemRights]::WriteData -bor
                  [int][System.Security.AccessControl.FileSystemRights]::AppendData -bor
                  [int][System.Security.AccessControl.FileSystemRights]::Delete -bor
                  [int][System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                  [int][System.Security.AccessControl.FileSystemRights]::TakeOwnership
    $unsafe = @()
    foreach ($ace in @($Acl.Access)) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if (([int]$ace.FileSystemRights -band $dangerBits) -eq 0) { continue }
        $sid = $null
        try {
            $sid = $ace.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]).Value
        } catch { }
        if ($sid -and $safeSids -contains $sid) { continue }
        $unsafe += $ace.IdentityReference.Value
    }
    return @($unsafe | Sort-Object -Unique)
}

<#
    Decide whether the rebuild may proceed after target discovery.
    Abort when any discovery source failed to read (its coverage is unknown,
    so a green "all covered" would be a lie) or when zero targets were found.
    Existing rules are never touched on abort.
    Returns @{ Abort; Reason }.
#>
function Get-KSDiscoveryVerdict {
    param($SourceStatuses, [int]$TargetCount)
    $failed = @($SourceStatuses | Where-Object { $_.Status -eq 'failed' })
    if ($failed.Count -gt 0) {
        return @{ Abort = $true
                  Reason = ('发现源读取失败：' + (($failed | ForEach-Object { $_.Source }) -join '、') + '，覆盖范围未知') }
    }
    if ($TargetCount -eq 0) {
        return @{ Abort = $true; Reason = '一个目标都没发现' }
    }
    return @{ Abort = $false; Reason = '' }
}

<#
    Exit code for 03-verify.ps1: 0 = all verified, 1 = something failed,
    2 = something could not be verified (incomplete conclusion, NOT a pass).
#>
function Get-KSVerifyExitCode {
    param([string[]]$Pass, [string[]]$Fail, [string[]]$Skip)
    if (@($Fail).Count -gt 0) { return 1 }
    if (@($Skip).Count -gt 0) { return 2 }
    if (@($Pass).Count -gt 0) { return 0 }
    return 2
}

<#
    Conclusion lines for 03-verify.ps1, split into four honest categories:
    installed / config-check passed / live-test passed / not verified.
    The decoy tests only cover IPv4+TCP; IPv6 and UDP/QUIC are called out
    explicitly so a pass is never over-read.
#>
function Get-KSVerifyConclusion {
    param([string[]]$Pass, [string[]]$Fail, [string[]]$Skip, [bool]$BasicInstalled, [bool]$AppInstalled)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add(('已安装：基础防护(Claude-KS)={0}；完整防护(Claude-KS-App)={1}' -f `
        $(if ($BasicInstalled) { '是' } else { '否' }), $(if ($AppInstalled) { '是' } else { '否' })))
    $mechanism = @($Pass | Where-Object { $_ -in '按目的地封', '按程序封' })
    if ($mechanism.Count -eq 2) {
        $lines.Add('配置检查通过：两种规则机制（按目的地、按程序）都已证明会开火')
    } elseif ($mechanism.Count -gt 0) {
        $lines.Add(('配置检查部分通过：{0}（另一种机制未通过或未验证）' -f ($mechanism -join '、')))
    } else {
        $lines.Add('配置检查：没有成功项（机制未通过或未验证）')
    }
    if (@($Pass) -contains 'Anthropic 规则') {
        $lines.Add('实测通过：Anthropic 正式规则已在物理网卡上实际拦截（有 WFP 归因证据）')
    } else {
        $lines.Add('实测通过：无（-TestAnthropic 未跑、被跳过或未通过）')
    }
    if (@($Skip).Count -gt 0) {
        $lines.Add(('未验证：{0}' -f (@($Skip) -join '、')))
    } else {
        $lines.Add('未验证：无')
    }
    $lines.Add('未实测范围：IPv6 与 UDP/QUIC —— 诱饵测试只覆盖 IPv4+TCP，这两条路径是否被挡住，本脚本没有证据。')
    return $lines
}

<#
    Final exit code for 02-full-install.ps1: propagate the first rebuild's
    exit code instead of always exiting 0, so scripted installs can detect
    partial coverage. Rules and the scheduled task are kept either way.
#>
function Get-KSInstallFinalExit {
    param([int]$RebuildExitCode)
    return $RebuildExitCode
}

<#
    Identity of a route created by 03-verify.ps1. Cleanup must use the FULL
    identity (prefix + ifIndex + next hop): deleting by bare prefix would
    also delete someone else's pre-existing route for the same prefix on a
    different interface.
#>
function New-KSRouteRef {
    param([string]$Prefix, [int]$IfIndex, [string]$NextHop)
    [pscustomobject]@{ Prefix = $Prefix; IfIndex = $IfIndex; NextHop = $NextHop }
}

<#
    Remove one test route by its full identity and verify by reading back.
    Returns 'removed' (was there, now gone), 'not-found' (already gone), or
    'failed' (still present after the attempt — must be reported, never
    swallowed behind a blanket 'cleaned up').
#>
function Remove-KSTestRoute {
    param($RouteRef)
    $caught = $null
    try {
        Remove-NetRoute -DestinationPrefix $RouteRef.Prefix -InterfaceIndex $RouteRef.IfIndex `
            -NextHop $RouteRef.NextHop -PolicyStore ActiveStore -Confirm:$false -ErrorAction Stop
    } catch {
        $caught = $_
    }
    $left = @(Get-NetRoute -DestinationPrefix $RouteRef.Prefix -InterfaceIndex $RouteRef.IfIndex `
        -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
    if ($left.Count -eq 0) {
        if ($caught) { return 'not-found' } else { return 'removed' }
    }
    return 'failed'
}
