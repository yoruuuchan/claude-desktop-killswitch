<#
    Claude 防直连 —— 共享判断函数库

    纯判断逻辑，供 01-basic.ps1 / 02-full-rebuild.ps1 / 02-full-install.ps1 /
    03-verify.ps1 dot-source。本文件只定义函数，加载时不做任何系统查询或
    修改 —— tests/ 下的单元测试也只 dot-source 这一个文件（配合 mock 函数），
    绝不加载主脚本（那会触发管理员检查和真实防火墙调用）。

    规则健康的定义（同名 ≠ 有效）：
      Enabled=True、Direction=Outbound、Action=Block、Profile=Any、
      RemoteAddress 覆盖期望集合（同时接受 CIDR 与点分掩码两种表示）、
      Program 精确相等（按进程的规则）、InterfaceAlias 覆盖当前全部物理网卡。
#>

# Convert 'a.b.c.d/255.255.252.0' to 'a.b.c.d/22'; pass everything else through
# unchanged (ranges like '1.0.0.0-9.255.255.255' and IPv6 prefixes compare literally).
function ConvertTo-KSNormalizedAddress {
    param([string]$Address)
    $a = $Address.Trim()
    if ($a -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$') {
        $bits = ''
        foreach ($octet in ($Matches[2].Split('.'))) {
            $bits += [Convert]::ToString([int]$octet, 2).PadLeft(8, '0')
        }
        # Non-contiguous masks are not valid prefix lengths; leave them as-is.
        if ($bits -match '^1*0*$') {
            return ('{0}/{1}' -f $Matches[1], $bits.TrimEnd('0').Length)
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
    if ("$($Rule.Enabled)"   -ne 'True')     { return $false }
    if ("$($Rule.Direction)" -ne 'Outbound') { return $false }
    if ("$($Rule.Action)"    -ne 'Block')    { return $false }
    if ("$($Rule.Profile)"   -ne 'Any')      { return $false }
    $addr = @(($Rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).RemoteAddress)
    if (-not (Test-KSAddressCoverage -Expected $ExpectedRemoteAddress -Actual $addr)) { return $false }
    if ($ExpectedProgram) {
        $prog = ($Rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program
        if ("$prog" -ne $ExpectedProgram) { return $false }
    }
    $ifa = @(($Rule | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue).InterfaceAlias)
    foreach ($i in @($ExpectedInterfaceAlias)) {
        if ($ifa -notcontains $i) { return $false }
    }
    return $true
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
    $writeRights = [int][System.Security.AccessControl.FileSystemRights]::Write -bor
                   [int][System.Security.AccessControl.FileSystemRights]::Modify -bor
                   [int][System.Security.AccessControl.FileSystemRights]::FullControl
    $unsafe = @()
    foreach ($ace in @($Acl.Access)) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if (([int]$ace.FileSystemRights -band $writeRights) -eq 0) { continue }
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
