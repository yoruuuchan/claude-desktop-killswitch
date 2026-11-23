<#
    Claude 防直连 —— 覆盖核对（只读）

    回答三个问题：
      · 已安装的基础版规则，是否仍覆盖 Anthropic 官方网段？
      · 已安装的完整版规则，是否仍覆盖当前机器上的全部 Claude 程序？
      · 已知的第三方端点（Sift 等）解析到哪里，哪一层能覆盖，哪一层覆盖不了？

    不创建、修改、删除任何防火墙规则，不建立 TCP/TLS 连接，只读本机配置、
    已装规则和系统 DNS。它不能证明「Claude 实际访问了哪个端点」—— 那需要
    抓包；它只核对「规则是否还在正确的位置」。

    退出码：
      0 = 已安装的防护层健康，没有发现具体缺口
      1 = 发现覆盖缺口（规则缺失/不健康、防火墙未开、基础层未安装等）
      2 = 无法完整核对（规则或 DNS 读取失败、完整版已装但找不到目标）
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'ks-lib.ps1')

function Section($t) {
    Write-Host ''
    Write-Host ('─' * 70) -ForegroundColor DarkGray
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ('─' * 70) -ForegroundColor DarkGray
}
function Ok($t)   { Write-Host "  [ 好 ] $t" -ForegroundColor Green }
function Warn($t) { Write-Host "  [注意] $t" -ForegroundColor Yellow }
function Bad($t)  { Write-Host "  [问题] $t" -ForegroundColor Red }
function Info($t) { Write-Host "         $t" -ForegroundColor Gray }

function Format-Coverage([string]$Status) {
    switch ($Status) {
        'covered'       { '覆盖' }
        'partial'       { '部分覆盖' }
        'not-covered'   { '未覆盖' }
        'unresolved'    { '无法解析' }
        'not-installed' { '未安装' }
        default         { $Status }
    }
}
function Format-Matrix([bool]$Covered) {
    if ($Covered) { return '覆盖' }
    return '未覆盖'
}

$gaps = [System.Collections.Generic.List[string]]::new()
$unverified = [System.Collections.Generic.List[string]]::new()

Write-Host ''
Write-Host '  Claude 防直连 —— 覆盖核对（只读，不会改动任何东西）' -ForegroundColor White


# ---------------------------------------------------------------- 网卡 ----
Section '0. 网卡与防火墙状态'

$phys = @((Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -ne 'Not Present' }).Name)
if ($phys.Count -eq 0) {
    Bad '找不到任何物理网卡。规则无法绑定到真实出口。'
    $gaps.Add('NO_PHYSICAL')
} else {
    Ok "物理网卡：$($phys -join '、')"
}

$firewallOn = $true
$fwOffReported = $false
try {
    foreach ($profile in @(Get-NetFirewallProfile -ErrorAction Stop)) {
        if ($profile.Enabled -ne $true) {
            $firewallOn = $false
            Bad "防火墙 profile「$($profile.Name)」未开启：已安装的规则不会生效。"
            if (-not $fwOffReported) {
                $gaps.Add('FW_PROFILE_OFF')
                $fwOffReported = $true
            }
        }
    }
    if ($firewallOn) { Ok 'Windows 防火墙 profile 全部开启。' }
} catch {
    Warn '无法读取 Windows 防火墙 profile 状态。'
    $unverified.Add('firewall-profile')
}

# PersistentStore 里有、ActiveStore 里没有 = 现在不生效（被禁用或被策略压掉）。
$allKsRules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.Group -like 'Claude-KS*' })
if ($allKsRules.Count -gt 0) {
    try {
        $activeRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { $_.Group -like 'Claude-KS*' })
        $activeByName = @{}
        foreach ($a in $activeRules) { $activeByName[$a.Name] = $a }

        $missingActive = @()
        $disabledActive = @()
        foreach ($r in $allKsRules) {
            $active = $activeByName[$r.Name]
            if (-not $active) { $missingActive += $r }
            elseif ("$($active.Enabled)" -ne 'True') { $disabledActive += $r }
        }
        if ($missingActive.Count -gt 0 -or $disabledActive.Count -gt 0) {
            if ($missingActive.Count -gt 0) {
                Bad ("有 {0} 条项目规则在持久存储里但不在生效存储（ActiveStore）中：" -f $missingActive.Count)
                $missingActive | Select-Object -First 5 | ForEach-Object { Info "  · $($_.DisplayName)" }
            }
            if ($disabledActive.Count -gt 0) {
                Bad ("有 {0} 条项目规则在生效存储中被禁用：" -f $disabledActive.Count)
                $disabledActive | Select-Object -First 5 | ForEach-Object { Info "  · $($_.DisplayName)" }
            }
            $gaps.Add('NOT_ACTIVE')
        } else {
            Ok '项目规则都在生效存储（ActiveStore）中且已启用。'
        }
    } catch {
        Warn '无法读取 ActiveStore，无法核对规则是否真的生效。'
        $unverified.Add('active-store')
    }
}


# ------------------------------------------------------------ 发现程序 ----
Section '1. 当前 Claude 程序'

$targets = [System.Collections.Generic.List[string]]::new()
$targetReadFailures = [System.Collections.Generic.List[string]]::new()
$desktopDiscoveryIncomplete = $false

function Add-ExeTargetsFromDir([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    try {
        Get-ChildItem -LiteralPath $Path -Recurse -File -Filter '*.exe' -ErrorAction Stop |
            ForEach-Object { $script:targets.Add($_.FullName) }
    } catch {
        $script:targetReadFailures.Add($Path)
    }
}

$userRoots = @($env:USERPROFILE)
try {
    $userRoots += @(Get-ChildItem -LiteralPath 'C:\Users' -Directory -ErrorAction Stop |
        Select-Object -ExpandProperty FullName)
} catch {
    $targetReadFailures.Add('C:\Users')
}
$userRoots = @($userRoots | Where-Object { $_ } | Sort-Object -Unique)

# Desktop (MSIX)：Appx API + WindowsApps 直接扫描，只读。
$installLocs = [System.Collections.Generic.List[string]]::new()
foreach ($query in @(
        { Get-AppxPackage -Name Claude -AllUsers -ErrorAction Stop },
        { Get-AppxPackage -Name Claude -ErrorAction Stop })) {
    try {
        foreach ($pkg in @(& $query)) {
            if ($pkg.InstallLocation) { $installLocs.Add($pkg.InstallLocation) }
        }
    } catch {
        # -AllUsers often needs admin; a failed enumeration does not by itself
        # prove Claude Desktop is absent, so keep it as a separate caveat.
        $script:desktopDiscoveryIncomplete = $true
    }
}
$winApps = Join-Path $env:ProgramFiles 'WindowsApps'
if (Test-Path -LiteralPath $winApps -PathType Container) {
    try {
        Get-ChildItem -LiteralPath $winApps -Directory -Filter 'Claude_*' -ErrorAction Stop |
            ForEach-Object { $installLocs.Add($_.FullName) }
    } catch {
        $script:desktopDiscoveryIncomplete = $true
    }
}
foreach ($loc in ($installLocs | Sort-Object -Unique)) { Add-ExeTargetsFromDir $loc }

# 包目录之外的扩展 / MCP 进程。
foreach ($u in $userRoots) {
    Add-ExeTargetsFromDir (Join-Path $u 'AppData\Roaming\Claude\Claude Extensions')
    Add-ExeTargetsFromDir (Join-Path $u 'AppData\Roaming\Claude\claude-code')
    $pkgRoot = Join-Path $u 'AppData\Local\Packages'
    if (Test-Path -LiteralPath $pkgRoot -PathType Container) {
        try {
            Get-ChildItem -LiteralPath $pkgRoot -Directory -Filter 'Claude_*' -ErrorAction Stop |
                ForEach-Object {
                    Add-ExeTargetsFromDir (Join-Path $_.FullName 'LocalCache\Roaming\Claude\Claude Extensions')
                }
        } catch {
            $targetReadFailures.Add($pkgRoot)
        }
    }
}

# Claude Code CLI：npm 自定义 prefix、默认全局位置、原生安装位置。
$npmPrefixes = [System.Collections.Generic.List[string]]::new()
foreach ($u in $userRoots) {
    foreach ($npmrc in @(
            (Join-Path $u '.npmrc'),
            (Join-Path $u 'AppData\Roaming\npm\etc\npmrc'))) {
        if (-not (Test-Path -LiteralPath $npmrc -PathType Leaf)) { continue }
        try {
            foreach ($line in @(Get-Content -LiteralPath $npmrc -ErrorAction Stop)) {
                if ($line -match '^\s*prefix\s*=\s*(.+?)\s*$') { $npmPrefixes.Add($Matches[1]) }
            }
        } catch {
            $targetReadFailures.Add($npmrc)
        }
    }
    $npmPrefixes.Add((Join-Path $u 'AppData\Roaming\npm'))
    # Do NOT scan all of ~/.local/bin: it contains unrelated tools. The CLI
    # loop below adds only claude.exe from this prefix.
    $npmPrefixes.Add((Join-Path $u '.local\bin'))
}
if ($env:NPM_CONFIG_PREFIX) { $npmPrefixes.Add($env:NPM_CONFIG_PREFIX) }
$npmPrefixes.Add((Join-Path $env:ProgramFiles 'nodejs'))

foreach ($prefix in ($npmPrefixes | Sort-Object -Unique)) {
    $pkgDir = Join-Path $prefix 'node_modules\@anthropic-ai\claude-code'
    $bin = Join-Path $pkgDir 'bin\claude.exe'
    if (Test-Path -LiteralPath $bin -PathType Leaf) { $targets.Add($bin) }

    $scoped = Join-Path $pkgDir 'node_modules\@anthropic-ai'
    if (Test-Path -LiteralPath $scoped -PathType Container) {
        try {
            Get-ChildItem -LiteralPath $scoped -Directory -Filter 'claude-code-*' -ErrorAction Stop |
                ForEach-Object {
                    $platform = Join-Path $_.FullName 'claude.exe'
                    if (Test-Path -LiteralPath $platform -PathType Leaf) { $targets.Add($platform) }
                }
        } catch {
            $targetReadFailures.Add($scoped)
        }
    }

    if ($prefix -notmatch '@anthropic-ai') {
        $native = Join-Path $prefix 'claude.exe'
        if (Test-Path -LiteralPath $native -PathType Leaf) { $targets.Add($native) }
    }
}

$targetList = @($targets | Sort-Object -Unique)
Info ("发现 {0} 个 Claude 相关可执行文件。" -f $targetList.Count)
foreach ($t in ($targetList | Select-Object -First 12)) { Info "  · $t" }
if ($targetList.Count -gt 12) { Info ("  … 还有 {0} 个" -f ($targetList.Count - 12)) }

$targetReadFailures = @($targetReadFailures | Sort-Object -Unique)
if ($targetReadFailures.Count -gt 0) {
    Warn '以下位置读取失败，程序清单可能不完整：'
    $targetReadFailures | ForEach-Object { Info "  · $_" }
}
if ($desktopDiscoveryIncomplete) {
    Info 'WindowsApps / Appx 包无法完整枚举（非管理员常见）；如果这台机器装了 Claude Desktop，上面的清单可能不含它。'
    Info '若完整版已安装，这种不完整会在下面标为「无法完整核对」，不会报成功。'
}


# ------------------------------------------------------------ 基础防护 ----
Section '2. 基础防护（按目的地）'

$basicRules = @(Get-NetFirewallRule -Group 'Claude-KS' -ErrorAction SilentlyContinue)
$basicInstalled = $basicRules.Count -gt 0
$basicSpecsOk = $false
$basicPrefixes = @()

if (-not $basicInstalled) {
    Bad '基础防护未安装：未知程序 → 已知 Anthropic 地址这一格没有覆盖。'
    $gaps.Add('BASIC_MISSING')
} else {
    $basicAddrById = Get-KSFilterIndex -FilterCommand 'Get-NetFirewallAddressFilter' -Rules $basicRules
    $basicIfById = Get-KSFilterIndex -FilterCommand 'Get-NetFirewallInterfaceFilter' -Rules $basicRules
    $basicViews = @(
        foreach ($rule in $basicRules) {
            $addrFilter = $basicAddrById[$rule.Name]
            $ifFilter = $basicIfById[$rule.Name]
            New-KSRuleView -Rule $rule `
                -RemoteAddress $(if ($addrFilter) { @($addrFilter.RemoteAddress) } else { @() }) `
                -Program '' `
                -InterfaceAlias $(if ($ifFilter) { @($ifFilter.InterfaceAlias) } else { @() })
        }
    )

    $specChecks = @(foreach ($spec in (Get-KSBasicRuleSpecs)) {
        [pscustomobject]@{ Spec = $spec; Required = $true }
    })
    if (@($basicRules | Where-Object { $_.DisplayName -eq 'KS - Block all IPv6 on physical' }).Count -gt 0) {
        $optional = @((Get-KSBasicRuleSpecs -BlockAllIPv6) |
            Where-Object { $_.Name -eq 'KS - Block all IPv6 on physical' })[0]
        $specChecks += [pscustomobject]@{ Spec = $optional; Required = $false }
    }

    $allRequiredOk = $true
    foreach ($check in $specChecks) {
        $spec = $check.Spec
        $same = @($basicViews | Where-Object { $_.Rule.DisplayName -eq $spec.Name })
        $healthy = @($same | Where-Object {
            Test-KSRuleHealthData -Rule $_.Rule -RemoteAddress $_.RemoteAddress -Program $_.Program `
                -InterfaceAlias $_.InterfaceAlias -ExpectedRemoteAddress $spec.Remote `
                -ExpectedInterfaceAlias $phys })
        if ($healthy.Count -gt 0) {
            Ok "健康：$($spec.Name)"
        } else {
            if ($check.Required) { $allRequiredOk = $false }
            Bad "缺失或不健康：$($spec.Name)"
            $gaps.Add("BASIC_RULE:$($spec.Name)")
        }
    }
    $basicSpecsOk = $allRequiredOk

    foreach ($view in $basicViews) {
        if (Test-KSRuleHealthData -Rule $view.Rule -RemoteAddress $view.RemoteAddress -Program $view.Program `
                -InterfaceAlias $view.InterfaceAlias -ExpectedRemoteAddress $view.RemoteAddress `
                -ExpectedInterfaceAlias $phys) {
            $basicPrefixes += @($view.RemoteAddress)
        }
    }
    Info ("基础规则的有效阻断地址集合：{0} 段" -f @($basicPrefixes).Count)
}


# ------------------------------------------------------------ 完整防护 ----
Section '3. 完整防护（按进程）'

$appRules = @(Get-NetFirewallRule -Group 'Claude-KS-App' -ErrorAction SilentlyContinue)
$appInstalled = $appRules.Count -gt 0
$fullCoverageOk = $false

if (-not $appInstalled) {
    Warn '完整版未安装：按进程层不存在。'
    Info '基础版只按目的地覆盖 Anthropic 网段；Sift / Sentry / Datadog 等第三方地址不在其中。'
    Info '如果你在意 Claude 程序自己的第三方遥测侧信道，装完整版。'
} elseif ($targetList.Count -eq 0) {
    Warn '完整版已安装，但没发现当前 Claude 程序 —— 无法证明覆盖。'
    $unverified.Add('no-targets')
} else {
    $appAddrById = Get-KSFilterIndex -FilterCommand 'Get-NetFirewallAddressFilter' -Rules $appRules
    $appProgById = Get-KSFilterIndex -FilterCommand 'Get-NetFirewallApplicationFilter' -Rules $appRules
    $appIfById = Get-KSFilterIndex -FilterCommand 'Get-NetFirewallInterfaceFilter' -Rules $appRules
    $appViews = @(
        foreach ($rule in $appRules) {
            $addrFilter = $appAddrById[$rule.Name]
            $progFilter = $appProgById[$rule.Name]
            $ifFilter = $appIfById[$rule.Name]
            New-KSRuleView -Rule $rule `
                -RemoteAddress $(if ($addrFilter) { @($addrFilter.RemoteAddress) } else { @() }) `
                -Program $(if ($progFilter) { $progFilter.Program } else { '' }) `
                -InterfaceAlias $(if ($ifFilter) { @($ifFilter.InterfaceAlias) } else { @() })
        }
    )
    $public = Get-KSPublicAddressSets
    $coverage = Get-KSAppRuleCoverage -Targets $targetList -RuleViews $appViews `
        -ExpectedRemote4 $public.V4 -ExpectedRemote6 $public.V6 -ExpectedInterfaceAlias $phys
    if ($coverage.Uncovered.Count -eq 0) {
        Ok ("全部 {0} 个程序都有健康的 IPv4 + IPv6 规则。" -f $targetList.Count)
        $fullCoverageOk = $true
    } else {
        Bad ("有 {0} 个程序没有被完整覆盖：" -f $coverage.Uncovered.Count)
        $coverage.Uncovered | ForEach-Object { Info "  · $_" }
        $gaps.Add('APP_UNCOVERED')
    }
    if ($targetReadFailures.Count -gt 0) {
        Warn '有目录读取失败，上面的完整覆盖结论可能不完整。'
        $unverified.Add('target-read-failure')
    }
    if ($desktopDiscoveryIncomplete) {
        $unverified.Add('desktop-discovery')
    }
}


# ------------------------------------------------------------ 端点核对 ----
Section '4. Anthropic 与第三方端点'

$anthroRanges = Get-KSAnthropicRanges
$officialPrefixes = @($anthroRanges.V4) + @($anthroRanges.V6)
foreach ($endpoint in (Get-KSKnownEndpoints)) {
    $dns = Get-KSEndpointDnsRecords -Name $endpoint.Name
    if (-not $dns.Resolved) {
        if ($endpoint.Category -eq 'Historical') {
            Warn ("{0,-24} 未解析 —— {1}" -f $endpoint.Name, $endpoint.Note)
        } else {
            Warn ("{0,-24} 未解析，无法核对（{1}）" -f $endpoint.Name, $dns.Error)
            $unverified.Add("dns:$($endpoint.Name)")
        }
        continue
    }

    $officialCoverage = Get-KSAddressSetCoverage -IPAddresses $dns.IPAddresses -Prefixes $officialPrefixes
    $basicCoverage = if ($basicInstalled) {
        Get-KSAddressSetCoverage -IPAddresses $dns.IPAddresses -Prefixes $basicPrefixes
    } else {
        'not-installed'
    }
    $cname = if ($dns.CNAME.Count -gt 0) { 'CNAME ' + ($dns.CNAME -join ' -> ') + ' -> ' } else { '' }
    $tag = switch ($officialCoverage) {
        'covered'     { '官方段内' }
        'not-covered' { '官方段外' }
        'partial'     { '部分官方段内' }
        default       { '未验证' }
    }
    Info ("{0,-24} {1}{2}  [{3}]" -f $endpoint.Name, $cname, ($dns.IPAddresses -join ', '), $tag)
    Info ("  {0}；基础版按目的地：{1}" -f $endpoint.Role, (Format-Coverage $basicCoverage))

    if ($endpoint.Category -eq 'Anthropic' -and $basicInstalled -and $basicCoverage -ne 'covered') {
        Bad ("  {0} 不在已安装基础规则的覆盖内。" -f $endpoint.Name)
        $gaps.Add("ENDPOINT:$($endpoint.Name)")
    }
    if ($endpoint.Category -eq 'ThirdParty' -and $officialCoverage -ne 'covered') {
        Info '  该地址不在 Anthropic 官方网段内：基础版不覆盖；完整版按进程可覆盖 Claude 程序。'
    }
}
Info ''
Info '本机解析器可能压平 CNAME；空 CNAME 不等于没有 CNAME。需要时用 DoH 复核，见 docs/verification.md。'
Info '只做 DNS 解析，不连接这些地址，也不产生任何流量到 Sift / Anthropic。'


# ------------------------------------------------------------ 覆盖矩阵 ----
Section '5. 覆盖矩阵与边界'

$basicEffective = $basicInstalled -and $basicSpecsOk -and $firewallOn
$fullEffective = $appInstalled -and $fullCoverageOk -and $firewallOn
Info ("已知程序 → 已知地址：{0}（基础版按目的地，或完整版按进程）" -f (Format-Matrix ($basicEffective -or $fullEffective)))
Info ("已知程序 → 未知/第三方地址：{0}（完整版按进程）" -f (Format-Matrix $fullEffective))
Info ("未知程序 → 已知地址：{0}（基础版按目的地）" -f (Format-Matrix $basicEffective))
Info '未知程序 → 未知地址：未覆盖 —— 本项目不包含全机 kill-switch。'
Info ''
Info '浏览器 → claude.ai / Sift：完整版不覆盖浏览器进程；基础版只封 Anthropic 官方网段。'
Info '代理挂掉时不要继续使用已打开的 claude.ai 页面 —— 第三方信标可能从浏览器直接出去。'
Info 'Sift / Datadog / Sentry 等共享 CDN/IP 会变；按 IP 封会误伤其他站点，本项目不建这类规则。'


# ---------------------------------------------------------------- 结论 ----
Section '结论'

if ($gaps.Count -eq 0 -and $unverified.Count -eq 0) {
    Ok '已安装的防护层健康，没有发现具体覆盖缺口。'
} else {
    if ($gaps.Count -gt 0) {
        Bad ("发现 {0} 个覆盖缺口：" -f $gaps.Count)
        $gaps | Sort-Object -Unique | ForEach-Object { Info "  · $_" }
    }
    if ($unverified.Count -gt 0) {
        Warn ("有 {0} 项无法完整核对：" -f $unverified.Count)
        $unverified | Sort-Object -Unique | ForEach-Object { Info "  · $_" }
    }
}
if (-not $appInstalled) {
    Info '完整版未安装是可选层的边界，不计为缺口；但它意味着「已知程序 → 第三方地址」这一格没有覆盖。'
}
Info ''
Info '本脚本只读：没有创建、修改、删除任何规则，也没有连接这些端点。'
Write-Host ''
exit (Get-KSCoverageExitCode -GapCount $gaps.Count -UnverifiedCount $unverified.Count)
