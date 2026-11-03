<#
    Claude 防直连 —— 环境体检

    这是一个【只读】脚本：不创建、不修改、不删除任何东西。
    跑完它你会知道：
      · 你现在是什么代理模式
      · 哪些是物理网卡（规则会绑在这些上面）
      · IPv6 是不是一个正在敞开的漏洞
      · 有没有已经脱靶的旧规则
      · 该不该装、装哪一档

    不需要管理员权限。
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

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

$findings = [System.Collections.Generic.List[string]]::new()

Write-Host ''
Write-Host '  Claude 防直连 —— 环境体检（只读，不会改动任何东西）' -ForegroundColor White


# ---------------------------------------------------------------- 网卡 ----
Section '1. 网卡'

$phys = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
          Where-Object { $_.Status -ne 'Not Present' })
if ($phys.Count -eq 0) {
    Bad '找不到任何物理网卡。这套方案没法用。'
    $findings.Add('NO_PHYSICAL')
} else {
    Ok "物理网卡（规则会绑在这些名字上）：$(($phys.Name) -join '、')"
    foreach ($a in $phys) {
        Info ("· {0} — {1} — {2}" -f $a.Name, $a.Status, $a.InterfaceDescription)
    }
}

$virt = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin $phys.Name -and $_.Status -eq 'Up' })
if ($virt.Count -gt 0) {
    Info ''
    Info '虚拟网卡（隧道 / 虚拟机，规则不会碰它们）：'
    foreach ($a in $virt) { Info ("· {0} — {1}" -f $a.Name, $a.InterfaceDescription) }
}


# ------------------------------------------------------------ 代理模式 ----
Section '2. 你现在是什么代理模式'

$ieKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$ie = Get-ItemProperty $ieKey -ErrorAction SilentlyContinue
$sysProxyOn = ($ie.ProxyEnable -eq 1)
if ($sysProxyOn) {
    Ok "系统代理：已开启  →  $($ie.ProxyServer)"
} else {
    Info '系统代理：未开启'
}

# 实际去哪个网卡出网？这是最准的判断方式
$tunActive = $false
$egressName = $null
try {
    $r = Find-NetRoute -RemoteIPAddress '1.1.1.1' -ErrorAction Stop | Select-Object -First 1
    $egress = Get-NetAdapter -ifIndex $r.InterfaceIndex -ErrorAction SilentlyContinue
    $egressName = $egress.Name
    if ($egressName -and $egressName -notin $phys.Name) {
        $tunActive = $true
        Ok "IPv4 出口网卡：$egressName  →  这是隧道（TUN 模式生效中）"
    } else {
        Info "IPv4 出口网卡：$egressName  →  物理网卡（没有 TUN 接管）"
    }
} catch {
    Bad '算不出 IPv4 出口路由，可能当前完全没有网络。'
}

$proxyProcs = @(Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.ProcessName -match 'v2ray|xray|sing-?box|clash|mihomo|nekoray|hysteria|tun2socks' })
if ($proxyProcs.Count -gt 0) {
    Ok "检测到代理进程：$((($proxyProcs.ProcessName) | Sort-Object -Unique) -join '、')"
} else {
    Warn '没有检测到常见的代理进程。'
}

if (-not $sysProxyOn -and -not $tunActive) {
    Bad '既没有系统代理，也没有 TUN 接管 —— 你现在是【直连】状态。'
    Info '这种情况下装规则，结果就是 Claude 直接用不了。'
    Info '请先把代理跑起来，确认能正常用 Claude，再回来装。'
    $findings.Add('NO_PROXY')
}


# -------------------------------------------------------------- IPv6 ----
Section '3. IPv6 —— 最容易被忽略的漏洞'

$v6Egress = $null
$hasV6Internet = $false
try {
    $r6 = Find-NetRoute -RemoteIPAddress '2606:4700:4700::1111' -ErrorAction Stop | Select-Object -First 1
    $v6Egress = (Get-NetAdapter -ifIndex $r6.InterfaceIndex -ErrorAction SilentlyContinue).Name
    $hasV6Internet = $true
} catch {
    $hasV6Internet = $false
}

if (-not $hasV6Internet) {
    Ok '当前没有 IPv6 出网路由 —— 现在不会从 IPv6 漏。'
    if ($tunActive) {
        Warn "但这是运气不是设计：换个能下发 IPv6 的网络（校园网、手机热点、新路由器），"
        Info  '  IPv6 流量很可能完全绕过隧道直连。'
        Info  '  建议装基础防护时加上 -BlockAllIPv6，今天零代价，将来救命。'
        $findings.Add('V6_RECOMMEND_BLOCK')
    }
} else {
    if ($v6Egress -and $v6Egress -notin $phys.Name) {
        Ok "IPv6 出口网卡：$v6Egress  →  也走隧道，没有漏。"
    } else {
        Bad "IPv6 出口网卡：$v6Egress  →  物理网卡！IPv6 流量【正在绕过隧道】。"
        Info '这就是一个正在敞开的直连通道，强烈建议 -BlockAllIPv6。'
        $findings.Add('V6_LEAKING')
    }
}


# --------------------------------------------------------- Anthropic ----
Section '4. Anthropic 的地址'

foreach ($n in 'api.anthropic.com', 'claude.ai', 'statsig.anthropic.com') {
    $ips = @()
    foreach ($t in 'A', 'AAAA') {
        try { $ips += (Resolve-DnsName -Name $n -Type $t -ErrorAction Stop | Where-Object IPAddress).IPAddress } catch {}
    }
    if ($ips) { Info ("{0,-24} {1}" -f $n, ($ips -join '  ')) }
    else      { Info ("{0,-24} （解析不到）" -f $n) }
}
Info ''
Info '注意：statsig.anthropic.com 通常不在 Anthropic 自己的网段里（托管在 Google Cloud）。'
Info '      这就是为什么光按目的地封不够，完整版还要按进程封一层。'
Info ''
Info '本脚本【不会】去实际连接这些地址 —— 那本身就是一次直连。'


# ------------------------------------------------------- 现有规则 ----
Section '5. 现有的防火墙规则'

$ksRules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -like 'Claude-KS*' })
if ($ksRules.Count -gt 0) {
    Ok "本项目的规则已安装：共 $($ksRules.Count) 条"
    $ksRules | Group-Object Group | ForEach-Object { Info ("  {0,-18} {1} 条" -f $_.Name, $_.Count) }
} else {
    Info '本项目的规则：尚未安装'
}

# 脱靶检测。
# 关键是要区分两种情况，它们的含义完全相反：
#   · 本项目的规则指向旧路径 —— 正常。本项目只增不删，旧规则留着无害。
#   · 别人/你以前写的 Block 规则指向旧路径 —— 那些规则现在【一条都不生效】。
$staleMine = @()
$staleOther = @()
Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match 'laude' -or $_.Group -like 'Claude-KS*' } |
    ForEach-Object {
        $p = ($_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program
        if ($p -and $p -ne 'Any' -and -not (Test-Path $p)) {
            $item = [pscustomobject]@{ Rule = $_.DisplayName; Program = $p; Action = $_.Action }
            if ($_.Group -like 'Claude-KS*') { $staleMine += $item } else { $staleOther += $item }
        }
    }

if ($staleMine.Count -gt 0) {
    Info ''
    Info "本项目有 $($staleMine.Count) 条规则指向旧版本路径 —— 这是正常的。"
    Info '本项目只增不删，旧规则留着无害，也避免了「拆旧墙时新墙还没建好」的窗口。'
}

$staleOtherBlock = @($staleOther | Where-Object { $_.Action -eq 'Block' })
if ($staleOtherBlock.Count -gt 0) {
    Write-Host ''
    Bad "发现 $($staleOtherBlock.Count) 条【非本项目】的 Block 规则指向已不存在的程序路径。"
    Info '如果这些是你以前手写的防护规则 —— 它们现在一条都不生效。'
    Info 'Claude 是 MSIX 商店应用，程序路径带版本号，一更新就全部脱靶，而且没有任何提示。'
    Info '这正是本项目要解决的问题。'
    $staleOtherBlock | Select-Object -First 5 | ForEach-Object {
        Info ("  · {0}" -f $_.Rule)
        Info ("      {0}" -f $_.Program)
    }
    if ($staleOtherBlock.Count -gt 5) { Info ("  … 还有 $($staleOtherBlock.Count - 5) 条") }
    $findings.Add('STALE_OTHER')
}


# ------------------------------------------------------------ 结论 ----
Section '结论'

if ($findings -contains 'NO_PHYSICAL') {
    Bad '没有物理网卡，装不了。'
}
elseif ($findings -contains 'NO_PROXY') {
    Bad '请先把代理跑起来再装。现在装只会让 Claude 直接不能用。'
}
else {
    Write-Host ''
    Write-Host '  可以安装。建议：' -ForegroundColor White
    Write-Host ''
    if ($findings -contains 'V6_LEAKING' -or $findings -contains 'V6_RECOMMEND_BLOCK') {
        Write-Host '    .\01-basic.ps1 -BlockAllIPv6' -ForegroundColor Green
        Info '（加 -BlockAllIPv6 是因为上面第 3 节的检测结果）'
    } else {
        Write-Host '    .\01-basic.ps1' -ForegroundColor Green
    }
    Write-Host ''
    Info '装完请务必跑 .\03-verify.ps1 验证规则真的会开火 ——'
    Info '「加了规则而且没坏」不等于「规则生效了」，两者现象一模一样。'
    Write-Host ''
    Info '想更完整（覆盖 Anthropic 之外的第三方地址）再跑 .\02-full-install.ps1'
}
Write-Host ''
