<#
    Claude 防直连 —— 基础防护（十分钟版）

    按【目的地】拦：任何程序都不能从物理网卡直连 Anthropic 的自有网段。
    规则不依赖 Claude 客户端版本；官方 IP 网段有更新时需要补充。

    用法（管理员 PowerShell）：
        .\01-basic.ps1                  只封 Anthropic 网段
        .\01-basic.ps1 -BlockAllIPv6    额外封掉全部 IPv6 出公网（先跑 00-check.ps1 看要不要）
        .\01-basic.ps1 -Yes             跳过确认

    撤销：
        .\99-uninstall.ps1
#>

[CmdletBinding()]
param(
    # 额外封掉所有 IPv6 出公网（物理网卡）。大部分 TUN 代理不承载 IPv6，
    # 所以这通常是零代价的，但请先跑 00-check.ps1 确认。
    [switch]$BlockAllIPv6,

    # 跳过交互确认
    [switch]$Yes,

    # 即使检测不到代理也强行安装（不推荐）
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$Group = 'Claude-KS'

# --------------------------------------------------------------------------
# Anthropic inbound IP ranges from the official documentation.
# The extra IPv6 prefix (2607:6bc0:11::/48) is also originated by AS399358.
# Sources: https://platform.claude.com/docs/en/api/ip-addresses
#          https://bgp.he.net/AS399358
# --------------------------------------------------------------------------
$AnthropicV4 = @('160.79.104.0/23', '153.61.224.0/22')
$AnthropicV6 = @('2607:6bc0::/48', '2607:6bc0:11::/48')

# 全部 IPv6 出公网 = 全球单播 + NAT64。
# 故意不含 fe80::/10（链路本地）和 fc00::/7（ULA，Tailscale 用这个）。
$AllV6 = @('2000::/3', '64:ff9b::/96', '64:ff9b:1::/48')


function Fail($m) { Write-Host "  [失败] $m" -ForegroundColor Red; exit 1 }
function Ok($m)   { Write-Host "  [ 好 ] $m" -ForegroundColor Green }
function Info($m) { Write-Host "         $m" -ForegroundColor Gray }

Write-Host ''
Write-Host '  Claude 防直连 —— 基础防护' -ForegroundColor White
Write-Host ''

# ---- 前置检查 ----
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail '需要管理员权限。请用「以管理员身份运行」打开 PowerShell 再试。'
}

$phys = @((Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -ne 'Not Present' }).Name)
if ($phys.Count -eq 0) { Fail '找不到物理网卡。' }
Ok "物理网卡：$($phys -join '、')"

# 有没有代理？没有的话装了就是纯粹让 Claude 用不了。
$sysProxy = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' `
                -ErrorAction SilentlyContinue).ProxyEnable -eq 1
$tunActive = $false
try {
    $r = Find-NetRoute -RemoteIPAddress '1.1.1.1' -ErrorAction Stop | Select-Object -First 1
    $eg = (Get-NetAdapter -ifIndex $r.InterfaceIndex -ErrorAction SilentlyContinue).Name
    if ($eg -and $eg -notin $phys) { $tunActive = $true }
} catch {}

if (-not $sysProxy -and -not $tunActive -and -not $Force) {
    Write-Host ''
    Fail @'
检测不到代理（既没有系统代理，也没有 TUN 接管）。

现在装规则，结果就是 Claude 直接连不上，而不是「多一层保护」。
请先把代理跑起来、确认 Claude 能正常用，再回来装。

确定要强行安装就加 -Force。
'@
}
if ($sysProxy)  { Ok '检测到系统代理' }
if ($tunActive) { Ok '检测到 TUN 接管（隧道生效中）' }

# ---- 说清楚要做什么 ----
Write-Host ''
Write-Host '  即将创建的规则（全部限定在物理网卡上，隧道流量不受影响）：' -ForegroundColor White
Write-Host ''
Info "  ① 阻断 → $($AnthropicV4 -join '、')          （Anthropic IPv4）"
Info "  ② 阻断 → $($AnthropicV6 -join '、')   （Anthropic IPv6）"
if ($BlockAllIPv6) {
    Info "  ③ 阻断 → $($AllV6 -join '、')  （全部 IPv6 出公网）"
}
Write-Host ''
Info '效果：代理正常时你感觉不到任何变化；代理一断，Claude 立刻断而不是偷偷直连。'
Write-Host ''

if (-not $Yes) {
    $a = Read-Host '  继续？(y/N)'
    if ($a -notmatch '^[yY]') { Write-Host '  已取消，什么都没改。' -ForegroundColor Yellow; exit 0 }
}

# ---- 创建（幂等） ----
function New-KSRule {
    param([string]$Name, [string[]]$Remote)

    $exist = Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue
    if ($exist) { Info "已存在，跳过：$Name"; return }

    New-NetFirewallRule -DisplayName $Name -Group $Group `
        -Direction Outbound -Action Block -Profile Any `
        -RemoteAddress $Remote -InterfaceAlias $phys | Out-Null
    Ok "已创建：$Name"
}

Write-Host ''
# Preserve the existing IPv4 block and install the new range as a separate rule.
# New-KSRule skips existing names, so changing only the address list would not upgrade old installs.
New-KSRule -Name 'KS - Block Anthropic IPv4 on physical' -Remote @('160.79.104.0/23')
New-KSRule -Name 'KS - Block Anthropic IPv4 153.61.224.0-22 on physical' -Remote @('153.61.224.0/22')
New-KSRule -Name 'KS - Block Anthropic IPv6 on physical' -Remote $AnthropicV6
if ($BlockAllIPv6) {
    New-KSRule -Name 'KS - Block all IPv6 on physical' -Remote $AllV6
}

# ---- 验证规则真的带上了网卡限定 ----
# 这一步很重要：如果 -InterfaceAlias 没写进去，规则会变成对所有网卡生效，
# 那就会把隧道也一起封掉（表现是 Claude 立刻用不了 —— 很吵，但至少不会静默泄漏）。
Write-Host ''
$bad = @()
foreach ($r in (Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue)) {
    $ifa = @(($r | Get-NetFirewallInterfaceFilter).InterfaceAlias)
    $adr = @(($r | Get-NetFirewallAddressFilter).RemoteAddress)
    Write-Host ("  {0}" -f $r.DisplayName) -ForegroundColor White
    Info   ("    网卡：{0}" -f ($ifa -join '、'))
    Info   ("    目标：{0}" -f ($adr -join '  '))
    if ($ifa -contains 'Any') { $bad += $r.DisplayName }
}

# Verify the new range is covered by an enabled block rule, even if its name already existed.
$newV4Rule = Get-NetFirewallRule -DisplayName 'KS - Block Anthropic IPv4 153.61.224.0-22 on physical' -ErrorAction SilentlyContinue
$newV4Addresses = if ($newV4Rule) { @(($newV4Rule | Get-NetFirewallAddressFilter).RemoteAddress) } else { @() }
if (-not $newV4Rule -or $newV4Rule.Enabled -ne 'True' -or
    $newV4Rule.Direction -ne 'Outbound' -or $newV4Rule.Action -ne 'Block' -or
    ($newV4Addresses -notcontains '153.61.224.0/22' -and
     $newV4Addresses -notcontains '153.61.224.0/255.255.252.0')) {
    $bad += '新增 IPv4 153.61.224.0/22 规则缺失或无效'
}

Write-Host ''
if ($bad.Count -gt 0) {
    Write-Host '  [问题] 以下规则的网卡限定或地址覆盖不符合预期：' -ForegroundColor Red
    $bad | ForEach-Object { Info "    $_" }
    Info '  请检查上面的规则详情。网卡为 Any 时会误伤隧道；地址缺失则没有形成预期拦截。'
    exit 1
}

Ok '装好了。网卡限定已确认写入。'
Write-Host ''
Info '下一步（不要跳过）：'
Write-Host '    .\03-verify.ps1' -ForegroundColor Green
Info '「加了规则而且没坏」不等于「规则生效了」—— 规则一条都没匹配上的时候，现象一模一样。'
Write-Host ''
Info '撤销：.\99-uninstall.ps1'
Write-Host ''
