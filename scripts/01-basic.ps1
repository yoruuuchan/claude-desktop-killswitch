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

# Shared pure-logic helpers (rule health check, create/skip/repair). Tests
# dot-source the same file, so it must stay free of side effects on load.
. (Join-Path $PSScriptRoot 'ks-lib.ps1')

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

# ---- 创建（幂等；同名但不健康的规则会被原地修复）----
# 「同名 ≠ 有效」：已存在的规则要做健康检查（启用 / 出站 / Block / Profile Any /
# 地址覆盖 / 网卡覆盖当前全部物理网卡）。健康的跳过；不健康的用 Set-NetFirewallRule
# 原地修复（不删旧规则，任何时刻都没有裸奔窗口）；缺失的才新建。
function New-KSRule {
    param([string]$Name, [string[]]$Remote)

    $existing = @(Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue)
    $result = Update-KSBlockRule -Name $Name -Group $Group -RemoteAddress $Remote -InterfaceAlias $phys -ExistingRules $existing
    switch ($result.Action) {
        'created'  { Ok "已创建：$Name" }
        'repaired' { Ok "已修复：$Name（同名规则存在但不健康，已原地修复）" }
        'skipped'  { Info "已存在且健康，跳过：$Name" }
    }
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

# ---- 验证：每条规则都要真的健康（同名 ≠ 有效）----
# 只排除「网卡为 Any」或只核对新增 IPv4 那一条是不够的：规则被禁用、地址被改、
# 新增物理网卡（USB 网卡 / 扩展坞）后旧规则不再覆盖新网卡 —— 这三种情况下
# 脚本仍然必须报失败，不能报 OK。对安全工具来说 fail-open 是致命的。
Write-Host ''
$expectedSpecs = @(
    @{ Name = 'KS - Block Anthropic IPv4 on physical';                 Remote = @('160.79.104.0/23') }
    @{ Name = 'KS - Block Anthropic IPv4 153.61.224.0-22 on physical'; Remote = @('153.61.224.0/22') }
    @{ Name = 'KS - Block Anthropic IPv6 on physical';                 Remote = $AnthropicV6 }
)
if ($BlockAllIPv6) {
    $expectedSpecs += @{ Name = 'KS - Block all IPv6 on physical'; Remote = $AllV6 }
}

$bad = @()
$allKs = @(Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue)
foreach ($r in $allKs) {
    $ifa = @(($r | Get-NetFirewallInterfaceFilter).InterfaceAlias)
    $adr = @(($r | Get-NetFirewallAddressFilter).RemoteAddress)
    Write-Host ("  {0}" -f $r.DisplayName) -ForegroundColor White
    Info   ("    网卡：{0}" -f ($ifa -join '、'))
    Info   ("    目标：{0}" -f ($adr -join '  '))
}
foreach ($spec in $expectedSpecs) {
    $rule = @($allKs | Where-Object { $_.DisplayName -eq $spec.Name })
    if ($rule.Count -eq 0) {
        $bad += "$($spec.Name) 缺失"
        continue
    }
    $unhealthy = @($rule | Where-Object {
        -not (Test-KSRuleHealth -Rule $_ -ExpectedRemoteAddress $spec.Remote -ExpectedInterfaceAlias $phys) })
    if ($unhealthy.Count -gt 0) {
        $bad += "$($spec.Name) 不健康（被禁用 / 地址被改 / 网卡未覆盖当前全部物理网卡）"
    }
}

Write-Host ''
if ($bad.Count -gt 0) {
    Write-Host '  [问题] 以下规则不符合健康标准：' -ForegroundColor Red
    $bad | ForEach-Object { Info "    $_" }
    Info '  规则被禁用、地址被改、或没有覆盖当前全部物理网卡时，防护是失效的。'
    Info '  重新运行本脚本会原地修复这些规则。'
    exit 1
}

Ok '装好了。所有规则都通过了健康检查（启用 / 出站 / Block / 地址覆盖 / 网卡覆盖）。'
Write-Host ''
Info '下一步（不要跳过）：'
Write-Host '    .\03-verify.ps1' -ForegroundColor Green
Info '「加了规则而且没坏」不等于「规则生效了」—— 规则一条都没匹配上的时候，现象一模一样。'
Write-Host ''
Info '撤销：.\99-uninstall.ps1'
Write-Host ''
