<#
    Claude 防直连 —— 验证规则真的会开火

    ────────────────────────────────────────────────────────────────
    为什么必须验证：

      「加了规则，然后 Claude 还能正常用」—— 这【不能】说明规则生效了。
      规则一条都没匹配上的时候，现象是一模一样的。

      静默失效是这类方案最主要的失败模式，比方案本身写错更常见。
    ────────────────────────────────────────────────────────────────

    做法：用一个跟你账号毫无关系的【诱饵地址】做正向验证。
    加一条主机路由把它强制走物理网卡，然后用构造上和正式规则完全一样、
    只是目标换成诱饵的规则去打它。打得中，正式规则就打得中。

    全程不碰 Anthropic。

    用法（管理员 PowerShell）：
        .\03-verify.ps1
        .\03-verify.ps1 -DecoyIP 114.114.114.114     换个诱饵地址
        .\03-verify.ps1 -TestAnthropic               额外直接验证 Anthropic 规则（见下）

    退出码：0 = 全部通过；1 = 有项目没通过。
#>

[CmdletBinding()]
param(
    # 诱饵地址。必须满足两个条件：
    #   1) 现在直连得通（不然测不出区别）
    #   2) 跟你的 Claude 账号毫无关系
    # 默认阿里公共 DNS。
    [string]$DecoyIP = '223.5.5.5',
    [int]$DecoyPort  = 443,

    # 额外做一次直接针对 Anthropic 规则的验证。
    # 它会把 Anthropic 的一个地址强制走物理网卡，然后尝试连接 —— 预期被你的规则挡住。
    # 残余风险：万一规则失效，会产生一次【裸 TCP 握手】。没有 TLS、没有域名、
    # 没有任何账号信息，Anthropic 只会看到一个 IP 连上来又立刻断开。
    # 建议先跑完前面的诱饵测试（证明机制可用）再考虑加这个。
    [switch]$TestAnthropic,

    [string]$AnthropicIP = '160.79.104.10'
)

$ErrorActionPreference = 'Stop'
$TestGroup = 'Claude-KS-VERIFY'

function Ok($m)   { Write-Host "  [通过] $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "  [失败] $m" -ForegroundColor Red }
function Warn($m) { Write-Host "  [注意] $m" -ForegroundColor Yellow }
function Info($m) { Write-Host "         $m" -ForegroundColor Gray }
function Step($m) { Write-Host ''; Write-Host "  ▸ $m" -ForegroundColor Cyan }

function Test-Tcp([string]$ip, [int]$port) {
    (Test-NetConnection -ComputerName $ip -Port $port -WarningAction SilentlyContinue -InformationLevel Quiet) -eq $true
}

Write-Host ''
Write-Host '  Claude 防直连 —— 验证' -ForegroundColor White

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Bad '需要管理员权限。'
    exit 1
}

$phys = @((Get-NetAdapter -Physical -ErrorAction SilentlyContinue).Name)
if ($phys.Count -eq 0) { Bad '找不到物理网卡。'; exit 1 }

# 找一条走物理网卡的默认路由，用它的网关来做主机路由
$physIdx = @((Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
              Where-Object Status -eq 'Up').ifIndex)
$defRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Where-Object { $_.ifIndex -in $physIdx -and $_.NextHop -ne '0.0.0.0' } |
            Sort-Object RouteMetric | Select-Object -First 1

if (-not $defRoute) {
    Bad '找不到走物理网卡的默认路由，没法把诱饵地址强制走物理网卡。'
    Info '如果你的代理把默认路由整个替换掉了，请先临时关掉 TUN 再跑这个脚本。'
    exit 1
}

Info "物理网卡：$($phys -join '、')"
Info "测试用网关：$($defRoute.NextHop)（接口 $($defRoute.ifIndex)）"
Info "诱饵地址：$DecoyIP : $DecoyPort"

$pass = @()
$fail = @()
$routesAdded = @()

try {
    # ================================================= 诱饵路由 + 基线 ====
    Step "第 1 步：把诱饵地址强制走物理网卡，测基线"

    New-NetRoute -DestinationPrefix "$DecoyIP/32" -InterfaceIndex $defRoute.ifIndex `
        -NextHop $defRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore -Confirm:$false | Out-Null
    $routesAdded += "$DecoyIP/32"
    Start-Sleep -Milliseconds 500

    if (Test-Tcp $DecoyIP $DecoyPort) {
        Ok "基线连通（诱饵地址现在确实走物理网卡出去）"
    } else {
        Bad "基线不通 —— 这个诱饵地址本身就连不上，测不出区别。"
        Info "换一个当前直连得通的地址再试：.\03-verify.ps1 -DecoyIP <地址>"
        exit 1
    }

    # =========================================== 测试一：按目的地封 ====
    Step "第 2 步：按【目的地】封（和基础防护同一种写法）"

    New-NetFirewallRule -DisplayName 'KS VERIFY - dest' -Group $TestGroup `
        -Direction Outbound -Action Block -Profile Any `
        -RemoteAddress $DecoyIP -InterfaceAlias $phys | Out-Null
    Start-Sleep -Milliseconds 500

    if (-not (Test-Tcp $DecoyIP $DecoyPort)) {
        Ok "被挡住了 —— 限定物理网卡的【目的地】规则确实会开火"
        $pass += '按目的地封'
    } else {
        Bad "没挡住 —— 限定物理网卡的规则在这台机器上没有生效"
        Info "你的基础防护很可能是摆设。请反馈这个结果。"
        $fail += '按目的地封'
    }

    Get-NetFirewallRule -Group $TestGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule

    # ============================================= 测试二：按程序封 ====
    Step "第 3 步：按【程序】封（和完整防护同一种写法）"

    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    if (-not (Test-Path $curl)) {
        Warn "找不到 $curl，跳过按程序封的测试。"
    } else {
        New-NetFirewallRule -DisplayName 'KS VERIFY - prog' -Group $TestGroup `
            -Direction Outbound -Action Block -Profile Any `
            -Program $curl -RemoteAddress $DecoyIP -InterfaceAlias $phys | Out-Null
        Start-Sleep -Milliseconds 500

        & $curl --noproxy '*' -sS --max-time 6 "https://$DecoyIP/" 2>&1 | Out-Null
        $curlBlocked = ($LASTEXITCODE -ne 0)
        $otherStillOk = Test-Tcp $DecoyIP $DecoyPort

        if ($curlBlocked -and $otherStillOk) {
            Ok "curl 被挡住，同一时刻其他程序访问同一地址仍然通"
            Info "这组对比排除了「其实是网络本身出问题」，证明防火墙确实在按程序路径区分。"
            $pass += '按程序封'
        } elseif (-not $curlBlocked) {
            Bad "curl 没被挡住 —— 按程序路径的规则没有生效"
            Info "完整防护那一层很可能是摆设。请反馈这个结果。"
            $fail += '按程序封'
        } else {
            Bad "curl 被挡住了，但其他程序也连不上 —— 说明规则范围过大或网络本身有问题"
            Info "这个结果不能证明按程序区分是有效的。"
            $fail += '按程序封'
        }

        Get-NetFirewallRule -Group $TestGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }

    # ================================== 可选：直接验证 Anthropic 规则 ====
    if ($TestAnthropic) {
        Step "第 4 步（可选）：直接验证 Anthropic 规则"

        if (-not (Get-NetFirewallRule -Group 'Claude-KS' -ErrorAction SilentlyContinue)) {
            Warn '还没装基础防护（Claude-KS），跳过这一项。'
        } else {
            Info "把 $AnthropicIP 强制走物理网卡，去撞你的正式规则。"
            Info "如果规则有效 → 连不上。这一步不产生任何 TLS 握手或域名信息。"

            New-NetRoute -DestinationPrefix "$AnthropicIP/32" -InterfaceIndex $defRoute.ifIndex `
                -NextHop $defRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore -Confirm:$false | Out-Null
            $routesAdded += "$AnthropicIP/32"
            Start-Sleep -Milliseconds 500

            if (-not (Test-Tcp $AnthropicIP 443)) {
                Ok "Anthropic 地址被你的正式规则挡住了"
                $pass += 'Anthropic 规则'
            } else {
                Bad "没挡住 —— 刚才产生了一次到 Anthropic 的 TCP 握手（无 TLS、无域名）"
                Info "请立刻检查基础防护的规则，或者跑 .\99-uninstall.ps1 后重装。"
                $fail += 'Anthropic 规则'
            }
        }
    }
}
finally {
    # 无论中间出什么事，都把测试用的东西清干净
    Write-Host ''
    Write-Host '  ▸ 清理测试用的规则和路由' -ForegroundColor Cyan
    Get-NetFirewallRule -Group $TestGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    foreach ($p in $routesAdded) {
        Remove-NetRoute -DestinationPrefix $p -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
    }
    Ok '已清理'
}

# ====================================================== 结论 ====
Write-Host ''
Write-Host ('─' * 70) -ForegroundColor DarkGray
if ($fail.Count -eq 0 -and $pass.Count -gt 0) {
    Write-Host '  全部通过：' -ForegroundColor Green -NoNewline
    Write-Host " $($pass -join '、')"
    Write-Host ''
    Info '这说明本方案依赖的两种规则写法在你这台机器上都确实会开火。'
    Info '你装的规则不是摆设。'
    Write-Host ''
    Info '想做最后的端到端验证（真的把代理弄没，看 Claude 会不会漏），'
    Info '见 docs/verification.md —— 那里有一套不会产生真实泄漏的做法。'
    $code = 0
} else {
    Write-Host '  有项目没通过：' -ForegroundColor Red -NoNewline
    Write-Host " $($fail -join '、')"
    Write-Host ''
    Info '在弄清楚原因之前，请【不要】认为自己已经受保护。'
    $code = 1
}
Write-Host ('─' * 70) -ForegroundColor DarkGray
Write-Host ''
exit $code
