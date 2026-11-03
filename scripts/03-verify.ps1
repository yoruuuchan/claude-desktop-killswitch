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

    退出码：
      0 = 全部验证通过
      1 = 有项目验证失败（规则没生效）
      2 = 有项目无法验证（测试环境不满足，结论不完整 —— 不等于通过）
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

$phys = @((Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -ne 'Not Present' }).Name)
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
$skip = @()          # 想测但测不了的项。绝不能当成通过。
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
        Warn "系统里没有 curl.exe，这一项无法验证。"
        $skip += '按程序封（找不到 curl.exe）'
    } else {
        # baseline 和加规则后必须用【完全相同】的命令，否则比较没有意义。
        # -k 是刻意加的：我们要测的是「连不连得上」，不是「证书对不对」。
        # 不能靠「curl 退出码非零」来推断被阻断 —— 证书错误、TLS 握手失败、
        # 服务端不说 HTTPS，都会让退出码非零，那样会得到假阳性。
        $curlArgs = @(
            '--noproxy', '*', '-k', '-sS', '--max-time', '6',
            '-o', 'NUL', "https://${DecoyIP}:${DecoyPort}/"
        )

        & $curl @curlArgs 2>&1 | Out-Null
        $baseCode = $LASTEXITCODE

        if ($baseCode -ne 0) {
            # 一条规则都没有的时候 curl 就失败了 —— 那么「加规则后 curl 失败」
            # 什么都证明不了。这种情况必须报「无法验证」，绝不能算通过。
            Bad "基线不成立：没有任何规则时 curl 就失败了（退出码 $baseCode）"
            Info '这不是防火墙的问题，是这个诱饵地址不适合用 curl 测（可能没有 HTTPS 服务）。'
            Info '换一个 HTTP(S) 服务正常的诱饵地址再试：'
            Info '  .\03-verify.ps1 -DecoyIP <地址> -DecoyPort <端口>'
            $skip += '按程序封（curl 基线不成立）'
        } else {
            Info "基线：curl 直连成功（退出码 0）"

            New-NetFirewallRule -DisplayName 'KS VERIFY - prog' -Group $TestGroup `
                -Direction Outbound -Action Block -Profile Any `
                -Program $curl -RemoteAddress $DecoyIP -InterfaceAlias $phys | Out-Null
            Start-Sleep -Milliseconds 500

            & $curl @curlArgs 2>&1 | Out-Null
            $afterCode = $LASTEXITCODE
            $otherStillOk = Test-Tcp $DecoyIP $DecoyPort

            Info "加规则后：curl 退出码 $afterCode；其他程序访问同一地址：$(if ($otherStillOk) { '仍然通' } else { '也不通' })"

            if ($afterCode -ne 0 -and $otherStillOk) {
                Ok "同一个程序、同一条命令：加规则前成功，加规则后失败"
                Ok "同一时刻另一个程序访问同一个地址仍然通"
                Info '这组 A/B 同时排除了「网络本身有问题」和「证书之类的其他失败原因」，'
                Info '证明防火墙确实在按程序路径区分。'
                $pass += '按程序封'
            } elseif ($afterCode -eq 0) {
                Bad "加了规则 curl 依然成功 —— 按程序路径的规则没有生效"
                Info '完整防护那一层很可能是摆设。请反馈这个结果。'
                $fail += '按程序封'
            } else {
                Bad "curl 被挡住了，但其他程序也连不上 —— 规则范围过大，或网络本身出了问题"
                Info '这个结果不能证明按程序区分是有效的。'
                $fail += '按程序封'
            }

            Get-NetFirewallRule -Group $TestGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        }
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

if ($pass.Count -gt 0) { Write-Host "  通过：    $($pass -join '、')" -ForegroundColor Green }
if ($skip.Count -gt 0) { Write-Host "  无法验证：$($skip -join '、')" -ForegroundColor Yellow }
if ($fail.Count -gt 0) { Write-Host "  没通过：  $($fail -join '、')" -ForegroundColor Red }

Write-Host ''
if ($fail.Count -gt 0) {
    Info '在弄清楚原因之前，请【不要】认为自己已经受保护。'
    $code = 1
} elseif ($skip.Count -gt 0) {
    Info '通过的部分是可信的，但有项目【没能验证】—— 那不等于它是好的，只是没测出来。'
    Info '按上面的提示换个诱饵地址重跑，把它变成明确的结论。'
    $code = 2
} elseif ($pass.Count -gt 0) {
    Info '本方案依赖的两种规则写法在你这台机器上都确实会开火。你装的规则不是摆设。'
    Write-Host ''
    Info '想做最后的端到端验证（真的把代理弄没，看 Claude 会不会漏），'
    Info '见 docs/verification.md —— 那里有一套不会产生真实泄漏的做法。'
    $code = 0
} else {
    Info '一项都没跑起来。'
    $code = 2
}
Write-Host ('─' * 70) -ForegroundColor DarkGray
Write-Host ''
# 退出码：0 = 全部验证通过；1 = 有项目验证失败；2 = 有项目无法验证（结论不完整）
exit $code
