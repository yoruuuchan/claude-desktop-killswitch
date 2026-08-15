# 零泄漏验证协议

> 要验证「配置失效时会不会漏」，似乎就得真的把配置弄失效 ——
> 而那一刻如果方案是错的，就是一次真实的直连。
>
> 这份文档解决的就是这个悖论。

核心思路只有一句：**先架一层独立的、已被证明有效的护栏，再故意破坏代理。**
而不是先关代理再祈祷。

---

## 为什么不能跳过验证

这类方案最主要的失败模式**不是规则写错，是规则根本没匹配上**。

而「规则没匹配上」和「规则生效了但没有流量触发它」——**现象一模一样**：
Claude 照常工作，什么都不报错。你会以为自己受保护了。

真实案例：某台机器上有四条写得很漂亮的防火墙规则，覆盖了 IPv4、IPv6、
甚至 NAT64 网段。它们**全部指向一个已经不存在的程序路径**（Claude 从
`1.17377` 更新到了 `1.30096`），因此一条都不生效。而机器的主人一直以为
自己是受保护的，直到有人去 `Test-Path` 了一下那些路径。

所以：**「加了规则而且没坏」不是证据。**

---

## 第一阶段：证明机制可用（零风险）

这一阶段由 `scripts/03-verify.ps1` 自动完成，全程不碰 Anthropic。

原理是用一个**跟你账号毫无关系的诱饵地址**，配合一条临时的主机路由，
把它强制走物理网卡，然后用**构造上与正式规则完全相同**的规则去打它。

```
1. 加主机路由：诱饵地址 → 物理网卡（/32 路由按最长前缀胜过 TUN 的 0.0.0.0/1）
2. 测基线                          → 必须【通】
3. 加「按目的地封」的规则          → 必须【不通】
4. 换成「按程序封」的规则，只封 curl
     · curl 访问诱饵地址           → 必须【不通】
     · 同一时刻其他程序访问同一地址 → 必须【通】
5. 清理路由和测试规则
```

第 4 步那组对比是关键。它排除了「其实是网络本身出问题」这种解释，
证明防火墙确实在**按程序路径区分**，而不是无差别封锁。

这一阶段全部通过，就意味着本方案依赖的两种规则写法在你这台机器上确实会开火。

---

## 第二阶段：直接验证 Anthropic 规则（风险极小）

```powershell
.\scripts\03-verify.ps1 -TestAnthropic
```

把 Anthropic 的一个地址强制走物理网卡，去撞你的正式规则。预期连不上。

**残余风险**：万一规则失效，会产生**一次裸 TCP 握手** —— 没有 TLS、没有
域名（SNI）、没有 HTTP 请求、没有任何账号信息。Anthropic 那边只会看到
一个 IP 连上来又立刻断开。

建议先跑完第一阶段（证明机制可用）再考虑这一步。第一阶段通过之后，
这一步失败的概率已经很低了。

---

## 第三阶段：拔插头实测（需要手动，全程有保护网）

这是唯一能回答「代理真的死了，Claude 会不会漏」的测试。

它需要你把电脑弄成最危险的状态，所以**必须先架保护网**。

### 为什么要临时全机墙

保护网的作用是：**让验证的安全性不依赖被验证对象本身。**

如果只靠你刚装的那些规则来保护这次测试，那就是循环论证 —— 你正在验证的
东西同时也是你的唯一保障。加一层构造完全不同、覆盖全部程序的临时墙，
就算被测规则全是假的，也不可能漏出去一次。

### 准备

- 挑一个 15 分钟不需要上网的时间
- 管理员 PowerShell，**全程同一个窗口**
- **把 Claude Desktop 完全退出**（托盘右键退出，不是点窗口的 ×）
  —— 后面要在「完全没有代理」的状态下重新打开它，才能观察到它从零开始
  尝试连接的全过程
- 代理现在必须是正常工作的

### 步骤

**1. 记下起点时间，确认基线正常**

```powershell
(Get-Date).ToString('yyyy-MM-dd HH:mm:ss') | Set-Content "$env:TEMP\ks-mark.txt"
```

然后找一个**走物理网卡**的地址测基线 —— 最方便的就是你自己代理节点的
IP 和端口（它必然走物理网卡，否则会路由环）：

```powershell
Test-NetConnection <你的节点IP> -Port <节点端口> | Select-Object TcpTestSucceeded
```

期望 `True`。

**2. 架临时全机墙**（整机立刻断网，这是故意的）

```powershell
New-NetFirewallRule -DisplayName "KS TEMP - global" -Group "Claude-KS-TEMP" `
  -Direction Outbound -Action Block -Profile Any `
  -RemoteAddress 1.0.0.0-9.255.255.255,11.0.0.0-100.63.255.255,100.128.0.0-126.255.255.255,128.0.0.0-169.253.255.255,169.255.0.0-172.15.255.255,172.32.0.0-192.167.255.255,192.169.0.0-223.255.255.255 `
  -InterfaceAlias (Get-NetAdapter -Physical).Name
```

**3. 证明这堵墙是真的** ← 千万别跳过

```powershell
Test-NetConnection <你的节点IP> -Port <节点端口> | Select-Object TcpTestSucceeded
```

期望 `False`。同一个地址，加墙前 `True`、加墙后 `False`。

**如果还是 `True`**：墙没立起来，后面的测试就没有保护了。
立刻删掉规则并停止，不要继续。

**4. 制造最危险的状态**

不要只杀代理进程。真实的崩溃场景里，系统代理设置往往也一起没了。
三样都要弄掉：

```powershell
# 关系统代理
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 0

# 结束代理进程（按你实际用的改）
Get-Process v2rayN,xray,sing-box,clash-verge,mihomo -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 6

# 确认隧道网卡消失、默认路由掉回物理网卡
Get-NetAdapter | Where-Object { $_.Name -notin (Get-NetAdapter -Physical).Name } | Select-Object Name,Status
Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object ifIndex,NextHop
```

**5. 打开 Claude，发一条消息**

期望：**报网络错误，发不出去。**

如果 Claude 明确说「被防火墙挡住」（而不是超时），那是更好的结果 ——
说明它确实发起了直连尝试，并且在 connect 那一刻被策略拒绝了。

**6. 看证据**

```powershell
$t0 = (Get-Content "$env:TEMP\ks-mark.txt").Trim()
$dir = "$env:SystemRoot\System32\LogFiles\Firewall"
$lines = @()
foreach ($f in @("$dir\pfirewall.log", "$dir\pfirewall.log.old")) {
    if (Test-Path $f) { $lines += @(Get-Content $f -ErrorAction SilentlyContinue) }
}
$new = @($lines | Where-Object { $_.Length -gt 19 -and $_.Substring(0,19) -ge $t0 })
"本次新增日志行数: $($new.Count)"
$new | Select-String 'DROP' | Select-String '160\.79\.104\.' | Select-Object -Last 30
```

> **注意**：一定要同时查 `pfirewall.log` 和 `pfirewall.log.old`，并且按
> **时间戳**而不是行号来定位。防火墙日志默认 4 MB 就轮转，用「跳过前 N 行」
> 的写法会在轮转时得到一个假的「0 条新增」，让你误以为什么都没发生。
> 想更保险可以先把上限调大：
> `Set-NetFirewallProfile -All -LogMaxSizeKilobytes 32767`

怎么读结果：

| 现象 | 含义 |
|---|---|
| 有 `160.79.104.x` 的 DROP 行 | **最有价值的结果**：Claude 确实试图直连 Anthropic，确实被拦下了。既证明了 fail-open 风险真实存在，也证明了墙在起作用 |
| 没有 Anthropic，但有别的 DROP | Claude 在更早的环节就失败了，没走到发起直连那一步。也是安全的，但信息量少 |
| 一条新增都没有 | 多半是日志还没落盘，等一两分钟再跑一次；或者你用了按行号定位而日志轮转了 |

**7. 恢复**

```powershell
Get-NetFirewallRule -Group "Claude-KS-TEMP" | Remove-NetFirewallRule
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 1
```

然后手动启动代理，确认节点连得上、Claude 恢复正常。

---

## 想要完整归因？用 WFP 5157

`pfirewall.log` 有个明显短板：**它不记录进程，也不记录是哪条规则干的**。
所以第三阶段结束后你知道「有东西被挡了」，但分不清是临时墙还是你的正式规则。

Windows 事件 **5157**（Filtering Platform Connection，失败审计）能给出：
应用程序路径、PID、源/目的地址端口、协议，以及 **Filter Origin —— 触发
阻断的那条防火墙规则的 ID**（Windows 11 / Server 2022 起）。

开启（管理员，会产生大量事件，建议先扩大 Security 日志）：

```powershell
auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable
```

关闭：

```powershell
auditpol /set /subcategory:"Filtering Platform Connection" /failure:disable
```

规则 ID 反查规则名：`Get-NetFirewallRule -Name <ID>`

这是唯一能证明「某个具体的 Claude 进程，被我们预期的那一条规则拦下」的办法。
对大多数人来说不是必需的，但如果你要较真到底，这是终点。

---

## 全机 kill-switch（覆盖最后一个缺口）

本项目不包含它，但这里说清楚它是什么。

「未知程序 → 未知地址」这一格，**任何黑白名单都关不上**。唯一能关上它的是：
**物理网卡默认拒绝，只放行代理程序本身。**

上面第三阶段的「临时全机墙」就是它的临时版本 —— 把它变成常驻，再加两条
Allow 例外（代理程序 → 你的节点；Tailscale 之类你确实需要的），就是完整的
VPN 式 kill-switch。

**代价，必须想清楚再做：**

- 代理没有开机自启的话，**开机到你启动代理之间整机没网**
- 节点 IP 变了（换订阅）你会把自己锁在外面，连查资料都做不到
- 必须事先把撤销命令**抄在纸上或存在手机里**

有意思的是，如果你本来就在用 TUN 模式，这个方案在**稳态下什么都不改变** ——
因为 TUN 已经接管了全部流量，本来就没有程序在用物理网卡直连。它改变的只是
失败时的行为：把 fail-open 变成 fail-close。

值不值得，你自己判断。
