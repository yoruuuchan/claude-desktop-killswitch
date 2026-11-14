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

这一阶段由 `scripts/03-verify.ps1` 自动完成，全程不碰 Anthropic。默认使用 `example.com`，将域名解析到一个 IPv4 后固定测试路由；curl 使用 `--resolve` 保持对应的 TLS 域名，避免直接访问 IP 时握手失败。无需关闭正在使用的系统代理。

原理是用一个**跟你账号毫无关系的诱饵地址**，配合一条临时的主机路由，
把它强制走物理网卡，然后用**构造上与正式规则完全相同**的规则去打它。

```
1. 加主机路由：诱饵地址 → 物理网卡（/32 路由按最长前缀胜过 TUN 的 0.0.0.0/1）
2. 测基线                            → 必须【通】
3. 加「按目的地封」的规则            → 必须【不通】
4. 换成「按程序封」的规则，只封 curl。这里要做一组严格的 A/B：
     a. 加规则【之前】先用 curl 测一次  → 必须【成功】
     b. 加规则【之后】用完全相同的命令  → 必须【失败】
     c. 同一时刻用另一个程序测同一地址  → 必须【仍然通】
5. 清理路由和测试规则
```

### 为什么第 4 步一定要有 baseline

一个很容易犯的错误是这样写：

```powershell
curl.exe --noproxy '*' --resolve example.com:443:<诱饵IP> https://example.com/
$blocked = ($LASTEXITCODE -ne 0)      # ← 错的
```

**curl 的退出码非零，不等于被防火墙阻断。** 证书不匹配（60）、TLS 握手失败（35）、
目标端口根本不说 HTTPS —— 都会让退出码非零，而这些情况下 TCP 连接其实已经建立了。
这样写会得到**假阳性**：你以为规则生效了，其实它一条流量都没拦住。

正确的证据链是：**同一个程序、同一条命令，加规则前成功，加规则后失败**，
同时另一个程序不受影响。三个条件缺一不可。

如果 baseline 本身就失败（比如诱饵地址上没有 HTTPS 服务），那这一轮验证是
**无效**的，必须报「无法验证」而不是「通过」。`03-verify.ps1` 遇到这种情况会
退出码 `2` 并提示你换一个诱饵地址。

> 退出码约定：`0` = 全部验证通过；`1` = 有项目验证失败（规则没生效）；
> `2` = 有项目无法验证（结论不完整 —— **不等于通过**）。

这一阶段全部通过，就意味着本方案依赖的两种规则写法在你这台机器上确实会开火。

---

## 第二阶段：直接验证 Anthropic 规则（风险极小）

```powershell
.\scripts\03-verify.ps1 -TestAnthropic
```

把 Anthropic 的一个地址强制走物理网卡，去撞你的正式规则。预期连不上。

脚本对这一步有门禁：前面的诱饵测试有失败项、`Claude-KS` 规则未安装、或检测到 Claude 相关进程还在运行时，它会被跳过或拒绝执行（退出码 `2`）。那条 /32 主机路由影响的是整机所有进程，不只是探针——进入这一步前请完全退出 Claude（托盘、CLI、扩展进程）。另外，「目标连不上」必须有归因证据（WFP 5157 的 `FilterOrigin` 指向本项目规则）才算「被你的正式规则挡住」；拿不到证据时结论是「无法证明」，不会当成通过。

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

IPv4 和 IPv6 各一条 —— 只封 IPv4 的话，一旦这个网络下发 IPv6（校园网、手机热点、新路由器），
流量就从 IPv6 侧绕过整堵墙，而你以为自己是被保护着的。

```powershell
$phys = @((Get-NetAdapter -Physical | Where-Object { $_.Status -ne 'Not Present' }).Name)

New-NetFirewallRule -DisplayName "KS TEMP - global v4" -Group "Claude-KS-TEMP" `
  -Direction Outbound -Action Block -Profile Any `
  -RemoteAddress @(
      '1.0.0.0-9.255.255.255'
      '11.0.0.0-100.63.255.255'
      '100.128.0.0-126.255.255.255'
      '128.0.0.0-169.253.255.255'
      '169.255.0.0-172.15.255.255'
      '172.32.0.0-192.167.255.255'
      '192.169.0.0-223.255.255.255'
  ) `
  -InterfaceAlias $phys

New-NetFirewallRule -DisplayName "KS TEMP - global v6" -Group "Claude-KS-TEMP" `
  -Direction Outbound -Action Block -Profile Any `
  -RemoteAddress @('2000::/3', '64:ff9b::/96', '64:ff9b:1::/48') `
  -InterfaceAlias $phys
```

地址段要写成**数组**，不要拼成一个字符串 —— 字符串会被 `-RemoteAddress` 截断成第一段，
而它**不报错**（见 README 里那一条）。

**2b. 回读，确认墙真的写全了**

```powershell
Get-NetFirewallRule -Group "Claude-KS-TEMP" |
    ForEach-Object {
        $n = @(($_ | Get-NetFirewallAddressFilter).RemoteAddress).Count
        $a = @(($_ | Get-NetFirewallInterfaceFilter).InterfaceAlias)
        "{0}: {1} 段 / 网卡 {2}" -f $_.DisplayName, $n, ($a -join ',')
    }
```

期望：v4 那条 **7 段**、v6 那条 **3 段**，网卡是物理网卡的名字（不是 `Any`）。
段数少了、或者网卡显示 `Any`，说明墙没立好，停止测试。

**3. 证明这堵墙是真的** ← 千万别跳过

```powershell
Test-NetConnection <你的节点IP> -Port <节点端口> | Select-Object TcpTestSucceeded
```

期望 `False`。同一个地址，加墙前 `True`、加墙后 `False`。

**如果还是 `True`**：墙没立起来，后面的测试就没有保护了。
立刻删掉规则并停止，不要继续。

> **这堵墙只拦「新建连接」。** 已经建立并授权的流（Tailscale 的 UDP 隧道、正在跑的
> 下载、已经连上的 SSH）会继续跑到自己断开为止 —— 这是 Windows 过滤平台的正常行为，
> 不是墙漏了。对本次测试没有影响：Claude 是新进程，它每一次连接都是新流。
> 但它意味着这堵墙的语义是「不再放行任何新的出网」，不是「物理气隙」。

**4. 制造最危险的状态**

不要只杀代理进程。真实的崩溃场景里，系统代理设置往往也一起没了。
三样都要弄掉：

```powershell
# 先保存当前值 —— 第 7 步恢复时恢复的是【测试前的原值】，不是无脑写回 1
$ksProxyBefore = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyEnable

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

测完先不要直接跳到第 7 步：恢复的第一步是**完全退出 Claude**（见下），
顺序错了会在「正式规则恰好失效 + Claude 还在后台重试」的窗口里制造一次真实直连。

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
$new | Select-String 'DROP' | Select-String '(160\.79\.10[45]\.|153\.61\.22[4-7]\.)' | Select-Object -Last 30
```

> **注意**：一定要同时查 `pfirewall.log` 和 `pfirewall.log.old`，并且按
> **时间戳**而不是行号来定位。防火墙日志默认 4 MB 就轮转，用「跳过前 N 行」
> 的写法会在轮转时得到一个假的「0 条新增」，让你误以为什么都没发生。
> 想更保险可以先把上限调大：
> `Set-NetFirewallProfile -All -LogMaxSizeKilobytes 32767`

怎么读结果：

| 现象 | 含义 |
|---|---|
| 有 Anthropic 已列入站 IPv4 网段的 DROP 行 | **最有价值的结果**：Claude 确实试图直连 Anthropic，确实被拦下了。既证明了 fail-open 风险真实存在，也证明了墙在起作用 |
| 没有 Anthropic，但有别的 DROP | Claude 在更早的环节就失败了，没走到发起直连那一步。也是安全的，但信息量少 |
| 一条新增都没有 | 多半是日志还没落盘，等一两分钟再跑一次；或者你用了按行号定位而日志轮转了 |

**7. 恢复（顺序不能乱）**

恢复顺序错了，会在「正式规则恰好失效 + Claude 还在后台重试」的窗口里制造一次
真实直连。严格按下面的顺序：

```powershell
# ① 完全退出 Claude（不是关窗口）：
#    托盘图标右键退出；Claude Code CLI 和扩展进程也要退干净，然后确认：
Get-Process claude -ErrorAction SilentlyContinue | Select-Object ProcessName, Id

# ② 恢复系统代理为【测试前保存的原值】（第 4 步存进 $ksProxyBefore 的那个），
#    然后手动启动代理进程
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value $ksProxyBefore

# ③ 确认代理真的回来了：节点 TCP 通、隧道网卡出现
Test-NetConnection <你的节点IP> -Port <节点端口> | Select-Object TcpTestSucceeded

# ④ Claude 保持关闭，撤掉临时墙
Get-NetFirewallRule -Group "Claude-KS-TEMP" | Remove-NetFirewallRule

# ⑤ 确认撤销：回读应该为空
Get-NetFirewallRule -Group "Claude-KS-TEMP"

# ⑥ 全部确认之后，才重新打开 Claude
```

为什么是这个顺序：

- **先退 Claude 再动任何东西**：只要 Claude 还开着，它就在后台重试连接。
  撤墙、恢复代理的每一个动作都可能恰好发生在它重试的瞬间。
- **先恢复代理再撤墙**：墙撤掉之后如果代理还没回来，Claude 一旦被重新打开
  （或还没退干净）就是直连。先让代理可用，撤墙才安全。
- **恢复 `ProxyEnable` 用保存的原值**：你测试前系统代理可能本来就是关的
  （比如纯 TUN 模式），无脑写回 1 会改变你的原始状态。

---

## 想要完整归因？用 WFP 5157

`pfirewall.log` 有个明显短板：**它不记录进程，也不记录是哪条规则干的**。
所以第三阶段结束后你知道「有东西被挡了」，但分不清是临时墙还是你的正式规则。

Windows 事件 **5157**（Filtering Platform Connection，失败审计）能给出：
应用程序路径、PID、源/目的地址端口、协议，以及 **Filter Origin —— 触发
阻断的那条防火墙规则的 ID**（Windows 11 / Server 2022 起）。

2026-11 在本机实测：`FilterOrigin` 就是规则的 `Name`（GUID），拿它
`Get-NetFirewallRule -Name <GUID>` 能直接查出是哪条规则；`Application` 是
发起连接的 exe 路径。两者都对得上，这条证据链是可靠的。

开启（管理员）。**别用子类别名字**：`/subcategory:"Filtering Platform Connection"`
在中文本地化的 Windows 上会直接报「参数错误 0x00000057」。用 GUID：

```powershell
# 0CCE9226 = Filtering Platform Connection
auditpol /set /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030} /failure:enable
```

关闭：

```powershell
auditpol /set /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030} /failure:disable
```

确认开成了（输出里那一行应该是「失败」/`Failure`）：

```powershell
auditpol /get /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}
```

规则 ID 反查规则名：`Get-NetFirewallRule -Name <ID>`

> **注意量**：开了之后每一次被挡的连接都会进 Security 日志。一个代理挂掉的
> Windows 机，两分钟就能攒出几千条。测完立刻关掉，并先把防火墙日志上限调大
> （`Set-NetFirewallProfile -All -LogMaxSizeKilobytes 32767`），否则 4 MB 轮转
> 会把关键片段冲掉。

### 关键限制：护栏一立起来，就证明不了正式规则

这是本协议最容易搞错的一点，务必先看。

临时墙和正式规则会**同时命中同一条流**（都覆盖 Anthropic 网段、都绑物理网卡），
而 Windows **只报告其中一个来源**。

2026-11 实测（同一台机器，两轮对照）：临时墙在的时候，Claude Code 的 101 次直连
尝试，`FilterOrigin` **全部**指向临时墙的规则 ID；3 条正式规则在全部 7686 个事件里
出现 **0 次**。把正式规则临时关掉再测一遍，归因结果**完全一样**。

也就是说：

| 你能证明的 | 你证明不了的 |
|---|---|
| 护栏有效（诱饵加墙前通、加墙后断） | 正式规则是否命中 |
| 「有东西挡住了 Claude 的直连」 | 「挡住它的是我们那条规则」 |
| fail-open 风险真实存在 | 正式规则的有效性 |

**要真正证明正式规则，必须让护栏退场。** 护栏一撤，正式规则失效就是一次真实直连 ——
所以只有「物理出口本身不存在」的环境才允许这么做：

- 拔网线 / 关掉上游（路由器断 WAN，保留本机 LAN）
- 或在一台宿主只开 host-only 网络的虚拟机里

这两种情况下包根本出不去，这时才可以撤掉护栏、单独验证正式规则。

**做不到就诚实写「护栏已验证、正式规则未证实」。** 把
「加了墙、Claude 连不上」写成「正式规则已验证」，正是这个项目最想避免的那种误判。

---

## 全机 kill-switch（覆盖最后一个缺口）

本项目不包含它，但这里说清楚它是什么。

「未知程序 → 未知地址」这一格，**任何黑白名单都关不上**。唯一能关上它的是：
**物理网卡默认拒绝，只放行代理程序本身。**

注意：第三阶段的「临时全机墙」**不能**直接变成常驻再加 Allow 例外。Windows
防火墙的规则匹配顺序里，**显式 Block 规则优先于任何 Allow 规则**（见微软文档
「Rule precedence」）——「全机 Block + 代理 Allow」会把代理自己也挡死，这个
组合是错的。常驻 kill-switch 需要一套「默认拒绝 + 精确放行」的**独立设计**
（默认拒绝怎么落地、代理程序怎么白名单、失效时 fail-open 还是 fail-close），
本项目不含这个方案。

**代价，必须想清楚再做：**

- 代理没有开机自启的话，**开机到你启动代理之间整机没网**
- 节点 IP 变了（换订阅）你会把自己锁在外面，连查资料都做不到
- 必须事先把撤销命令**抄在纸上或存在手机里**

有意思的是，如果你本来就在用 TUN 模式，这个方案在**稳态下什么都不改变** ——
因为 TUN 已经接管了全部流量，本来就没有程序在用物理网卡直连。它改变的只是
失败时的行为：把 fail-open 变成 fail-close。

值不值得，你自己判断。
