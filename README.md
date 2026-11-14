# Claude Desktop 防直连 Kill-Switch（Windows）

> 给在中国大陆用 Claude 的人：确保代理挂掉的那一刻，Claude 是**断掉**，而不是**悄悄用你家宽带 IP 直连 Anthropic**。

---

## 这个问题长什么样

大部分人以为「代理挂了 = 用不了」。实际情况是：

**代理挂了 = 应用可能直接连出去，而且连得上，不报错。**

下面是一次真实测试的防火墙日志。测试方法是：关掉系统代理、结束代理进程、让隧道网卡消失（也就是代理崩溃时的真实状态），然后打开 Claude Desktop。

```
2026-08-15 19:58:24  DROP TCP  192.168.x.x → 160.79.104.10:443
2026-08-15 19:58:24  DROP TCP  192.168.x.x → 160.79.104.10:443
2026-08-15 19:58:24  DROP TCP  192.168.x.x → 160.79.104.10:443
...
（12 秒内约 25 条，全部指向 160.79.104.10:443）
```

`160.79.104.10` 就是 `api.anthropic.com` / `claude.ai`。

**12 秒，25 次直连尝试。** 如果没有这套规则，这 25 次每一次都会成功 —— 从中国大陆访问 Anthropic 的服务器在网络层是通的，TCP 和 TLS 都能建立，只是内容层面会被拒绝。也就是说：

- Anthropic 那边会记录到你的大陆家宽 IP
- 你这边**不会收到任何提示**
- 等你发现的时候，账号可能已经被标记了

这就是「静默泄漏」。你的代理越稳定，你越不会去检查它。

---

## 谁需要这个

- 在中国大陆用 Claude Desktop / Claude Code，靠代理访问
- 代理客户端偶尔会崩（v2rayN、Clash、sing-box 都会）
- 在意账号安全，不想赌运气

## 谁不需要

- 不在需要代理的地区
- 用的是路由器级/网关级代理，本机根本没有直连出口
- macOS / Linux（这套是 Windows 防火墙实现，其他系统要用 pf / nftables 重写）

---

## 核心思路：只在物理网卡上拦

这是整套方案能成立的关键，也是它跟「一刀切封掉 Claude」的区别。

所有规则都加上 `-InterfaceAlias (Get-NetAdapter -Physical).Name`，也就是**只作用在网线和 WiFi 上**：

```
代理正常时：
  Claude → 127.0.0.1:代理端口（回环）→ 代理程序 → 出去      ← 规则碰不到
  或
  Claude → 隧道网卡（TUN）→ 代理程序 → 出去                  ← 规则碰不到

代理挂掉时：
  隧道网卡消失，路由掉回 WiFi
  Claude → WiFi → Anthropic                                  ← 规则在这里拦住
```

**结果是：日常零感知，代理一断立刻断。**

这个设计顺带解决了几个很烦的问题：

- **扩展 / MCP 还能不能上网？** 能，走隧道。只有隧道断了才没网。不会被降级成只能 localhost。
- **会不会误伤局域网、打印机、Tailscale？** 不会。规则的地址集里排除了回环、RFC1918、100.64/10（Tailscale CGNAT）、链路本地。
- **改配置会不会把自己锁死？** 不会。所有规则一条命令全撤。

---

## 快速开始（十分钟版）

用**管理员身份**打开 PowerShell，然后：

```powershell
# 1. 先体检（只读，不改任何东西）
.\scripts\00-check.ps1

# 2. 装基础防护（3~4 条规则，Claude 客户端更新无需维护）
.\scripts\01-basic.ps1

# 3. 验证它真的会开火（用诱饵地址，全程不碰 Anthropic）
.\scripts\03-verify.ps1
```

**先跑 `00-check.ps1`。** 它会告诉你：你是什么代理模式、有哪些物理网卡、IPv6 是不是漏的、有没有已经脱靶的旧规则；还会核对 Windows 防火墙本身是否开启、已装的规则是否真的在生效存储（ActiveStore）里、是否覆盖当前**全部**物理网卡——插了新网卡（USB 网卡 / 扩展坞）而旧规则没绑上，体检会直接告诉你。这套方案的所有正确性都建立在「先量后写」上，别抄了就跑。

基础版做了两件事：

| 规则 | 作用 |
|---|---|
| 挡住 Anthropic 已知服务入站网段 | `160.79.104.0/23`、`153.61.224.0/22`、`2607:6bc0::/48`、`2607:6bc0:11::/48`，**所有程序**都不能从物理网卡直连过去 |
| （可选）挡住全部 IPv6 出公网 | 大部分 TUN 代理**不承载 IPv6**。今天你可能没有 IPv6 所以没事，换个网络（校园网、热点、新路由器）可能突然就有了，那一刻 IPv6 流量完全绕过隧道。`00-check.ps1` 会告诉你你属于哪种情况 |

其中 `2607:6bc0:11::/48` 是从 [AS399358 的 BGP 路由信息](https://bgp.he.net/AS399358) 补充的 IPv6 范围；官方 IP 文档当前只列出 `2607:6bc0::/48`。

规则不依赖 Claude 客户端版本；Anthropic 官方 IP 列表变化时需要更新。**大部分人到这里就够了。**

### 已安装旧版？补上新增 IPv4 网段

Anthropic 当前公布的入站 IPv4 包含 `153.61.224.0/22`。如果之前安装过旧版，只要更新仓库，然后在**管理员 PowerShell** 中运行：

```powershell
.\scripts\00-check.ps1
.\scripts\01-basic.ps1
.\scripts\00-check.ps1
```

新版对 `153.61.224.0/22` 单独创建一条规则，保留旧规则，不需要先卸载。`01-basic.ps1` 对已存在的同名规则先做健康检查（启用、出站、Block、地址覆盖、覆盖当前全部物理网卡）：**同名但被禁用 / 地址被改 / 缺新网卡绑定的规则，会被 `Set-NetFirewallRule` 原地修复**——不删旧规则，中间没有裸奔窗口。最后一次体检应显示两个 IPv4 网段都已拦截。安装前请确认代理正在正常运行。

官方列表同时列出了 `153.61.208.0/20` 作为 **Anthropic 向外发起请求时的源地址**（例如调用外部 MCP），它不是本工具所需的客户端连接目的地范围。具体列表以 [官方文档](https://platform.claude.com/docs/en/api/ip-addresses) 为准。

---

## 完整版

基础版按**目的地**拦，只覆盖 Anthropic 自己的 IP 段。但 Claude 也会连一些第三方托管的地址 —— 比如 `statsig.anthropic.com` 解析到 `34.36.57.103`，那是 Google Cloud，不在 Anthropic 网段里，按目的地拦不住。

完整版补上按**进程**拦的一层：把 Claude 全家（Desktop 包内程序、扩展进程、Claude Code CLI）从物理网卡上封掉**所有公网地址**，不看目的地。

为什么要封到「所有公网地址」而不只是 Anthropic 网段：Claude Code CLI 的错误上报走 Sentry 和 Datadog，这些端点托管在 Google Cloud 网段（`34.149.x.x` / `2600:1901::`），**不在 Anthropic 的 IP 段里**——按目的地拦不住。更麻烦的是，代理掉线时 CLI 连不上 API 这件事本身会触发错误上报（`tengu_streaming_error` 一类事件，带 `device_id` 和 `account_uuid`），等于「拦截动作自己制造泄露」。按进程封一层不看目的地，这类侧信道全部关死。

```powershell
.\scripts\02-full-install.ps1
```

它会：

1. 扫出所有 Claude 相关的可执行文件，逐个建规则
2. 装一个计划任务，负责在 Claude 更新后自动补规则

### 关于 MSIX 更新的竞态

Claude Desktop 是商店 MSIX 包，程序路径带版本号：

```
C:\Program Files\WindowsApps\Claude_1.30096.1.0_x64__pzs8sxrjxfjjc\app\Claude.exe
```

**它一更新，按路径写的规则就全部脱靶，而且没有任何提示。** 这不是理论问题 —— 本项目就是在发现某台机器上四条「看起来很漂亮」的规则因为版本从 `1.17377` 跳到 `1.30096` 而全部失效之后写的。

解决办法不是事后追赶，是**提前预置**：

Windows 在真正替换文件**几小时前**就会把新版本的完整包名写进事件日志：

```
事件 855：... is updating to Claude_1.28929.0.0_x64__pzs8sxrjxfjjc
事件 574：新的首选版本为：Claude_1.28929.0.0_x64__pzs8sxrjxfjjc
事件 638：程序包未更新，因为受影响的应用仍在运行    ← 更新会等 Claude 关闭
事件 617：已成功更新程序包 ...
```

所以重建脚本会：

- 被事件 574 / 855 触发 → 从日志里读出**还不存在**的新路径，**提前**建好规则（防火墙接受指向不存在文件的规则）
- 被事件 617 触发 → 重新扫描真实目录，补上任何新出现的程序
- 另有登录时和每 10 分钟的兜底触发

### 重建脚本是「只增不删」的

这一点很重要。常见写法是「删掉旧规则 → 重新扫描 → 建新规则」，那中间有一个窗口是**旧保护已经删了，新保护还没建**。如果扫描那一步出错，就永久裸奔了。

本项目的重建脚本**从不删除任何规则**。指向已删除路径的规则是无害的，留着就留着。任何一步失败都保持现状并写日志。

### 单用户限制

计划任务绑定的是**安装者**的账号（SID + 交互会话令牌）：只有安装者登录时，任务才会触发，规则才会自动重建。安装者注销后，这台机器上其他用户使用、更新 Claude 都不会自动补规则 —— **已建好的规则仍然生效**，但新版本的程序路径不在保护范围内。多用户机器上，每个需要保护的用户要各自安装一次。

---

## 怎么证明它真的生效

**这是最容易被跳过、也最不该跳过的一步。**

> 加了规则，然后 Claude 还能正常用 —— 这**不能**说明规则生效了。
> 规则一条都没匹配上的时候，现象是一模一样的。

`03-verify.ps1` 用一个诱饵地址做正向验证，全程不碰 Anthropic：

1. 加一条主机路由，把与 Claude 无关的测试地址（默认解析 `example.com` 的 IPv4）强制走物理网卡；curl 保留网站域名完成正常 TLS 握手
2. 测基线 → 应该**通**
3. 加一条构造上和正式规则完全一样、只是目标换成诱饵的规则
4. 再测 → 应该**不通**
5. 换成「按程序」的规则，只封 `curl.exe`，做一组严格的 A/B：
   - **先**用 curl 测一次（还没有规则）→ 必须**成功**
   - 加规则后，用**完全相同的命令**再测一次 → 必须**失败**
   - 同一时刻用另一个程序访问同一地址 → 必须**仍然通**

第 5 步的三个条件缺一不可。特别是那个 baseline：**不能靠「curl 退出码非零」来推断被阻断** —— 证书错误、TLS 握手失败、目标端口不说 HTTPS，都会让退出码非零，那样会得到假阳性。只有「同一个程序、同一条命令，加规则前成功、加规则后失败」才是证据。如果 baseline 本身就失败，脚本会报**「无法验证」**并退出码 `2`，不会当成通过。测试不需要关闭 Claude 代理，也不会访问 Anthropic。

可选的 `-TestAnthropic` 有门禁保护：前面的诱饵测试有失败项、`Claude-KS` 规则未安装、或检测到 Claude 相关进程还在运行（那条 /32 主机路由影响整机所有进程，不只是探针）时，这一步会被跳过或拒绝执行，退出码 `2`——拿不到 WFP 归因证据时也只报「无法证明」，不会把「目标不通」当成「被你的规则挡住了」。第一次跑还是建议用无参数版本，把机制先证明出来。

完整的零泄漏验证流程（包括怎么安全地做「拔掉代理」这种危险测试）见 **[docs/verification.md](docs/verification.md)**。核心思路是：**先架一层临时的全机阻断，再故意破坏代理**，这样无论被测的规则是真是假，都不可能产生一次真实的直连。

注意这两件事不是一回事：这层护栏保证的是**「不会漏」**，保证不了**「证明正式规则命中」**。两者重叠时 Windows 只报告其中一个来源，护栏会盖掉归因。区别和补救办法见 [docs/verification.md](docs/verification.md) 的「关键限制：护栏一立起来，就证明不了正式规则」。

---

## 那些看起来对、但其实会漏的方案

这些是做这个项目时逐个验证掉的。如果你问 AI 怎么做这件事，它大概率会给你其中之一。

### ❌ 用 `-Package` / AppContainer 包 SID 绑定应用

看起来完美：MSIX 应用有稳定的包标识，不受版本路径影响。

**但 Claude Desktop 是 `Windows.FullTrustApplication`，不跑在 AppContainer 里。** Windows 过滤平台（WFP）对非 AppContainer 进程会把包 SID 设成 NULL SID，所以 `-Package <SID>` 的规则**根本匹配不上**。

旁证：Windows 自己给 Claude 建的防火墙规则，全都是按**路径**写的，`Package` 字段是空的。如果包身份对这个应用可用，系统不会需要逐个 exe 写路径规则。

### ❌ 用 `-RemoteAddress Internet4,Internet6` 关键字

语法合法，文档也确实支持给关键字加 `4` / `6` 限定地址族。

**但 `Internet` / `Intranet` 这两个关键字的含义由「网络隔离策略」定义**，普通家用机上 `HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation` 是空的，这个关键字实际展开成什么地址集合，你查不出来、也验证不了。

更糟的是 PowerShell 对 `-RemoteAddress` 没有取值校验 —— 关键字写错不会报错，只会生成一条**匹配不到任何东西的规则**。对一个「失败必须很吵」的方案来说，这是最差的选择。

**本项目用显式网段。** 不好看，但可以逐条核对。

### ❌ 把地址段拼成一个字符串传给 `-RemoteAddress`

```powershell
# 错的：看着是 7 段，实际只写进去 1 段
$ranges = '1.0.0.0-9.255.255.255,11.0.0.0-100.63.255.255,100.128.0.0-126.255.255.255,...'
New-NetFirewallRule -DisplayName x -Direction Outbound -Action Block -RemoteAddress $ranges ...
```

`-RemoteAddress` 收的是**数组**。传一个逗号拼接的字符串进去，它不报错、也不替你拆，只保留**第一段**，其余静默丢弃。

2026-11 实测：这样建出来的规则，`(Get-NetFirewallRule ... | Get-NetFirewallAddressFilter).RemoteAddress` 只剩 `1.0.0.0-9.255.255.255` 一段。规则是 Block、也启用了，看着一切正常，实际只覆盖 1/7 的地址空间 —— 又是一个安静的 fail-open。

**正确写法**（本项目全部脚本都是这个写法）：

```powershell
$ranges = @(
    '1.0.0.0-9.255.255.255'
    '11.0.0.0-100.63.255.255'
    '100.128.0.0-126.255.255.255'
    # ...
)
New-NetFirewallRule -DisplayName x -Direction Outbound -Action Block -RemoteAddress $ranges ...
```

**装完回读，段数对不上就是没写全**：

```powershell
Get-NetFirewallRule -Group <你的组名> | Get-NetFirewallAddressFilter |
    ForEach-Object { "{0} 段" -f @($_.RemoteAddress).Count }
```

### ❌ 用 Dynamic Keyword / FQDN 规则

Windows 11 确实支持按域名写防火墙规则（`New-NetFirewallDynamicKeywordAddress -AutoResolve`）。

**但微软文档明确写了：规则如果只包含尚未解析的 AutoResolve 对象，规则不会被执行。** 而且 IP 要等到系统「观察到 DNS 查询」才会填充。

如果你的代理用 DoH 解析、或者应用走 HTTP 代理由远端解析域名，本机可能**永远观察不到那次 DNS 查询** —— 规则永远是空的，永远不执行。这是文档级别的 fail-open，不能当安全边界。

### ❌ 用 hosts 文件把域名指到黑洞

覆盖不全（子域名、新域名），而且很多代理客户端用自己的 DNS（比如 DoH），根本不读 hosts —— 既伤不到代理，也帮不上忙。

### ❌ 只封 IPv4

Anthropic 有 IPv6（`2607:6bc0::10`）。而大部分 TUN 代理不承载 IPv6。今天没有 IPv6 不代表明天没有。

### ❌ 只封 TCP

QUIC 走 UDP/443。本项目所有规则都不指定 `-Protocol`。

### ❌ 只封 `Claude.exe`

Claude Desktop 包内还有 `cowork-svc.exe`、`chrome-native-host.exe` 等；扩展 / MCP 进程跑在**包目录之外**（`%APPDATA%\Claude\Claude Extensions\...`）；Claude Code 是另一个程序——npm 安装的 CLI 位于 `<npm prefix>\node_modules\@anthropic-ai\claude-code\bin\claude.exe`（路径不带版本号，npm 升级原地覆盖，不会脱靶），原生安装则在 `~\.local\bin\claude.exe`。重建脚本会从用户 `.npmrc` 的 `prefix=`、npm 默认全局位置和 `npm prefix -g` 三条线索找到它。

---

## 覆盖不到什么

诚实地说清楚边界：

| 情况 | 覆盖 |
|---|---|
| 已知程序 → 已知地址 | ✅ 基础版 + 完整版 |
| 已知程序 → **未知/新增**地址 | ✅ 完整版（按进程封，不看目的地） |
| **未知程序** → 已知地址 | ✅ 基础版（按目的地封，不看程序） |
| **未知程序 → 未知地址** | ❌ **没有覆盖** |

最后一格只能靠「物理网卡默认拒绝 + 只放行代理程序」这种全机 kill-switch 来关。那个方案的代价是：开机到启动代理之间整机没网、代理节点变了会把自己锁在外面。本项目**不包含**它，因为对大多数人不划算。如果你想要，思路在 [docs/verification.md](docs/verification.md) 里有描述（临时全机墙那一节就是它的临时版本）。

另外：

- 这一切的前提是 **Windows 防火墙本身正常工作**。防火墙被关掉就什么都没了。
- 它保证「不会从大陆 IP 直连」，**保证不了「你走的是哪个节点」**。后者要靠你自己的习惯（切节点前先完全退出 Claude —— 关窗口不等于退出，它在托盘里还连着，切节点会带着账号换 IP）。
- Anthropic 的 IP 段可能变化。当前值来自 [Anthropic 官方文档](https://platform.claude.com/docs/en/api/ip-addresses)，写在 `scripts/01-basic.ps1` 顶部，建议偶尔核对。

---

## 卸载

```powershell
.\scripts\99-uninstall.ps1
```

删掉全部规则和计划任务，回到什么都没装的状态。规则都在 Windows 防火墙的 PersistentStore 里，删除即完全恢复，不留残留配置。

---

## 文件说明

| 文件 | 作用 |
|---|---|
| `scripts/00-check.ps1` | 环境体检，**只读**，什么都不改（含防火墙 profile、ActiveStore、网卡覆盖核对） |
| `scripts/01-basic.ps1` | 基础防护：按目的地封 Anthropic 网段；同名不健康的规则原地修复 |
| `scripts/02-full-install.ps1` | 完整防护：按进程封 + 装自动重建任务 |
| `scripts/02-full-rebuild.ps1` | 被计划任务调用的重建脚本（只增不删） |
| `scripts/ks-lib.ps1` | 共享判断函数库（规则健康判定、门禁、清理），被主脚本和测试引用 |
| `scripts/03-verify.ps1` | 诱饵验证，证明规则真的会开火 |
| `scripts/99-uninstall.ps1` | 全部撤销（先停计划任务再删规则） |
| `docs/verification.md` | 完整的零泄漏验证流程 |
| `tests/run-tests.ps1` | 回归测试（纯 mock，不碰真实防火墙） |

---

## 测试与验证状态

```powershell
# 单元测试：纯内存 mock，不加载主脚本、不碰真实防火墙
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\run-tests.ps1
```

- **单元测试**：76 条断言全绿。覆盖规则健康四场景（禁用 / 改地址 / 缺新网卡 / 健康）、`-TestAnthropic` 门禁与退出码语义、发现源失败传播、路由按完整身份清理、安装目录 ACL 判定。
- **真机验证**（2026-11，Windows 11 + sing-box TUN + v2rayN，WLAN）：诱饵 A/B（按目的地、按程序）实测开火；`-TestAnthropic` 在 Claude CLI 存活时实测拒绝执行（退出码 `2`）；同名规则缺网卡绑定实测被 `Set-NetFirewallRule` 原地修复；测试路由按完整身份清理、零残留。IPv6 / UDP/QUIC 路径与拔插头端到端测试未在本机做。

---

## License

MIT

---

## 一句话总结

> 你的担心不是洁癖。代理挂掉的时候，Claude 真的会去直连，而且很积极 —— 20 秒内 30 次。
> 区别只在于，那 30 次是留在防火墙日志里，还是留在 Anthropic 的访问记录里。
