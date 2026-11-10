<#
    Claude 防直连 —— 按进程封的规则重建脚本

    这个脚本【不需要你手动跑】。02-full-install.ps1 会把它复制到
    C:\ProgramData\ClaudeKillSwitch\ 并注册成计划任务，由以下事件触发：

      · AppX 部署事件 574 / 855  → Claude 更新【前】几小时就预置好新路径的规则
      · AppX 部署事件 617        → 更新完成后重扫真实目录，补上新出现的程序
      · 用户登录
      · 每 10 分钟（兜底）

    ────────────────────────────────────────────────────────────────
    三个关键设计，改动前请先理解：

    1) 只增不删。
       常见写法是「删旧规则 → 重新扫描 → 建新规则」，那中间存在一个
       "旧保护已删、新保护未建" 的窗口。扫描那一步一旦出错就永久裸奔。
       本脚本从不删除任何规则。指向已删除路径的规则是无害的。

    2) 规则只作用在物理网卡上。
       隧道（TUN）和 Tailscale 的流量完全不受影响。只有当隧道消失、
       流量掉回网线/WiFi 时，规则才会生效。

    3) 目标发现不依赖运行身份。
       计划任务可能在无用户会话的上下文里跑，那时 Get-AppxPackage 返回空、
       $env:APPDATA 指向 systemprofile —— 只依赖这两者的发现逻辑会全灭
       （2026-09 实测：规则停止自动更新两个月没被发现）。所以发现只走
       文件系统可验证的路径：WindowsApps 直接扫、C:\Users 遍历、.npmrc 解析。
    ────────────────────────────────────────────────────────────────

    退出码：0 = 所有发现的目标都已覆盖；1 = 有遗漏（看日志）。
    无论哪种情况，都不会删掉任何已存在的东西。
#>

$ErrorActionPreference = 'Stop'

$Group   = 'Claude-KS-App'
$LogDir  = 'C:\ProgramData\ClaudeKillSwitch'
$LogFile = Join-Path $LogDir 'rebuild.log'
$Stamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
function Write-Log([string]$m) { "$Stamp $m" | Add-Content -Path $LogFile -Encoding UTF8 }

# 公网 IPv4。故意排除：回环 127/8、RFC1918、CGNAT 100.64/10（Tailscale 用这段）、
# 链路本地 169.254/16。所以局域网、Tailscale、localhost 全部照常。
$Public4 = @(
    '1.0.0.0-9.255.255.255'
    '11.0.0.0-100.63.255.255'
    '100.128.0.0-126.255.255.255'
    '128.0.0.0-169.253.255.255'
    '169.255.0.0-172.15.255.255'
    '172.32.0.0-192.167.255.255'
    '192.169.0.0-223.255.255.255'
)
# 公网 IPv6 = 全球单播 + NAT64。不含 fe80::/10 和 fc00::/7（Tailscale 的 ULA 在这里）。
$Public6 = @('2000::/3', '64:ff9b::/96', '64:ff9b:1::/48')

$phys = @((Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -ne 'Not Present' }).Name)
if ($phys.Count -eq 0) {
    Write-Log 'ABORT: 看不到任何物理网卡，未做任何改动。'
    exit 1
}

# ============================================================ 发现目标 ====
# 发现逻辑不依赖「任务以哪个身份跑」。
# 踩过的坑（2026-09）：任务在无用户会话的上下文里执行时，Get-AppxPackage
# 返回空（Appx 包按用户注册），$env:APPDATA 又指向 systemprofile，
# 目标发现全灭 —— 规则停止自动更新两个月没人发现。
# 所以这里只用「文件系统就能验证」的探测：WindowsApps 直接扫、用户
# profile 遍历、.npmrc 解析，不依赖任何按用户注册的 API。

$targets = [System.Collections.Generic.List[string]]::new()

# 所有真实用户的 profile 根（比 $env:USERPROFILE 可靠：SYSTEM 跑时它指向
# systemprofile；比 $env:APPDATA 可靠：S4U 会话里它可能为空）
$userRoots = @((Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName))
$userRoots += $env:USERPROFILE
$userRoots = @($userRoots | Sort-Object -Unique)

# --- 1. Claude Desktop (MSIX)：Appx API + WindowsApps 直接扫描，两条腿走路 ---
$pkgs = @()
try { $pkgs = @(Get-AppxPackage -Name Claude -AllUsers -ErrorAction SilentlyContinue) } catch { }
try { $pkgs += @(Get-AppxPackage -Name Claude -ErrorAction SilentlyContinue) } catch { }
$pkg  = $pkgs | Select-Object -First 1
$installLocs = @($pkgs | Where-Object InstallLocation |
    Select-Object -ExpandProperty InstallLocation -Unique)

# 兜底：直接扫 WindowsApps 里的 Claude_* 目录（管理员/SYSTEM 可读）。
# 不依赖包注册状态：卸载重装、注册表没跟上、跨用户上下文，都能发现。
$winApps = Join-Path $env:ProgramFiles 'WindowsApps'
if (Test-Path $winApps) {
    $installLocs += @(Get-ChildItem $winApps -Directory -Filter 'Claude_*' -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName)
}
foreach ($loc in ($installLocs | Sort-Object -Unique)) {
    Get-ChildItem $loc -Recurse -File -Filter *.exe -ErrorAction SilentlyContinue |
        ForEach-Object { $targets.Add($_.FullName) }
}
$pfn = if ($pkg -and $pkg.PackageFamilyName) { $pkg.PackageFamilyName } else { 'Claude_pzs8sxrjxfjjc' }

# --- 2. 预置：从 AppX 部署日志里读出「即将安装」的包名 ---
# Windows 在真正替换文件几小时前就会把新版本的完整包名写进日志（事件 574 / 855），
# 而且不会在 Claude 运行时替换文件（事件 638）。所以我们可以在新程序还不存在的时候
# 就为它建好规则 —— 防火墙接受指向不存在路径的规则。这才是消除更新竞态的办法。

# MSIX 包全名的格式是   Name_Version_Architecture__PublisherId
# 架构可能是 x86 / x64 / arm / arm64 / neutral，不能写死。
# 从 PackageFamilyName 拆出 Name 和 PublisherId 来约束匹配（避免误伤日志里别的应用），
# 架构那一段保持开放，并且【从日志里原样提取完整包名】，不自己拼接。
$pkgName = $pfn -replace '_[^_]+$', ''
$pubId   = ($pfn -split '_')[-1]
$fullNameRx = '{0}_[0-9][0-9.]*_(?:x86|x64|arm|arm64|neutral)__{1}' -f
              [regex]::Escape($pkgName), [regex]::Escape($pubId)

# 未来的版本里该给哪些文件建规则？用【当前版本的相对路径】当模板，
# 比硬编码一串文件名准确，而且包结构变了会自动跟上。
$relTemplate = @()
if ($pkg -and $pkg.InstallLocation -and (Test-Path $pkg.InstallLocation)) {
    $base = $pkg.InstallLocation.TrimEnd('\')
    $relTemplate = @(
        Get-ChildItem $base -Recurse -File -Filter *.exe -ErrorAction SilentlyContinue |
            ForEach-Object { $_.FullName.Substring($base.Length).TrimStart('\') }
    )
}
if ($relTemplate.Count -eq 0) {
    # 读不到当前包时的兜底清单
    $relTemplate = @(
        'app\claude.exe'
        'app\resources\chrome-native-host.exe'
        'app\resources\cowork-svc.exe'
        'app\resources\app.asar.unpacked\resources\github-mcp\github-mcp-server.exe'
    )
}

try {
    Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-AppXDeploymentServer/Operational'
            StartTime = (Get-Date).AddDays(-14)
        } -MaxEvents 2000 -ErrorAction Stop |
        ForEach-Object { [regex]::Matches($_.Message, $fullNameRx) } |
        ForEach-Object { $_.Value } |
        Sort-Object -Unique |
        ForEach-Object {
            $pkgRoot = Join-Path (Join-Path $env:ProgramFiles 'WindowsApps') $_
            foreach ($rel in $relTemplate) { $targets.Add((Join-Path $pkgRoot $rel)) }
        }
} catch {
    Write-Log "WARN: 读不到 AppX 部署日志：$($_.Exception.Message)"
}

# --- 3. 包目录之外的进程：扩展 / MCP（遍历所有用户 profile）---
foreach ($u in $userRoots) {
    @(
        (Join-Path $u 'AppData\Roaming\Claude\Claude Extensions')
        (Join-Path $u "AppData\Local\Packages\$pfn\LocalCache\Roaming\Claude\Claude Extensions")
        (Join-Path $u 'AppData\Roaming\Claude\claude-code')
    ) | ForEach-Object {
        if (Test-Path $_) {
            Get-ChildItem $_ -Recurse -File -Filter *.exe -ErrorAction SilentlyContinue |
                ForEach-Object { $targets.Add($_.FullName) }
        }
    }
}

# --- 4. Claude Code CLI（npm 全局安装）---
# npm 装的 CLI 不在 Desktop 包里，也不在扩展目录里，必须单独找。
# 依据（对 claude.exe 2.1.322 的静态逆向，2026-11）：
#   · CLI 的错误上报走 Sentry / Datadog，端点在 Google Cloud 网段，
#     不在 Anthropic 网段里 —— 基础防护（按目的地）拦不住，必须按进程封。
#   · 二进制位于 <npm prefix>\node_modules\@anthropic-ai\claude-code\bin\claude.exe，
#     以及同包嵌套的平台包 claude-code-win32-x64\claude.exe（同一文件的硬链接）。
$cliCandidates = [System.Collections.Generic.List[string]]::new()
foreach ($u in $userRoots) {
    # a) 用户 .npmrc 里自定义的 prefix=（自定义安装盘的机器只有这里能查到）
    $npmrc = Join-Path $u '.npmrc'
    if (Test-Path $npmrc) {
        foreach ($line in (Get-Content $npmrc -ErrorAction SilentlyContinue)) {
            if ($line -match '^\s*prefix\s*=\s*(.+?)\s*$') {
                $cliCandidates.Add((Join-Path $Matches[1] 'node_modules\@anthropic-ai\claude-code'))
            }
        }
    }
    # b) npm 默认全局位置
    $cliCandidates.Add((Join-Path $u 'AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code'))
    # c) 原生安装器位置
    $cliCandidates.Add((Join-Path $u '.local\bin'))
}
# d) npm 命令自己报告 prefix（以用户身份跑时最准；SYSTEM 下没有 npm 就跳过）
try {
    $npm = Get-Command npm -ErrorAction Stop
    $prefix = (& $npm.Source prefix -g 2>$null | Select-Object -First 1)
    if ($prefix) { $cliCandidates.Add((Join-Path $prefix 'node_modules\@anthropic-ai\claude-code')) }
} catch { }

foreach ($pkgDir in ($cliCandidates | Sort-Object -Unique)) {
    # wrapper 包的 bin（postinstall 已把真实二进制放进来）
    $bin = Join-Path $pkgDir 'bin\claude.exe'
    if (Test-Path $bin) { $targets.Add($bin) }
    # 嵌套的平台包（install.cjs 的复制来源，硬链接同源）
    $scoped = Join-Path $pkgDir 'node_modules\@anthropic-ai'
    if (Test-Path $scoped) {
        Get-ChildItem $scoped -Directory -Filter 'claude-code-*' -ErrorAction SilentlyContinue |
            ForEach-Object {
                $plat = Join-Path $_.FullName 'claude.exe'
                if (Test-Path $plat) { $targets.Add($plat) }
            }
    }
    # c) 原生安装器的独立可执行文件
    if ($pkgDir -notmatch '@anthropic-ai') {
        $native = Join-Path $pkgDir 'claude.exe'
        if (Test-Path $native) { $targets.Add($native) }
    }
}

$wanted = @($targets | Sort-Object -Unique)
if ($wanted.Count -eq 0) {
    Write-Log 'ABORT: 一个目标都没发现，未做任何改动。'
    exit 1
}

# ====================================================== 创建（只增不删） ====

$have = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue |
    ForEach-Object { [void]$have.Add($_.DisplayName) }

$added = 0
foreach ($exe in $wanted) {
    foreach ($fam in @(
            @{ Tag = 'v4'; Addr = $Public4 },
            @{ Tag = 'v6'; Addr = $Public6 })) {

        $name = "Claude KS App $($fam.Tag) - $exe"
        if ($have.Contains($name)) { continue }
        try {
            New-NetFirewallRule -DisplayName $name -Group $Group `
                -Direction Outbound -Action Block -Profile Any `
                -Program $exe -RemoteAddress $fam.Addr -InterfaceAlias $phys | Out-Null
            $added++
        } catch {
            Write-Log "ERROR 建规则失败 ${name}: $($_.Exception.Message)"
        }
    }
}

# ============================================================== 验证 ====
# 一条规则只有同时满足「有程序路径」且「带了网卡限定」才算数。
# 如果 InterfaceAlias 变成了 Any，说明出了问题（那样会连隧道一起封），
# 不能当成功上报。

$covered = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$rules = @(Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue)
foreach ($r in $rules) {
    $p = ($r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program
    $i = @(($r | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue).InterfaceAlias)
    if ($p -and $i -notcontains 'Any') {
        [void]$covered.Add("$($r.DisplayName)")
    }
}

$missing = @()
foreach ($exe in $wanted) {
    foreach ($tag in 'v4', 'v6') {
        if (-not $covered.Contains("Claude KS App $tag - $exe")) { $missing += "$tag $exe" }
    }
}

if ($missing.Count -gt 0) {
    Write-Log ("FAIL: 新增 $added 条，共 $($rules.Count) 条，$($missing.Count) 个目标未覆盖 -> " +
               ($missing -join ' | '))
    exit 1
}

Write-Log ("OK: 新增 $added 条，共 $($rules.Count) 条规则，覆盖 $($wanted.Count) 个程序，" +
           "网卡=$($phys -join ',')")
exit 0
