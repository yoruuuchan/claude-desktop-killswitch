<#
    Claude 防直连 —— 按进程封的规则重建脚本

    这个脚本【不需要你手动跑】。02-full-install.ps1 会把它复制到
    C:\ProgramData\ClaudeKillSwitch\ 并注册成计划任务，由以下事件触发：

      · AppX 部署事件 574 / 855  → Claude 更新【前】几小时就预置好新路径的规则
      · AppX 部署事件 617        → 更新完成后重扫真实目录，补上新出现的程序
      · 用户登录
      · 每 10 分钟（兜底）

    ────────────────────────────────────────────────────────────────
    两个关键设计，改动前请先理解：

    1) 只增不删。
       常见写法是「删旧规则 → 重新扫描 → 建新规则」，那中间存在一个
       "旧保护已删、新保护未建" 的窗口。扫描那一步一旦出错就永久裸奔。
       本脚本从不删除任何规则。指向已删除路径的规则是无害的。

    2) 规则只作用在物理网卡上。
       隧道（TUN）和 Tailscale 的流量完全不受影响。只有当隧道消失、
       流量掉回网线/WiFi 时，规则才会生效。
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

$phys = @((Get-NetAdapter -Physical -ErrorAction SilentlyContinue).Name)
if ($phys.Count -eq 0) {
    Write-Log 'ABORT: 看不到任何物理网卡，未做任何改动。'
    exit 1
}

# ============================================================ 发现目标 ====

$targets = [System.Collections.Generic.List[string]]::new()

# --- 1. 当前安装的 MSIX 包内的所有 exe ---
$pkg = Get-AppxPackage -Name Claude -ErrorAction SilentlyContinue | Select-Object -First 1
if ($pkg -and $pkg.InstallLocation) {
    Get-ChildItem $pkg.InstallLocation -Recurse -File -Filter *.exe -ErrorAction SilentlyContinue |
        ForEach-Object { $targets.Add($_.FullName) }
}
$pfn = if ($pkg) { $pkg.PackageFamilyName } else { 'Claude_pzs8sxrjxfjjc' }

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

# --- 3. 包目录之外的进程：扩展 / MCP / Claude Code ---
@(
    (Join-Path $env:APPDATA 'Claude\Claude Extensions')
    (Join-Path $env:LOCALAPPDATA "Packages\$pfn\LocalCache\Roaming\Claude\Claude Extensions")
    (Join-Path $env:APPDATA 'Claude\claude-code')
) | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem $_ -Recurse -File -Filter *.exe -ErrorAction SilentlyContinue |
            ForEach-Object { $targets.Add($_.FullName) }
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
