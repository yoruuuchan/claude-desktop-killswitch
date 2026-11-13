<#
    Claude 防直连 —— 完整防护

    在基础防护（按目的地封 Anthropic 网段）之上，再加一层按【进程】封：
    把 Claude 全家从物理网卡上封掉所有公网地址，不看目的地。

    为什么需要这一层：
      Claude 也会连一些第三方托管的地址，比如 statsig.anthropic.com
      解析到 Google Cloud，根本不在 Anthropic 的网段里。按目的地封拦不住。

    这个脚本会：
      1. 把 02-full-rebuild.ps1 复制到 C:\ProgramData\ClaudeKillSwitch\rebuild.ps1
      2. 注册计划任务，让它在 Claude 更新时自动补规则（只增不删）
      3. 立刻跑一次

    用法（管理员 PowerShell）：
        .\02-full-install.ps1
        .\02-full-install.ps1 -Yes    跳过确认

    撤销：
        .\99-uninstall.ps1
#>

[CmdletBinding()]
param([switch]$Yes)

$ErrorActionPreference = 'Stop'

# Shared pure-logic helpers (install-dir ACL safety check).
. (Join-Path $PSScriptRoot 'ks-lib.ps1')

$InstallDir = 'C:\ProgramData\ClaudeKillSwitch'
$RebuildDst = Join-Path $InstallDir 'rebuild.ps1'
$LibDst     = Join-Path $InstallDir 'ks-lib.ps1'
$TaskName   = 'Claude KS Rebuild'

function Fail($m) { Write-Host "  [失败] $m" -ForegroundColor Red; exit 1 }
function Ok($m)   { Write-Host "  [ 好 ] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [注意] $m" -ForegroundColor Yellow }
function Info($m) { Write-Host "         $m" -ForegroundColor Gray }

Write-Host ''
Write-Host '  Claude 防直连 —— 完整防护' -ForegroundColor White
Write-Host ''

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail '需要管理员权限。'
}

$RebuildSrc = Join-Path $PSScriptRoot '02-full-rebuild.ps1'
if (-not (Test-Path $RebuildSrc)) { Fail "找不到 $RebuildSrc" }
$LibSrc = Join-Path $PSScriptRoot 'ks-lib.ps1'
if (-not (Test-Path $LibSrc)) { Fail "找不到 $LibSrc" }

if (-not (Get-NetFirewallRule -Group 'Claude-KS' -ErrorAction SilentlyContinue)) {
    Warn '还没装基础防护。建议先跑 .\01-basic.ps1 —— 那一层是身份无关的，'
    Info '没有更新竞态，是整套方案里最可靠的一层。'
    Write-Host ''
}

$pkg = Get-AppxPackage -Name Claude -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $pkg) {
    Warn '没有检测到 Claude Desktop（MSIX 包）。'
    Info '如果你只用 Claude Code，这一层依然会覆盖它，可以继续。'
} else {
    Ok "检测到 Claude Desktop $($pkg.Version)"
}

Write-Host ''
Info '即将安装的东西：'
Info "  · 脚本      $RebuildDst"
Info "  · 计划任务  「$TaskName」（以你当前账号运行，最高权限）"
Info '  · 防火墙规则组 Claude-KS-App —— 每个 Claude 相关程序两条（IPv4 / IPv6）'
Write-Host ''
Info '规则数量会比较多（几十到上百条），这是正常的 —— Claude 的扩展自带一整个'
Info 'Python 环境，里面有几十个可执行文件。首次创建大约需要半分钟。'
Write-Host ''
Info '日常影响：零。隧道正常时这些规则碰不到任何流量。'
Write-Host ''

if (-not $Yes) {
    $a = Read-Host '  继续？(y/N)'
    if ($a -notmatch '^[yY]') { Write-Host '  已取消，什么都没改。' -ForegroundColor Yellow; exit 0 }
}

# ---- 1. 安装脚本（先校验目录，再落文件）----
# 计划任务以 HighestAvailable 权限执行这个目录里的脚本。目录本身如果允许
# 非管理员写入，高权限任务就等于在执行「低权限用户可以替换的代码」——
# 这是确定的提权路径，必须先校验再安装。
$adminSid = 'S-1-5-32-544'
$systemSid = 'S-1-5-18'

if (Test-Path $InstallDir) {
    $dirItem = Get-Item $InstallDir -Force
    if ($dirItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        Fail "$InstallDir 是 reparse point（junction / symlink）。为避免高权限任务执行被重定向的脚本，拒绝安装。请手动检查这个位置。"
    }
    $unsafe = Get-KSUnsafeAclIdentities -Acl (Get-Acl $InstallDir)
    if ($unsafe.Count -gt 0) {
        Fail ("$InstallDir 的 ACL 允许非管理员写入：{0}。" -f ($unsafe -join '、'))
        Info '这个目录可能已被篡改，或者带着 ProgramData 的默认宽松继承（Users 可写）。'
        Info '手动处置：确认目录内容可信后，删除该目录，或手动把 ACL 收紧为 SYSTEM + Administrators，再重新运行本脚本。'
    }
} else {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# 显式收紧 ACL：切断继承，只留 SYSTEM 和 Administrators 完全控制，
# Owner 设为 Administrators，然后回读验证 —— 不信任「设过了」。
$dirAcl = Get-Acl $InstallDir
$dirAcl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($adminSid)))
$dirAcl.SetAccessRuleProtection($true, $false)
$dirAcl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    (New-Object System.Security.Principal.SecurityIdentifier($systemSid)),
    'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
$dirAcl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    (New-Object System.Security.Principal.SecurityIdentifier($adminSid)),
    'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl -Path $InstallDir -AclObject $dirAcl

$checkAcl = Get-Acl $InstallDir
$checkUnsafe = Get-KSUnsafeAclIdentities -Acl $checkAcl
if ($checkUnsafe.Count -gt 0) {
    Fail ("收紧 ACL 后回读仍发现非管理员可写：{0}。拒绝继续安装。" -f ($checkUnsafe -join '、'))
}
$ownerSid = $null
try {
    $ownerSid = (New-Object System.Security.Principal.NTAccount($checkAcl.Owner)).Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
} catch { }
if ($ownerSid -ne $adminSid) {
    Fail "目录 Owner 设置失败（当前 Owner：$($checkAcl.Owner)）。拒绝继续安装。"
}
Ok "目录已就绪并通过 ACL 校验：$InstallDir"

Copy-Item $RebuildSrc $RebuildDst -Force
Copy-Item $LibSrc $LibDst -Force
Ok "脚本已安装：$RebuildDst"

# ---- 2. 注册计划任务 ----
$sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

$sub = '&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-AppXDeploymentServer/Operational"&gt;' +
       '&lt;Select Path="Microsoft-Windows-AppXDeploymentServer/Operational"&gt;' +
       '*[System[(EventID=574 or EventID=855 or EventID=617)]]' +
       '&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;'

$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Claude 防直连：重建按进程封的防火墙规则。只增不删。</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>$sub</Subscription>
    </EventTrigger>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>$sid</UserId>
    </LogonTrigger>
    <TimeTrigger>
      <StartBoundary>2020-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <Repetition>
        <Interval>PT10M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$sid</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -File "$RebuildDst"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

$xmlPath = Join-Path $InstallDir 'task.xml'
[System.IO.File]::WriteAllText($xmlPath, $xml, [System.Text.Encoding]::Unicode)

& schtasks /Create /TN $TaskName /XML $xmlPath /F | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "计划任务注册失败（schtasks 退出码 $LASTEXITCODE）" }
Ok "计划任务已注册：$TaskName"
Info '触发条件：Claude 更新事件（574/855/617）、登录时、每 10 分钟兜底'

# ---- 3. 立刻跑一次 ----
Write-Host ''
Info '正在首次生成规则，请稍候（可能要半分钟）…'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $RebuildDst | Out-Null
$code = $LASTEXITCODE

$log = Join-Path $InstallDir 'rebuild.log'
$last = if (Test-Path $log) { (Get-Content $log -Tail 1) } else { '(没有日志)' }

Write-Host ''
if ($code -eq 0) {
    Ok '规则生成完成'
    Info $last
} else {
    Warn "重建脚本返回了非零退出码（$code），说明有目标没覆盖到。"
    Info $last
    Info '注意：即使失败，它也不会删掉任何已存在的规则。'
}

$n = @(Get-NetFirewallRule -Group 'Claude-KS-App' -ErrorAction SilentlyContinue).Count
Write-Host ''
Ok "Claude-KS-App 规则组现有 $n 条规则"
Write-Host ''
Info '下一步（不要跳过）：'
Write-Host '    .\03-verify.ps1' -ForegroundColor Green
Write-Host ''
Info "日志：$log"
Info '撤销：.\99-uninstall.ps1'
Write-Host ''
