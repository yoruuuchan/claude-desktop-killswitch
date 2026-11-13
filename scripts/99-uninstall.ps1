<#
    Claude 防直连 —— 全部撤销

    删掉本项目创建的所有东西，回到什么都没装的状态：
      · 防火墙规则组 Claude-KS / Claude-KS-App / 以及任何 Claude-KS* 开头的组
      · 计划任务「Claude KS Rebuild」
      · （可选）C:\ProgramData\ClaudeKillSwitch 目录

    所有规则都在 Windows 防火墙的 PersistentStore 里，删除即完全恢复，
    不会留下任何残留配置。

    用法（管理员 PowerShell）：
        .\99-uninstall.ps1
        .\99-uninstall.ps1 -RemoveFiles    连脚本目录和日志一起删
        .\99-uninstall.ps1 -Yes            跳过确认
#>

[CmdletBinding()]
param([switch]$RemoveFiles, [switch]$Yes)

$ErrorActionPreference = 'Continue'

$InstallDir = 'C:\ProgramData\ClaudeKillSwitch'
$TaskName   = 'Claude KS Rebuild'

function Ok($m)   { Write-Host "  [ 好 ] $m" -ForegroundColor Green }
function Info($m) { Write-Host "         $m" -ForegroundColor Gray }

Write-Host ''
Write-Host '  Claude 防直连 —— 全部撤销' -ForegroundColor White
Write-Host ''

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '  [失败] 需要管理员权限。' -ForegroundColor Red
    exit 1
}

$rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -like 'Claude-KS*' })
$task  = & schtasks /Query /TN $TaskName 2>$null
$taskExists = ($LASTEXITCODE -eq 0)

Info "将要删除："
Info "  · 防火墙规则 $($rules.Count) 条"
if ($rules.Count -gt 0) {
    $rules | Group-Object Group | ForEach-Object { Info ("      {0,-20} {1} 条" -f $_.Name, $_.Count) }
}
Info ("  · 计划任务「$TaskName」" + $(if ($taskExists) { '' } else { '（不存在）' }))
if ($RemoveFiles) { Info "  · 目录 $InstallDir" }
Write-Host ''

if (-not $Yes) {
    $a = Read-Host '  确认撤销？(y/N)'
    if ($a -notmatch '^[yY]') { Write-Host '  已取消，什么都没改。' -ForegroundColor Yellow; exit 0 }
}

Write-Host ''
# 顺序很重要：先停住计划任务（禁用新触发 + 结束正在运行的实例），再删规则。
# 反过来做的话，正在跑的重建任务可能在「刚删完规则」的瞬间把它们加回来。
if ($taskExists) {
    & schtasks /Change /TN $TaskName /DISABLE 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Ok "已禁用计划任务「$TaskName」（停止新触发）" }
    else { Write-Host "  [注意] 禁用计划任务失败（schtasks 退出码 $LASTEXITCODE）—— 删规则后它可能还会触发。" -ForegroundColor Yellow }

    & schtasks /End /TN $TaskName 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Ok '已结束正在运行的任务实例（如有）' }
    else { Info '结束任务实例返回非零 —— 可能本来就没在跑，也可能没停掉。' }
}

if ($rules.Count -gt 0) {
    $rules | Remove-NetFirewallRule
    Ok "已删除 $($rules.Count) 条防火墙规则"
} else {
    Info '没有找到本项目的防火墙规则'
}

if ($taskExists) {
    & schtasks /Delete /TN $TaskName /F 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Ok "已删除计划任务「$TaskName」" }
    else { Write-Host "  [注意] 删除计划任务失败（schtasks 退出码 $LASTEXITCODE）。" -ForegroundColor Yellow }
} else {
    Info '计划任务不存在，跳过'
}

if ($RemoveFiles -and (Test-Path $InstallDir)) {
    Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $InstallDir) { Info "目录删除失败，可以手动删：$InstallDir" }
    else { Ok "已删除 $InstallDir" }
} elseif (Test-Path $InstallDir) {
    Info "脚本目录和日志保留在 $InstallDir （加 -RemoveFiles 可一并删除）"
}

# 复查（如实报告剩余，不装作干净）
$left = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -like 'Claude-KS*' })
& schtasks /Query /TN $TaskName 2>$null | Out-Null
$taskLeft = ($LASTEXITCODE -eq 0)
Write-Host ''
if ($left.Count -eq 0 -and -not $taskLeft) {
    Ok '已完全撤销。你的网络恢复成安装前的样子。'
} else {
    if ($left.Count -gt 0) {
        Write-Host "  [注意] 还剩 $($left.Count) 条规则没删掉：" -ForegroundColor Yellow
        $left | ForEach-Object { Info "    $($_.DisplayName)" }
    }
    if ($taskLeft) {
        Write-Host "  [注意] 计划任务「$TaskName」仍然存在。" -ForegroundColor Yellow
    }
}
Write-Host ''
