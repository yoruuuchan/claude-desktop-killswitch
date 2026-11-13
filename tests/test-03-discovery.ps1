# P1-4: discovery verdict - a failed source aborts the rebuild honestly.

$okUser    = [pscustomobject]@{ Source = 'user-profiles';    Status = 'ok' }
$okDesktop = [pscustomobject]@{ Source = 'desktop-package'; Status = 'ok' }
$okLog     = [pscustomobject]@{ Source = 'appx-deploy-log'; Status = 'ok' }
$absentExt = [pscustomobject]@{ Source = 'extension-dirs';  Status = 'absent' }
$badCli    = [pscustomobject]@{ Source = 'claude-code-cli'; Status = 'failed' }

$v = Get-KSDiscoveryVerdict -SourceStatuses @($okUser, $badCli, $okLog, $absentExt) -TargetCount 5
Assert-True ($v.Abort) 'discovery: one failed source aborts (rebuild exits non-zero)'
Assert-True ($v.Reason -match 'claude-code-cli') 'discovery: abort reason names the failed source'

$v = Get-KSDiscoveryVerdict -SourceStatuses @($okUser, $okLog, $absentExt) -TargetCount 0
Assert-True ($v.Abort) 'discovery: zero targets aborts'
Assert-True ($v.Reason -match '一个目标都没发现') 'discovery: zero-target abort reason'

$v = Get-KSDiscoveryVerdict -SourceStatuses @($okUser, $okDesktop, $okLog, $absentExt) -TargetCount 3
Assert-True (-not $v.Abort) 'discovery: ok/absent sources with targets proceed'

# absent is not failed: a machine with no extension dirs must not abort
$v = Get-KSDiscoveryVerdict -SourceStatuses @($okUser, $absentExt) -TargetCount 1
Assert-True (-not $v.Abort) 'discovery: absent sources are legitimate, not failures'
