# P0-2: -TestAnthropic gate, exit codes, honest conclusion, WFP attribution.

# ---- Get-KSAnthropicGateDecision ----
$g = Get-KSAnthropicGateDecision -FailedCount 1 -HasClaudeKS $true -ClaudeProcessNames @()
Assert-True (-not $g.Run -and $g.Category -eq 'skip') 'gate: prior test failures skip -TestAnthropic'
Assert-True ($g.SkipItem -like 'Anthropic*') 'gate: prior-failure skip records a skip item (exit 2 path)'

$g = Get-KSAnthropicGateDecision -FailedCount 0 -HasClaudeKS $false -ClaudeProcessNames @()
Assert-True (-not $g.Run -and $g.Category -eq 'skip') 'gate: missing Claude-KS rules skip instead of proceeding'
Assert-True ($g.SkipItem -like 'Anthropic*') 'gate: missing-rules skip records a skip item -> exit code 2'

$g = Get-KSAnthropicGateDecision -FailedCount 0 -HasClaudeKS $true -ClaudeProcessNames @('claude')
Assert-True (-not $g.Run -and $g.Category -eq 'refuse') 'gate: live Claude process refuses execution'
Assert-True ($g.Reason -match 'claude') 'gate: refusal tells the user to exit Claude first'

$g = Get-KSAnthropicGateDecision -FailedCount 0 -HasClaudeKS $true -ClaudeProcessNames @()
Assert-True ($g.Run -and $g.Category -eq 'run') 'gate: all clear -> run'

# ---- Get-KSVerifyExitCode ----
Assert-True ((Get-KSVerifyExitCode -Pass @('a') -Fail @() -Skip @()) -eq 0) 'exit code: passes only -> 0'
Assert-True ((Get-KSVerifyExitCode -Pass @('a') -Fail @('b') -Skip @()) -eq 1) 'exit code: any failure -> 1'
Assert-True ((Get-KSVerifyExitCode -Pass @('a') -Fail @() -Skip @('b')) -eq 2) 'exit code: skip without fail -> 2 (missing rules is not a pass)'
Assert-True ((Get-KSVerifyExitCode -Pass @() -Fail @() -Skip @()) -eq 2) 'exit code: nothing ran -> 2'

# ---- Get-KSVerifyConclusion ----
$lines = Get-KSVerifyConclusion -Pass @('按目的地封', '按程序封') -Fail @() -Skip @() -BasicInstalled $true -AppInstalled $false
Assert-True (@($lines | Where-Object { $_ -like '已安装：基础防护(Claude-KS)=是*' }).Count -eq 1) 'conclusion: installed category shown'
Assert-True (@($lines | Where-Object { $_ -like '配置检查通过：*' }).Count -eq 1) 'conclusion: config-check-passed category shown'
Assert-True (@($lines | Where-Object { $_ -like '实测通过：无*' }).Count -eq 1) 'conclusion: live-test category shown as none when -TestAnthropic not run'
Assert-True (@($lines | Where-Object { $_ -eq '未验证：无' }).Count -eq 1) 'conclusion: not-verified category shown'
Assert-True (@($lines | Where-Object { $_ -match 'IPv6 与 UDP/QUIC' }).Count -eq 1) 'conclusion: IPv6 and UDP/QUIC explicitly called out as untested'

$lines = Get-KSVerifyConclusion -Pass @('按目的地封', '按程序封', 'Anthropic 规则') -Fail @() -Skip @() -BasicInstalled $true -AppInstalled $true
Assert-True (@($lines | Where-Object { $_ -like '实测通过：Anthropic*' }).Count -eq 1) 'conclusion: live-test pass shown with attribution note'

$lines = Get-KSVerifyConclusion -Pass @() -Fail @() -Skip @('Anthropic 规则（未安装基础防护）') -BasicInstalled $false -AppInstalled $false
Assert-True (@($lines | Where-Object { $_ -like '未验证：Anthropic 规则*' }).Count -eq 1) 'conclusion: skipped items land in the not-verified category'

# ---- Find-KSWfpBlockOrigin ----
$xml5157 = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID Qualifiers="0">5157</EventID>
  </System>
  <EventData>
    <Data Name="Application">C:\test\curl.exe</Data>
    <Data Name="SourceAddress">192.168.1.10</Data>
    <Data Name="DestAddress">160.79.104.10</Data>
    <Data Name="DestPort">443</Data>
    <Data Name="FilterOrigin">{11111111-2222-3333-4444-555555555555}</Data>
  </EventData>
</Event>
'@

$script:MockWinEventThrows = $true
Assert-True ($null -eq (Find-KSWfpBlockOrigin -DestinationIP '160.79.104.10' -Since (Get-Date).AddMinutes(-5))) 'wfp: audit off / log unreadable -> no attribution (must report cannot-prove)'

$script:MockWinEventThrows = $false
$script:MockWinEvents = @(New-MockWinEvent -XmlText $xml5157)
Assert-True ((Find-KSWfpBlockOrigin -DestinationIP '160.79.104.10' -Since (Get-Date).AddMinutes(-5)) -eq '{11111111-2222-3333-4444-555555555555}') 'wfp: matching 5157 event returns FilterOrigin'

$script:MockWinEvents = @(New-MockWinEvent -XmlText $xml5157)
Assert-True ($null -eq (Find-KSWfpBlockOrigin -DestinationIP '153.61.224.10' -Since (Get-Date).AddMinutes(-5))) 'wfp: non-matching destination -> no attribution'

$xmlNoOrigin = $xml5157 -replace '<Data Name="FilterOrigin">.*</Data>', ''
$script:MockWinEvents = @(New-MockWinEvent -XmlText $xmlNoOrigin)
Assert-True ($null -eq (Find-KSWfpBlockOrigin -DestinationIP '160.79.104.10' -Since (Get-Date).AddMinutes(-5))) 'wfp: event without FilterOrigin -> no attribution (cannot prove)'
