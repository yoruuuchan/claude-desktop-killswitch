# P0-1: rule health - same name does not mean valid.
# Four scenarios must trigger repair; only a fully healthy rule may be skipped.

$phys = @('Ethernet', 'Wi-Fi')
$pub4 = @('1.0.0.0-9.255.255.255', '11.0.0.0-100.63.255.255')

# ---- ConvertTo-KSNormalizedAddress ----
Assert-True ((ConvertTo-KSNormalizedAddress '153.61.224.0/255.255.252.0') -eq '153.61.224.0/22') 'normalize: dotted mask /255.255.252.0 -> /22'
Assert-True ((ConvertTo-KSNormalizedAddress '160.79.104.0/23') -eq '160.79.104.0/23') 'normalize: CIDR passthrough'
Assert-True ((ConvertTo-KSNormalizedAddress '1.0.0.0-9.255.255.255') -eq '1.0.0.0-9.255.255.255') 'normalize: range passthrough'
Assert-True ((ConvertTo-KSNormalizedAddress '2607:6bc0::/48') -eq '2607:6bc0::/48') 'normalize: IPv6 passthrough'
Assert-True ((ConvertTo-KSNormalizedAddress '0.0.0.0/0.0.0.0') -eq '0.0.0.0/0') 'normalize: default mask -> /0'

# ---- Test-KSAddressCoverage ----
Assert-True (Test-KSAddressCoverage -Expected @('153.61.224.0/22') -Actual @('153.61.224.0/255.255.252.0')) 'coverage: dotted-mask actual satisfies CIDR expected'
Assert-True (Test-KSAddressCoverage -Expected @('160.79.104.0/23') -Actual @('160.79.104.0/23', '153.61.224.0/22')) 'coverage: extra actual addresses are fine'
Assert-True (-not (Test-KSAddressCoverage -Expected @('160.79.104.0/23', '153.61.224.0/22') -Actual @('160.79.104.0/23'))) 'coverage: missing expected address fails'

# ---- Test-KSRuleHealth ----
Assert-True (Test-KSRuleHealth -Rule (New-MockRule -Name r1 -DisplayName d -RemoteAddress @('160.79.104.0/23') -InterfaceAlias $phys) `
    -ExpectedRemoteAddress @('160.79.104.0/23') -ExpectedInterfaceAlias $phys) 'health: fully healthy rule passes'
Assert-True (-not (Test-KSRuleHealth -Rule (New-MockRule -Name r2 -DisplayName d -Enabled 'False' -RemoteAddress @('160.79.104.0/23') -InterfaceAlias $phys) `
    -ExpectedRemoteAddress @('160.79.104.0/23') -ExpectedInterfaceAlias $phys)) 'health: disabled rule fails'
Assert-True (-not (Test-KSRuleHealth -Rule (New-MockRule -Name r3 -DisplayName d -Direction 'Inbound' -RemoteAddress @('160.79.104.0/23') -InterfaceAlias $phys) `
    -ExpectedRemoteAddress @('160.79.104.0/23') -ExpectedInterfaceAlias $phys)) 'health: inbound rule fails'
Assert-True (-not (Test-KSRuleHealth -Rule (New-MockRule -Name r4 -DisplayName d -Action 'Allow' -RemoteAddress @('160.79.104.0/23') -InterfaceAlias $phys) `
    -ExpectedRemoteAddress @('160.79.104.0/23') -ExpectedInterfaceAlias $phys)) 'health: allow rule fails'
Assert-True (-not (Test-KSRuleHealth -Rule (New-MockRule -Name r5 -DisplayName d -Profile 'Domain' -RemoteAddress @('160.79.104.0/23') -InterfaceAlias $phys) `
    -ExpectedRemoteAddress @('160.79.104.0/23') -ExpectedInterfaceAlias $phys)) 'health: profile-scoped rule fails'
Assert-True (-not (Test-KSRuleHealth -Rule (New-MockRule -Name r6 -DisplayName d -RemoteAddress @('1.2.3.0/24') -InterfaceAlias $phys) `
    -ExpectedRemoteAddress @('160.79.104.0/23') -ExpectedInterfaceAlias $phys)) 'health: retargeted address fails'
Assert-True (Test-KSRuleHealth -Rule (New-MockRule -Name r7 -DisplayName d -RemoteAddress @('153.61.224.0/255.255.252.0') -InterfaceAlias $phys) `
    -ExpectedRemoteAddress @('153.61.224.0/22') -ExpectedInterfaceAlias $phys) 'health: dotted-mask address counts as the CIDR'
Assert-True (-not (Test-KSRuleHealth -Rule (New-MockRule -Name r8 -DisplayName d -Program 'C:\old\claude.exe' -RemoteAddress $pub4 -InterfaceAlias $phys) `
    -ExpectedRemoteAddress $pub4 -ExpectedProgram 'C:\new\claude.exe' -ExpectedInterfaceAlias $phys)) 'health: program mismatch fails'
Assert-True (Test-KSRuleHealth -Rule (New-MockRule -Name r9 -DisplayName d -Program 'C:\new\claude.exe' -RemoteAddress $pub4 -InterfaceAlias $phys) `
    -ExpectedRemoteAddress $pub4 -ExpectedProgram 'C:\new\claude.exe' -ExpectedInterfaceAlias $phys) 'health: exact program match passes'
Assert-True (-not (Test-KSRuleHealth -Rule (New-MockRule -Name r10 -DisplayName d -RemoteAddress @('160.79.104.0/23') -InterfaceAlias @('Ethernet')) `
    -ExpectedRemoteAddress @('160.79.104.0/23') -ExpectedInterfaceAlias $phys)) 'health: missing new adapter fails (USB NIC / dock)'

# ---- Update-KSBlockRule: the four P0-1 scenarios ----
$name = 'KS - Block Anthropic IPv4 on physical'

# (1) same name but disabled -> repaired via Set, never New
$script:MockCalls = @()
$disabled = New-MockRule -Name a1 -DisplayName $name -Enabled 'False' -RemoteAddress @('160.79.104.0/23') -InterfaceAlias $phys
$r = Update-KSBlockRule -Name $name -Group 'Claude-KS' -RemoteAddress @('160.79.104.0/23') -InterfaceAlias $phys -ExistingRules @($disabled)
Assert-True ($r.Action -eq 'repaired') 'P0-1 (1) same name but disabled -> repaired'
Assert-True ($script:MockCalls -contains 'Set-NetFirewallRule') 'P0-1 (1) repair calls Set-NetFirewallRule (in place, no delete window)'
Assert-True ($script:MockCalls -notcontains 'New-NetFirewallRule') 'P0-1 (1) no New-NetFirewallRule for existing rule'

# (2) same name but address changed -> repaired
$script:MockCalls = @()
$retargeted = New-MockRule -Name a2 -DisplayName $name -RemoteAddress @('1.2.3.0/24') -InterfaceAlias $phys
$r = Update-KSBlockRule -Name $name -Group 'Claude-KS' -RemoteAddress @('160.79.104.0/23') -InterfaceAlias $phys -ExistingRules @($retargeted)
Assert-True ($r.Action -eq 'repaired') 'P0-1 (2) same name but address changed -> repaired'
Assert-True ($script:MockCalls -contains 'Set-NetFirewallRule') 'P0-1 (2) repair calls Set-NetFirewallRule'

# (3) same name but missing the new adapter -> repaired
$script:MockCalls = @()
$staleIf = New-MockRule -Name a3 -DisplayName $name -RemoteAddress @('160.79.104.0/23') -InterfaceAlias @('Ethernet')
$r = Update-KSBlockRule -Name $name -Group 'Claude-KS' -RemoteAddress @('160.79.104.0/23') -InterfaceAlias $phys -ExistingRules @($staleIf)
Assert-True ($r.Action -eq 'repaired') 'P0-1 (3) same name but missing new adapter -> repaired'
Assert-True ($script:MockCalls -contains 'Set-NetFirewallRule') 'P0-1 (3) repair calls Set-NetFirewallRule'

# (4) fully healthy -> skipped, zero side effects
$script:MockCalls = @()
$healthy = New-MockRule -Name a4 -DisplayName $name -RemoteAddress @('160.79.104.0/23') -InterfaceAlias $phys
$r = Update-KSBlockRule -Name $name -Group 'Claude-KS' -RemoteAddress @('160.79.104.0/23') -InterfaceAlias $phys -ExistingRules @($healthy)
Assert-True ($r.Action -eq 'skipped') 'P0-1 (4) fully healthy -> skipped'
Assert-True ($script:MockCalls.Count -eq 0) 'P0-1 (4) healthy rule triggers no firewall calls'

# (4b) healthy with dotted-mask address representation -> skipped
$dotted = New-MockRule -Name a5 -DisplayName $name -RemoteAddress @('153.61.224.0/255.255.252.0') -InterfaceAlias $phys
$r = Update-KSBlockRule -Name $name -Group 'Claude-KS' -RemoteAddress @('153.61.224.0/22') -InterfaceAlias $phys -ExistingRules @($dotted)
Assert-True ($r.Action -eq 'skipped') 'P0-1 (4b) dotted-mask healthy rule -> skipped (representation-insensitive)'

# (5) missing rule -> created
$script:MockCalls = @()
$r = Update-KSBlockRule -Name 'KS - Block Anthropic IPv6 on physical' -Group 'Claude-KS' -RemoteAddress @('2607:6bc0::/48') -InterfaceAlias $phys -ExistingRules @()
Assert-True ($r.Action -eq 'created') 'P0-1 (5) missing rule -> created'
Assert-True ($script:MockCalls -contains 'New-NetFirewallRule') 'P0-1 (5) creation calls New-NetFirewallRule'

# (6) per-process rule: program mismatch -> repaired
$script:MockCalls = @()
$appName = 'Claude KS App v4 - C:\x\claude.exe'
$appRule = New-MockRule -Name a6 -DisplayName $appName -Program 'C:\old\claude.exe' -RemoteAddress $pub4 -InterfaceAlias $phys
$r = Update-KSBlockRule -Name $appName -Group 'Claude-KS-App' -RemoteAddress $pub4 -InterfaceAlias $phys -Program 'C:\x\claude.exe' -ExistingRules @($appRule)
Assert-True ($r.Action -eq 'repaired') 'P0-1 (6) app rule with stale program path -> repaired'
Assert-True ($script:MockCalls -contains 'Set-NetFirewallRule') 'P0-1 (6) repair calls Set-NetFirewallRule'
