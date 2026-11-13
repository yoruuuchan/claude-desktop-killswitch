# P1-3: install-dir ACL safety check + installer exit-code propagation.

# Well-known SIDs are used directly so the test is locale-independent.
$sidAdmin  = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$sidSystem = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$sidUsers  = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')

$aceAdminFull  = New-Object System.Security.AccessControl.FileSystemAccessRule($sidAdmin, 'FullControl', 'Allow')
$aceSystemFull = New-Object System.Security.AccessControl.FileSystemAccessRule($sidSystem, 'FullControl', 'Allow')
$aceUsersWrite = New-Object System.Security.AccessControl.FileSystemAccessRule($sidUsers, 'Write', 'Allow')
$aceUsersRead  = New-Object System.Security.AccessControl.FileSystemAccessRule($sidUsers, 'ReadAndExecute', 'Allow')
$aceUsersDeny  = New-Object System.Security.AccessControl.FileSystemAccessRule($sidUsers, 'FullControl', 'Deny')
# What ProgramData's default inheritance actually grants Users on new subdirs:
# create-files/append-data special rights.
$aceUsersAppend = New-Object System.Security.AccessControl.FileSystemAccessRule($sidUsers, 'AppendData', 'Allow')

# ---- Get-KSUnsafeAclIdentities ----
$unsafe = Get-KSUnsafeAclIdentities -Acl ([pscustomobject]@{ Access = @($aceAdminFull, $aceSystemFull) })
Assert-True (@($unsafe).Count -eq 0) 'acl: SYSTEM + Administrators FullControl only -> safe'

$unsafe = Get-KSUnsafeAclIdentities -Acl ([pscustomobject]@{ Access = @($aceAdminFull, $aceUsersWrite) })
Assert-True (@($unsafe).Count -eq 1) 'acl: Users write ACE -> unsafe (install must be refused)'
Assert-True (@($unsafe)[0] -match 'S-1-5-32-545') 'acl: the offending identity is reported'

$unsafe = Get-KSUnsafeAclIdentities -Acl ([pscustomobject]@{ Access = @($aceAdminFull, $aceUsersRead) })
Assert-True (@($unsafe).Count -eq 0) 'acl: read-only ACE for Users -> safe'

$unsafe = Get-KSUnsafeAclIdentities -Acl ([pscustomobject]@{ Access = @($aceAdminFull, $aceUsersAppend) })
Assert-True (@($unsafe).Count -eq 1) 'acl: append-only ACE (ProgramData default inheritance) -> unsafe'

$unsafe = Get-KSUnsafeAclIdentities -Acl ([pscustomobject]@{ Access = @($aceAdminFull, $aceUsersDeny) })
Assert-True (@($unsafe).Count -eq 0) 'acl: deny ACEs are not write access -> safe'

# ---- Get-KSInstallFinalExit ----
Assert-True ((Get-KSInstallFinalExit -RebuildExitCode 0) -eq 0) 'install exit: rebuild success -> installer exits 0'
Assert-True ((Get-KSInstallFinalExit -RebuildExitCode 3) -eq 3) 'install exit: rebuild failure code propagates (no silent 0)'
Assert-True ((Get-KSInstallFinalExit -RebuildExitCode 1) -eq 1) 'install exit: rebuild exit 1 propagates'
