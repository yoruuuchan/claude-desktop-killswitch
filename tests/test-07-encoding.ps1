# Encoding invariants. Pure file reads, no system state touched.
#
# Windows PowerShell5.1 decodes a BOM-less script as the system ANSI code page,
# so a UTF-8 file with Chinese text becomes mojibake and can fail to parse. Every
# execution path here (installer, scheduled task, launcher) goes through
# powershell.exe5.1, so a BOM is required on any script that contains non-ASCII
# bytes. The .vbs launcher is the opposite case: wscript has no encoding
# detection at all, so it must stay pure ASCII.

$utf8Strict = [System.Text.UTF8Encoding]::new($false, $true)
$repoRoot = Split-Path -Parent $PSScriptRoot

$scriptFiles = @()
$scriptFiles += Get-ChildItem -Path (Join-Path $repoRoot 'scripts') -Filter '*.ps1' -File -ErrorAction SilentlyContinue
$scriptFiles += Get-ChildItem -Path $PSScriptRoot -Filter '*.ps1' -File -ErrorAction SilentlyContinue

$noBom = @()
$badUtf8 = @()
$nonAsciiFiles =0

foreach ($f in $scriptFiles) {
	$bytes = [System.IO.File]::ReadAllBytes($f.FullName)
	$hasBom = ($bytes.Length -ge (3)) -and ($bytes[0] -eq (0xEF)) -and ($bytes[1] -eq (0xBB)) -and ($bytes[2] -eq (0xBF))

	$body = @()
	if ($bytes.Length -gt (3)) { $body = $bytes[3..($bytes.Length - (1))] }

	$hasNonAscii = $false
	foreach ($b in $body) {
		if ($b -ge (128)) { $hasNonAscii = $true; break }
	}

	if ($hasNonAscii) {
		$nonAsciiFiles++
		if (-not $hasBom) { $noBom += $f.Name }
	}

	try { [void]$utf8Strict.GetString($body) }
	catch { $badUtf8 += $f.Name }
}

$vbsPath = Join-Path (Join-Path $repoRoot 'scripts') 'run-hidden.vbs'
$vbsNonAscii =0
if (Test-Path $vbsPath) {
	foreach ($b in [System.IO.File]::ReadAllBytes($vbsPath)) {
		if ($b -ge (128)) { $vbsNonAscii++ }
	}
}

Assert-True ($nonAsciiFiles -ge (1)) 'encoding: scan found non-ASCII scripts to check'
Assert-True ($noBom.Count -eq (0)) ("encoding: every non-ASCII .ps1 is saved with a UTF-8 BOM" +
	$(if ($noBom.Count -ge (1)) { ' [missing: ' + ($noBom -join ', ') + ']' } else { '' }))
Assert-True ($badUtf8.Count -eq (0)) ("encoding: every .ps1 decodes as strict UTF-8" +
	$(if ($badUtf8.Count -ge (1)) { ' [' + ($badUtf8 -join ', ') + ']' } else { '' }))
Assert-True ($vbsNonAscii -eq (0)) 'encoding: run-hidden.vbs stays pure ASCII'
