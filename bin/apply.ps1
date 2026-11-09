<#
.SYNOPSIS
    Apply the J3-SEC patch set to a Joomla 3.10.12 installation.

.DESCRIPTION
    Checks every patch applies before applying any of them, so a failure leaves
    the target untouched rather than half-patched. Requires git on PATH.

.PARAMETER Target
    Path to the Joomla root directory.

.PARAMETER Check
    Only verify the patches apply; do not change anything.

.EXAMPLE
    .\bin\apply.ps1 C:\inetpub\mysite
    .\bin\apply.ps1 C:\inetpub\mysite -Check
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $Target,

    [switch] $Check
)

$ErrorActionPreference = 'Stop'

$here     = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$patchDir = Join-Path $here 'patches'

if (-not (Test-Path (Join-Path $Target 'libraries\src\Filter\InputFilter.php'))) {
    Write-Error "$Target does not look like a Joomla 3 root (expected libraries\src\Filter\InputFilter.php)"
    exit 2
}

if (-not (Test-Path $patchDir)) {
    Write-Error "No patches directory at $patchDir"
    exit 2
}

$git = Get-Command git -ErrorAction SilentlyContinue

if ($null -eq $git) {
    Write-Error "git was not found on PATH. Install Git for Windows, or use bin/apply.sh under Git Bash / WSL."
    exit 2
}

$patches = Get-ChildItem -Path $patchDir -Filter '*.patch' | Sort-Object Name

if ($patches.Count -eq 0) {
    Write-Error "No .patch files found in $patchDir"
    exit 2
}

Write-Host "target: $Target"
Write-Host "tool:   git"
Write-Host ""

# --- version warning -------------------------------------------------------
$verFile = Join-Path $Target 'libraries\src\Version.php'

if (Test-Path $verFile) {
    $verText = Get-Content $verFile -Raw
    $relMatch = [regex]::Match($verText, "RELEASE\s*=\s*'([0-9.]+)'")
    $devMatch = [regex]::Match($verText, "DEV_LEVEL\s*=\s*'([0-9]+)'")

    if ($relMatch.Success) {
        $detected = $relMatch.Groups[1].Value
        if ($devMatch.Success) { $detected = "$detected.$($devMatch.Groups[1].Value)" }

        Write-Host "detected Joomla $detected"

        if ($detected -ne '3.10.12') {
            Write-Warning "Patches were built against 3.10.12. Hunks may not apply."
        }

        Write-Host ""
    }
}

Push-Location $Target

try {
    # --- dry run -----------------------------------------------------------
    Write-Host "checking all patches apply..."
    $failed = @()

    foreach ($p in $patches) {
        Write-Host ("  {0,-64} " -f $p.Name) -NoNewline
        & git apply --check -p1 $p.FullName 2>$null

        if ($LASTEXITCODE -eq 0) {
            Write-Host "ok"
        } else {
            Write-Host "FAIL"
            $failed += $p.Name
        }
    }

    if ($failed.Count -gt 0) {
        Write-Host ""
        Write-Host "One or more patches do not apply. Nothing has been changed." -ForegroundColor Red
        Write-Host "Either core files are modified, or a patch is already applied." -ForegroundColor Red
        Write-Host "Run: php `"$here\tests\probe.php`" `"$Target`"   to see what is already fixed."
        exit 1
    }

    Write-Host ""
    Write-Host "all patches apply cleanly"

    if ($Check) {
        Write-Host "(-Check given: stopping without applying)"
        exit 0
    }

    # --- apply -------------------------------------------------------------
    Write-Host ""
    Write-Host "applying..."

    foreach ($p in $patches) {
        Write-Host ("  {0,-64} " -f $p.Name) -NoNewline
        & git apply -p1 $p.FullName

        if ($LASTEXITCODE -ne 0) {
            Write-Host "FAILED"
            Write-Error "git apply failed on $($p.Name) after the dry run passed. The tree may be partially patched; restore your backup."
            exit 1
        }

        Write-Host "applied"
    }

    Write-Host ""
    Write-Host "done. Verify with:"
    Write-Host "  php `"$here\tests\probe.php`" `"$Target`""
}
finally {
    Pop-Location
}
