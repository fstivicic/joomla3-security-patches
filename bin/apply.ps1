<#
.SYNOPSIS
    Apply the J3-SEC patch set to a Joomla 3.10.12 installation.

.DESCRIPTION
    Checks every patch applies before applying any of them, then verifies each
    one actually landed. A failure leaves the target untouched rather than
    half-patched.

    Uses GNU patch if it is on PATH, otherwise git. Note that `git apply`
    resolves paths relative to the enclosing REPOSITORY ROOT, not the working
    directory, and silently ignores paths outside it -- so a Joomla install
    inside a git work tree would appear to patch and not be patched at all.
    This script forces GIT_DIR to a throwaway and GIT_WORK_TREE to the target,
    which makes the target the work tree root and restores correct behaviour.

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

if (-not (Test-Path -PathType Container $Target)) {
    Write-Error "$Target is not a directory"
    exit 2
}

$Target = (Resolve-Path $Target).Path

if (-not (Test-Path (Join-Path $Target 'libraries\src\Filter\InputFilter.php'))) {
    Write-Error "$Target does not look like a Joomla 3 root (expected libraries\src\Filter\InputFilter.php)"
    exit 2
}

if (-not (Test-Path $patchDir)) {
    Write-Error "No patches directory at $patchDir"
    exit 2
}

$patches = Get-ChildItem -Path $patchDir -Filter '*.patch' | Sort-Object Name

if ($patches.Count -eq 0) {
    Write-Error "No .patch files found in $patchDir"
    exit 2
}

# --- tool selection --------------------------------------------------------
$patchExe = Get-Command patch -ErrorAction SilentlyContinue
$gitExe   = Get-Command git -ErrorAction SilentlyContinue
$scratch  = $null

if ($null -ne $patchExe) {
    $tool = 'patch'
} elseif ($null -ne $gitExe) {
    $tool = 'git'
    $scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("j3sec-" + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $scratch | Out-Null
} else {
    Write-Error "Neither patch nor git was found on PATH. Install Git for Windows, or use bin/apply.sh under Git Bash or WSL."
    exit 2
}

# Zero fuzz (-F0) is deliberate: with GNU patch's default fuzz of 2, an
# already-applied patch can match again at a shifted offset and be applied a
# second time, duplicating the inserted code. -N turns an already-applied patch
# into a clean skip instead of an interactive prompt.
# Both helpers set $ErrorActionPreference locally to 'Continue'. In Windows
# PowerShell 5.1, redirecting a native executable's stderr wraps each line in a
# NativeCommandError ErrorRecord, which under 'Stop' throws even when the exe
# exited 0. Capturing the merged streams into $null suppresses the output
# without turning an expected non-zero exit into a terminating error.
function Test-PatchApplies {
    param([string] $PatchFile)

    $ErrorActionPreference = 'Continue'

    if ($tool -eq 'patch') {
        $null = & $patchExe.Source -p1 -F0 -N --dry-run -s -i $PatchFile 2>&1
    } else {
        $env:GIT_DIR       = $scratch
        $env:GIT_WORK_TREE = $Target
        try {
            $null = & $gitExe.Source apply --check -p1 $PatchFile 2>&1
        } finally {
            Remove-Item Env:\GIT_DIR, Env:\GIT_WORK_TREE -ErrorAction SilentlyContinue
        }
    }

    return ($LASTEXITCODE -eq 0)
}

function Invoke-Patch {
    param([string] $PatchFile)

    $ErrorActionPreference = 'Continue'

    if ($tool -eq 'patch') {
        $null = & $patchExe.Source -p1 -F0 -N -s -i $PatchFile 2>&1
    } else {
        $env:GIT_DIR       = $scratch
        $env:GIT_WORK_TREE = $Target
        try {
            $null = & $gitExe.Source apply -p1 $PatchFile 2>&1
        } finally {
            Remove-Item Env:\GIT_DIR, Env:\GIT_WORK_TREE -ErrorAction SilentlyContinue
        }
    }

    return ($LASTEXITCODE -eq 0)
}

Write-Host "target: $Target"
Write-Host "tool:   $tool"
Write-Host ""

Push-Location $Target

try {
    # --- version warning ---------------------------------------------------
    $verFile = Join-Path $Target 'libraries\src\Version.php'

    if (Test-Path $verFile) {
        $verText  = Get-Content $verFile -Raw
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

    # --- dry run -----------------------------------------------------------
    Write-Host "checking all patches apply..."
    $failed = @()

    foreach ($p in $patches) {
        Write-Host ("  {0,-64} " -f $p.Name) -NoNewline

        if (Test-PatchApplies $p.FullName) {
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

        if (-not (Invoke-Patch $p.FullName)) {
            Write-Host "FAILED"
            Write-Error "$($p.Name) failed to apply after the dry run passed. The tree may be partially patched; restore your backup."
            exit 1
        }

        # Verify it landed. An already-applied patch must no longer apply
        # cleanly; if it still does, the tool changed nothing and claimed success.
        if (Test-PatchApplies $p.FullName) {
            Write-Host "NO-OP"
            Write-Error "$($p.Name) reported success but changed nothing. The tree may be partially patched. Restore your backup and report this with your tool versions."
            exit 1
        }

        Write-Host "applied"
    }

    Write-Host ""
    Write-Host "done. Verify with:"
    Write-Host "  php `"$here\tests\probe.php`" `"$Target`""

    # Explicit, so callers do not read a lingering $LASTEXITCODE from the last
    # native patch-tool invocation (which is expected to be non-zero here).
    exit 0
}
finally {
    Pop-Location

    if ($null -ne $scratch -and (Test-Path $scratch)) {
        Remove-Item -Recurse -Force $scratch -ErrorAction SilentlyContinue
    }
}
