#!/usr/bin/env pwsh
<#
.SYNOPSIS
    One-command DFIR-Nexus install for Windows (PowerShell 7+).

.DESCRIPTION
    Verifies Python 3.12+, creates a venv at .venv\, runs pip install -e .[all],
    prompts for examiner identity and approval password, then runs `nexus init`.

.PARAMETER NoVenv
    Install into the active interpreter without creating a venv.

.PARAMETER SkipInit
    Stop after the install (useful for CI).

.PARAMETER SkipPassword
    Skip the password setup prompt. Run `nexus config --setup-password` later.

.EXAMPLE
    .\setup-windows.ps1

.EXAMPLE
    .\setup-windows.ps1 -SkipPassword -SkipInit
#>

param(
    [switch]$NoVenv,
    [switch]$SkipInit,
    [switch]$SkipPassword
)

$ErrorActionPreference = "Stop"

$RepoRoot = $PSScriptRoot
Push-Location $RepoRoot

try {
    Write-Host "==> DFIR-Nexus setup (Windows)"
    Write-Host "    Repo: $RepoRoot"

    # 1. Python version
    $pythonCmd = $null
    foreach ($candidate in @("python3.12", "python3.13", "python3.14", "python3", "python")) {
        if (Get-Command $candidate -ErrorAction SilentlyContinue) {
            $pythonCmd = $candidate
            break
        }
    }

    if (-not $pythonCmd) {
        Write-Host "ERROR: no python on PATH." -ForegroundColor Red
        Write-Host "  Install Python 3.12+ from https://www.python.org/downloads/ and check 'Add to PATH'."
        exit 1
    }

    $pyVer = & $pythonCmd -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'
    $pyOk = & $pythonCmd -c 'import sys; print(1 if sys.version_info >= (3,12) else 0)'
    if ($pyOk -ne "1") {
        Write-Host "ERROR: Python $pyVer detected via $pythonCmd; DFIR-Nexus needs >= 3.12." -ForegroundColor Red
        exit 1
    }
    Write-Host "    Python $pyVer OK ($pythonCmd)"

    # 2. Venv
    if (-not $NoVenv) {
        if (Test-Path .venv) {
            Write-Host "    venv already exists at .venv\ (reusing)"
        } else {
            Write-Host "==> Creating venv at .venv\"
            & $pythonCmd -m venv .venv
        }
        & ".venv\Scripts\Activate.ps1"
    }

    # 3. Install
    Write-Host "==> pip install -e .[all]"
    python -m pip install --upgrade pip
    python -m pip install -e ".[all]"

    # 4. Examiner + password
    if (-not $SkipPassword) {
        if (-not $env:NEXUS_EXAMINER) {
            $defaultUser = $env:USERNAME
            $examiner = Read-Host "    Examiner name (Enter to use OS username '$defaultUser')"
            if ($examiner) {
                nexus config --examiner "$examiner"
            }
        }
        Write-Host ""
        Write-Host "==> Set the approval password now (required for nexus approve)."
        Write-Host "    You can skip with Ctrl-C and run 'nexus config --setup-password' later."
        try { nexus config --setup-password } catch { Write-Host "    Skipped." }
    }

    # 5. nexus init
    if (-not $SkipInit) {
        Write-Host ""
        nexus init
    }

    Write-Host ""
    Write-Host "==> Done. Start the server with:"
    Write-Host "      nexus serve                       # stdio mode (zero config)"
    Write-Host "      nexus serve --http --port 4508    # HTTP mode + Examiner Portal"
} finally {
    Pop-Location
}
