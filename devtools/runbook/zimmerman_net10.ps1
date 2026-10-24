# The official Zimmerman .NET 10 command-line tools, from the pins in zimmerman-net10.json (TIER1-WORK-ORDERS 11.12, TA-Z).
#
#   pwsh -NoProfile -File devtools/runbook/zimmerman_net10.ps1 -Verify            # every pinned tool: present, version, SHA-256
#   pwsh -NoProfile -File devtools/runbook/zimmerman_net10.ps1 -Install           # download, check the zip hash, extract, verify
#   pwsh -NoProfile -File devtools/runbook/zimmerman_net10.ps1 -Verify -LaneOnly  # what run_lane.ps1 checks before a lane
#
# A zip whose SHA-256 differs from its pin is refused: a new vendor release is a new pin, made on purpose.
# A zip with one top-level folder (EvtxECmd, RECmd, SQLECmd) is installed without that folder, so every tool is
# <install_root>/<Tool>/<Tool>.exe with its Maps or BatchExamples next to it.
[CmdletBinding()]
param(
    [switch] $Install,
    [switch] $Verify,
    [switch] $LaneOnly
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$pins = Get-Content -Raw (Join-Path $PSScriptRoot 'zimmerman-net10.json') | ConvertFrom-Json
$root = Join-Path $repo $pins.install_root

function Test-Pin([string] $name, $pin) {
    $exe = Join-Path $root $pin.exe
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { return "missing $exe" }
    $version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe).FileVersion
    $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash.ToUpperInvariant()
    if ($version -ne $pin.version) { return "version $version, pinned $($pin.version)" }
    if ($sha -ne $pin.exe_sha256.ToUpperInvariant()) { return "SHA-256 $sha, pinned $($pin.exe_sha256)" }
    $rc = Join-Path (Split-Path $exe) "$name.runtimeconfig.json"
    if ((Test-Path -LiteralPath $rc) -and ((Get-Content -Raw -LiteralPath $rc) -notmatch '"tfm":\s*"net10\.0"')) {
        return "$rc does not name net10.0"
    }
    return ''
}

if ($Install) {
    $dl = Join-Path ([IO.Path]::GetTempPath()) "zimmerman-net10-$PID"
    New-Item -ItemType Directory -Force $dl | Out-Null
    try {
        foreach ($p in $pins.tools.PSObject.Properties) {
            $name = $p.Name; $pin = $p.Value
            $zip = Join-Path $dl "$name.zip"
            Invoke-WebRequest -Uri $pin.url -OutFile $zip -TimeoutSec 300
            $zsha = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToUpperInvariant()
            if ($zsha -ne $pin.zip_sha256.ToUpperInvariant()) {
                throw "$name.zip SHA-256 $zsha does not match its pin $($pin.zip_sha256); refusing to install"
            }
            $x = Join-Path $dl $name
            Expand-Archive -LiteralPath $zip -DestinationPath $x -Force
            $top = @(Get-ChildItem -LiteralPath $x -Force)
            $src = if ($top.Count -eq 1 -and $top[0].PSIsContainer) { $top[0].FullName } else { $x }
            $dest = Join-Path $root $name
            if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
            New-Item -ItemType Directory -Force $dest | Out-Null
            Copy-Item -Path (Join-Path $src '*') -Destination $dest -Recurse -Force
            Write-Output "installed $name $($pin.version) -> $dest"
        }
    } finally {
        Remove-Item -LiteralPath $dl -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$bad = 0
foreach ($p in $pins.tools.PSObject.Properties) {
    if ($LaneOnly -and -not $p.Value.lane) { continue }
    $why = Test-Pin $p.Name $p.Value
    if ($why) { $bad++; Write-Output "FAIL $($p.Name): $why" }
    elseif ($Verify -or $Install) { Write-Output "OK   $($p.Name) $($p.Value.version)" }
}
if ($bad) { exit 1 }
exit 0
