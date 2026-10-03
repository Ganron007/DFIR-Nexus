<#
.SYNOPSIS
  Fetch the K1 sample datasets into Evidence-files\_k1-datasets.

.DESCRIPTION
  Downloads with resume, verifies the size, extracts, and writes the hash table
  in README.md. Repeatable: an already-complete file is skipped.

  Roles are fixed by §3Y (see README.md): dev / heldout / benign. Keep dev and
  heldout on DIFFERENT AIT testbeds, and never change a file's role - K2-K7 are
  re-measured on dev, and GATE-H scores against heldout.

.EXAMPLE
  pwsh -File scripts\fetch-k1-datasets.ps1            # all roles
  pwsh -File scripts\fetch-k1-datasets.ps1 -Role dev  # one role
  pwsh -File scripts\fetch-k1-datasets.ps1 -WhatIf
#>
[CmdletBinding()]
param(
    [ValidateSet('all', 'dev', 'heldout', 'benign')][string] $Role = 'all',
    [switch] $WhatIf,
    [switch] $KeepArchives
)

$ErrorActionPreference = 'Stop'
# scripts/ is directly under the repo root.
$Repo = Split-Path $PSScriptRoot -Parent
$Root = Join-Path $Repo 'Evidence-files\_k1-datasets'
if (-not (Test-Path -LiteralPath $Root)) {
    throw "dataset folder missing: $Root (create it first, or run from the repo)"
}
$Archives = Join-Path $Root '_archives'
New-Item -ItemType Directory -Force -Path $Archives | Out-Null

$ZEN = 'https://zenodo.org/api/records/19483937/files'
$NR = 'https://github.com/NextronSystems/evtx-baseline/releases/download/v0.8.3'

# name, role, url, expected bytes, extract-into
$Manifest = @(
    @{ Name = 'russellmitchell_no-pcaps.zip'; Role = 'dev';
       Url = "$ZEN/russellmitchell_no-pcaps.zip/content"; Bytes = 522084364
       Into = 'dev'; Format = 'zip' }
    @{ Name = 'santos_no-pcaps.zip'; Role = 'heldout';
       Url = "$ZEN/santos_no-pcaps.zip/content"; Bytes = 576734274
       Into = 'heldout'; Format = 'zip' }
    @{ Name = 'win2022-ad.tgz'; Role = 'benign';
       Url = "$NR/win2022-ad.tgz"; Bytes = 65991035
       Into = 'benign/win2022-ad'; Format = 'tgz' }
    @{ Name = 'win10-client.tgz'; Role = 'benign';
       Url = "$NR/win10-client.tgz"; Bytes = 70844052
       Into = 'benign/win10-client'; Format = 'tgz' }
)

$wanted = $Manifest | Where-Object { $Role -eq 'all' -or $_.Role -eq $Role }
Write-Host "K1 datasets -> $Root"
Write-Host ("Roles: {0}" -f (($wanted | Select-Object -ExpandProperty Role -Unique) -join ', '))
$totalGB = ($wanted | Measure-Object -Property Bytes -Sum).Sum / 1GB
Write-Host ("Total: {0:N2} GB across {1} file(s)`n" -f $totalGB, $wanted.Count)

function Format-Size([int64] $b) { "{0:N1} MB" -f ($b / 1MB) }

foreach ($item in $wanted) {
    $dest = Join-Path $Archives $item.Name
    $into = Join-Path $Root $item.Into
    Write-Host ("=== {0}  [{1}]  {2}" -f $item.Name, $item.Role, (Format-Size $item.Bytes))

    $need = -not (Test-Path -LiteralPath $dest) -or ((Get-Item -LiteralPath $dest).Length -ne $item.Bytes)
    if ($need) {
        if ($WhatIf) { Write-Host "    would download -> $dest"; continue }
        Write-Host "    downloading (resumable)..."
        # --retry/--continue-at: a 500 MB+ pull over a lab link should survive a blip.
        & curl.exe -L --fail --retry 5 --retry-delay 3 -C - -o $dest $item.Url
        if ($LASTEXITCODE -ne 0) { throw "curl failed for $($item.Name) (exit $LASTEXITCODE)" }
    } else {
        Write-Host "    archive already complete, skipping download"
    }

    $size = (Get-Item -LiteralPath $dest).Length
    if ($size -ne $item.Bytes) {
        throw "$($item.Name): size $size != expected $($item.Bytes) - not extracting"
    }

    # "Already extracted" must mean content is there. A pre-created empty
    # directory would otherwise be read as done - a silent skip that reports
    # success while leaving the dataset empty.
    $hasContent = (Test-Path -LiteralPath $into) -and
        [bool](Get-ChildItem -LiteralPath $into -Force -ErrorAction SilentlyContinue |
               Select-Object -First 1)

    if ($hasContent) {
        Write-Host "    already extracted -> $into"
    } elseif ($WhatIf) {
        Write-Host "    would extract -> $into"
    } else {
        New-Item -ItemType Directory -Force -Path $into | Out-Null
        Write-Host "    extracting -> $into"
        if ($item.Format -eq 'zip') {
            Expand-Archive -LiteralPath $dest -DestinationPath $into -Force
        } else {
            & tar.exe -xzf $dest -C $into
            if ($LASTEXITCODE -ne 0) { throw "tar failed for $($item.Name)" }
        }
        if (-not (Get-ChildItem -LiteralPath $into -Force -ErrorAction SilentlyContinue |
                  Select-Object -First 1)) {
            throw "$($item.Name): extraction produced nothing in $into"
        }
    }

    $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $dest).Hash.ToLower()
    $item.Sha256 = $sha
    Write-Host ("    sha256 {0}" -f $sha)
    Write-Host ""
}

if (-not $KeepArchives -and -not $WhatIf) {
    Write-Host "Archives kept in $Archives (use -KeepArchives to silence this note);"
    Write-Host "they are the re-extract source and are gitignored like the rest."
}

Write-Host "`nHashes for README.md:"
foreach ($item in $wanted) {
    $line = "| ``_archives/{0}`` | {1} | {2} | ``{3}`` |" -f $item.Name, $item.Role, $item.Bytes, $item.Sha256
    Write-Host $line
}
