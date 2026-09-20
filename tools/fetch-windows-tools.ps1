# Download CURRENT Windows forensic binaries from official internet sources
# into Tools/windows/ (gitignored). Official internet URLs only.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Win = Join-Path $Root "windows"
$Zim = Join-Path $Win "zimmerman"
$Sys = Join-Path $Win "sysinternals"
$Hay = Join-Path $Win "hayabusa"
$Suz = Join-Path $Win "suzaku"
$Ext = Join-Path $Win "extra"
New-Item -ItemType Directory -Force -Path $Zim, $Sys, $Hay, $Suz, $Ext | Out-Null

$script:Versions = @()
$script:Report = @()

function Add-Report($name, $status, $detail) {
    $script:Report += [pscustomobject]@{ Name = $name; Status = $status; Detail = "$detail" }
}

function Get-GitHubRelease($repo) {
    return Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers @{ "User-Agent" = "dfir-nexus-fetch" }
}

function Expand-Any($archive, $dest) {
    # .zip -> Expand-Archive; otherwise 7z (scoop/PATH) or bsdtar (libarchive reads 7z).
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    if ([IO.Path]::GetExtension($archive).ToLower() -eq ".zip") {
        Expand-Archive -Path $archive -DestinationPath $dest -Force -ErrorAction Stop
        return
    }
    $sevenZip = Get-Command 7z -ErrorAction SilentlyContinue
    if ($sevenZip) {
        & $sevenZip.Source x -y "-o$dest" $archive | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "7z extraction failed ($LASTEXITCODE) for $archive" }
        return
    }
    & tar -xf $archive -C $dest
    if ($LASTEXITCODE -ne 0) { throw "tar extraction failed ($LASTEXITCODE) for $archive" }
}

function Get-GitHubAsset($repo, $match) {
    $rel = Get-GitHubRelease $repo
    $asset = $rel.assets | Where-Object { $_.name -match $match } | Select-Object -First 1
    if (-not $asset) {
        $names = ($rel.assets | ForEach-Object { $_.name }) -join ", "
        throw "No GitHub asset matching /$match/ in $repo@$($rel.tag_name). Assets: $names"
    }
    return @{ Asset = $asset; Tag = $rel.tag_name; Published = $rel.published_at }
}

function Expand-To($zip, $dest) {
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Expand-Archive -Path $zip -DestinationPath $dest -Force
}

Write-Host "==> Zimmerman (Get-ZimmermanTools, net9 — latest from ericzimmerman.github.io)"
$gz = Join-Path $env:TEMP "Get-ZimmermanTools.ps1"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1" -OutFile $gz
& powershell -NoProfile -ExecutionPolicy Bypass -File $gz -Dest $Zim
$script:Versions += "zimmerman`tGet-ZimmermanTools.ps1 net9`thttps://ericzimmerman.github.io/"

Write-Host "==> Sysinternals Suite (live zip)"
$sysZip = Join-Path $env:TEMP "SysinternalsSuite.zip"
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile $sysZip
Expand-To $sysZip $Sys
$script:Versions += "sysinternals`tlive-zip`thttps://download.sysinternals.com/files/SysinternalsSuite.zip"

Write-Host "==> Hayabusa (GitHub latest win-x64)"
$ha = Get-GitHubAsset "Yamato-Security/hayabusa" "hayabusa-.*-win-x64\.zip$"
$haZip = Join-Path $env:TEMP $ha.Asset.name
Invoke-WebRequest -Uri $ha.Asset.browser_download_url -OutFile $haZip
Expand-To $haZip $Hay
Get-ChildItem $Hay -Filter "hayabusa*.exe" -Recurse | Select-Object -First 1 | ForEach-Object {
    Copy-Item $_.FullName (Join-Path $Hay "hayabusa.exe") -Force
}
$script:Versions += "hayabusa`t$($ha.Tag)`t$($ha.Asset.browser_download_url)"

Write-Host "==> Suzaku (GitHub latest win-x64)"
$sz = Get-GitHubAsset "Yamato-Security/suzaku" "suzaku-.*-win-x64\.zip$"
$szZip = Join-Path $env:TEMP $sz.Asset.name
Invoke-WebRequest -Uri $sz.Asset.browser_download_url -OutFile $szZip
Expand-To $szZip $Suz
Get-ChildItem $Suz -Filter "suzaku*.exe" -Recurse | Select-Object -First 1 | ForEach-Object {
    Copy-Item $_.FullName (Join-Path $Suz "suzaku.exe") -Force
}
$script:Versions += "suzaku`t$($sz.Tag)`t$($sz.Asset.browser_download_url)"

Write-Host "==> Chainsaw (GitHub latest windows-msvc)"
try {
    $cs = Get-GitHubAsset "WithSecureLabs/chainsaw" "x86_64-pc-windows-msvc\.zip$"
    $csZip = Join-Path $env:TEMP $cs.Asset.name
    Invoke-WebRequest -Uri $cs.Asset.browser_download_url -OutFile $csZip
    Expand-To $csZip $Ext
    $script:Versions += "chainsaw`t$($cs.Tag)`t$($cs.Asset.browser_download_url)"
} catch { Write-Host "    chainsaw skipped: $_" }

Write-Host "==> YARA (GitHub latest win64 if published)"
try {
    $yr = Get-GitHubAsset "VirusTotal/yara" "win64|windows-x64|win-x64"
    $yrZip = Join-Path $env:TEMP $yr.Asset.name
    Invoke-WebRequest -Uri $yr.Asset.browser_download_url -OutFile $yrZip
    Expand-To $yrZip $Ext
    $script:Versions += "yara`t$($yr.Tag)`t$($yr.Asset.browser_download_url)"
} catch { Write-Host "    yara skipped (no win64 asset on latest): $_" }

Write-Host "==> capa (GitHub latest windows)"
try {
    $cp = Get-GitHubAsset "mandiant/capa" "windows\.zip$"
    $cpZip = Join-Path $env:TEMP $cp.Asset.name
    Invoke-WebRequest -Uri $cp.Asset.browser_download_url -OutFile $cpZip
    Expand-To $cpZip $Ext
    $script:Versions += "capa`t$($cp.Tag)`t$($cp.Asset.browser_download_url)"
} catch { Write-Host "    capa skipped: $_" }

Write-Host "==> Thumbcache Viewer CMD (official v1.0.2.1 release zip)"
try {
    $tvZip = Join-Path $env:TEMP "thumbcache_viewer_cmd_64.zip"
    Invoke-WebRequest -Uri "https://github.com/thumbcacheviewer/thumbcacheviewer/releases/download/v1.0.2.1/thumbcache_viewer_cmd_64.zip" -OutFile $tvZip
    $tvDest = Join-Path $Ext "thumbcache_viewer"
    if (Test-Path $tvDest) { Remove-Item $tvDest -Recurse -Force }
    Expand-Any $tvZip $tvDest
    $tvExe = Get-ChildItem $tvDest -Recurse -Filter "thumbcache_viewer_cmd.exe" | Select-Object -First 1
    if (-not $tvExe) { throw "thumbcache_viewer_cmd.exe not found in archive" }
    Add-Report "thumbcache_viewer" "FETCHED" "v1.0.2.1; $($tvExe.FullName)"
    $script:Versions += "thumbcache_viewer`tv1.0.2.1`thttps://github.com/thumbcacheviewer/thumbcacheviewer/releases"
} catch { Add-Report "thumbcache_viewer" "FAILED" "$_" }

Write-Host "==> bmc-tools.py (ANSSI — standalone portable)"
try {
    $bmc = Join-Path $Ext "bmc-tools.py"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ANSSI-FR/bmc-tools/master/bmc-tools.py" -OutFile $bmc
    $script:Versions += "bmc-tools`tmaster`thttps://github.com/ANSSI-FR/bmc-tools"
} catch { Write-Host "    bmc-tools skipped: $_" }

Write-Host "==> BitsParser (FireEye tree + vendored ANSSI bits/construct — not pip'd into Nexus)"
try {
    # Single-file raw download is not enough (imports ese + bits).
    # mandiant/BitsParser 404s; FireEye tree is the current source.
    # bits_parser pins construct==2.8.12 which breaks regipy — vendor into the tree.
    $bpZip = Join-Path $env:TEMP "BitsParser-master.zip"
    Invoke-WebRequest -Uri "https://github.com/fireeye/BitsParser/archive/refs/heads/master.zip" -OutFile $bpZip
    $bpDest = Join-Path $Ext "BitsParser"
    if (Test-Path $bpDest) { Remove-Item $bpDest -Recurse -Force }
    Expand-Archive -Path $bpZip -DestinationPath $env:TEMP -Force
    $unpacked = Join-Path $env:TEMP "BitsParser-master"
    Move-Item $unpacked $bpDest -Force
    $orphan = Join-Path $Ext "BitsParser.py"
    if (Test-Path $orphan) { Remove-Item $orphan -Force }

    $venv = Join-Path $env:TEMP "nexus-bits-venv"
    if (Test-Path $venv) { Remove-Item $venv -Recurse -Force }
    $pyHost = (Get-Command python -ErrorAction SilentlyContinue)
    if (-not $pyHost) { $pyHost = Get-Command python3 -ErrorAction SilentlyContinue }
    if (-not $pyHost) { throw "python required to vendor bits_parser into BitsParser/" }
    & $pyHost.Source -m venv $venv
    & (Join-Path $venv "Scripts\python.exe") -m pip install --quiet bits_parser
    $sp = Join-Path $venv "Lib\site-packages"
    foreach ($pkg in @("bits", "construct")) {
        $src = Join-Path $sp $pkg
        $dst = Join-Path $bpDest $pkg
        if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
        Copy-Item $src $dst -Recurse -Force
    }
    $script:Versions += "bitsparser`tmaster+vendored-bits_parser`thttps://github.com/fireeye/BitsParser"
} catch { Write-Host "    BitsParser skipped: $_" }

Write-Host "==> KStrike.py (BriMor Labs UAL parser)"
try {
    $ks = Join-Path $Ext "KStrike.py"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/brimorlabs/KStrike/master/KStrike.py" -OutFile $ks
    $script:Versions += "kstrike`tmaster`thttps://github.com/brimorlabs/KStrike"
} catch { Write-Host "    KStrike skipped: $_" }

Write-Host "==> LogFileParser (jschicht, GitHub latest release zip)"
try {
    $lf = Get-GitHubAsset "jschicht/LogFileParser" "\.zip$"
    $lfZip = Join-Path $env:TEMP $lf.Asset.name
    Invoke-WebRequest -Uri $lf.Asset.browser_download_url -OutFile $lfZip
    $lfDest = Join-Path $Ext "logfileparser"
    if (Test-Path $lfDest) { Remove-Item $lfDest -Recurse -Force }
    Expand-Any $lfZip $lfDest
    $lfExe = Get-ChildItem $lfDest -Recurse -Filter "LogFileParser64*.exe" | Select-Object -First 1
    if (-not $lfExe) {
        $lfExe = Get-ChildItem $lfDest -Recurse -Filter "LogFileParser*.exe" | Sort-Object Length -Descending | Select-Object -First 1
    }
    if (-not $lfExe) { throw "no LogFileParser exe in release zip" }
    $lfTarget = Join-Path $lfDest "LogFileParser64.exe"
    if ($lfExe.FullName -ne $lfTarget) { Copy-Item $lfExe.FullName $lfTarget -Force }
    Add-Report "logfileparser" "FETCHED" "$($lf.Tag); $($lfExe.Name)"
    $script:Versions += "logfileparser`t$($lf.Tag)`t$($lf.Asset.browser_download_url)"
} catch { Add-Report "logfileparser" "FAILED" "$_" }

Write-Host "==> Zircolite (GitHub latest windows-x64)"
try {
    $zr = Get-GitHubAsset "wagga40/Zircolite" "windows-x64\.zip$"
    $zrZip = Join-Path $env:TEMP $zr.Asset.name
    Invoke-WebRequest -Uri $zr.Asset.browser_download_url -OutFile $zrZip
    $zrDest = Join-Path $Ext "zircolite"
    if (Test-Path $zrDest) { Remove-Item $zrDest -Recurse -Force }
    Expand-Any $zrZip $zrDest
    $zrExe = Get-ChildItem $zrDest -Recurse -Filter "Zircolite.exe" | Select-Object -First 1
    if (-not $zrExe) { throw "no Zircolite.exe in release zip" }
    # Keep the PyInstaller layout intact (Zircolite.exe needs its _internal dir
    # next to it) — do not copy the exe out of its folder.
    Remove-Item (Join-Path $zrDest "zircolite.exe") -Force -ErrorAction SilentlyContinue
    Add-Report "zircolite" "FETCHED" "$($zr.Tag); $($zrExe.FullName)"
    $script:Versions += "zircolite`t$($zr.Tag)`t$($zr.Asset.browser_download_url)"
} catch { Add-Report "zircolite" "FAILED" "$_" }

Write-Host "==> USBDeview x64 (NirSoft official zip)"
try {
    $usbZip = Join-Path $env:TEMP "usbdeview-x64.zip"
    Invoke-WebRequest -Uri "https://www.nirsoft.net/utils/usbdeview-x64.zip" -OutFile $usbZip
    $usbDest = Join-Path $Ext "usbdeview"
    if (Test-Path $usbDest) { Remove-Item $usbDest -Recurse -Force }
    Expand-Any $usbZip $usbDest
    Add-Report "usbdeview" "FETCHED" "nirsoft usbdeview-x64.zip"
    $script:Versions += "usbdeview`tlive`thttps://www.nirsoft.net/utils/usbdeview-x64.zip"
} catch { Add-Report "usbdeview" "FAILED" "$_" }

Write-Host "==> DeepBlueCLI (sans-blue-team archive + run-deepblue.ps1 wrapper)"
try {
    $dbZip = Join-Path $env:TEMP "DeepBlueCLI-master.zip"
    Invoke-WebRequest -Uri "https://github.com/sans-blue-team/DeepBlueCLI/archive/refs/heads/master.zip" -OutFile $dbZip
    $dbDest = Join-Path $Ext "deepbluecli"
    if (Test-Path $dbDest) { Remove-Item $dbDest -Recurse -Force }
    Expand-Any $dbZip $dbDest
    $dbScript = Get-ChildItem $dbDest -Recurse -Filter "DeepBlue.ps1" | Select-Object -First 1
    if (-not $dbScript) { throw "DeepBlue.ps1 not found in archive" }
    $wrapper = @'
param(
    [Parameter(Mandatory=$true)][string]$Evtx,
    [Parameter(Mandatory=$true)][string]$Out
)
$ErrorActionPreference = "Continue"
$script = (Get-ChildItem -Path $PSScriptRoot -Recurse -Filter "DeepBlue.ps1" | Select-Object -First 1).FullName
# DeepBlueCLI reads regexes.txt / safelist.txt relative to the working directory.
Push-Location (Split-Path $script)
try {
    $result = & $script $Evtx 2>&1 | ConvertTo-Json -Depth 6
} finally {
    Pop-Location
}
$result | Out-File -Encoding utf8 $Out
$result
'@
    Set-Content -Path (Join-Path $dbDest "run-deepblue.ps1") -Value $wrapper -Encoding UTF8
    Add-Report "deepbluecli" "FETCHED" "master archive + run-deepblue.ps1 wrapper"
    $script:Versions += "deepbluecli`tmaster`thttps://github.com/sans-blue-team/DeepBlueCLI"
} catch { Add-Report "deepbluecli" "FAILED" "$_" }

Write-Host "==> Hindsight (pip pyhindsight + ccl_chromium_reader from GitHub + launcher)"
try {
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { throw "python not on PATH" }
    & $py.Source -m pip install --upgrade --quiet pyhindsight
    if ($LASTEXITCODE -ne 0) { throw "pip install pyhindsight failed ($LASTEXITCODE)" }
    # ccl_chromium_reader is not on PyPI; upstream pyhindsight imports it without
    # declaring it. Official GitHub repo (its own git dep ccl_simplesnappy pulls in).
    & $py.Source -m pip install --upgrade --quiet "git+https://github.com/cclgroupltd/ccl_chromium_reader.git"
    if ($LASTEXITCODE -ne 0) { throw "pip install ccl_chromium_reader failed ($LASTEXITCODE)" }
    $hsDest = Join-Path $Ext "hindsight"
    if (Test-Path $hsDest) { Remove-Item $hsDest -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $hsDest | Out-Null
    $candidates = @(
        (Join-Path (Split-Path $py.Source) "Scripts\hindsight.py"),
        (Join-Path (Split-Path $py.Source) "hindsight.py")
    )
    if ($env:APPDATA) {
        $candidates += @(Get-ChildItem (Join-Path $env:APPDATA "Python") -Recurse -Filter "hindsight.py" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    }
    $launcher = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if (-not $launcher) { throw "hindsight.py launcher not found (looked next to python and under %APPDATA%\Python)" }
    Copy-Item $launcher (Join-Path $hsDest "Hindsight.py") -Force
    Add-Report "hindsight" "FETCHED" "pip pyhindsight + ccl_chromium_reader; launcher $launcher"
    $script:Versions += "hindsight`tpip-latest`tpypi:pyhindsight + github ccl_chromium_reader"
} catch { Add-Report "hindsight" "FAILED" "$_" }

# NTFSLogTracker: upstream (Google Code ntfs-log-tracker) is dead; only unofficial
# fork mirrors exist. Pruned from the catalog — LogFileParser covers $LogFile and
# MFTECmd covers $J (USN journal).
Add-Report "ntfslogtracker" "REMOVED" "no official upstream; LogFileParser + MFTECmd cover the family"

# KAPE is Kroll-licensed — no public direct URL. Do NOT copy old local installs.
$kapeNote = "KAPE is not fetched (Kroll registration). Download current from https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor and unpack to Tools/windows/kape/"
Write-Host "==> KAPE: $kapeNote"
$script:Versions += "kape`tNOT-FETCHED`thttps://www.kroll.com/ (operator download)"

Write-Host "==> Stage 0 IR collectors (Kansa / UAC / AVML)"
try {
    & (Join-Path $Root "fetch-ir-collect.ps1")
    $script:Versions += "ir-collect`tfetch-ir-collect.ps1`ttools/fetch-ir-collect.ps1"
} catch { Write-Host "    ir-collect skipped: $_" }

Write-Host "==> Python dep for KStrike (pyesedb via libesedb-python)"
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
if ($py) {
    & $py.Source -m pip install --upgrade libesedb-python
    $script:Versions += "pip`tlibesedb-python`tpypi"
} else {
    Write-Host "    python not on PATH — install libesedb-python into the interpreter that runs nexus serve"
}

$verFile = Join-Path $Win "VERSIONS.txt"
@(
    "DFIR-Nexus Tools/windows — fetched $(Get-Date -Format o)"
    "Source: official internet URLs only."
    ""
) + $script:Versions + @("", "fetch report:") + @(
    $script:Report | ForEach-Object { "report`t$($_.Name)`t$($_.Status)`t$($_.Detail)" }
) | Set-Content -Path $verFile -Encoding UTF8
Write-Host "Wrote $verFile"

Write-Host ""
Write-Host "==> fetch report"
foreach ($row in $script:Report) {
    Write-Host ("  [{0}] {1}: {2}" -f $row.Status, $row.Name, $row.Detail)
}
if (($script:Report | Where-Object { $_.Status -eq "FAILED" }).Count -gt 0) {
    Write-Host "WARNING: some acquisitions FAILED — see report above."
}
Write-Host "Done. Binaries under $Win"
Write-Host "Then: nexus doctor   (bmc-tools.py + BitsParser.py must be found)"
