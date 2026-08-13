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

function Get-GitHubRelease($repo) {
    return Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers @{ "User-Agent" = "dfir-nexus-fetch" }
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

Write-Host "==> Thumbcache Viewer CMD (GitHub latest)"
try {
    $tv = Get-GitHubAsset "thumbcacheviewer/thumbcacheviewer" "ThumbcacheViewer|\.zip$"
    $tvZip = Join-Path $env:TEMP $tv.Asset.name
    Invoke-WebRequest -Uri $tv.Asset.browser_download_url -OutFile $tvZip
    Expand-To $tvZip (Join-Path $Ext "thumbcache")
    $script:Versions += "thumbcache_viewer`t$($tv.Tag)`t$($tv.Asset.browser_download_url)"
} catch { Write-Host "    thumbcache_viewer skipped: $_" }

Write-Host "==> bmc-tools.py (ANSSI)"
try {
    $bmc = Join-Path $Ext "bmc-tools.py"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ANSSI-FR/bmc-tools/master/bmc-tools.py" -OutFile $bmc
    $script:Versions += "bmc-tools`tmaster`thttps://github.com/ANSSI-FR/bmc-tools"
} catch { Write-Host "    bmc-tools skipped: $_" }

Write-Host "==> BitsParser.py (Mandiant)"
try {
    $bp = Join-Path $Ext "BitsParser.py"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/mandiant/BitsParser/master/BitsParser.py" -OutFile $bp
    $script:Versions += "bitsparser`tmaster`thttps://github.com/mandiant/BitsParser"
} catch { Write-Host "    BitsParser skipped: $_" }

Write-Host "==> KStrike.py"
try {
    $ks = Join-Path $Ext "KStrike.py"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/BrandonLeBlanc/KStrike/master/KStrike.py" -OutFile $ks
    $script:Versions += "kstrike`tmaster`thttps://github.com/BrandonLeBlanc/KStrike"
} catch { Write-Host "    KStrike skipped: $_" }

Write-Host "==> LogFileParser (jschicht, if a Windows zip is published)"
try {
    $lf = Get-GitHubAsset "jschicht/LogFileParser" "\.zip$|\.7z$|LogFileParser"
    $lfZip = Join-Path $env:TEMP $lf.Asset.name
    Invoke-WebRequest -Uri $lf.Asset.browser_download_url -OutFile $lfZip
    Expand-To $lfZip (Join-Path $Ext "logfileparser")
    $script:Versions += "logfileparser`t$($lf.Tag)`t$($lf.Asset.browser_download_url)"
} catch { Write-Host "    LogFileParser skipped: $_" }

# KAPE is Kroll-licensed — no public direct URL. Do NOT copy old local installs.
$kapeNote = "KAPE is not fetched (Kroll registration). Download current from https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor and unpack to Tools/windows/kape/"
Write-Host "==> KAPE: $kapeNote"
$script:Versions += "kape`tNOT-FETCHED`thttps://www.kroll.com/ (operator download)"

$verFile = Join-Path $Win "VERSIONS.txt"
@(
    "DFIR-Nexus Tools/windows — fetched $(Get-Date -Format o)"
    "Source: official internet URLs only."
    ""
) + $script:Versions | Set-Content -Path $verFile -Encoding UTF8
Write-Host "Wrote $verFile"
Write-Host "Done. Binaries under $Win"
