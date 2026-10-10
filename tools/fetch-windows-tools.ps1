# Download CURRENT Windows forensic binaries from official internet sources
# into Tools/windows/ (gitignored). Official internet URLs only.
param(
    # Install only the WO-TA pinned tools (hash-checked). Skips the long fetches.
    [switch]$PinsOnly
)
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

function Save-PinnedFile($name, $url, $sha256, $destFile) {
    $expect = $sha256.ToUpperInvariant()
    Invoke-WebRequest -Uri $url -OutFile $destFile -UseBasicParsing
    $got = (Get-FileHash -Path $destFile -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($got -ne $expect) {
        Remove-Item $destFile -Force -ErrorAction SilentlyContinue
        throw "$name SHA-256 mismatch: expected $expect got $got"
    }
    return $destFile
}

function Install-PinnedWheel($name, $version, $url, $sha256, $licence) {
    # Keep the upstream wheel name. A prefix adds a hyphen and pip rejects it.
    $wheel = Join-Path $env:TEMP ([IO.Path]::GetFileName($url))
    Save-PinnedFile $name $url $sha256 $wheel | Out-Null
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { throw "python not on PATH; cannot install $name" }
    & $py.Source -m pip install --upgrade --no-deps --disable-pip-version-check $wheel
    if ($LASTEXITCODE -ne 0) { throw "pip install $name failed ($LASTEXITCODE)" }
    Add-Report $name "FETCHED" "$version $licence"
    $script:Versions += "$name`t$version`t$url`t$sha256`t$licence"
}

# WO-TA item 0. Every URL, version and SHA-256 below was checked against the
# upstream release or the PyPI digest for that exact file.
function Install-WoTaPins {
    $pin = Join-Path $env:TEMP "nexus-pin"
    New-Item -ItemType Directory -Force -Path $pin | Out-Null

    Write-Host "==> MemProcFS 5.19 Windows zip (AGPL-3.0; no Dokany mount)"
    $mpZip = Join-Path $pin "MemProcFS_files_and_binaries_v5.19.0-win_x64-20261005.zip"
    Save-PinnedFile "memprocfs-win" `
        "https://github.com/ufrisk/MemProcFS/releases/download/v5.19/MemProcFS_files_and_binaries_v5.19.0-win_x64-20261005.zip" `
        "718389C254A66587A0555F3758B37709BB2916BD0B7D1C99D162DF25796F063E" $mpZip | Out-Null
    $mpDest = Join-Path $Ext "memprocfs"
    if (Test-Path $mpDest) { Remove-Item $mpDest -Recurse -Force }
    Expand-To $mpZip $mpDest
    Add-Report "memprocfs-win" "FETCHED" "5.19 AGPL-3.0; Python API is the lane path, not a drive mount"
    $script:Versions += "memprocfs-win`t5.19`thttps://github.com/ufrisk/MemProcFS/releases/download/v5.19/MemProcFS_files_and_binaries_v5.19.0-win_x64-20261005.zip`t718389C254A66587A0555F3758B37709BB2916BD0B7D1C99D162DF25796F063E`tAGPL-3.0"

    Install-PinnedWheel "memprocfs" "5.19.0" `
        "https://files.pythonhosted.org/packages/8b/20/a5c046f6ac1d6b04a682ff56b6e703dadb67de424a03e88bf9cf2b48df3a/memprocfs-5.19.0-cp36-abi3-win_amd64.whl" `
        "97d59cfd101751522bca3147a40c47e612a279b1692de116a361c78d34e6cd70" "AGPL-3.0"
    # The PyPI wheel ships vmmpyc.pyd and vmm.dll but not leechcore.dll.
    # vmmpyc fails to load until leechcore.dll from the pinned Windows zip
    # sits beside the pyd. This is not a mount and does not use Dokany.
    $py = Get-Command python -ErrorAction SilentlyContinue
    $pkg = & $py.Source -c "import importlib.metadata as m; print(m.distribution('memprocfs').locate_file('memprocfs'))"
    foreach ($dll in @("leechcore.dll", "leechcore_device_hvsavedstate.dll", "leechcore_device_rawtcp.dll", "leechcore_driver.dll", "tinylz4.dll")) {
        Copy-Item (Join-Path $mpDest $dll) -Destination $pkg -Force
    }

    Install-PinnedWheel "maldump" "0.5.0" `
        "https://files.pythonhosted.org/packages/27/22/2d94b48d2ed4948f3324232b5a60dca3fdefaf91dd049e4de82b0e75e8f5/maldump-0.5.0-py3-none-any.whl" `
        "5c7ed44d408fe6a454dbca3bc47795d09cdf0601035fd8fa0dc6004e730c5d6e" "GPL-3.0"
    # Declared runtime deps of maldump 0.5.0. arc4==0.4.0 has no Python 3.14 wheel.
    Install-PinnedWheel "colorama" "0.4.6" `
        "https://files.pythonhosted.org/packages/d1/d6/3965ed04c63042e047cb6a3e6ed1a63a35087b6a609aa3a15ed8ac56c221/colorama-0.4.6-py2.py3-none-any.whl" `
        "4f1d9991f5acc0ca119f9d443620b77f9d6b33703e51011c16baf57afb285fc6" "BSD-3-Clause"
    Install-PinnedWheel "defusedxml" "0.7.1" `
        "https://files.pythonhosted.org/packages/07/6c/aa3f2f849e01cb6a001cd8554a88d4c77c5c1a31c95bdf1cf9301e6d9ef4/defusedxml-0.7.1-py2.py3-none-any.whl" `
        "a352e7e428770286cc899e2542b6cdaedb2b4953ff269a210103ec58f6198a61" "PSF-2.0"
    Install-PinnedWheel "kaitaistruct" "0.10" `
        "https://files.pythonhosted.org/packages/4e/bf/88ad23efc08708bda9a2647169828e3553bb2093a473801db61f75356395/kaitaistruct-0.10-py2.py3-none-any.whl" `
        "a97350919adbf37fda881f75e9365e2fb88d04832b7a4e57106ec70119efb235" "MIT"
    # maldump 0.5.0 declares these. arc4 0.4.0 publishes no cp314 wheel, so the
    # pinned sdist is built for this interpreter. types-colorama is a stub only.
    Install-PinnedWheel "colorama" "0.4.6" `
        "https://files.pythonhosted.org/packages/d1/d6/3965ed04c63042e047cb6a3e6ed1a63a35087b6a609aa3a15ed8ac56c221/colorama-0.4.6-py2.py3-none-any.whl" `
        "4f1d9991f5acc0ca119f9d443620b77f9d6b33703e51011c16baf57afb285fc6" "BSD-3-Clause"
    Install-PinnedWheel "defusedxml" "0.7.1" `
        "https://files.pythonhosted.org/packages/07/6c/aa3f2f849e01cb6a001cd8554a88d4c77c5c1a31c95bdf1cf9301e6d9ef4/defusedxml-0.7.1-py2.py3-none-any.whl" `
        "a352e7e428770286cc899e2542b6cdaedb2b4953ff269a210103ec58f6198a61" "PSF-2.0"
    Install-PinnedWheel "kaitaistruct" "0.10" `
        "https://files.pythonhosted.org/packages/4e/bf/88ad23efc08708bda9a2647169828e3553bb2093a473801db61f75356395/kaitaistruct-0.10-py2.py3-none-any.whl" `
        "a97350919adbf37fda881f75e9365e2fb88d04832b7a4e57106ec70119efb235" "MIT"
    Install-PinnedWheel "arc4" "0.4.0" `
        "https://files.pythonhosted.org/packages/63/2d/abd2c4d7ac0b515c63787a32e7ccb47c6a66fb4cd33ac5ad159fb2bf64b2/arc4-0.4.0.tar.gz" `
        "d431b53d11b24d62521dbbd06d755bf9d6d11a03cc7bbbdf37a13a12ee0747b6" "MIT"

    Write-Host "==> mplog_parser v1.0 (MIT)"
    $mplog = Join-Path $Ext "mplog_parser.exe"
    Save-PinnedFile "mplog_parser" `
        "https://github.com/Qazeer/mplog_parser-compiled/releases/download/v1.0/mplog_parser.exe" `
        "695555A3F493EDDEB02976D66A37DE932C04150AD3ABB561E1B9480C188CFCB3" $mplog | Out-Null
    Add-Report "mplog_parser" "FETCHED" "v1.0 MIT"
    $script:Versions += "mplog_parser`tv1.0`thttps://github.com/Qazeer/mplog_parser-compiled/releases/download/v1.0/mplog_parser.exe`t695555A3F493EDDEB02976D66A37DE932C04150AD3ABB561E1B9480C188CFCB3`tMIT"

    Write-Host "==> defender-detectionhistory-parser v1.0.1 (GPL-3.0, pinned commit)"
    $dh = Join-Path $Ext "dhparser.exe"
    Save-PinnedFile "dhparser" `
        "https://raw.githubusercontent.com/jklepsercyber/defender-detectionhistory-parser/c5543f2d4807ac75f830c54c3f4f1361e84c5302/dhparser.exe" `
        "989038DA175C80BEE12B59427BC01C57347CFE168FE911E2B9669EF291DFAFE6" $dh | Out-Null
    Add-Report "dhparser" "FETCHED" "v1.0.1 GPL-3.0 commit c5543f2"
    $script:Versions += "dhparser`tv1.0.1`thttps://github.com/jklepsercyber/defender-detectionhistory-parser/blob/c5543f2d4807ac75f830c54c3f4f1361e84c5302/dhparser.exe`t989038DA175C80BEE12B59427BC01C57347CFE168FE911E2B9669EF291DFAFE6`tGPL-3.0"

    Write-Host "==> WMI-Parser v0.0.3 (no licence asserted; fetched, not redistributed)"
    $wmiZip = Join-Path $pin "WMI-Parser.zip"
    Save-PinnedFile "wmi-parser" `
        "https://github.com/AndrewRathbun/WMI-Parser/releases/download/v0.0.3/WMI-Parser.zip" `
        "C698B370C5CCC87401A0EF86BEC85E77C345854DA3EF5B80688E3CE80123CE09" $wmiZip | Out-Null
    $wmiDest = Join-Path $Ext "wmi-parser"
    if (Test-Path $wmiDest) { Remove-Item $wmiDest -Recurse -Force }
    Expand-To $wmiZip $wmiDest
    Add-Report "wmi-parser" "FETCHED" "v0.0.3 no licence asserted; net6.0 binary, help works with DOTNET_ROLL_FORWARD=LatestMajor on this host (runtimes 9 and 10, no net6)"
    $script:Versions += "wmi-parser`tv0.0.3`thttps://github.com/AndrewRathbun/WMI-Parser/releases/download/v0.0.3/WMI-Parser.zip`tC698B370C5CCC87401A0EF86BEC85E77C345854DA3EF5B80688E3CE80123CE09`tNONE"

    Write-Host "==> SIDR v0.9.2 (no licence asserted; fetched, not redistributed)"
    $sidr = Join-Path $Ext "sidr.exe"
    Save-PinnedFile "sidr" `
        "https://github.com/strozfriedberg/sidr/releases/download/v0.9.2/sidr.exe" `
        "634BE2A03263F0C83CC6CA5DFB1A582F3072BBC320490418DCB0DCEBE0474C97" $sidr | Out-Null
    Add-Report "sidr" "FETCHED" "v0.9.2 no licence asserted"
    $script:Versions += "sidr`tv0.9.2`thttps://github.com/strozfriedberg/sidr/releases/download/v0.9.2/sidr.exe`t634BE2A03263F0C83CC6CA5DFB1A582F3072BBC320490418DCB0DCEBE0474C97`tNONE"

    Write-Host "==> thumbcache_viewer 1.0.4.0 (GUI zip; no thumbcache_viewer_cmd.exe in this release)"
    $tvZip = Join-Path $pin "thumbcache_viewer_64.zip"
    Save-PinnedFile "thumbcache_viewer" `
        "https://github.com/thumbcacheviewer/thumbcacheviewer/releases/download/v1.0.4.0/thumbcache_viewer_64.zip" `
        "8D91A3156318ED26DF11202A86DC0B53E2D85FD7E2CB02CAF67F2FB63006E5ED" $tvZip | Out-Null
    $tvDest = Join-Path $Ext "thumbcache_viewer"
    if (Test-Path $tvDest) { Remove-Item $tvDest -Recurse -Force }
    Expand-To $tvZip $tvDest
    Add-Report "thumbcache_viewer" "FETCHED" "v1.0.4.0 GUI only (thumbcache_viewer.exe); cmd build is not in this tag"
    $script:Versions += "thumbcache_viewer`tv1.0.4.0`thttps://github.com/thumbcacheviewer/thumbcacheviewer/releases/download/v1.0.4.0/thumbcache_viewer_64.zip`t8D91A3156318ED26DF11202A86DC0B53E2D85FD7E2CB02CAF67F2FB63006E5ED`tNONE"

    Write-Host "==> Zircolite 4.2.0 windows-x64 (upstream SHA256SUMS)"
    $zrZip = Join-Path $pin "Zircolite-4.2.0-windows-x64.zip"
    Save-PinnedFile "zircolite" `
        "https://github.com/wagga40/Zircolite/releases/download/v4.2.0/Zircolite-4.2.0-windows-x64.zip" `
        "47942EA5CA5D314B1161FE3EE48D6B3E35CEDDFBAEA36E9DB9751A2ED82D6834" $zrZip | Out-Null
    $zrDest = Join-Path $Ext "zircolite"
    if (Test-Path $zrDest) { Remove-Item $zrDest -Recurse -Force }
    Expand-To $zrZip $zrDest
    Add-Report "zircolite" "FETCHED" "4.2.0"
    $script:Versions += "zircolite`t4.2.0`thttps://github.com/wagga40/Zircolite/releases/download/v4.2.0/Zircolite-4.2.0-windows-x64.zip`t47942EA5CA5D314B1161FE3EE48D6B3E35CEDDFBAEA36E9DB9751A2ED82D6834`tNOASSERTION"

    # VirusTotal/yara v4.5.6, v4.5.7 and v4.5.8 published no release assets.
    # v4.5.5 is the newest tag that ships an official win64 zip.
    Write-Host "==> YARA v4.5.5 win64 (newest official Windows asset; v4.5.8 has none)"
    $yrZip = Join-Path $pin "yara-4.5.5-2368-win64.zip"
    Save-PinnedFile "yara" `
        "https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip" `
        "352396C8A3D9B31B157A4820ABD3B9347FC934A2314CDDA8A4F566A5570163E4" $yrZip | Out-Null
    $yrDest = Join-Path $Ext "yara"
    if (Test-Path $yrDest) { Remove-Item $yrDest -Recurse -Force }
    Expand-To $yrZip $yrDest
    Add-Report "yara" "FETCHED" "v4.5.5 win64 (v4.5.8 tag has no Windows asset)"
    $script:Versions += "yara`tv4.5.5`thttps://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip`t352396C8A3D9B31B157A4820ABD3B9347FC934A2314CDDA8A4F566A5570163E4`tBSD-3-Clause"

    Install-PinnedWheel "hindsight" "20260600" `
        "https://files.pythonhosted.org/packages/79/55/c0f8c96000bf66b60c4c3c444c958dc9e0308d6099aa3ef5eb96a7efa3b2/pyhindsight-20260600-py3-none-any.whl" `
        "2c0e83cd59a9e891746547b28de7a53fa1802f5e679a34305f49a131a1833ccf" "Apache-2.0"
}

if ($PinsOnly) {
    Install-WoTaPins
    $verFile = Join-Path $Win "VERSIONS.txt"
    @(
        "DFIR-Nexus Tools/windows — WO-TA pins $(Get-Date -Format o)"
        "Each row: name, version, url, sha256, licence. Hash checked before install."
        ""
    ) + $script:Versions + @("", "fetch report:") + @(
        $script:Report | ForEach-Object { "report`t$($_.Name)`t$($_.Status)`t$($_.Detail)" }
    ) | Set-Content -Path $verFile -Encoding UTF8
    Write-Host "Wrote $verFile"
    foreach ($row in $script:Report) {
        Write-Host ("  [{0}] {1}: {2}" -f $row.Status, $row.Name, $row.Detail)
    }
    return
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
# Extract into a clean staging dir and take the binary from THERE. The old
# code globbed `hayabusa*.exe` out of $Hay with -First 1, but that directory
# accumulates every version ever fetched and "hayabusa-4.0.0-..." sorts before
# "hayabusa-4.1.0-..." - so a stale binary was copied over the freshly
# downloaded one while VERSIONS.txt recorded a version the lane never ran.
# Proven on this host: hayabusa.exe was byte-identical to the 4.0.0 build
# while the manifest said 4.1.0.
$haStage = Join-Path $env:TEMP ("hayabusa-stage-" + [guid]::NewGuid().ToString("n"))
Expand-To $haZip $haStage
$haExe = Get-ChildItem $haStage -Filter "hayabusa*.exe" -Recurse | Select-Object -First 1
if (-not $haExe) { throw "no hayabusa exe in $($ha.Asset.name)" }
Copy-Item $haExe.FullName (Join-Path $Hay "hayabusa.exe") -Force
Remove-Item $haStage -Recurse -Force -ErrorAction SilentlyContinue
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

# YARA is pinned in Install-WoTaPins (v4.5.5 win64). v4.5.8 has no Windows asset.

Write-Host "==> capa (GitHub latest windows)"
try {
    $cp = Get-GitHubAsset "mandiant/capa" "windows\.zip$"
    $cpZip = Join-Path $env:TEMP $cp.Asset.name
    Invoke-WebRequest -Uri $cp.Asset.browser_download_url -OutFile $cpZip
    Expand-To $cpZip $Ext
    $script:Versions += "capa`t$($cp.Tag)`t$($cp.Asset.browser_download_url)"
} catch { Write-Host "    capa skipped: $_" }

# thumbcache_viewer 1.0.4.0 is pinned in Install-WoTaPins.

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

Write-Host "==> RegRipper 3.0 (keydet89; Perl required at run time)"
try {
    $rrZip = Join-Path $env:TEMP "RegRipper3.0-master.zip"
    Invoke-WebRequest -Uri "https://github.com/keydet89/RegRipper3.0/archive/refs/heads/master.zip" -OutFile $rrZip
    $rrDest = Join-Path $Ext "regripper"
    if (Test-Path $rrDest) { Remove-Item $rrDest -Recurse -Force }
    Expand-Any $rrZip $rrDest
    $rip = Get-ChildItem $rrDest -Recurse -Filter "rip.pl" | Select-Object -First 1
    if (-not $rip) { throw "rip.pl not found in archive" }
    Add-Report "regripper" "FETCHED" "RegRipper3.0 (Perl; rip.pl needs perl on PATH) -> $($rip.FullName)"
    $script:Versions += "regripper`tmaster`thttps://github.com/keydet89/RegRipper3.0"
} catch { Add-Report "regripper" "FAILED" "$_" }

# Zircolite 4.2.0 is pinned in Install-WoTaPins.

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
    # run-deepblue.ps1 is TRACKED SOURCE (see .gitignore's negations), not a
    # fetched artifact. Writing it here destroyed the wrapper's documented
    # reasoning about DeepBlueCLI's own behaviour, so the fetch only creates it
    # when it is absent and never rewrites the copy in git.
    $wrapperPath = Join-Path $dbDest "run-deepblue.ps1"
    if (-not (Test-Path $wrapperPath)) {
        Set-Content -Path $wrapperPath -Value $wrapper -Encoding UTF8
    }
    Add-Report "deepbluecli" "FETCHED" "master archive + run-deepblue.ps1 wrapper"
    $script:Versions += "deepbluecli`tmaster`thttps://github.com/sans-blue-team/DeepBlueCLI"
} catch { Add-Report "deepbluecli" "FAILED" "$_" }

# Hindsight (pyhindsight 20260600) is pinned in Install-WoTaPins.

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

Install-WoTaPins

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
