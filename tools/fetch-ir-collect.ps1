# Stage 0 live-IR collectors into Tools/windows and Tools/linux (gitignored).
# Run from a Windows examiner host. Linux ELF/scripts are stored locally and
# copied to the target at collect time (SSH). Does not fetch KAPE (already
# operator-staged) or re-download Zimmerman/Hayabusa.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Win = Join-Path $Root "windows"
. (Join-Path $Root "lib-git-rules.ps1")
$Lin = Join-Path $Root "linux"
$KansaDir = Join-Path $Win "kansa"
$UacDir = Join-Path $Lin "uac"
$AvmlDir = Join-Path $Lin "avml"
$MemWin = Join-Path $Win "memory"
New-Item -ItemType Directory -Force -Path $Win, $Lin, $MemWin | Out-Null

$script:Versions = @()
$UA = @{ "User-Agent" = "dfir-nexus-fetch" }

function Get-GitHubRelease {
    param([string]$Repo)
    return Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $UA
}

function Get-GitHubAsset {
    param([string]$Repo, [string]$Match)
    $rel = Get-GitHubRelease -Repo $Repo
    $asset = $rel.assets | Where-Object { $_.name -match $Match } | Select-Object -First 1
    if (-not $asset) {
        $names = ($rel.assets | ForEach-Object { $_.name }) -join ", "
        throw "No GitHub asset matching /$Match/ in $Repo@$($rel.tag_name). Assets: $names"
    }
    return @{ Asset = $asset; Tag = $rel.tag_name; Url = $asset.browser_download_url }
}

function Copy-NeedleTree {
    param([string]$ExtractRoot, [string]$Dest, [string]$NeedleFile)
    if (Test-Path $Dest) { Remove-Item $Dest -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    $hit = Get-ChildItem $ExtractRoot -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $NeedleFile } |
        Select-Object -First 1
    if (-not $hit) { throw "Did not find $NeedleFile under $ExtractRoot" }
    $srcDir = $hit.Directory.FullName
    Copy-Item (Join-Path $srcDir "*") $Dest -Recurse -Force
}

Write-Host "==> Kansa (davehull/Kansa master; refreshed when master has a newer commit)"
$kansaCommit = (Invoke-RestMethod -Uri "https://api.github.com/repos/davehull/Kansa/commits/master" -Headers $UA).sha
$kansaRecord = Join-Path $KansaDir ".installed-commit"
$kansaInstalled = if (Test-Path $kansaRecord) { (Get-Content $kansaRecord -Raw).Trim() } else { "" }
if ((Test-Path (Join-Path $KansaDir "kansa.ps1")) -and $kansaInstalled -eq $kansaCommit) {
    $script:Versions += "kansa`tmaster@$($kansaCommit.Substring(0, 12))`tcurrent"
    Write-Host "    kansa master $($kansaCommit.Substring(0, 12)) already installed"
} else {
    $kansaZip = Join-Path $env:TEMP "Kansa-master.zip"
    Invoke-WebRequest -Uri "https://github.com/davehull/Kansa/archive/refs/heads/master.zip" -Headers $UA -OutFile $kansaZip
    $kansaTmp = Join-Path $env:TEMP ("kansa-" + [guid]::NewGuid().ToString("n").Substring(0, 8))
    if (Test-Path $kansaTmp) { Remove-Item $kansaTmp -Recurse -Force }
    Expand-Archive -Path $kansaZip -DestinationPath $kansaTmp -Force
    Copy-NeedleTree -ExtractRoot $kansaTmp -Dest $KansaDir -NeedleFile "kansa.ps1"
    Set-Content -Path $kansaRecord -Value $kansaCommit -Encoding ASCII
    $script:Versions += "kansa`tmaster@$($kansaCommit.Substring(0, 12))`thttps://github.com/davehull/Kansa/archive/refs/heads/master.zip"
}

Write-Host '==> UAC (tclahr/uac latest; Linux collector staged on this host)'
# Refreshed when the latest tag differs from the one recorded beside the tree (.installed-tag).
$uac = Get-GitHubAsset -Repo "tclahr/uac" -Match "uac-.*\.(tar\.gz|tgz|zip)$"
$uacRecord = Join-Path $UacDir ".installed-tag"
$uacInstalled = if (Test-Path $uacRecord) { (Get-Content $uacRecord -Raw).Trim() } else { "" }
if ((Test-Path (Join-Path $UacDir "uac")) -and $uacInstalled -eq $uac.Tag) {
    $script:Versions += "uac`t$($uac.Tag)`tcurrent"
    Write-Host "    uac $($uac.Tag) already installed"
} else {
    $uacFile = Join-Path $env:TEMP $uac.Asset.name
    Invoke-WebRequest -Uri $uac.Url -Headers $UA -OutFile $uacFile
    $uacTmp = Join-Path $env:TEMP ("uac-" + [guid]::NewGuid().ToString("n").Substring(0, 8))
    New-Item -ItemType Directory -Force -Path $uacTmp | Out-Null
    if ($uacFile -match "\.zip$") {
        Expand-Archive -Path $uacFile -DestinationPath $uacTmp -Force
    } else {
        tar -xf $uacFile -C $uacTmp
    }
    Copy-NeedleTree -ExtractRoot $uacTmp -Dest $UacDir -NeedleFile "uac"
    Set-Content -Path $uacRecord -Value $uac.Tag -Encoding ASCII
    $script:Versions += "uac`t$($uac.Tag)`t$($uac.Url)"
}

Write-Host "==> AVML (microsoft/avml latest Linux x86_64 binary)"
$avmlBin = Join-Path $AvmlDir "avml"
$av = Get-GitHubAsset -Repo "microsoft/avml" -Match "^avml$"
$avmlRecord = Join-Path $AvmlDir ".installed-tag"
$avmlInstalled = if (Test-Path $avmlRecord) { (Get-Content $avmlRecord -Raw).Trim() } else { "" }
if ((Test-Path $avmlBin) -and $avmlInstalled -eq $av.Tag) {
    $script:Versions += "avml`t$($av.Tag)`tcurrent"
    Write-Host "    avml $($av.Tag) already installed"
} else {
    New-Item -ItemType Directory -Force -Path $AvmlDir | Out-Null
    Invoke-WebRequest -Uri $av.Url -Headers $UA -OutFile $avmlBin
    Set-Content -Path $avmlRecord -Value $av.Tag -Encoding ASCII
    $script:Versions += "avml`t$($av.Tag)`t$($av.Url)"
}

$wp = Get-ChildItem $MemWin -Filter "winpmem*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($wp) {
    $script:Versions += "winpmem`talready-present $($wp.Name)`t$($wp.FullName)"
    Write-Host "==> WinPmem: already present $($wp.Name)"
} else {
    Write-Host "==> WinPmem: not found under Tools/windows/memory (optional --memory)"
    $script:Versions += "winpmem`tMISSING`tTools/windows/memory/"
}

$kape = Join-Path $Win "kape\kape.exe"
if (Test-Path $kape) {
    $script:Versions += "kape`talready-present`t$kape"
    Write-Host "==> KAPE: already present"
} else {
    $script:Versions += "kape`tMISSING`tTools/windows/kape/"
    Write-Host "==> KAPE: MISSING - unpack KAPE to Tools/windows/kape/"
}

Write-Host '==> DFIR-ORC (DFIR-ORC/dfir-orc latest) - collect-only snapshot; DumpIt skipped (commercial; use WinPmem --memory)'
$OrcDir = Join-Path $Win "orc"
New-Item -ItemType Directory -Force -Path $OrcDir | Out-Null
$orcExe = Join-Path $OrcDir "DFIR-ORC.exe"
$orcAsset = Get-GitHubAsset -Repo "DFIR-ORC/dfir-orc" -Match "^DFIR-ORC\.exe$"
$orcRecord = Join-Path $OrcDir ".installed-tag-dfir-orc"
$orcInstalled = if (Test-Path $orcRecord) { (Get-Content $orcRecord -Raw).Trim() } else { "" }
if ((Test-Path $orcExe) -and $orcInstalled -eq $orcAsset.Tag) {
    $script:Versions += "dfir-orc|$($orcAsset.Tag)|current"
    Write-Host "    DFIR-ORC $($orcAsset.Tag) already installed"
} else {
    Invoke-WebRequest -Uri $orcAsset.Url -Headers $UA -OutFile $orcExe
    Set-Content -Path $orcRecord -Value $orcAsset.Tag -Encoding ASCII
    $script:Versions += "dfir-orc|$($orcAsset.Tag)|$($orcAsset.Url)"
}

$OrcCfg = Join-Path $OrcDir "config"
if (Test-Path (Join-Path $OrcCfg "Build.cmd")) {
    $script:Versions += "dfir-orc-config|already-present|$OrcCfg"
    Write-Host "    dfir-orc-config already present - skip clone"
} else {
    if (Test-Path $OrcCfg) { Remove-Item $OrcCfg -Recurse -Force }
    git clone --depth 1 https://github.com/DFIR-ORC/dfir-orc-config.git $OrcCfg
    if (-not (Test-Path (Join-Path $OrcCfg "Build.cmd"))) {
        throw "git clone dfir-orc-config did not produce Build.cmd"
    }
    $script:Versions += "dfir-orc-config|master|https://github.com/DFIR-ORC/dfir-orc-config"
}

$cfgTools = Join-Path $OrcCfg "tools"
New-Item -ItemType Directory -Force -Path $cfgTools | Out-Null
$Sys = Join-Path $Win "sysinternals"
foreach ($n in @("autorunsc.exe", "handle.exe", "Tcpvcon.exe", "Listdlls.exe")) {
    $src = Get-ChildItem $Sys -Filter $n -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($src) { Copy-Item $src.FullName (Join-Path $cfgTools $n) -Force }
}

$psniper = Join-Path $cfgTools "PersistenceSniper.psm1"
$psRelease = (Invoke-RestMethod -Uri "https://api.github.com/repos/last-byte/PersistenceSniper/releases/latest" -Headers $UA).tag_name -replace '^v', ''
$psInstalled = if (Test-Path $psniper) { [regex]::Match((Get-Content $psniper -Raw), '\.VERSION\s+(\S+)').Groups[1].Value } else { "" }
if ($psInstalled -ne $psRelease) {
    $psniperRepo = Join-Path $env:TEMP "PersistenceSniper-git"
    if (Test-Path $psniperRepo) { Remove-Item $psniperRepo -Recurse -Force }
    git clone --depth 1 https://github.com/last-byte/PersistenceSniper.git $psniperRepo
    $hit = Get-ChildItem $psniperRepo -Recurse -Filter "PersistenceSniper.psm1" | Select-Object -First 1
    if (-not $hit) { throw "PersistenceSniper.psm1 not found after clone" }
    Copy-Item $hit.FullName $psniper -Force
}
$script:Versions += "persistencesniper|v$psRelease|https://github.com/last-byte/PersistenceSniper"

Write-Host "==> Sigma rules for Chainsaw hunt (SigmaHQ/sigma sparse rules/ — full tree hits Windows MAX_PATH)"
$SigmaDir = Join-Path $Win "extra\chainsaw\sigma"
# Kept at the head of master (lib-git-rules.ps1); the sparse checkout holds rules/ only.
$sigmaHead = Sync-GitRules -Dir $SigmaDir -Url "https://github.com/SigmaHQ/sigma.git" -Branch "master" -SparsePath "rules"
if (-not (Test-Path (Join-Path $SigmaDir "rules"))) {
    throw "Sigma sparse checkout did not produce rules/"
}
$script:Versions += "sigma|$sigmaHead|https://github.com/SigmaHQ/sigma"

Write-Host "==> Stage 0 inventory (Hayabusa/Suzaku/Chainsaw/Sysinternals — fetched by tools/fetch-windows-tools.ps1)"
$Hay = Get-ChildItem (Join-Path $Win "hayabusa") -Filter "hayabusa*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
$Suz = Get-ChildItem (Join-Path $Win "suzaku") -Filter "suzaku*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
$Cs = Join-Path $Win "extra\chainsaw\chainsaw.exe"
$Ar = Get-ChildItem (Join-Path $Win "sysinternals") -Filter "autorunsc*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($Hay) { $script:Versions += "hayabusa|present|$($Hay.FullName)" } else { $script:Versions += "hayabusa|MISSING|run tools/fetch-windows-tools.ps1" }
if ($Suz) { $script:Versions += "suzaku|present|$($Suz.FullName)" } else { $script:Versions += "suzaku|MISSING|run tools/fetch-windows-tools.ps1" }
if (Test-Path $Cs) { $script:Versions += "chainsaw|present|$Cs" } else { $script:Versions += "chainsaw|MISSING|run tools/fetch-windows-tools.ps1" }
if ($Ar) { $script:Versions += "sysinternals|present|$($Ar.FullName)" } else { $script:Versions += "sysinternals|MISSING|run tools/fetch-windows-tools.ps1" }
$script:Versions += "dumpit|skipped-commercial|never invoked; memory is WinPmem"

# DumpIt is Magnet/commercial. Drop it from the ANSSI example embed; Nexus memory is WinPmem --memory.
$embedXml = Join-Path $OrcCfg "config\Embed.xml"
$wolfXml = Join-Path $OrcCfg "config\ORC_config.xml"
if (Test-Path $embedXml) {
    $txt = Get-Content $embedXml -Raw
    $txt = $txt -replace '(?m)^\s*<file name="dumpit"[^/]*/>\s*', ''
    Set-Content -Path $embedXml -Value $txt -Encoding UTF8
}
if (Test-Path $wolfXml) {
    $txt = Get-Content $wolfXml -Raw
    $txt = $txt -replace '(?is)\s*<command keyword="GetRam_dmp"[\s\S]*?</command>', "`r`n        <!-- GetRam_dmp/DumpIt omitted: commercial; use nexus collect --memory -->"
    Set-Content -Path $wolfXml -Value $txt -Encoding UTF8
}

$ready = Join-Path $OrcDir "DFIR-ORC-ready.exe"
$embedXmlRel = Join-Path $OrcCfg "config\Embed.xml"
if (Test-Path -LiteralPath $ready) {
    $script:Versions += "dfir-orc-ready|already-present|$ready"
    Write-Host "    DFIR-ORC-ready.exe already present - skip ToolEmbed"
} elseif (Test-Path $embedXmlRel) {
    Write-Host "==> ToolEmbed DFIR-ORC-ready.exe (DumpIt omitted; PersistenceSniper + Sysinternals embedded)"
    Push-Location $OrcCfg
    try {
        & $orcExe ToolEmbed "/embed=.\config\Embed.xml" "/out=$ready" /force
        $embedCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    Start-Sleep -Milliseconds 500
    if (Test-Path -LiteralPath $ready) {
        $script:Versions += "dfir-orc-ready|ToolEmbed ok|$ready"
        Write-Host "    wrote $ready"
    } else {
        $script:Versions += "dfir-orc-ready|ToolEmbed exit $embedCode missing $ready|$orcExe"
        Write-Host "ToolEmbed exit $embedCode - ready exe missing, capsule still at $orcExe"
    }
} else {
    $script:Versions += "dfir-orc-ready|no Embed.xml|$OrcCfg"
}

$verFile = Join-Path $Win "COLLECT-VERSIONS.txt"
@(
    "DFIR-Nexus Stage 0 collect tools - fetched $(Get-Date -Format o)"
    "Linux binaries live under Tools/linux/ and are copied to the target at run time."
    ""
) + $script:Versions | Set-Content -Path $verFile -Encoding UTF8
Copy-Item $verFile (Join-Path $Lin "COLLECT-VERSIONS.txt") -Force
Write-Host "Wrote $verFile"
Write-Host "Done."
