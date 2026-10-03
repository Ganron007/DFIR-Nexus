<#
.SYNOPSIS
  Stage evidence onto the SIFT host for a case, and verify it landed intact.

.DESCRIPTION
  Repeatable version of the manual step: copy evidence into
  `~/.nexus/cases/<CaseId>/evidence/` on the SIFT host, extract any archive
  there, and prove by hash that the bytes arrived.

  Two things this encodes that a hand-run `scp` does not:

  * **Transfer the archive, extract on the host.** The 608-sift disk ships as a
    996 MB `.7z` holding the 20 GiB image, so pushing the archive and running
    `7z x` on the host moves ~4 GB instead of ~24 GB. `-Extract` does that and
    removes the archive afterwards (keep it with `-KeepArchive`).
  * **Verify, do not assume.** Sizes and hashes are compared after the copy; the
    script fails loudly on a mismatch. For a `.7z` it verifies the extracted
    file against the `.md5` the archive carries, else the local file's SHA-256
    against the remote file's.

  Evidence is staged on demand - there is no persistent copy on the host between
  cases, so this is the step to re-run whenever a case needs SIFT.

  NOTE: no lab address is baked in. Set `NEXUS_SIFT_SSH_HOST` / `-SiftHost`.

.EXAMPLE
  # The 608-sift pair, transferring the archive and extracting on the host
  ./scripts/stage-sift-evidence.ps1 -CaseId CASE-XXXX `
      -Evidence Evidence-files\_staging\608-sift\dmz-www-disk.img,
                Evidence-files\_staging\608-sift\mem.raw `
      -Archive  Evidence-files\03-linux\608-sift\dmz-www\dmz-www-disk.7z `
      -Extract -Verify

.EXAMPLE
  # What would be transferred, without transferring
  ./scripts/stage-sift-evidence.ps1 -CaseId CASE-XXXX `
      -Evidence path\to\mem.raw -WhatIf
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $CaseId,

    # Files to end up in the remote evidence dir. Any path given in -Archive is
    # transferred instead of the plain file of the same base name.
    [Parameter(Mandatory = $true)][string[]] $Evidence,

    # Omitted by default: the archive form of a file, pushed instead of the
    # large plain form. e.g. dmz-www-disk.7z stands in for dmz-www-disk.img.
    [string[]] $Archive = @(),

    [string] $SiftHost = $env:NEXUS_SIFT_SSH_HOST,
    [string] $SiftUser = $(if ($env:NEXUS_SIFT_SSH_USER) { $env:NEXUS_SIFT_SSH_USER } else { 'sansforensics' }),
    [string] $SshKey = $(if ($env:NEXUS_SIFT_SSH_KEY) { $env:NEXUS_SIFT_SSH_KEY } else { "$env:USERPROFILE\.ssh\cadre-sift-key" }),

    # Run `7z x` on the host for each transferred archive.
    [switch] $Extract,
    # Keep the transferred archive after extraction (default: remove it).
    [switch] $KeepArchive,
    # Compare hashes after the copy (recommended; on by default for a run).
    [switch] $SkipVerify,
    # Re-verify what is already on the host without transferring anything.
    [switch] $VerifyOnly,
    [switch] $WhatIf
)

$ErrorActionPreference = 'Stop'

# `pwsh -File script.ps1 -Evidence a,b` passes "a,b" as ONE string (unlike a
# direct call where @('a','b') is an array). Split on commas so both forms work.
function Expand-List {
    param([string[]] $Values)
    $out = @()
    foreach ($v in $Values) {
        foreach ($part in ([string]$v -split ',')) {
            $p = $part.Trim().Trim('"')
            if ($p) { $out += $p }
        }
    }
    return $out
}
$Evidence = Expand-List $Evidence
$Archive = Expand-List $Archive

if (-not $SiftHost) { throw "Set NEXUS_SIFT_SSH_HOST or pass -SiftHost." }
if (-not (Test-Path $SshKey)) { throw "SSH key not found: $SshKey" }

# ABSOLUTE path, not ~. A quoted remote path ('~/.nexus/...') is not
# tilde-expanded by the remote shell, so `stat`/`sha256sum` saw a literal
# "~" directory and reported every file missing (found 2026-10-03).
$remoteDir = "/home/$SiftUser/.nexus/cases/$CaseId/evidence"
$remote = "$SiftUser@$SiftHost"
$sshOpts = @('-i', $SshKey, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15')

function Invoke-Ssh {
    param([string] $Command, [int] $TimeoutSec = 900)
    # NOT $args: that is an automatic variable inside a function.
    $argv = @('ssh') + $sshOpts + @($remote, $Command)
    $out = & $argv[0] $argv[1..($argv.Count - 1)] 2>&1
    return [pscustomobject]@{ Exit = $LASTEXITCODE; Out = ($out | Out-String).Trim() }
}

function Get-LocalSha256 {
    param([string] $Path)
    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower()
}

# Map expected plain name -> archive that can stand in for it.
$archiveFor = @{}
foreach ($a in $Archive) {
    if (-not (Test-Path $a)) { throw "Archive not found: $a" }
    # dmz-www-disk.7z -> dmz-www-disk (strip one extension)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($a)
    $archiveFor[$base] = (Resolve-Path $a).Path
}

Write-Host "Target : $remote`:$remoteDir"
Write-Host "Case   : $CaseId"
Write-Host ""

$transfers = @()
foreach ($item in $Evidence) {
    if (-not (Test-Path $item)) { throw "Evidence not found: $item" }
    $leaf = Split-Path $item -Leaf
    $base = [System.IO.Path]::GetFileNameWithoutExtension($leaf)
    $useArchive = $archiveFor.ContainsKey($base)
    $sendFrom = if ($useArchive) { $archiveFor[$base] } else { (Resolve-Path $item).Path }
    $sendBytes = (Get-Item $sendFrom).Length
    $plainBytes = (Get-Item $item).Length
    $transfers += [pscustomobject]@{
        Plain      = (Resolve-Path $item).Path
        PlainName  = $leaf
        Send       = $sendFrom
        SendName   = (Split-Path $sendFrom -Leaf)
        Archive    = $useArchive
        SendBytes  = $sendBytes
        PlainBytes = $plainBytes
    }
}

$totalSend = ($transfers | Measure-Object -Property SendBytes -Sum).Sum
$totalPlain = ($transfers | Measure-Object -Property PlainBytes -Sum).Sum
if (-not $VerifyOnly) {
    Write-Host ("Plan: {0} file(s), transferring {1:N0} bytes instead of {2:N0} ({3:N1}x smaller)" -f `
        $transfers.Count, $totalSend, $totalPlain, ($totalPlain / [Math]::Max($totalSend, 1)))
    foreach ($t in $transfers) {
        $via = if ($t.Archive) { "  (archive stands in for $($t.PlainName))" } else { "" }
        Write-Host ("  -> {0}  {1:N0} bytes{2}" -f $t.SendName, $t.SendBytes, $via)
    }
}

if ($WhatIf) { Write-Host "`n-WhatIf: nothing transferred."; return }

# --- 1..3. layout, transfer, extract (skipped by -VerifyOnly) --------------
if (-not $VerifyOnly) {
    $r = Invoke-Ssh "mkdir -p $remoteDir && echo OK"
    if ($r.Exit -ne 0 -or $r.Out -notmatch 'OK') { throw "could not create $remoteDir : $($r.Out)" }
    Write-Host "`n[1/4] remote dir ready: $remoteDir"

    foreach ($t in $transfers) {
        Write-Host ("[2/4] scp {0} ({1:N0} bytes)..." -f $t.SendName, $t.SendBytes)
        $scpArgv = @('scp') + $sshOpts + @($t.Send, "${remote}:$remoteDir/")
        & $scpArgv[0] $scpArgv[1..($scpArgv.Count - 1)] | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "scp failed for $($t.SendName)" }
    }

    if ($Extract) {
        foreach ($t in ($transfers | Where-Object { $_.Archive })) {
            Write-Host "[3/4] 7z x $($t.SendName) on the host..."
            $r = Invoke-Ssh "cd $remoteDir && 7z x -y '$($t.SendName)' >/dev/null && echo EXTRACTED"
            if ($r.Exit -ne 0 -or $r.Out -notmatch 'EXTRACTED') { throw "extract failed: $($r.Out)" }
            if (-not $KeepArchive) {
                $r = Invoke-Ssh "rm -f $remoteDir/'$($t.SendName)' && echo REMOVED"
                if ($r.Out -notmatch 'REMOVED') { Write-Warning "could not remove $($t.SendName) on the host" }
            }
        }
        $r = Invoke-Ssh "ls -la $remoteDir"
        Write-Host $r.Out
    }
    else {
        Write-Host "[3/4] -Extract not set: archive(s) left as transferred."
    }
}
else {
    Write-Host "`n-VerifyOnly: no layout, transfer or extract; checking what is on the host."
}

# --- 4. verify ------------------------------------------------------------
if (-not $SkipVerify) {
    Write-Host "[4/4] verifying..."
    $fail = $false
    foreach ($t in $transfers) {
        $remoteFile = "$remoteDir/$($t.PlainName)"
        $r = Invoke-Ssh "stat -c '%s' '$remoteFile' 2>/dev/null || echo MISSING"
        if ($r.Out -notmatch '^\d+$') {
            Write-Warning "  $($t.PlainName): NOT PRESENT on the host"
            $fail = $true
            continue
        }
        $remoteSize = [int64]$r.Out
        if ($remoteSize -ne $t.PlainBytes) {
            Write-Warning ("  {0}: size mismatch remote={1} expected={2}" -f $t.PlainName, $remoteSize, $t.PlainBytes)
            $fail = $true
            continue
        }
        if ($t.Archive) {
            # The archive carries its own .md5; use it rather than re-reading 20 GB.
            $md5Name = [System.IO.Path]::GetFileNameWithoutExtension($t.PlainName) + '.md5'
            $r = Invoke-Ssh "cd $remoteDir && md5sum '$($t.PlainName)' > /tmp/.stage.md5 && echo DONE"
            $want = (Get-Content (Join-Path (Split-Path $t.Plain -Parent) $md5Name) -ErrorAction SilentlyContinue)
            if ($want) {
                $got = (Invoke-Ssh "cut -d' ' -f1 /tmp/.stage.md5").Out
                $exp = ($want -split '\s+')[0].Trim().ToLower()
                if ($got -and $got.Trim().ToLower() -eq $exp) {
                    Write-Host "  $($t.PlainName): size OK + md5 matches the shipped .md5"
                } else {
                    Write-Warning "  $($t.PlainName): md5 mismatch (remote=$got expected=$exp)"
                    $fail = $true
                }
            } else {
                Write-Host "  $($t.PlainName): size OK (no local .md5 to compare)"
            }
        } else {
            $localHash = Get-LocalSha256 $t.Plain
            $got = (Invoke-Ssh "sha256sum '$remoteFile' | cut -d' ' -f1").Out
            if ($got -and $got.Trim().ToLower() -eq $localHash) {
                Write-Host "  $($t.PlainName): size OK + sha256 matches"
            } else {
                Write-Warning "  $($t.PlainName): sha256 mismatch (remote=$got local=$localHash)"
                $fail = $true
            }
        }
    }
    if ($fail) { throw "verification FAILED - do not trust this staging" }
    Write-Host "  all files verified."
}

# --- intake keys ----------------------------------------------------------
$mem = ($transfers | Where-Object { $_.PlainName -match '\.(raw|mem|vmem|dmp|img)$' -and $_.PlainName -match 'mem' } | Select-Object -First 1)
Write-Host ""
Write-Host "Case intake for $CaseId (set on the OPERATOR side):"
Write-Host "  sift_required: true"
Write-Host "  sift_evidence_root: /home/$SiftUser/.nexus/cases/$CaseId/evidence"
if ($mem) {
    Write-Host "  sift_memory_file: /home/$SiftUser/.nexus/cases/$CaseId/evidence/$($mem.PlainName)"
}
Write-Host "  sift_os: <windows|linux>   # match the IMAGE, not the host"
Write-Host ""
Write-Host "Then: nexus sift setup --case $CaseId   (starts the MCP and prints the env block)"
