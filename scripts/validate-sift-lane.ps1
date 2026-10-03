# Validate the corrected SIFT lane end-to-end on ONE small case.
#
# The sequence the diagnosis identified (each step was missing or wrong before):
#   setup -> enable -> stage evidence ON the SIFT host -> register --sift-hosted
#   -> tools lane (must plan jobs > 0) -> interpret
#
# A lane that plans 0 jobs reports "clear" and produces no findings, which reads
# as a clean result. Every stage below therefore checks its artifact, not its exit code.
[CmdletBinding()]
param(
    [string] $CaseId = "CASE-CS-ROCBA1",
    [string] $LocalEvidence = "Evidence-files\showcase\rocba-500\host\evtx",
    [string] $Question = "Investigate this host for compromise"
)

$ErrorActionPreference = 'Continue'
$Repo = Split-Path $PSScriptRoot -Parent
Set-Location $Repo
if (-not $Repo) { $Repo = (Get-Location).Path }

# The SIFT MCP basics. Point these at your host; NEXUS_BEARER_TOKEN must already
# be in the environment - NEVER hardcode it here, this file is committed.
$env:NEXUS_SIFT_SSH_HOST = $env:NEXUS_SIFT_SSH_HOST
if (-not $env:NEXUS_SIFT_SSH_HOST) { $env:NEXUS_SIFT_SSH_HOST = "192.168.77.135" }
if (-not $env:NEXUS_SIFT_SSH_USER) { $env:NEXUS_SIFT_SSH_USER = "sansforensics" }
if (-not $env:NEXUS_SIFT_SSH_KEY) { $env:NEXUS_SIFT_SSH_KEY = "C:\Users\$env:USERNAME\.ssh\cadre-sift-key" }
if (-not $env:NEXUS_SIFT_MCP_URL) { $env:NEXUS_SIFT_MCP_URL = "http://$($env:NEXUS_SIFT_SSH_HOST):4508/mcp" }
if (-not $env:NEXUS_BEARER_TOKEN) {
    Write-Host "NEXUS_BEARER_TOKEN is not set." -ForegroundColor Yellow
    Write-Host "  It is printed by 'nexus sift setup' (the MCP rejects unauthenticated /mcp calls)." -ForegroundColor Yellow
    Write-Host "  Set it in the environment and re-run; it is deliberately not stored in this script." -ForegroundColor Yellow
    exit 2
}

function Step($n, $msg) { Write-Host "`n=== [$n] $msg" -ForegroundColor Cyan }
function Check($label, $ok, $detail) {
    $flag = if ($ok) { "OK  " } else { "FAIL" }
    Write-Host ("  [{0}] {1}: {2}" -f $flag, $label, $detail)
    return [bool]$ok
}

$evidence = (Resolve-Path -LiteralPath $LocalEvidence).Path
$files = Get-ChildItem -LiteralPath $evidence -Recurse -File
$siftDir = "/home/sansforensics/.nexus/cases/$CaseId/evidence"
$ssh = @("-i", $env:NEXUS_SIFT_SSH_KEY, "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=20")

Step 1 "host layout + MCP (nexus sift setup)"
python -m nexus sift setup --case $CaseId 2>&1 | Select-Object -Last 12

Step 2 "mark SIFT required (without this the lane never routes to the host)"
$en = python -m nexus sift enable --case $CaseId 2>&1
$en | Select-Object -Last 6
$status = python -m nexus sift status --case $CaseId 2>&1
$selected = ($status -join " ") -match "sift_required\):\s*yes"
Check "sift_required" $selected ($status -join " | ")

Step 3 "copy evidence ONTO the SIFT host"
& ssh @ssh "sansforensics@192.168.77.135" "mkdir -p '$siftDir'"
foreach ($f in $files) {
    & scp @ssh $f.FullName "sansforensics@192.168.77.135:$siftDir/" 2>&1 | Out-Null
}
$remote = & ssh @ssh "sansforensics@192.168.77.135" "ls -1 '$siftDir' | wc -l"
Check "copied" ([int]$remote -eq $files.Count) "remote=$remote local=$($files.Count)"

Step 4 "case init + register as SIFT-hosted"
python -m nexus case init "case-set validation" --case-id $CaseId 2>&1 | Select-Object -Last 3
foreach ($f in $files) {
    $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName).Hash.ToLower()
    python -m nexus evidence register "/evidence/$($f.Name)" --case $CaseId --sift-hosted --sha256 $sha -d "sift-hosted $($f.Name)" 2>&1 | Out-Null
}
Write-Host "  registered $($files.Count) sift-hosted file(s)"

Step 5 "tools lane - it MUST plan jobs"
$lane = python -m nexus pipeline --from-case $CaseId --mode tools 2>&1
$lane | Select-Object -Last 8
$gatePath = "$Repo\cases\$CaseId\analysis\lane_gate.json"
if (Test-Path $gatePath) {
    $gate = Get-Content $gatePath -Raw | ConvertFrom-Json
    $jobs = @($gate.jobs).Count
    Check "lane planned work" ($jobs -gt 0) "jobs=$jobs unprocessed=$(@($gate.unprocessed).Count) status=$($gate.status)"
    if ($jobs -eq 0) {
        Write-Host "  NOTE: 0 jobs means NOTHING was examined - any finding count would be meaningless." -ForegroundColor Yellow
    }
} else { Check "lane_gate.json" $false "absent" }

Write-Host "`nDone. Case: $CaseId" -ForegroundColor Cyan
