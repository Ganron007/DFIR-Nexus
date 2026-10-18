# TIER1-WORK-ORDERS Part 10 RB-A7/RB-A8: the lane re-runs (S08, S09, S06) and fresh mode runs on all nine samples,
# in two queues, as started on 2026-10-18. Run each queue in its own process:
#   pwsh -NoProfile -File devtools/runbook/batch_runs.ps1 -Queue lanes|q1|q2 [-LogDir <folder>]
# A mode queue waits for a sample's lane marker (lane-done-<Sxx> in the log folder) before that sample's modes; a
# sample without a lane re-run has its index rebuilt first (P2 step 5).
param(
    [Parameter(Mandatory)] [ValidateSet('lanes', 'q1', 'q2')] [string] $Queue,
    [string] $LogDir = ''
)
$ErrorActionPreference = 'Continue'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$sp = if ($LogDir) { $LogDir } else { Join-Path $repo '.runlogs' }
New-Item -ItemType Directory -Force $sp | Out-Null
Set-Location $repo
$env:PYTHONIOENCODING = 'utf-8'
$cases = @{ S01 = 'CASE-0D525078'; S02 = 'CASE-55762EBF'; S03 = 'CASE-EA24B279'; S04 = 'CASE-5891325B'; S05 = 'CASE-56423D77';
            S06 = 'CASE-FC43714F'; S07 = 'CASE-F8811FAB'; S08 = 'CASE-230BD8C3'; S09 = 'CASE-1655B9C5' }
$log = Join-Path $sp "orch-$Queue.out"
function Note([string] $m) { "$(Get-Date -Format o) $m" | Out-File $log -Append }

if ($Queue -eq 'lanes') {
    foreach ($s in 'S08', 'S09') {
        Note "lane $s start (HEAD $(git rev-parse --short HEAD))"
        pwsh -NoProfile -File devtools/runbook/run_lane.ps1 -CaseId $cases[$s] -Tag $s *> (Join-Path $sp "orch-lane-$s.txt")
        Note "lane $s done"
        New-Item -ItemType File -Force (Join-Path $sp "lane-done-$s") | Out-Null
    }
    Note 'lane S06 start'
    pwsh -NoProfile -File devtools/runbook/run_lane.ps1 -CaseId $cases['S06'] -Tag S06 -Sift -Capture 'Evidence-files\_samples\S06\capture\capture.pcap' *> (Join-Path $sp 'orch-lane-S06.txt')
    Note 'lane S06 done'
    New-Item -ItemType File -Force (Join-Path $sp 'lane-done-S06') | Out-Null
    Note 'LANES_DONE'
    exit 0
}

$order = if ($Queue -eq 'q1') { 'S01', 'S07', 'S05', 'S08' } else { 'S02', 'S04', 'S03', 'S06', 'S09' }
foreach ($s in $order) {
    if ($s -in 'S06', 'S08', 'S09') {
        while (-not (Test-Path (Join-Path $sp "lane-done-$s"))) { Start-Sleep 60 }
    } else {
        Note "$s index rebuild"
        python -m nexus index rebuild --case $cases[$s] *> (Join-Path $sp "orch-rebuild-$s.txt")
        Note "$s index rebuild exit $LASTEXITCODE"
    }
    Note "$s modes start (HEAD $(git rev-parse --short HEAD))"
    bash devtools/runbook/sample_runs.sh $cases[$s] $s '1 2 3' *> (Join-Path $sp "orch-modes-$s.txt")
    Note "$s modes done: $(Get-Content (Join-Path $sp "orch-modes-$s.txt") -Tail 1)"
}
Note "QUEUE_DONE $Queue"
