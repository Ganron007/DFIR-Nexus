# One round of the tiny cases (TIER1-WORK-ORDERS Part 11, TP3/TP4): the lane on each case, then fresh Mode 1/2/3
# runs on each case whose own lane gate is clear. One build for the whole round (rule 10.1): commit first.
#   pwsh -NoProfile -File devtools/runbook/tiny_round.ps1 -Round R1 [-Cases T01,T05] [-Stage lanes|modes|all]
#        [-Modes "1 2 3"] [-Parallel 2]
# Tags are <Txx>-<Round>: lane log cases/<id>/.trace/lane-<tag>.log, mode logs run-<tag>-mode<N>.log, run ids
# runs-<tag>.ids. The round's table is .runlogs/tiny-<Round>/round.tsv; then run coverage_matrix.py --round <Round>.
param(
    [Parameter(Mandatory)] [string] $Round,
    [string] $Cases = '',
    [ValidateSet('lanes', 'modes', 'all')] [string] $Stage = 'all',
    [string] $Modes = '1 2 3',
    [int] $Parallel = 2
)
$ErrorActionPreference = 'Continue'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $repo
$env:PYTHONIOENCODING = 'utf-8'
$out = Join-Path $repo ".runlogs\tiny-$Round"
New-Item -ItemType Directory -Force $out | Out-Null
$table = Join-Path $out 'round.tsv'
if (-not (Test-Path $table)) { "case`tcase_id`tstep`tstart`tminutes`tresult" | Out-File $table -Encoding utf8 }
$head = git rev-parse --short HEAD
$dirty = git status --porcelain --untracked-files=no
if ($dirty) { throw "The tree has uncommitted changes: a round runs on one committed build (rule 10.1)." }
"$(Get-Date -Format o) round $Round on HEAD $head" | Out-File (Join-Path $out 'round.log') -Append

$manifest = python -c "import json,yaml; print(json.dumps(yaml.safe_load(open('Docs/internal/eval/tiny-cases.yaml', encoding='utf-8'))['cases']))" | ConvertFrom-Json
$wanted = if ($Cases) { $Cases -split ',' | ForEach-Object { $_.Trim() } } else { $manifest.PSObject.Properties.Name }

function Row([string] $t, [string] $cid, [string] $step, [datetime] $start, [string] $result) {
    $min = [math]::Round(((Get-Date) - $start).TotalMinutes, 1)
    "$t`t$cid`t$step`t$($start.ToString('o'))`t$min`t$result" | Out-File $table -Append -Encoding utf8
}

if ($Stage -in 'lanes', 'all') {
    foreach ($t in $wanted) {
        $e = $manifest.$t
        if (-not $e.case_id) { Write-Warning "$t has no case_id: run tiny_cases.py first"; continue }
        $tag = "$t-$Round"
        $laneArgs = @('-NoProfile', '-File', 'devtools/runbook/run_lane.ps1', '-CaseId', $e.case_id, '-Tag', $tag)
        if ($e.sift_inputs -and $e.sift_inputs.Count -gt 0) {
            # A folder is passed as itself; run_lane.ps1 expands it (a file list would pass the command-line limit).
            $inputs = foreach ($rel in $e.sift_inputs) { Join-Path $e.folder $rel }
            $laneArgs += @('-Sift', '-Capture', ($inputs -join ','))
        }
        $start = Get-Date
        pwsh @args *> (Join-Path $out "lane-$tag.txt")
        $code = $LASTEXITCODE
        $gate = python devtools/runbook/gate_unread.py $e.case_id 2>&1 | Select-Object -First 1
        Row $t $e.case_id 'lane' $start "exit $code; $gate"
    }
}

if ($Stage -in 'modes', 'all') {
    $queue = New-Object System.Collections.Queue
    foreach ($t in $wanted) {
        $e = $manifest.$t
        if (-not $e.case_id) { continue }
        $gateFile = Join-Path $repo "cases\$($e.case_id)\analysis\lane_gate.json"
        $status = if (Test-Path $gateFile) { (Get-Content $gateFile -Raw | ConvertFrom-Json).status } else { 'none' }
        if ($status -ne 'clear') { Row $t $e.case_id 'modes' (Get-Date) "not run: gate $status"; continue }
        $queue.Enqueue($t)
    }
    $running = @{}
    while ($queue.Count -gt 0 -or $running.Count -gt 0) {
        foreach ($t in @($running.Keys)) {
            $j = $running[$t]
            if ($j.Process.HasExited) {
                $e = $manifest.$t
                $last = Get-Content (Join-Path $out "modes-$t-$Round.txt") -Tail 1 -ErrorAction SilentlyContinue
                Row $t $e.case_id 'modes' $j.Start "exit $($j.Process.ExitCode); $last"
                $running.Remove($t)
            }
        }
        while ($queue.Count -gt 0 -and $running.Count -lt $Parallel) {
            $t = $queue.Dequeue()
            $e = $manifest.$t
            $log = Join-Path $out "modes-$t-$Round.txt"
            $p = Start-Process -FilePath 'bash' -ArgumentList @('devtools/runbook/sample_runs.sh', $e.case_id, "$t-$Round", "`"$Modes`"") `
                -RedirectStandardOutput $log -RedirectStandardError "$log.err" -NoNewWindow -PassThru
            $running[$t] = [pscustomobject]@{ Process = $p; Start = Get-Date }
        }
        Start-Sleep -Seconds 30
    }
}
"$(Get-Date -Format o) round $Round done" | Out-File (Join-Path $out 'round.log') -Append
Write-Output "Round $Round done. Table: $table. Next: python devtools/runbook/coverage_matrix.py --round $Round --md $out\coverage.md"
