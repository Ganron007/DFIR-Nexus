# A mode round under Part 11 rule 17: one mode run at a time, each checked before the next starts. A non-zero exit, a
# refused or failed tool call, a failed model call or any traceback stops the round at that point, so the defect is
# fixed before the next run; rerun with the remaining steps. Nothing is excused by name.
#   pwsh -NoProfile -File devtools/runbook/rule17_round.ps1 -Round R1z3b -Steps "T21|3;T05|1;T12|123"
# One string, steps split on ';', each `<case>|<modes as digits>`: `pwsh -File` does not pass an array whose items hold
# spaces, so the first form ('T12|1 2 3') never started.
param(
    [Parameter(Mandatory)] [string] $Round,
    [Parameter(Mandatory)] [string] $Steps
)
$ErrorActionPreference = 'Continue'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $repo
$env:PYTHONIOENCODING = 'utf-8'
$out = Join-Path $repo ".runlogs\tiny-$Round"
New-Item -ItemType Directory -Force $out | Out-Null
$table = Join-Path $out 'round.tsv'
if (-not (Test-Path $table)) { "case`tcase_id`tstep`tstart`tminutes`tresult" | Out-File $table -Encoding utf8 }
if (git status --porcelain --untracked-files=no) { throw "The tree has uncommitted changes: a round runs on one committed build." }
"$(Get-Date -Format o) round $Round on HEAD $(git rev-parse --short HEAD)" | Out-File (Join-Path $out 'round.log') -Append
$manifest = python -c "import json,yaml; print(json.dumps(yaml.safe_load(open('Docs/internal/eval/tiny-cases.yaml', encoding='utf-8'))['cases']))" | ConvertFrom-Json

function Flagged([string] $log) {
    $lines = Get-Content $log
    $hits = @()
    foreach ($line in $lines) {
        if ($line -match ' failed: |model call failed|Traceback \(most recent call last\)|status=failed') { $hits += $line.Trim() }
    }
    return , $hits
}

foreach ($step in ($Steps -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    $t, $digits = $step -split '\|'
    if ($digits -notmatch '^[123]+$') { throw "step '$step': modes are digits 1-3, e.g. T12|123" }
    $modes = ($digits.ToCharArray() | ForEach-Object { [string]$_ }) -join ' '
    $cid = $manifest.$t.case_id
    if (-not $cid) { throw "no case id for $t" }
    $trace = Join-Path $repo "cases\$cid\.trace"
    $tag = "$t-$Round"
    foreach ($m in ($modes -split ' ')) {
        if (Test-Path (Join-Path $trace 'HOLD')) { "$t HOLD is set: $(Get-Content (Join-Path $trace 'HOLD'))"; exit 3 }
        # The tag's later modes append to its run ids; passed as an argument (WSL's bash sees no Windows variable).
        $append = if (Test-Path (Join-Path $trace "runs-$tag.ids")) { 'append' } else { '' }
        $start = Get-Date
        bash devtools/runbook/sample_runs.sh $cid $tag $m $append *> (Join-Path $out "modes-$t-mode$m.txt")
        $code = $LASTEXITCODE
        $log = Join-Path $trace "run-$tag-mode$m.log"
        $hits = @()
        $status = ''
        if (Test-Path $log) {
            $hits = Flagged $log
            $status = (Select-String $log -Pattern 'status=\S+|  completed  |  settled  ' | Select-Object -Last 1).Line
        } else {
            # No log: the runner refused before the mode started; its own output says why.
            $hits = @("the mode did not start: $((Get-Content (Join-Path $out "modes-$t-mode$m.txt") -ErrorAction SilentlyContinue) -join ' ')")
        }
        $min = [math]::Round(((Get-Date) - $start).TotalMinutes, 1)
        "$t`t$cid`tmode $m`t$($start.ToString('o'))`t$min`texit $code; $($hits.Count) flagged; $status" | Out-File $table -Append -Encoding utf8
        "$(Get-Date -Format HH:mm) $t mode $m exit $code in $min min; $($hits.Count) flagged; $status"
        if ($code -ne 0 -or $hits.Count -gt 0) {
            $hits | Select-Object -First 12 | ForEach-Object { "  flagged: $_" }
            "STOPPED after $t mode $m (rule 17): fix the cause, then rerun the remaining steps"
            exit 4
        }
    }
}
"$(Get-Date -Format o) round $Round done" | Out-File (Join-Path $out 'round.log') -Append
"ROUND $Round DONE"
