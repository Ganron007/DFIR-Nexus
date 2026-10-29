# The seven pre-push gates (TIER1-WORK-ORDERS Part 11 rule 12), in order, one result line each.
#   pwsh -NoProfile -File devtools/runbook/gates.ps1
# Every file the gates write stays in the repository's one gitignored folder (AGENTS.md, devtools/scratch.py): the logs
# in scratch/gates/, pytest's root in scratch/pytest/ (tests/conftest.py refuses any other). Exit 0 only when all seven
# pass. Run it with nothing else running (no lane, no mode run).
$ErrorActionPreference = 'Continue'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $repo
# A lane's leftover settings would send the suite to the live SIFT and Windows MCP hosts.
Get-ChildItem env: | Where-Object Name -match '^NEXUS_(SIFT|WINDOWS_MCP)' | ForEach-Object { Remove-Item "env:$($_.Name)" }
$env:PYTHONIOENCODING = 'utf-8'
$out = Join-Path $repo 'scratch\gates'
New-Item -ItemType Directory -Force $out | Out-Null
$codes = [ordered]@{}

ruff check src/ tests/ *> "$out\ruff.txt"; $codes.RUFF = $LASTEXITCODE
python -m pytest -q -p no:cacheprovider --basetemp=scratch/pytest *> "$out\suite.txt"; $codes.SUITE = $LASTEXITCODE
Get-Content "$out\suite.txt" -Tail 1
python tests/functional_audit.py *> "$out\functional_audit.txt"; $codes.FAUDIT = $LASTEXITCODE
Select-String -Path "$out\functional_audit.txt" -Pattern 'RESULTS' | ForEach-Object Line
Push-Location frontend
npm run lint *> "$out\lint.txt"; $codes.LINT = $LASTEXITCODE
npx vitest run *> "$out\vitest.txt"; $codes.VITEST = $LASTEXITCODE
Get-Content "$out\vitest.txt" | Select-String -Pattern 'Test Files|Tests ' | ForEach-Object Line
npm run build *> "$out\build.txt"; $codes.BUILD = $LASTEXITCODE
Pop-Location
python scripts/frontend_style_budget.py *> "$out\style.txt"; $codes.STYLE = $LASTEXITCODE
Get-Content "$out\style.txt" -Tail 1

$codes.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
if ($codes.Values | Where-Object { $_ -ne 0 }) { "GATES NOT GREEN (logs in $out)"; exit 1 }
"GATES GREEN"
exit 0
