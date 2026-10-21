# Run the evidence lane (tools, importer pass, gate, index) on one case (TIER1-WORK-ORDERS Part 10, P2).
#   pwsh -NoProfile -File devtools/runbook/run_lane.ps1 -CaseId CASE-X -Tag S05 [-Sift -Capture <path under the sample>]
# -Sift stages the capture on the SIFT host, sets the remote case up and runs Zeek there; without it the lane runs
# on this host only. The log is cases/<CASE>/.trace/lane-<Tag>.log; the summary is printed at the end.
param(
    [Parameter(Mandatory)] [string] $CaseId,
    [Parameter(Mandatory)] [string] $Tag,
    [switch] $Sift,
    [string] $Capture = '',
    [string] $SiftHost = '192.168.77.135'
)
$ErrorActionPreference = 'Continue'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $repo
$repoSrc = [System.IO.Path]::GetFullPath((Join-Path $repo 'src'))
$pythonPathSeparator = [System.IO.Path]::PathSeparator
if ($env:PYTHONPATH) {
    $env:PYTHONPATH = "$repoSrc$pythonPathSeparator$env:PYTHONPATH"
} else {
    $env:PYTHONPATH = $repoSrc
}
$loadedSrc = & python -c "from pathlib import Path; import nexus; print(Path(nexus.__file__).resolve().parent.parent)"
if ($LASTEXITCODE -ne 0 -or [System.IO.Path]::GetFullPath($loadedSrc.Trim()) -ne $repoSrc) {
    throw "Python imported nexus from '$loadedSrc'; expected this checkout's source at '$repoSrc'. Refusing to run the lane against another tree."
}
$trace = Join-Path $repo "cases\$CaseId\.trace"
New-Item -ItemType Directory -Force $trace | Out-Null
$log = Join-Path $trace "lane-$Tag.log"
$env:PYTHONIOENCODING = 'utf-8'
foreach ($n in 'NEXUS_SIFT_MCP_URL', 'NEXUS_SIFT_EVIDENCE_ROOT', 'NEXUS_SIFT_ZEEK', 'NEXUS_WINDOWS_MCP_URL') {
    Remove-Item "Env:$n" -ErrorAction SilentlyContinue
}
if ($Sift) {
    if (-not $Capture) { throw '-Sift needs -Capture <the capture file to stage>' }
    $env:NEXUS_SIFT_SSH_HOST = $SiftHost
    pwsh -NoProfile -File scripts/stage-sift-evidence.ps1 -CaseId $CaseId -Evidence $Capture
    # The host runs this tree's code: setup refuses to start the MCP on stale code, and --sync-code pushes this
    # tree (the host's previous src is kept as src.bak-<stamp>).
    python -m nexus sift setup --case $CaseId --sync-code
    if ($LASTEXITCODE -ne 0) { throw "nexus sift setup failed for $CaseId (exit $LASTEXITCODE): the SIFT lane cannot run" }
    $env:NEXUS_SIFT_MCP_URL = "http://${SiftHost}:4508/mcp"
    $env:NEXUS_SIFT_ZEEK = '1'
    # Set here, in PowerShell: Git Bash rewrites a /home/... value into a Windows path.
    $env:NEXUS_SIFT_EVIDENCE_ROOT = "/home/sansforensics/.nexus/cases/$CaseId/evidence"
}
"== $Tag $CaseId $(Get-Date -Format o) HEAD $(git rev-parse --short HEAD) PythonSource $repoSrc" | Tee-Object -FilePath $log
python -m nexus pipeline --mode tools --from-case $CaseId *>> $log
$pipelineExitCode = $LASTEXITCODE
"exit $pipelineExitCode" | Tee-Object -FilePath $log -Append
if ($pipelineExitCode -ne 0) {
    $message = "Pipeline failed with exit $pipelineExitCode; skipping the case-wide gate because it may belong to an earlier run."
    $message | Tee-Object -FilePath $log -Append
    Write-Error $message
    exit $pipelineExitCode
}
$completedRun = Select-String -Path $log -Pattern '^\s*run_id=(?<id>RUN-[A-Za-z0-9-]+)\s+status=completed mode=tools\s*$' |
    Select-Object -Last 1
if (-not $completedRun) {
    $message = 'Pipeline returned without a completed tools run_id; skipping the case-wide gate summary.'
    $message | Tee-Object -FilePath $log -Append
    Write-Error $message
    exit 1
}
$runId = $completedRun.Matches[0].Groups['id'].Value
$gatePath = Join-Path $repo "cases\$CaseId\analysis\lane_gate.json"
if (-not (Test-Path -LiteralPath $gatePath)) {
    $message = "Completed run $runId did not write $gatePath; refusing to report a prior gate."
    $message | Tee-Object -FilePath $log -Append
    Write-Error $message
    exit 1
}
$gate = Get-Content -LiteralPath $gatePath -Raw | ConvertFrom-Json
if ($gate.run_id -ne $runId) {
    $message = "Gate run_id '$($gate.run_id)' does not match completed run $runId; refusing to report a stale gate."
    $message | Tee-Object -FilePath $log -Append
    Write-Error $message
    exit 1
}
Select-String -Path $log -Pattern 'tool (FAIL|BLOCKED)|lane complete|auto-index|N2 gate|I0 archive|REJECTED|timed out' |
    Select-Object -Last 40 | ForEach-Object { '   ' + $_.Line.Substring(0, [Math]::Min(240, $_.Line.Length)) }
python devtools/runbook/gate_unread.py $CaseId
exit $LASTEXITCODE
