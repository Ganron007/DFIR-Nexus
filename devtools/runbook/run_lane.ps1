# Run the evidence lane (tools, importer pass, gate, index) on one case (TIER1-WORK-ORDERS Part 10, P2).
#   pwsh -NoProfile -File devtools/runbook/run_lane.ps1 -CaseId CASE-X -Tag S05 [-Sift -Capture <file or folder>[,...]]
# -Sift stages the capture(s) on the SIFT host (a folder stands for every file under it), sets the remote case up
# and runs Zeek there; without it the lane runs
# on this host only. The log is cases/<CASE>/.trace/lane-<Tag>.log; the summary is printed at the end.
param(
    [Parameter(Mandatory)] [string] $CaseId,
    [Parameter(Mandatory)] [string] $Tag,
    [switch] $Sift,
    [switch] $PreflightOnly,
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

# Worktrees share the ignored tool installation through the main checkout. Resolve the
# Git common directory instead of trusting a caller-provided NEXUS_TOOL_PATHS value.
$gitCommonDir = & git rev-parse --path-format=absolute --git-common-dir
if ($LASTEXITCODE -ne 0 -or -not $gitCommonDir) {
    throw 'Cannot resolve the repository Git common directory; refusing to run the lane.'
}
$mainRepo = Split-Path -Parent $gitCommonDir.Trim()
$toolRoot = Join-Path $mainRepo 'Tools\windows'
if (-not (Test-Path -LiteralPath $toolRoot -PathType Container)) {
    throw "Shared Windows tool root is missing at '$toolRoot'; refusing to run the lane."
}
$env:NEXUS_TOOL_PATHS = $toolRoot
# TA-Z: every Zimmerman tool the lane runs is the pinned .NET 10 build (zimmerman-net10.json), and the
# resolver picks exactly that file. A missing tool, another version or another hash refuses the lane.
$pinCheck = & pwsh -NoProfile -File (Join-Path $PSScriptRoot 'zimmerman_net10.ps1') -Verify -LaneOnly 2>&1
$pinExit = $LASTEXITCODE
$pinCheck | Tee-Object -FilePath $log -Append | Out-Null
if ($pinExit -ne 0) {
    $message = "Zimmerman pin preflight failed: $(($pinCheck | Where-Object { $_ -like 'FAIL*' }) -join '; '). Refusing to process evidence."
    $message | Tee-Object -FilePath $log -Append
    throw $message
}
$pins = Get-Content -Raw (Join-Path $PSScriptRoot 'zimmerman-net10.json') | ConvertFrom-Json
$laneTools = @($pins.tools.PSObject.Properties | Where-Object { $_.Value.lane } | ForEach-Object { $_.Name })
$resolved = & python -c "import sys; from nexus.tools.windows import _find_binary; [print(n + '|' + (_find_binary(n.lower()) or '')) for n in sys.argv[1:]]" @laneTools 2>$null
if ($LASTEXITCODE -ne 0 -or -not $resolved) {
    $message = 'Zimmerman resolver preflight could not run; refusing to run the lane.'
    $message | Tee-Object -FilePath $log -Append
    throw $message
}
$wrong = @()
foreach ($line in $resolved) {
    $name, $path = $line.Trim().Split('|', 2)
    $pinned = [IO.Path]::GetFullPath((Join-Path (Join-Path $mainRepo $pins.install_root) $pins.tools.$name.exe))
    if (-not $path -or [IO.Path]::GetFullPath($path) -ne $pinned) { $wrong += "$name resolves to '$path', pinned '$pinned'" }
}
if ($wrong) {
    $message = "Zimmerman resolver preflight: $($wrong -join '; '). Refusing to process evidence."
    $message | Tee-Object -FilePath $log -Append
    throw $message
}
$preflight = "Zimmerman preflight: $($laneTools.Count) lane tools pinned and resolved under $($pins.install_root)"
$preflight | Tee-Object -FilePath $log -Append
if ($PreflightOnly) {
    Write-Output $preflight
    exit 0
}

foreach ($n in 'NEXUS_SIFT_MCP_URL', 'NEXUS_SIFT_EVIDENCE_ROOT', 'NEXUS_SIFT_ZEEK', 'NEXUS_WINDOWS_MCP_URL') {
    Remove-Item "Env:$n" -ErrorAction SilentlyContinue
}
if ($Sift) {
    if (-not $Capture) { throw '-Sift needs -Capture <the capture file(s) or folder(s) to stage, comma-separated>' }
    $env:NEXUS_SIFT_SSH_HOST = $SiftHost
    # A folder is expanded here and the list is passed in-process, as an array: hundreds of paths on one command
    # line pass Windows' 32,767-character limit (T18's NetFlow folder holds 338 files).
    $siftFiles = @(foreach ($item in ($Capture -split ',')) {
        $item = $item.Trim()
        if (-not $item) { continue }
        if (Test-Path -LiteralPath $item -PathType Container) {
            Get-ChildItem -LiteralPath $item -Recurse -File | ForEach-Object FullName
        } else { $item }
    })
    & (Join-Path $repo 'scripts\stage-sift-evidence.ps1') -CaseId $CaseId -Evidence $siftFiles
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
