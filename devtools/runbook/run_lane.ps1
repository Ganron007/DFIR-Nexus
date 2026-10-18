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
    python -m nexus sift setup --case $CaseId
    $env:NEXUS_SIFT_MCP_URL = "http://${SiftHost}:4508/mcp"
    $env:NEXUS_SIFT_ZEEK = '1'
    # Set here, in PowerShell: Git Bash rewrites a /home/... value into a Windows path.
    $env:NEXUS_SIFT_EVIDENCE_ROOT = "/home/sansforensics/.nexus/cases/$CaseId/evidence"
}
"== $Tag $CaseId $(Get-Date -Format o) HEAD $(git rev-parse --short HEAD)" | Tee-Object -FilePath $log
python -m nexus pipeline --mode tools --from-case $CaseId *>> $log
"exit $LASTEXITCODE"
Select-String -Path $log -Pattern 'tool (FAIL|BLOCKED)|lane complete|auto-index|N2 gate|I0 archive|REJECTED|timed out' |
    Select-Object -Last 40 | ForEach-Object { '   ' + $_.Line.Substring(0, [Math]::Min(240, $_.Line.Length)) }
python devtools/runbook/gate_unread.py $CaseId
