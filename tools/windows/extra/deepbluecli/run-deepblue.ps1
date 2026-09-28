param(
    [Parameter(Mandatory=$true)][string]$Evtx,
    [Parameter(Mandatory=$true)][string]$Out
)
$ErrorActionPreference = "Continue"
$script = (Get-ChildItem -Path $PSScriptRoot -Recurse -Filter "DeepBlue.ps1" | Select-Object -First 1).FullName
if (-not $script) {
    Write-Host "run-deepblue: DeepBlue.ps1 not found under $PSScriptRoot"
    exit 2
}

# Accept one EVTX file or a directory of them. DeepBlueCLI's own behaviour drives
# this wrapper's shape:
#   * it takes a single file, reads the first event's LogName, and queries that
#     log's EventID set with -ErrorAction Stop;
#   * when none of the queried EventIDs exist it writes "Get-WinEvent error: No
#     events were found..." and calls `exit` - a legitimate "no detections";
#   * when the file's LogName is outside its supported set it prints
#     "Logic error 3, should not reach here..." and exits 1 - a tool limitation,
#     not a failure of the evidence.
# The earlier wrapper passed a directory straight through, so every run errored
# with "does not appear to be a valid log file", wrote a 0-byte JSON, and was
# still recorded OK by the lane. This version runs one file at a time, survives
# the per-file exits, merges the detection records with their source file, and
# always writes valid JSON so a 0-byte output means the wrapper itself died.

$files = @()
if (Test-Path -LiteralPath $Evtx -PathType Container) {
    $files = @(Get-ChildItem -LiteralPath $Evtx -Recurse -Filter *.evtx -File | Sort-Object FullName)
} elseif (Test-Path -LiteralPath $Evtx -PathType Leaf) {
    $files = @(Get-Item -LiteralPath $Evtx)
} else {
    Write-Host "run-deepblue: no such path: $Evtx"
    exit 2
}
if ($files.Count -eq 0) {
    Write-Host "run-deepblue: no .evtx files under $Evtx"
    exit 2
}

$records = New-Object System.Collections.ArrayList
$hard = 0
foreach ($f in $files) {
    Push-Location (Split-Path $script)
    try {
        # `$captured`, not `$out`: PowerShell variables are case-insensitive, and
        # `$out` is the same variable as the mandatory `$Out` parameter - the
        # first capture overwrote the output path and the JSON was written to a
        # file named after the capture text.
        $captured = & $script $f.FullName 6>&1 2>&1
    } finally {
        Pop-Location
    }
    $text = (@($captured | ForEach-Object { "$_" }) -join "`n")
    if ($text -match "No events were found that match the specified selection criteria") {
        Write-Host "deepblue: $($f.Name): no matching events (none of the queried EventIDs present)"
        continue
    }
    if ($text -match "Logic error 3") {
        Write-Host "deepblue: $($f.Name): unsupported log type - DeepBlueCLI covers Security, System, Application, AppLocker, PowerShell, Sysmon, WMI-Activity; skipped"
        continue
    }
    if ($text -match "does not appear to be a valid log file" -or $text -match "no such file") {
        Write-Host "deepblue: $($f.Name): HARD ERROR: $(($text.Trim() -replace '\s+', ' '))"
        $hard++
        continue
    }
    $before = $records.Count
    foreach ($o in $captured) {
        if ($o -is [System.Management.Automation.PSCustomObject]) {
            Add-Member -InputObject $o -NotePropertyName SourceFile -NotePropertyValue $f.Name -Force
            [void]$records.Add($o)
        }
    }
    if ($records.Count -eq $before) {
        Write-Host "deepblue: $($f.Name): processed, no detections"
    }
}

# One JSON object per line (NDJSON). The case indexer works row-by-row: a
# pretty-printed array fragments every record across ~10 line-documents, splits
# the Date away from the rest of the record, and inflates the doc count 10x
# (1,982 docs for 198 detections, measured on the R1 Security.evtx). NDJSON
# keeps one complete record per line, which is the shape the ES mappings and
# the timestamp extractor both expect.
$arr = @($records)
if ($arr.Count -eq 0) {
    "[]" | Out-File -Encoding utf8 $Out
} else {
    $lines = foreach ($r in $arr) { ConvertTo-Json -InputObject $r -Depth 6 -Compress }
    $lines | Out-File -Encoding utf8 $Out
}
Write-Host "deepblue: $($arr.Count) detection(s) from $($files.Count) file(s), $hard hard error(s) -> $Out"
if ($hard -gt 0) { exit 1 }
exit 0
