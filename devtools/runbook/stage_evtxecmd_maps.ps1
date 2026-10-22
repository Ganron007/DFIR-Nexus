[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceMaps,

    [Parameter(Mandatory = $true)]
    [string]$RuntimeDirectory
)

$ErrorActionPreference = 'Stop'

$sourceRoot = (Resolve-Path -LiteralPath $SourceMaps).Path
$runtimeRoot = (Resolve-Path -LiteralPath $RuntimeDirectory).Path
$sourceFiles = @(Get-ChildItem -LiteralPath $sourceRoot -File -Recurse | Sort-Object FullName)
if ($sourceFiles.Count -eq 0) {
    throw "No EvtxECmd map files found under '$sourceRoot'."
}

$mapsDirectory = Join-Path $runtimeRoot 'Maps'
if (-not (Test-Path -LiteralPath $mapsDirectory)) {
    New-Item -ItemType Directory -Path $mapsDirectory | Out-Null
}

foreach ($sourceFile in $sourceFiles) {
    $relativePath = [IO.Path]::GetRelativePath($sourceRoot, $sourceFile.FullName)
    $destinationFile = Join-Path $mapsDirectory $relativePath
    $destinationParent = Split-Path -Parent $destinationFile
    if (-not (Test-Path -LiteralPath $destinationParent)) {
        New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
    }

    if (Test-Path -LiteralPath $destinationFile) {
        $sourceHash = (Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash -LiteralPath $destinationFile -Algorithm SHA256).Hash
        if ($sourceHash -ne $destinationHash) {
            throw "Refusing to overwrite a different map file: '$destinationFile'."
        }
    } else {
        Copy-Item -LiteralPath $sourceFile.FullName -Destination $destinationFile
    }
}

$sourceRelativePaths = @($sourceFiles | ForEach-Object {
    [IO.Path]::GetRelativePath($sourceRoot, $_.FullName)
})
$destinationFiles = @(Get-ChildItem -LiteralPath $mapsDirectory -File -Recurse | Sort-Object FullName)
$destinationRelativePaths = @($destinationFiles | ForEach-Object {
    [IO.Path]::GetRelativePath($mapsDirectory, $_.FullName)
})
if (Compare-Object $sourceRelativePaths $destinationRelativePaths) {
    throw "The staged Maps file set does not match '$sourceRoot'."
}

foreach ($sourceFile in $sourceFiles) {
    $relativePath = [IO.Path]::GetRelativePath($sourceRoot, $sourceFile.FullName)
    $destinationFile = Join-Path $mapsDirectory $relativePath
    $sourceHash = (Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash
    $destinationHash = (Get-FileHash -LiteralPath $destinationFile -Algorithm SHA256).Hash
    if ($sourceHash -ne $destinationHash) {
        throw "The staged map hash differs from its source: '$relativePath'."
    }
}

[pscustomobject]@{
    source = $sourceRoot
    destination = $mapsDirectory
    files = $sourceFiles.Count
    status = 'verified'
}
