# Shared by tools/fetch-windows-tools.ps1 and tools/fetch-ir-collect.ps1 (dot-sourced).
#
# A rule tree is a shallow git clone of its upstream repository. A fetch fast-forwards the clone to the head of its
# branch, so a run never leaves the rules at an older snapshot; a missing tree is cloned. Untracked files are not
# deleted here: they are reported, because a rule file that upstream renamed or re-IDed is a duplicate to review.
# Returns the short head commit of the tree.
function Sync-GitRules {
    param(
        [Parameter(Mandatory)][string]$Dir,
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Branch,
        [string]$SparsePath = ""
    )
    # Rule paths can pass MAX_PATH below a deep checkout root, so long paths stay on for every git call on the tree.
    if (Test-Path -LiteralPath (Join-Path $Dir ".git")) {
        git -C $Dir config core.longpaths true
        git -C $Dir fetch --depth 1 origin $Branch
        if ($LASTEXITCODE) { throw "fetch of $Url ($Branch) failed" }
        # Always reset, not only when HEAD moved: the reset also repairs an index or working tree that a failed run left behind.
        git -C $Dir reset --hard FETCH_HEAD | Out-Null
        if ($LASTEXITCODE) { throw "reset of $Dir to $Branch failed" }
        $untracked = @(git -C $Dir status --porcelain | Where-Object { $_ -like "?? *" })
        if ($untracked.Count) {
            Write-Warning "$Dir has $($untracked.Count) untracked file(s) that upstream does not hold; review them"
        }
    } else {
        if (Test-Path -LiteralPath $Dir) { Remove-Item -LiteralPath $Dir -Recurse -Force }
        New-Item -ItemType Directory -Force -Path (Split-Path $Dir) | Out-Null
        $cloneArgs = @("--depth", "1", "--branch", $Branch)
        if ($SparsePath) { $cloneArgs += @("--filter=blob:none", "--sparse") }
        git -c core.longpaths=true clone @cloneArgs $Url $Dir
        if ($LASTEXITCODE) { throw "clone of $Url failed" }
        git -C $Dir config core.longpaths true
        if ($SparsePath) {
            git -C $Dir sparse-checkout set $SparsePath
            if ($LASTEXITCODE) { throw "sparse checkout of $SparsePath failed" }
        }
    }
    return (git -C $Dir rev-parse --short HEAD)
}
