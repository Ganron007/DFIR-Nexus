# Local forensic binaries

This folder is **local-only**. Binaries under `windows/` and `linux/` are gitignored.

Default Windows layout (what `run_windows_command` searches):

```
Tools/windows/zimmerman/     Eric Zimmerman (Get-ZimmermanTools, latest net9)
Tools/windows/sysinternals/  Sysinternals Suite (live zip)
Tools/windows/hayabusa/      Hayabusa (GitHub latest)
Tools/windows/suzaku/        Suzaku (GitHub latest / Yamato 2.x)
Tools/windows/extra/         chainsaw, capa, yara (GitHub latest)
Tools/windows/kape/          KAPE — operator download from Kroll only
Tools/windows/VERSIONS.txt   What was fetched + URLs
```

Refresh from official internet URLs only (see fetch script). Do not point Nexus at unrelated personal tool trees.

Refresh Windows downloads:

```powershell
pwsh -File Tools/fetch-windows-tools.ps1
```

Then point Nexus at the tree (semicolon on Windows):

```powershell
$root = (Resolve-Path .\Tools\windows).Path
$env:NEXUS_TOOL_PATHS = "$root\zimmerman;$root\sysinternals;$root\hayabusa;$root\kape;$root\extra"
```

Or set `tool_paths` in `~/.nexus/config.yaml`. The Windows resolver also auto-scans `Tools/windows/*` when that directory exists.

Official sources:

| Tool | URL |
|------|-----|
| Zimmerman | https://ericzimmerman.github.io/ / `Get-ZimmermanTools.ps1` |
| Sysinternals | https://download.sysinternals.com/files/SysinternalsSuite.zip |
| Hayabusa | https://github.com/Yamato-Security/hayabusa/releases |
| Suzaku | https://github.com/Yamato-Security/suzaku/releases |
| KAPE | https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor (no public direct URL) |
| Chainsaw | https://github.com/WithSecureLabs/chainsaw/releases |
| YARA | https://github.com/VirusTotal/yara/releases |
| capa | https://github.com/mandiant/capa/releases |
