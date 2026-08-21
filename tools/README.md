# Local forensic binaries

This folder is **local-only**. Binaries under `windows/` and `linux/` are gitignored.
**Fetch them before any pipeline run.** `nexus doctor` must be golden-path ok.

Default Windows layout (what `run_windows_command` searches):

```
Tools/windows/zimmerman/     Eric Zimmerman (Get-ZimmermanTools, latest net9)
Tools/windows/sysinternals/  Sysinternals Suite (Stage 0 live: autorunsc, handle, tcpvcon, listdlls, pslist, psloggedon, logonsessions, pipelist)
Tools/windows/hayabusa/      Hayabusa — N2 parser and Stage 0 live EVTX hunter
Tools/windows/suzaku/        Suzaku — N2 parser and Stage 0 live EVTX hunter
Tools/windows/extra/         chainsaw (+ sigma/rules sparse tree), capa, yara, bmc-tools.py, KStrike.py,
                             BitsParser/ (FireEye tree — not a single file)
Tools/windows/kape/          KAPE — operator download from Kroll only
Tools/windows/kansa/         Kansa (`tools/fetch-ir-collect.ps1`)
Tools/windows/orc/           DFIR-ORC (ANSSI; same fetch script)
Tools/windows/memory/        WinPmem (DumpIt if present is never invoked)
Tools/linux/uac/             UAC (staged here; copied to Linux target at collect)
Tools/linux/avml/avml        AVML Linux x86_64 (copied to target at collect)
Tools/windows/VERSIONS.txt   What was fetched + URLs
Tools/windows/COLLECT-VERSIONS.txt  Stage 0 fetch log
```

Default Linux / SIFT layout (what `run_command` searches after PATH):

```
Tools/linux/extra/           bmc-tools.py, BitsParser/, KStrike.py
Tools/linux/VERSIONS.txt
```

Core SIFT binaries (`vol`, `fls`, `mactime`, `esedbexport`) come from the SIFT
workstation / apt. The fetch script only vendors the same portable Python
parsers the Windows lane uses.

Refresh from official internet URLs only. Do not point Nexus at unrelated
personal tool trees.

```powershell
# Windows examiner host
pwsh -File tools/fetch-windows-tools.ps1
nexus doctor
```

```bash
# SIFT / Linux analysis host
bash tools/fetch-linux-tools.sh
nexus doctor
```

The Windows resolver auto-scans `Tools/windows/*` when that directory exists.
The SIFT resolver auto-scans `Tools/linux/*` in addition to `PATH`.
You can still set `NEXUS_TOOL_PATHS` / `tool_paths` in `~/.nexus/config.yaml`.

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
| bmc-tools | https://github.com/ANSSI-FR/bmc-tools (portable `.py`) |
| BitsParser | https://github.com/fireeye/BitsParser (full tree). Fetch vendors ANSSI `bits`+`construct` 2.8 **inside that folder** — do not pip-install `bits_parser` into Nexus |
| KStrike | https://github.com/brimorlabs/KStrike + `pip install libesedb-python` (Nexus interpreter) |
