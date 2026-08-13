# Docs layout (DFIR-Nexus)

| Path | Purpose |
|------|---------|
| `Docs/guide.md`, `ARCHITECTURE.md`, `CLI.md`, `SETUP.md`, `FAQ.md` | **Public product docs** |
| `Docs/cases/TOOL-EVIDENCE-MAP.md` | **Evidence ↔ tool map + report/LLM/RAG contract** |
| `Docs/cases/` | **Live case exports** from the pipeline (`NEXUS_REPO_CASE_ROOT`) |
| `Docs/internal/` | Operator notes (not product surface) |
| `Docs/internal/archive/` | Historical experiments / superseded reports |

## Modes (read TOOL-EVIDENCE-MAP first)

| Mode | LLM? | Output |
|------|------|--------|
| `tools` | **No** | `reports/TOOL-RUN.md` (MCP OK/FAIL ledger) |
| `coverage` | Interpret only | `REPORT.md` from APPROVED findings |
| `design` | ReAct selects tools | `REPORT.md` from APPROVED findings |

`REPORT.md` is a **template from findings**, not an LLM dump of every CSV.

## Cases

Each completed run mirrors into:

```text
Docs/cases/<CASE_ID>/
  README.md
  CASE.yaml
  findings.json          (design/coverage only)
  reports/REPORT.md      ← IR report OR tool-run ledger (tools mode)
  reports/TOOL-RUN.md    ← tools mode
  extractions/
  sift/                  ← pulled via scp until NEXUS_SHARE_ROOT is live
  analysis/snippets.md
  ledger/_tool_lane_ledger.json
  INVENTORY.json
```

Set upfront (KAPE triage + memory — **no E01 required**):

```powershell
$env:NEXUS_REPO_CASE_ROOT = "C:\STUDY\Github\CADRE-Platform\DFIR-Nexus\Docs\cases"
$env:NEXUS_SIFT_SSH_HOST = "192.168.77.135"
$env:NEXUS_SIFT_SSH_KEY = "$env:USERPROFILE\.ssh\cadre-sift-key"
$env:NEXUS_SIFT_EVIDENCE_ROOT = "/home/sansforensics/Evidence-files/rocba-500"
$env:NEXUS_SIFT_MEMORY_FILE = "/home/sansforensics/Evidence-files/rocba-500/memory/Rocba-Memory.raw"
$env:NEXUS_SIFT_TRIAGE_ROOT = "/mnt/windows_mount"
$env:NEXUS_SHARE_ROOT = "H:\C"
$env:NEXUS_RAG_MODEL = "BAAI/bge-base-en-v1.5"
# Optional only — full disk image, not part of KAPE triage pack testing:
# $env:NEXUS_SIFT_E01 = "/home/sansforensics/Evidence-files/rocba-500/C-Drive/rocba-cdrive.e01"
$env:NEXUS_TOOL_LANE_STRICT = "1"
$env:NEXUS_PIPELINE_MODE = "tools"   # prove MCP tools first
```

**Shared evidence:** Windows SMB-shares `H:\C` as `kape`; SIFT mounts `/mnt/windows_mount`. Run `scripts/lab_share_kape.ps1` (elevated). SCP is fallback for SIFT case pull only.

## Rocba-500 runs (2026-08-12)

Read [ROCBA-500-MODES.md](ROCBA-500-MODES.md) first. Do **not** treat `C:\Users\Ganro\.nexus\cases\` as the report folder — that is the runtime store (audit DB + full CSVs). Pipeline `report_path` is the repo export under this directory.

| Mode | Case | Report |
|------|------|--------|
| tools | `INC-20260812165727` | [TOOL-RUN.md](INC-20260812165727/reports/TOOL-RUN.md) |
| coverage | `INC-20260812171906` | [REPORT.md](INC-20260812171906/reports/REPORT.md) |
| design | `INC-20260812173933` | [REPORT.md](INC-20260812173933/reports/REPORT.md) |
