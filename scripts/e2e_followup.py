"""Close remaining E2E gaps: JSON Zeek, Hayabusa CSV, M3, DRAFT, leftover MCP, M4 ping."""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EV = ROOT / "Evidence-files"
OUT = EV / "_e2e-out" / "followup"
REP = ROOT / "Docs" / "internal" / "E2E-FINAL-REPORT.md"
sys.path.insert(0, str(ROOT / "src"))
os_chdir = ROOT
import os

os.chdir(ROOT)
OUT.mkdir(parents=True, exist_ok=True)

rows: list[str] = ["", "## Follow-up (same session — remaining gaps)", "", "| ok | name | detail |", "|----|------|--------|"]


def rec(ok: bool, name: str, detail: str) -> None:
    rows.append(f"| {'yes' if ok else 'NO'} | `{name}` | {detail[:300].replace('|','/')} |")
    print(("PASS" if ok else "FAIL"), name, detail[:160])


# JSON Zeek live
from nexus.ingest.detect import ingest_auto

p = EV / "04-network/monitor-live/conn.log"
r = ingest_auto(p)
rec(bool(r.get("success")), "Zeek JSON live conn.log", f"artifacts={r.get('artifacts')} src={r.get('source')} err={r.get('error')}")
r2 = ingest_auto(EV / "04-network/monitor-live/kerberos-20260804.log")
rec(bool(r2.get("success")), "Zeek JSON kerberos-20260804", f"artifacts={r2.get('artifacts')} src={r2.get('source')}")

# TSV zeek still works
tsv = EV / "04-network/zeek/conn.log"
if tsv.is_file():
    r3 = ingest_auto(tsv)
    rec(bool(r3.get("success")), "Zeek TSV conn.log (regression)", f"artifacts={r3.get('artifacts')}")

# Hayabusa csv-timeline then ingest
from nexus.tools.windows import _find_binary

hay = _find_binary("Hayabusa") or _find_binary("hayabusa")
evtxs = [p for p in (EV / "01-windows/evtx").rglob("*.evtx") if 200_000 <= p.stat().st_size <= 1_200_000]
evtx = sorted(evtxs, key=lambda x: x.stat().st_size)[0] if evtxs else None
hay_csv = OUT / "hayabusa.csv"
if hay and evtx:
    proc = subprocess.run(
        [hay, "csv-timeline", "-f", str(evtx), "-o", str(hay_csv), "-q", "--no-wizard"],
        capture_output=True, text=True, timeout=180,
    )
    rec(proc.returncode == 0 and hay_csv.is_file(), "Hayabusa csv-timeline", f"rc={proc.returncode} size={hay_csv.stat().st_size if hay_csv.is_file() else 0}")
    if hay_csv.is_file():
        rh = ingest_auto(hay_csv)
        rec(bool(rh.get("success")), "HayabusaImporter", f"artifacts={rh.get('artifacts')} src={rh.get('source')}")
else:
    rec(False, "Hayabusa csv-timeline", "missing binary or evtx")

# M3
try:
    from nexus.case import CaseManager
    from nexus.config import settings
    from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity
    from nexus.langgraph.pipeline import run_analysis_without_interrupt
    arts = [Artifact(
        id=Artifact.new_id(), artifact_type=ArtifactType.NETWORK,
        source=ArtifactSource.ZEEK, timestamp=datetime.now(UTC),
        severity=Severity.INFORMATIONAL, description="json zeek", host="monitor",
    )]
    cm = CaseManager(settings.cases_root / "cases.db")
    state = run_analysis_without_interrupt("E2E-M3b", arts, cm, case_name="E2E-M3b")
    rec(True, "M3 heuristic pipeline", type(state).__name__)
except Exception as exc:
    rec(False, "M3 heuristic pipeline", f"{type(exc).__name__}: {exc}")

# DRAFT with interpretation
from nexus.app import create_server

server = create_server()
tools = server._tool_manager._tools
r = tools["record_finding"].fn(
    title="Monitor Zeek JSON conn ingested",
    description="Live monitor spool JSON Zeek conn.log",
    interpretation="Lab monitor is shipping Zeek JSON (not TSV) to ELK; importer now parses both.",
    confidence="HIGH",
    confidence_justification="ingest_auto returned artifacts>0 on live conn.log after JSON parse fix",
    attack_ids=["T1071"],
)
rec(r.get("status") != "VALIDATION_FAILED", "record_finding DRAFT", json.dumps(r, default=str)[:240])

# leftover MCP that are safe
for name, kwargs in (
    ("scan_tools", {}),
    ("suggest_windows_tools", {"artifact_type": "evtx"} if "artifact_type" in getattr(tools.get("suggest_windows_tools"), "fn", lambda: None).__code__.co_varnames else {}),
    ("sigma_translate", {"yaml_content": "title: t\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 4688\n  condition: sel\n", "target": "kql"}),
    ("search_threat_intel", {"query": "mimikatz"} if tools.get("search_threat_intel") else None),
    ("get_windows_tool_help", {"tool_name": "PECmd"} if tools.get("get_windows_tool_help") else None),
    ("list_kape_targets", {}),
    ("batch_scan", {"paths": [str(EV / "04-network/monitor-live/dns.log")]} if tools.get("batch_scan") else None),
):
    if name not in tools or kwargs is None:
        rec(False, f"mcp {name}", "missing or skipped")
        continue
    try:
        fn = tools[name].fn
        # drop unknown kwargs
        import inspect
        sig = inspect.signature(fn)
        kw = {k: v for k, v in (kwargs or {}).items() if k in sig.parameters}
        out = fn(**kw)
        rec(True, f"mcp {name}", json.dumps(out, default=str)[:200])
    except Exception as exc:
        rec(False, f"mcp {name}", f"{type(exc).__name__}: {exc}")

# doctor
p = subprocess.run([sys.executable, "-m", "nexus.cli.main", "doctor"], capture_output=True, text=True, cwd=str(ROOT), timeout=90)
rec(p.returncode == 0, "nexus doctor", (p.stdout or p.stderr)[-300:].replace("\n", " | "))

# M4 LLM ping
try:
    from nexus.langgraph.llm_pipeline import get_model
    model = get_model()
    rec(model is not None, "M4 get_model()", type(model).__name__)
except Exception as exc:
    rec(False, "M4 get_model()", f"{type(exc).__name__}: {exc}")

# archive fixture if any zip exists
zips = list(EV.rglob("*.zip"))[:1]
if zips:
    ra = ingest_auto(zips[0])
    rec(bool(ra.get("success")), "ArchiveImporter", f"{zips[0].name} artifacts={ra.get('artifacts')} src={ra.get('source')}")
else:
    rec(False, "ArchiveImporter", "no zip in Evidence-files")

text = REP.read_text(encoding="utf-8")
if "## Follow-up" in text:
    text = text.split("## Follow-up")[0].rstrip() + "\n"
REP.write_text(text + "\n".join(rows) + "\n", encoding="utf-8")
print("updated", REP)
