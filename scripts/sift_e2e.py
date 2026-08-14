#!/usr/bin/env python3
"""SIFT Linux-lane E2E — run ON the SIFT VM (ssh), not on Windows."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0, str(ROOT / "src"))

EV = Path.home() / "DFIR-Nexus" / "Evidence-files"
if not EV.is_dir():
    EV = ROOT / "Evidence-files"
OUT = Path.home() / "sift-e2e-report.md"
rows: list[str] = []


def rec(ok: bool, name: str, detail: str) -> None:
    d = str(detail)[:280].replace("|", "/").replace("\n", " ")
    rows.append(f"| {'yes' if ok else 'NO'} | `{name}` | {d} |")
    print(("PASS" if ok else "FAIL"), name, d[:160])


def sh(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(ROOT))


# ── CLI surface ───────────────────────────────────────────────────────
p = sh([sys.executable, "-m", "nexus.cli.main", "doctor"], timeout=90)
rec(p.returncode == 0, "nexus doctor", (p.stdout or p.stderr)[-350:].replace("\n", " | "))

p = sh([sys.executable, "-m", "nexus.cli.main", "config", "--show"])
rec(p.returncode == 0 and "examiner" in (p.stdout or "").lower(), "nexus config --show", p.stdout[:200])

p = sh([sys.executable, "-m", "nexus.cli.main", "setup", "test"])
rec(p.returncode == 0, "nexus setup test", (p.stdout or p.stderr)[-200:].replace("\n", " "))

# ── MCP Linux tools ───────────────────────────────────────────────────
from nexus.app import create_server

server = create_server()
tools = server._tool_manager._tools
rec("run_command" in tools and "check_tools" in tools, "Linux MCP registered",
    f"n={len(tools)} run_command={'run_command' in tools} check_tools={'check_tools' in tools}")

chk = tools["check_tools"].fn()
present = [t for t in chk if t.get("installed")]
missing = [t for t in chk if not t.get("installed")]
rec(len(present) > 0, "check_tools catalog",
    f"present={len(present)} missing={len(missing)} missing_names={[t['name'] for t in missing[:20]]}")

sug = tools["suggest_tools"].fn(artifact_type="memory")
rec(bool(sug), "suggest_tools memory", json.dumps(sug, default=str)[:200])
sug2 = tools["suggest_tools"].fn(artifact_type="network")
rec(bool(sug2), "suggest_tools network", json.dumps(sug2, default=str)[:200])

runcmd = tools["run_command"].fn
SAFE_CMDS = [
    ("fls", "fls"),
    ("mmls", "mmls"),
    ("tshark -v", "tshark -v"),
    ("yara -v", "yara -v"),
    ("strings --version", "strings --version"),
    ("exiftool -ver", "exiftool -ver"),
    ("ssdeep -V", "ssdeep -V"),
    ("jq --version", "jq --version"),
    ("tcpdump --version", "tcpdump --version"),
    ("evtxinfo", "evtxinfo"),
    ("vol3 -h", "vol3 -h"),
    ("log2timeline.py -h", "log2timeline.py -h"),
    ("bulk_extractor", "bulk_extractor"),
    ("mactime", "mactime"),
    ("capa --version", "capa --version"),
]
for label, cmd in SAFE_CMDS:
    try:
        tout = 90 if any(x in label for x in ("vol3", "log2timeline", "capa")) else 30
        out = runcmd(command=cmd, purpose="sift e2e", timeout=tout)
        ok = bool(out.get("success")) or out.get("metadata", {}).get("exit_code") in (0, 1, 2)
        rec(ok, f"run_command {label}",
            f"ok={out.get('success')} rc={out.get('metadata', {}).get('exit_code')} "
            f"audit={out.get('audit_id')} err={str(out.get('stderr') or out.get('error') or '')[:80]}")
    except Exception as exc:
        rec(False, f"run_command {label}", f"{type(exc).__name__}: {exc}")

# ── Ingest Linux + live Zeek JSON ─────────────────────────────────────
from nexus.ingest.detect import ingest_auto

ingest_targets = [
    EV / "03-linux" / "audit.log",
    EV / "03-linux" / "auth.log",
    EV / "03-linux" / "syslog",
    EV / "03-linux" / "journal.json",
    EV / "03-linux" / "bash_history",
    EV / "04-network" / "monitor-live" / "conn.log",
    EV / "04-network" / "monitor-live" / "eve-tail.json",
    EV / "04-network" / "monitor-live" / "kerberos-20260804.log",
    EV / "_fixtures" / "hayabusa-timeline.csv",
    EV / "_fixtures" / "volatility-pslist.json",
    EV / "_fixtures" / "falco-sysdig.json",
    EV / "_fixtures" / "wmi_subscriptions.csv",
]
for path in ingest_targets:
    if not path.is_file():
        rec(False, f"ingest {path.name}", f"missing {path}")
        continue
    r = ingest_auto(path)
    rec(bool(r.get("success")) and int(r.get("artifacts") or 0) > 0,
        f"ingest {path.name}",
        f"src={r.get('source')} artifacts={r.get('artifacts')} err={r.get('error') or r.get('errors')}")

# ── Case stack on SIFT ────────────────────────────────────────────────
ci = tools["case_init"].fn(name=f"SIFT-E2E-{datetime.now(UTC).strftime('%H%M%S')}",
                           description="Linux lane E2E on siftworkstation")
rec("case_id" in ci or ci.get("status") == "created", "case_init", json.dumps(ci, default=str)[:200])

conn = EV / "04-network" / "monitor-live" / "conn.log"
if conn.is_file():
    er = tools["evidence_register"].fn(path=str(conn), description="live zeek json from monitor")
    aid = er.get("audit_id")
    rec(bool(aid), "evidence_register", json.dumps(er, default=str)[:200])
    ia = tools["ingest_auto"].fn(path=str(conn))
    rec(bool(ia.get("success")) and int(ia.get("artifacts") or 0) > 0,
        "mcp ingest_auto conn.log", f"artifacts={ia.get('artifacts')} src={ia.get('source')}")
    rf = tools["record_finding"].fn(
        title="SIFT ingested live Zeek JSON",
        description="conn.log parsed on SIFT Linux MCP",
        interpretation="Linux lane can ingest CADRE monitor Zeek 8 JSON without Windows.",
        confidence="HIGH",
        confidence_justification="ingest_auto on SIFT returned artifacts>0 for live conn.log",
        attack_ids=["T1071"],
        audit_ids=[aid] if aid else None,
        artifacts=[{"audit_id": aid, "path": str(conn)}] if aid else None,
    )
    rec(rf.get("status") in ("STAGED", "DRAFT") or "finding_id" in rf,
        "record_finding DRAFT", json.dumps(rf, default=str)[:240])

if "generate_report" in tools:
    try:
        gr = tools["generate_report"].fn(profile="executive")
        rec(True, "generate_report", json.dumps(gr, default=str)[:200])
    except Exception as exc:
        rec(False, "generate_report", f"{type(exc).__name__}: {exc}")

# ── Detection extra on SIFT ───────────────────────────────────────────
if "sigma_translate" in tools:
    st = tools["sigma_translate"].fn(
        yaml_content="title: t\nlogsource:\n  product: linux\ndetection:\n  sel:\n    exe: /usr/bin/fls\n  condition: sel\n",
        target="kql",
    )
    rec(bool(st.get("ok")), "sigma_translate", json.dumps(st, default=str)[:200])

if "ti_list_providers" in tools:
    rec(True, "ti_list_providers", json.dumps(tools["ti_list_providers"].fn(), default=str)[:200])

# ── Write report ──────────────────────────────────────────────────────
yes = sum(1 for r in rows if r.startswith("| yes"))
no = sum(1 for r in rows if r.startswith("| NO"))
body = [
    f"# SIFT E2E — {datetime.now(UTC).isoformat()}",
    "",
    f"host=`siftworkstation` tools_mcp=`{len(tools)}` pass=`{yes}` fail=`{no}`",
    "",
    "| ok | name | detail |",
    "|----|------|--------|",
    *rows,
    "",
]
OUT.write_text("\n".join(body) + "\n", encoding="utf-8")
print(f"REPORT {OUT} pass={yes} fail={no}")
sys.exit(0 if no == 0 else 2)
