#!/usr/bin/env python3
"""SIFT evidence-backed tool runs — ON the VM via SSH wrapper."""
from __future__ import annotations

import os
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path.home() / "DFIR-Nexus"
os.chdir(ROOT)
sys.path.insert(0, str(ROOT / "src"))
EV = ROOT / "Evidence-files"
OUT = Path.home() / "sift-feature-report.md"
rows = []


def rec(ok, name, detail):
    rows.append(f"| {'PASS' if ok else 'FAIL'} | `{name}` | {str(detail)[:280].replace('|','/').replace(chr(10),' ')} |")
    print(("PASS" if ok else "FAIL"), name, str(detail)[:160])


from nexus.app import create_server

s = create_server()
t = s._tool_manager._tools
rc = t["run_command"].fn

auth = EV / "03-linux" / "auth.log"
audit = EV / "03-linux" / "audit.log"
conn = EV / "04-network" / "monitor-live" / "conn.log"
eve = EV / "04-network" / "monitor-live" / "eve-tail.json"
pcap = EV / "04-network" / "httpload-firstseconds.pcap"
bash = EV / "03-linux" / "bash_history"

cmds = [
    ("strings auth.log", f"strings {auth}" if auth.is_file() else None),
    ("strings audit.log", f"strings {audit}" if audit.is_file() else None),
    ("jq conn.log type", f"jq -r .id.resp_p {conn}" if conn.is_file() else None),
    ("tshark -r pcap", f"tshark -r {pcap} -c 10" if pcap.is_file() else None),
    ("file auth.log", f"file {auth}" if auth.is_file() else None),
    ("sha256sum auth", f"sha256sum {auth}" if auth.is_file() else None),
    ("yara -v", "yara -v"),
    ("vol3 -h", "vol3 -h"),
    ("log2timeline.py -h", "log2timeline.py -h"),
    ("fls", "fls"),
    ("mmls", "mmls"),
    ("exiftool auth", f"exiftool {auth}" if auth.is_file() else None),
    ("ssdeep auth", f"ssdeep {auth}" if auth.is_file() else None),
    ("capa --version", "capa --version"),
]

for label, cmd in cmds:
    if not cmd:
        rec(False, label, "evidence missing on SIFT")
        continue
    try:
        out = rc(command=cmd, purpose="sift feature matrix", timeout=60)
        ok = bool(out.get("success")) or out.get("metadata", {}).get("exit_code") in (0, 1, 2)
        rec(ok, label, f"audit={out.get('audit_id')} rc={out.get('metadata',{}).get('exit_code')} head={(out.get('data') or '')[:100]}")
    except Exception as exc:
        rec(False, label, f"{type(exc).__name__}: {exc}")

# ingest on SIFT
from nexus.ingest.detect import ingest_auto

for p in (auth, audit, conn, eve, bash):
    if not p.is_file():
        rec(False, f"ingest {p.name}", "missing")
        continue
    r = ingest_auto(p)
    rec(bool(r.get("success")) and int(r.get("artifacts") or 0) > 0,
        f"ingest {p.name}", f"src={r.get('source')} artifacts={r.get('artifacts')}")

yes = sum(1 for r in rows if r.startswith("| PASS"))
no = sum(1 for r in rows if r.startswith("| FAIL"))
body = [
    f"# SIFT evidence feature run — {datetime.now(UTC).isoformat()}",
    "",
    f"pass={yes} fail={no}",
    "",
    "| status | name | detail |",
    "|--------|------|--------|",
    *rows,
    "",
]
OUT.write_text("\n".join(body) + "\n", encoding="utf-8")
print(f"REPORT {OUT} pass={yes} fail={no}")
sys.exit(0 if no == 0 else 2)
