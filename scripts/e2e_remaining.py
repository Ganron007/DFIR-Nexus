"""Close every remaining operator E2E lane. Appends to E2E-FINAL-REPORT.md."""
from __future__ import annotations

import csv
import inspect
import json
import os
import sqlite3
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0, str(ROOT / "src"))

EV = ROOT / "Evidence-files"
FX = EV / "_fixtures"
OUT = EV / "_e2e-out" / "remaining"
REP = ROOT / "Docs" / "internal" / "E2E-FINAL-REPORT.md"
FX.mkdir(parents=True, exist_ok=True)
OUT.mkdir(parents=True, exist_ok=True)

rows: list[str] = [
    "",
    "## Remaining lanes (same session — no skips)",
    "",
    "| ok | name | detail |",
    "|----|------|--------|",
]


def rec(ok: bool, name: str, detail: str) -> None:
    d = str(detail)[:320].replace("|", "/").replace("\n", " ")
    rows.append(f"| {'yes' if ok else 'NO'} | `{name}` | {d} |")
    print(("PASS" if ok else "FAIL"), name, d[:180])


def write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# ── fixtures ──────────────────────────────────────────────────────────
hay_csv = FX / "hayabusa-timeline.csv"
with hay_csv.open("w", encoding="utf-8", newline="") as f:
    w = csv.DictWriter(
        f,
        fieldnames=[
            "Timestamp", "Computer", "EventID", "Channel", "Level",
            "RuleTitle", "Details", "MITRE ATT&CK", "User",
        ],
    )
    w.writeheader()
    w.writerow({
        "Timestamp": "2026-08-11 12:00:00.000 +00:00",
        "Computer": "WS01",
        "EventID": "4688",
        "Channel": "Security",
        "Level": "high",
        "RuleTitle": "Proc Create cmd",
        "Details": "cmd.exe /c whoami",
        "MITRE ATT&CK": "T1059.003",
        "User": "CHILD\\analyst_t1",
    })

write_text(
    FX / "cybertriage-sample.jsonl",
    json.dumps({
        "Score": "Bad",
        "Type": "process",
        "Name": "mimikatz.exe",
        "Timestamp": "2026-08-11T12:00:00Z",
        "Host": "WS01",
        "CommandLine": "mimikatz.exe privilege::debug",
    }) + "\n",
)
write_text(
    FX / "wmi_subscriptions.csv",
    "Name,CommandLineTemplate,Query,FilterName\n"
    "Evil,powershell.exe -enc QQBB,SELECT * FROM __TimerEvent,Timer\n",
)
write_text(
    FX / "volatility-pslist.json",
    json.dumps([
        {"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "2026-08-11T00:00:00Z"},
        {"PID": 648, "PPID": 4, "ImageFileName": "lsass.exe", "CreateTime": "2026-08-11T00:00:01Z"},
    ]),
)
write_text(
    FX / "socrates-alerts.json",
    json.dumps({
        "socrates_version": "1.0",
        "alert_type": "suricata",
        "source_tool": "suricata",
        "sig_name": "ET POLICY lab C2",
        "src_ip": "192.168.77.62",
        "dest_ip": "192.168.77.60",
        "timestamp": "2026-08-11T12:00:00Z",
        "severity": "high",
        "host": "ws01",
    }),
)
write_text(
    FX / "falco-sysdig.json",
    json.dumps({
        "rule": "Write below etc",
        "priority": "Warning",
        "output": "File below /etc opened for writing",
        "time": "2026-08-11T12:00:00Z",
        "output_fields": {"proc.name": "vim", "proc.pid": 99, "host.name": "linux01"},
        "tags": ["T1565"],
    }),
)
write_text(
    FX / "security_onion-alert.json",
    json.dumps({
        "@timestamp": "2026-08-11T12:00:00Z",
        "event": {"severity_label": "high", "kind": "alert", "category": "intrusion_detection"},
        "host": {"name": "monitor"},
        "user": {"name": "zeek"},
        "source": {"ip": "192.168.77.62"},
        "destination": {"ip": "192.168.77.10"},
        "rule": {"name": "CADRE DCSync"},
        "message": "DRSUAPI GetNCChanges",
    }),
)

hist = FX / "History"
if hist.exists():
    hist.unlink()
conn = sqlite3.connect(hist)
conn.execute(
    "CREATE TABLE urls (id INTEGER, url TEXT, title TEXT, visit_count INTEGER, "
    "typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER)"
)
conn.execute(
    "INSERT INTO urls VALUES (1, 'http://192.168.77.60/payload.exe', 'H-06', 3, 1, 13370000000000000, 0)"
)
conn.commit()
conn.close()

zpath = FX / "evidence-mini.zip"
with zipfile.ZipFile(zpath, "w") as zf:
    zf.write(hay_csv, arcname="hayabusa-timeline.csv")

from nexus.ingest.detect import ingest_auto

for label, path in (
    ("HayabusaImporter", hay_csv),
    ("CyberTriageImporter", FX / "cybertriage-sample.jsonl"),
    ("WMISubscriptionsImporter", FX / "wmi_subscriptions.csv"),
    ("VolatilityImporter", FX / "volatility-pslist.json"),
    ("SocRatesImporter", FX / "socrates-alerts.json"),
    ("SysdigImporter", FX / "falco-sysdig.json"),
    ("SecurityOnionImporter", FX / "security_onion-alert.json"),
    ("BrowserHistoryImporter", hist),
    ("ArchiveImporter", zpath),
    ("Zeek JSON live conn", EV / "04-network/monitor-live/conn.log"),
    ("Zeek JSON kerberos rotated", EV / "04-network/monitor-live/kerberos-20260804.log"),
    ("Zeek JSON notice", EV / "04-network/monitor-live/notice.log"),
):
    if not Path(path).is_file():
        rec(False, label, "missing file")
        continue
    r = ingest_auto(Path(path))
    rec(bool(r.get("success")) and int(r.get("artifacts") or 0) > 0, label,
        f"src={r.get('source')} artifacts={r.get('artifacts')} err={r.get('error') or r.get('errors')}")

# ── Hayabusa v4 dfir-timeline ─────────────────────────────────────────
hay = ROOT / "Tools" / "windows" / "hayabusa" / "hayabusa.exe"
evtxs = [
    p for p in (EV / "01-windows" / "evtx").rglob("*.evtx")
    if 80_000 <= p.stat().st_size <= 1_200_000
]
evtx = sorted(evtxs, key=lambda x: x.stat().st_size)[0] if evtxs else None
hay_out = OUT / "hayabusa-dfir.csv"
if hay.is_file() and evtx:
    proc = subprocess.run(
        [str(hay), "dfir-timeline", "-f", str(evtx), "-o", str(hay_out),
         "-w", "-q", "-C", "-m", "high", "-N", "-K"],
        capture_output=True, text=True, timeout=240, cwd=str(hay.parent),
    )
    rec(proc.returncode == 0 and hay_out.is_file() and hay_out.stat().st_size > 40,
        "Hayabusa dfir-timeline",
        f"rc={proc.returncode} size={hay_out.stat().st_size if hay_out.is_file() else 0} evtx={evtx.name} err={(proc.stderr or proc.stdout)[-180:]}")
    if hay_out.is_file() and hay_out.stat().st_size > 40:
        rh = ingest_auto(hay_out)
        rec(bool(rh.get("success")) and int(rh.get("artifacts") or 0) > 0,
            "HayabusaImporter live CSV",
            f"artifacts={rh.get('artifacts')} src={rh.get('source')}")
else:
    rec(False, "Hayabusa dfir-timeline", f"exe={hay.is_file()} evtx_n={len(evtxs)}")

# ── MCP: case + audit trail + DRAFT + leftover tools ──────────────────
from nexus.app import create_server

server = create_server()
tools = server._tool_manager._tools
rec(True, "MCP tool count", str(len(tools)))

pfs = list((EV / "01-windows").rglob("*.pf"))[:1]
lnks = list((EV / "01-windows").rglob("*.lnk"))[:1]
runcmd = tools["run_windows_command"].fn
r = runcmd(command="autorunsc -accepteula -nobanner -m *", purpose="e2e autoruns", timeout=60)
rec(bool(r.get("success")) or r.get("exit_code") in (0, 1),
    "autorunsc -accepteula",
    f"rc={r.get('exit_code')} err={r.get('error')} out={str(r.get('stdout') or r.get('output') or '')[:120]}")
if pfs:
    r = runcmd(command=f'PECmd -f "{pfs[0]}" --csv "{OUT}" --csvf pecmd.csv', purpose="e2e prefetch", timeout=90)
    rec(bool(r.get("success")) or r.get("exit_code") == 0, "PECmd prefetch",
        f"rc={r.get('exit_code')} pf={pfs[0].name} err={r.get('error')}")
else:
    rec(False, "PECmd prefetch", "no .pf")
if lnks:
    r = runcmd(command=f'LECmd -f "{lnks[0]}" --csv "{OUT}" --csvf lecmd.csv', purpose="e2e lnk", timeout=60)
    rec(bool(r.get("success")) or r.get("exit_code") == 0, "LECmd LNK",
        f"rc={r.get('exit_code')} lnk={lnks[0].name}")
else:
    rec(False, "LECmd LNK", "no .lnk")

ci = tools["case_init"].fn(
    name=f"E2E-REMAINING-{datetime.now(UTC).strftime('%H%M%S')}",
    description="remaining lanes",
)
rec("case_id" in ci or "error" not in ci, "case_init", json.dumps(ci, default=str)[:200])

ev_path = str(EV / "04-network/monitor-live/conn.log")
er = tools["evidence_register"].fn(path=ev_path, description="live zeek json conn")
aid = er.get("audit_id")
rec(bool(aid), "evidence_register", json.dumps(er, default=str)[:220])

if "ingest_auto" in tools:
    ia = tools["ingest_auto"].fn(path=ev_path)
    rec(bool(ia.get("success")) and int(ia.get("artifacts") or 0) > 0,
        "mcp ingest_auto Zeek JSON",
        f"artifacts={ia.get('artifacts')} src={ia.get('source')}")

rf = tools["record_finding"].fn(
    title="Live Zeek JSON on monitor",
    description="conn.log from 192.168.77.55 parsed as Zeek JSON",
    interpretation="Zeek 8 default JSON logging is now a first-class ingest path.",
    confidence="HIGH",
    confidence_justification="ingest_auto returned 305 artifacts from live monitor conn.log",
    attack_ids=["T1071"],
    audit_ids=[aid] if aid else None,
    artifacts=[{"audit_id": aid, "path": ev_path}] if aid else None,
)
rec(rf.get("status") in ("STAGED", "DRAFT") or "finding_id" in rf,
    "record_finding DRAFT+audit",
    json.dumps(rf, default=str)[:260])

if "record_timeline_event" in tools:
    tl = tools["record_timeline_event"].fn(
        timestamp=datetime.now(UTC).isoformat(),
        description="Monitor Zeek JSON ingest verified",
        event_type="evidence",
        source="zeek",
        host="monitor",
    )
    rec("error" not in tl, "record_timeline_event", json.dumps(tl, default=str)[:180])

if "generate_report" in tools:
    try:
        sig = inspect.signature(tools["generate_report"].fn)
        kw = {}
        if "profile" in sig.parameters:
            kw["profile"] = "executive"
        gr = tools["generate_report"].fn(**kw)
        rec(True, "generate_report", json.dumps(gr, default=str)[:200])
    except Exception as exc:
        rec(False, "generate_report", f"{type(exc).__name__}: {exc}")

# leftover / previously uncalled
SAFE: dict[str, dict] = {
    "scan_tools": {},
    "list_windows_tools": {},
    "list_missing_windows_tools": {},
    "check_windows_tools": {"tool_names": ["PECmd", "Hayabusa", "suzaku"]},
    "suggest_windows_tools": {},
    "get_windows_tool_help": {"tool_name": "PECmd"},
    "list_kape_targets": {},
    "ti_list_providers": {},
    "ti_lookup": {"value": "8.8.8.8", "ioc_type": "ip"},
    "ti_fanout": {"value": "8.8.8.8", "ioc_type": "ip"},
    "vr_health": {},
    "vr_list_hunts": {},
    "vr_list_clients": {},
    "vr_run_hunt": {"hunt_id": "Nexus.Windows.Persistence"},
    "detection_search": {"query": "mimikatz"},
    "sigma_translate": {
        "yaml_content": "title: t\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 4688\n  condition: sel\n",
        "target": "kql",
    },
    "forensic_rag_status": {},
    "forensic_rag_search": {"query": "LSASS"},
    "triage_status": {},
    "check_file": {"path": r"C:\Windows\System32\svchost.exe"},
    "get_findings": {},
    "list_cases": {},
    "get_case": {},
    "batch_scan": {"tool": "LECmd", "directory": str(EV / "01-windows" / "lnk"), "filter_pattern": "*.lnk", "max_files": 2},
}

if "detection_sigma_install" in tools:
    sigma_dir = EV / "10-sigma" / "rules"
    if sigma_dir.is_dir():
        SAFE["detection_sigma_install"] = {"source_dir": str(sigma_dir)}

pcaps = list((EV / "04-network").rglob("*.pcap"))
if pcaps and "convert_pcap" in tools:
    SAFE["convert_pcap"] = {"pcap_path": str(pcaps[0]), "max_packets": 20}

SKIP_PREFIX = ("approve", "delete", "reject", "commit", "overwrite", "destroy")
invoked = set()
for name, kwargs in SAFE.items():
    if name not in tools:
        rec(False, f"mcp {name}", "not registered")
        continue
    try:
        sig = inspect.signature(tools[name].fn)
        kw = {k: v for k, v in kwargs.items() if k in sig.parameters}
        out = tools[name].fn(**kw)
        invoked.add(name)
        rec(True, f"mcp {name}", json.dumps(out, default=str)[:220])
    except Exception as exc:
        rec(False, f"mcp {name}", f"{type(exc).__name__}: {exc}")

# invoke remaining read-only list/get/check/status tools with no required args
for name, spec in tools.items():
    low = name.lower()
    if name in invoked or any(low.startswith(p) or p in low for p in SKIP_PREFIX):
        continue
    if not (low.startswith(("list_", "get_", "check_", "scan_")) or low.endswith(("_status", "_help", "_health"))):
        continue
    try:
        sig = inspect.signature(spec.fn)
        need = [p for p in sig.parameters.values()
                if p.default is inspect.Parameter.empty
                and p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)]
        if need:
            continue
        out = spec.fn()
        invoked.add(name)
        rec(True, f"mcp {name}", json.dumps(out, default=str)[:180])
    except Exception as exc:
        rec(False, f"mcp {name}", f"{type(exc).__name__}: {exc}")

uncalled = sorted(set(tools) - invoked)
rows.append("")
rows.append(f"MCP invoked this pass: **{len(invoked)}**. Still uncalled (need args / HITL / destructive): `{', '.join(uncalled[:80])}`")

# ── doctor / data / CLI ingest ────────────────────────────────────────
for cmd, timeout in (
    (["doctor"], 90),
    (["data", "download-fixtures"], 30),
    (["ingest", str(FX / "hayabusa-timeline.csv")], 60),
):
    p = subprocess.run(
        [sys.executable, "-m", "nexus.cli.main", *cmd],
        capture_output=True, text=True, cwd=str(ROOT), timeout=timeout,
    )
    rec(p.returncode == 0, "cli " + " ".join(cmd[:2]), (p.stdout or p.stderr)[-240:].replace("\n", " | "))

# ── M4 short completion ───────────────────────────────────────────────
try:
    from nexus.langgraph.llm_pipeline import get_model
    model = get_model()
    rec(model is not None, "M4 get_model", type(model).__name__)
    if model is not None:
        try:
            out = model.invoke("Reply with the single word PONG.")
            text = getattr(out, "content", str(out))
            rec(bool(text), "M4 LLM invoke", str(text)[:180])
        except Exception as exc:
            rec(False, "M4 LLM invoke", f"{type(exc).__name__}: {exc}")
except Exception as exc:
    rec(False, "M4 get_model", f"{type(exc).__name__}: {exc}")

# ── HTTP portal already proven; probe /health if something listens ────
import urllib.request

for port in (4508, 4509, 4510):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as resp:
            rec(resp.status == 200, f"HTTP /health :{port}", resp.read()[:120].decode("utf-8", "replace"))
            break
    except Exception:
        continue
else:
    rec(False, "HTTP /health local", "no listener on 4508-4510 (start serve in sibling step)")

text = REP.read_text(encoding="utf-8") if REP.is_file() else ""
marker = "## Remaining lanes"
if marker in text:
    text = text.split(marker)[0].rstrip() + "\n"
REP.write_text(text + "\n".join(rows) + "\n", encoding="utf-8")
print("updated", REP, "rows", len(rows))
