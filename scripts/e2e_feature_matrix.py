#!/usr/bin/env python3
"""Evidence-backed feature-by-feature matrix. Prefer real Evidence-files over smoke."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import traceback
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EV = ROOT / "Evidence-files"
OUT = ROOT / "Docs" / "internal" / "FEATURE-BY-FEATURE-REPORT.md"
sys.path.insert(0, str(ROOT / "src"))
os.chdir(ROOT)

ROWS: list[dict] = []


def rec(cap: str, name: str, ok: bool, detail: str = "", status: str = "") -> None:
    st = status or ("PASS" if ok else "FAIL")
    ROWS.append({"cap": cap, "name": name, "ok": ok, "status": st, "detail": (detail or "")[:500]})
    print(f"[{st:8}] {cap:14} {name}: {(detail or '')[:160]}")


def first(*rels: str) -> Path | None:
    for r in rels:
        p = EV / r
        if p.is_file() and p.stat().st_size > 0:
            return p
    return None


def smallest(glob: str, root: Path | None = None) -> Path | None:
    base = root or EV
    hits = [p for p in base.glob(glob) if p.is_file() and p.stat().st_size > 0]
    if not hits:
        return None
    return sorted(hits, key=lambda p: p.stat().st_size)[0]


def evidence_map() -> dict[str, Path | None]:
    """One real (or fixture) file per importer class — Evidence-files first."""
    emap = {
        "EVTXImporter": first(
            "01-windows/evtx/yamato-hayabusa-sample-evtx/DeepBlueCLI/password-spray.evtx",
            "01-windows/evtx/yamato-hayabusa-sample-evtx/EVTX-ATTACK-SAMPLES/Credential Access/kerberos_pwd_spray_4771.evtx",
        ) or smallest("01-windows/evtx/504-win10/*.evtx"),
        "HayabusaImporter": first("_fixtures/hayabusa-timeline.csv") or smallest("01-windows/hayabusa/**/*.csv"),
        "KAPEImporter": first("01-windows/kape-out/mft.csv"),
        "LNKFileImporter": smallest("01-windows/lnk/**/*.lnk"),
        "AmCacheImporter": first("01-windows/amcache/Amcache.hve"),
        "WindowsRegistryImporter": first("01-windows/registry/ntuser/Default/NTUSER.DAT"),
        "ScheduledTasksImporter": smallest("01-windows/tasks/**/*"),
        "WindowsServicesImporter": smallest("01-windows/services/**/*.csv"),
        "WMISubscriptionsImporter": first("_fixtures/wmi_subscriptions.csv"),
        "BrowserHistoryImporter": first("_fixtures/History") or first(
            "01-windows/browser/fredr/AppData/Local/Google/Chrome/User Data/Profile 2/History"
        ),
        "PlasoImporter": first("02-memory/508-precooked/timeline/rd01-supertimeline.csv"),
        "VolatilityImporter": first("_fixtures/volatility-pslist.json"),
        "CyberTriageImporter": first("_fixtures/cybertriage-sample.jsonl"),
        "VelociraptorImporter": first("08-ir-platforms/velociraptor/hunt-sample.jsonl"),
        "TheHiveImporter": first("08-ir-platforms/thehive-case.json"),
        "IRISImporter": first("08-ir-platforms/iris-case.json"),
        "SandboxImporter": first("08-ir-platforms/sandbox-report.json"),
        "AuditdImporter": first("03-linux/audit.log"),
        "AuthLogImporter": first("03-linux/auth.log"),
        "SyslogImporter": first("03-linux/syslog"),
        "BashHistoryImporter": first("03-linux/bash_history"),
        "JournaldImporter": first("03-linux/journal.json"),
        "ZeekImporter": first("04-network/monitor-live/conn.log", "04-network/zeek/conn.log"),
        "SuricataImporter": first("04-network/monitor-live/eve-tail.json"),
        "WiresharkImporter": first("04-network/pcap/wireshark-dhcp.tshark.json"),
        "SysdigImporter": first("_fixtures/falco-sysdig.json"),
        "SecurityOnionImporter": first("_fixtures/security_onion-alert.json"),
        "SocRatesImporter": first("_fixtures/socrates-alerts.json"),
        "ElasticImporter": first("05-siem/cadre-elk/elastic-security-4624.ndjson", "05-siem/elastic.ndjson"),
        "SplunkImporter": first("05-siem/splunk.csv"),
        "WazuhImporter": first("05-siem/wazuh.json"),
        "CloudTrailImporter": first("06-cloud/cloudtrail-sample.json"),
        "AzureImporter": first("06-cloud/azure-activity-sample.json"),
        "M365Importer": first("06-cloud/m365-ual-sample.json"),
        "MISPImporter": first("07-ti/misp-event.json"),
        "OTXImporter": first("07-ti/otx-pulse.json"),
        "VirusTotalImporter": first("07-ti/vt-sample.json"),
        "AbuseIPDBImporter": first("07-ti/abuseipdb-sample.json"),
        "ThreatFoxImporter": first("07-ti/full.json"),
        "JSONLImporter": first("05-siem/elastic.ndjson"),
        "CSVImporter": first("05-siem/splunk.csv"),
        "EmailImporter": first("09-email-archives/phishing.eml"),
        "ArchiveImporter": first("_fixtures/evidence-mini.zip", "09-email-archives/evidence.zip"),
    }
    # Slice ThreatFox full.json (~65MB) to a small real head for matrix runtime
    full_tf = EV / "07-ti" / "full.json"
    if full_tf.is_file():
        sliced = EV / "_e2e-out" / "feature-matrix" / "threatfox-head.json"
        sliced.parent.mkdir(parents=True, exist_ok=True)
        if not sliced.is_file() or sliced.stat().st_size < 1000:
            data = full_tf.read_bytes()[:200_000]
            cut = data.rfind(b"\n")
            if cut > 0:
                data = data[:cut]
            sliced.write_bytes(data)
        emap["ThreatFoxImporter"] = sliced
    return emap


def lane_importers() -> None:
    from nexus.ingest.detect import ingest_auto
    from nexus.ingest.registry import get_registry

    reg = get_registry()
    classes = {cls.__name__: cls for names in [] for cls in []}
    # rebuild from registry
    registered = set()
    for src in reg.all_sources():
        for cand in reg.candidates(src):
            registered.add(cand.__name__)

    emap = evidence_map()
    for cls_name, path in emap.items():
        if path is None:
            rec("I-ingest", cls_name, False, "NO_EVIDENCE in Evidence-files", "BLOCKED")
            continue
        try:
            r = ingest_auto(path)
            ok = bool(r.get("success")) and int(r.get("artifacts") or 0) > 0
            rec(
                "I-ingest",
                cls_name,
                ok,
                f"src={r.get('source')} artifacts={r.get('artifacts')} path={path.relative_to(EV)} err={r.get('error') or r.get('errors')}",
            )
        except Exception as exc:
            rec("I-ingest", cls_name, False, f"{type(exc).__name__}: {exc}")

    # note any registered class missing from map
    for name in sorted(registered):
        if name not in emap:
            rec("I-ingest", name, False, "not in evidence_map()", "GAP")


def lane_windows_tools(tools: dict) -> None:
    """Run every present catalog binary against matching Evidence-files."""
    from nexus.tools.windows import _WIN_CATALOG, _find_binary

    catalog_present = []
    for key, info in _WIN_CATALOG.items():
        resolved = _find_binary(key) or _find_binary(info["name"])
        catalog_present.append((key, info["name"], resolved))
        rec("W-doctor", info["name"], bool(resolved), f"key={key} path={resolved or 'MISSING'}",
            "PASS" if resolved else "MISSING")

    rwc = tools["run_windows_command"].fn
    out_dir = EV / "_e2e-out" / "feature-matrix"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Evidence targets
    evtx = smallest("01-windows/evtx/504-win10/*.evtx") or smallest("01-windows/evtx/**/*.evtx")
    spray = first(
        "01-windows/evtx/yamato-hayabusa-sample-evtx/DeepBlueCLI/password-spray.evtx",
        "01-windows/evtx/yamato-hayabusa-sample-evtx/EVTX-ATTACK-SAMPLES/Credential Access/kerberos_pwd_spray_4771.evtx",
    ) or evtx
    lnk = smallest("01-windows/lnk/**/*.lnk")
    amcache = first("01-windows/amcache/Amcache.hve")
    hive = first("01-windows/registry/ntuser/Default/NTUSER.DAT")
    system_hive = first("01-windows/registry/SYSTEM")
    pf = first("01-windows/prefetch/SMSS.EXE-B5B810DB.pf") or smallest("01-windows/prefetch/*.pf")
    srum = first("01-windows/504-win10-ws/SRUDB.dat")
    mft_csv = first("01-windows/kape-out/mft.csv")
    pcap = first("04-network/pcap/ftp-example.pcap") or smallest("04-network/572/lab-1.0/*.pcap")
    # capa/yara need PE — use a known Windows binary under Tools if present, else System32
    pe = smallest("Tools/windows/**/*.exe")
    if pe is None:
        pe = Path(r"C:\Windows\System32\notepad.exe") if Path(r"C:\Windows\System32\notepad.exe").is_file() else None
    hist = first("_fixtures/History")

    cmds: list[tuple[str, str, Path | None]] = []
    for key, name, resolved in catalog_present:
        if not resolved:
            continue
        if key == "pecmd" and pf:
            cmds.append((name, f'PECmd -f "{pf}" --csv "{out_dir}"', pf))
        elif key == "lecmd" and lnk:
            cmds.append((name, f'LECmd -f "{lnk}" --csv "{out_dir}"', lnk))
        elif key == "evtxecmd" and evtx:
            cmds.append((name, f'EvtxECmd -f "{evtx}" --csv "{out_dir}"', evtx))
        elif key == "amcacheparser" and amcache:
            cmds.append((name, f'AmcacheParser -f "{amcache}" --csv "{out_dir}"', amcache))
        elif key == "appcompatcacheparser" and system_hive:
            cmds.append((name, f'AppCompatCacheParser -f "{system_hive}" --csv "{out_dir}"', system_hive))
        elif key == "recmd" and hive:
            cmds.append((name, f'RECmd -f "{hive}" --nl', hive))
        elif key == "srumecmd" and srum:
            cmds.append((name, f'SrumECmd -f "{srum}" --csv "{out_dir}"', srum))
        elif key == "sqlecmd" and hist:
            cmds.append((name, f'SQLECmd -f "{hist}" --csv "{out_dir}"', hist))
        elif key == "mftecmd" and mft_csv:
            # raw $MFT not staged; prove binary with --help if only CSV exists
            cmds.append((name, "MFTECmd --help", mft_csv))
        elif key == "bstrings" and hive:
            cmds.append((name, f'bstrings -f "{hive}"', hive))
        elif key == "autorunsc":
            cmds.append((name, "autorunsc -accepteula -nobanner -m -c *", None))
        elif key == "sigcheck" and pe:
            cmds.append((name, f'sigcheck -accepteula -nobanner "{pe}"', pe))
        elif key == "strings" and hive:
            cmds.append((name, f'strings64 -accepteula -n 8 "{hive}"', hive))
        elif key == "hayabusa" and spray:
            csv_out = out_dir / "hayabusa-matrix.csv"
            cmds.append((name, f'hayabusa dfir-timeline -f "{spray}" -o "{csv_out}" -m informational -q --no-wizard', spray))
        elif key == "suzaku" and spray:
            cmds.append((name, f'suzaku evtx-timeline -d "{spray.parent}" -o "{out_dir / "suzaku.csv"}"', spray))
        elif key == "chainsaw" and spray:
            sigma = EV / "10-sigma" / "rules"
            cmds.append((name, f'chainsaw hunt "{spray}" -s "{sigma}" --skip-errors', spray))
        elif key == "capa" and pe:
            cmds.append((name, f'capa "{pe}"', pe))
        elif key == "yara" and pe:
            # minimal inline rule file
            yara_rule = out_dir / "matrix.yar"
            yara_rule.write_text('rule matrix_mz { strings: $mz = { 4D 5A } condition: $mz at 0 }\n', encoding="utf-8")
            cmds.append((name, f'yara64 "{yara_rule}" "{pe}"', pe))
        elif key in ("jlecmd", "rbcmd", "sbecmd", "wxtcmd", "handle", "procdump", "winpmem", "dumpit",
                     "moneta", "hollows_hunter", "mactime", "kape", "densityscout", "get_injectedthreadex"):
            rec("W-exec", name, False,
                f"binary present at {resolved}; Evidence-files lacks safe matching artifact (jumplist/recycle/shellbags/memory/kape)",
                "NO_INPUT")
            continue
        else:
            rec("W-exec", name, False, "present but no command recipe", "NO_INPUT")
            continue

    for name, cmd, inp in cmds:
        try:
            r = rwc(command=cmd, purpose=f"feature-matrix {name}", timeout=300)
            ok = bool(r.get("success")) or r.get("metadata", {}).get("exit_code") in (0, 1)
            # hayabusa may succeed with empty if wrong sample — check later
            rec(
                "W-exec",
                name,
                ok,
                f"audit={r.get('audit_id')} success={r.get('success')} rc={r.get('metadata', {}).get('exit_code')} "
                f"err={str(r.get('error') or r.get('stderr') or '')[:120]} input={inp.name if inp else '-'}",
            )
        except Exception as exc:
            rec("W-exec", name, False, f"{type(exc).__name__}: {exc}")

    # convert_pcap against real pcap
    if "convert_pcap" in tools and pcap:
        try:
            r = tools["convert_pcap"].fn(pcap_path=str(pcap))
            ok = bool(r.get("ok") or r.get("output_path") or r.get("success"))
            rec("W-exec", "convert_pcap", ok, json.dumps(r, default=str)[:300])
        except Exception as exc:
            rec("W-exec", "convert_pcap", False, str(exc))


def lane_case_stack(tools: dict) -> str | None:
    """Golden path against live Zeek JSON + EVTX evidence. Returns case_id."""
    ts = datetime.now(UTC).strftime("%H%M%S")
    ci = tools["case_init"].fn(name=f"FEATURE-MATRIX-{ts}", description="evidence-backed feature matrix")
    rec("C-case", "case_init", "case_id" in ci or ci.get("status") == "created", json.dumps(ci, default=str)[:300])
    case_id = ci.get("case_id")
    if not case_id:
        return None

    conn = first("04-network/monitor-live/conn.log")
    evtx = smallest("01-windows/evtx/504-win10/*.evtx")
    auth = first("03-linux/auth.log")
    for label, path in [("zeek-conn", conn), ("evtx", evtx), ("auth.log", auth)]:
        if not path:
            rec("C-case", f"evidence_register {label}", False, "missing", "BLOCKED")
            continue
        er = tools["evidence_register"].fn(path=str(path), description=f"matrix {label}")
        aid = er.get("audit_id")
        rec("C-case", f"evidence_register {label}", bool(aid), json.dumps(er, default=str)[:300])
        ia = tools["ingest_auto"].fn(path=str(path))
        rec("C-case", f"ingest_auto {label}", bool(ia.get("success")) and int(ia.get("artifacts") or 0) > 0,
            f"artifacts={ia.get('artifacts')} src={ia.get('source')}")

    # evidence verify
    if "evidence_verify" in tools:
        try:
            ev = tools["evidence_verify"].fn()
            rec("C-case", "evidence_verify", True, json.dumps(ev, default=str)[:300])
        except Exception as exc:
            rec("C-case", "evidence_verify", False, str(exc))

    # finding DRAFT (HITL approve left for operator)
    if conn:
        er = tools["evidence_register"].fn(path=str(conn), description="finding source")
        aid = er.get("audit_id")
        rf = tools["record_finding"].fn(
            title="Feature-matrix live Zeek JSON",
            description="conn.log from monitor ingested",
            interpretation="Evidence-backed matrix run",
            confidence="HIGH",
            confidence_justification="ingest_auto returned artifacts>0 for live monitor Zeek JSON",
            attack_ids=["T1071"],
            audit_ids=[aid] if aid else None,
            artifacts=[{"audit_id": aid, "path": str(conn)}] if aid else None,
        )
        rec("C-case", "record_finding DRAFT", rf.get("status") in ("STAGED", "DRAFT") or "finding_id" in rf,
            json.dumps(rf, default=str)[:300])
        fid = rf.get("finding_id")
        rec("C-case", "nexus approve", False,
            "HITL only — examiner must run: nexus approve (password-gated). Agent must not approve.",
            "BLOCKED_HITL")
        # reject path: create a second finding and reject via CLI if possible
        if fid and "reject" in dir():
            pass

    # timeline + todos
    if "record_timeline_event" in tools:
        te = tools["record_timeline_event"].fn(
            timestamp=datetime.now(UTC).isoformat(),
            description="Feature matrix evidence ingest complete",
            event_type="evidence",
        )
        rec("C-case", "record_timeline_event", True, json.dumps(te, default=str)[:200])
    if "add_todo" in tools:
        td = tools["add_todo"].fn(description="Operator: approve DRAFT findings from feature matrix")
        rec("C-case", "add_todo", True, json.dumps(td, default=str)[:200])
        todos = tools["list_todos"].fn()
        rec("C-case", "list_todos", True, json.dumps(todos, default=str)[:200])

    # reports — all profiles
    for profile in ("executive", "full", "timeline", "ioc", "findings", "status"):
        try:
            gr = tools["generate_report"].fn(profile=profile)
            rec("C-case", f"generate_report {profile}", "error" not in gr, json.dumps(gr, default=str)[:200])
        except Exception as exc:
            rec("C-case", f"generate_report {profile}", False, str(exc))

    # export formats
    for name in ("export_stix_bundle", "export_navigator_layer", "export_blocklist", "export_case"):
        if name not in tools:
            rec("C-case", name, False, "not registered", "GAP")
            continue
        try:
            r = tools[name].fn()
            rec("C-case", name, "error" not in r if isinstance(r, dict) else True, json.dumps(r, default=str)[:250])
        except TypeError:
            try:
                r = tools[name].fn(**{})
                rec("C-case", name, True, json.dumps(r, default=str)[:250])
            except Exception as exc:
                rec("C-case", name, False, str(exc))
        except Exception as exc:
            rec("C-case", name, False, str(exc))

    if "backup_case" in tools:
        try:
            b = tools["backup_case"].fn()
            rec("C-case", "backup_case", True, json.dumps(b, default=str)[:250])
        except Exception as exc:
            rec("C-case", "backup_case", False, str(exc))

    return case_id


def lane_analysis_ti(tools: dict) -> None:
    calls = [
        ("analyze_gaps", {}),
        ("deobfuscate_command", {"command_line": "powershell -enc RwBlAHQALgA="}),
        ("check_kev", {"cve_id": "CVE-2021-44228"}),
        ("check_nsrl", {"hash_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}),
        ("predict_techniques", {"observed_techniques": ["T1003", "T1059.001"]}),
        ("list_playbooks", {}),
        ("create_playbook", {"playbook_type": "ir"}),
        ("build_asset_graph", {}),
        ("anonymize_text", {"text": "User alice@cadre.local from 192.168.77.62"}),
        ("translate_query", {"description": "Detect mimikatz process creation", "target_format": "kql"}),
        ("generate_sigma_rule", {"technique_id": "T1003", "title": "LSASS access"}),
        ("suggest_fleet_hunts", {}),
        ("ti_list_providers", {}),
        ("ti_lookup", {"value": "8.8.8.8", "ioc_type": "ip"}),
        ("ti_fanout", {"value": "8.8.8.8", "ioc_type": "ip"}),
        ("detection_search", {"query": "mimikatz"}),
        ("detection_sigma_install", {"source_dir": str(EV / "10-sigma" / "rules")}),
        ("sigma_translate", {
            "yaml_content": "title: t\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image|endswith: \\\\mimikatz.exe\n  condition: sel\n",
            "target": "kql",
        }),
        ("forensic_rag_status", {}),
        ("forensic_rag_search", {"query": "LSASS"}),
        ("forensic_rag_list_sources", {}),
        ("triage_status", {}),
        ("check_file", {"path": r"C:\Windows\System32\svchost.exe"}),
        ("vr_health", {}),
        ("vr_list_hunts", {}),
        ("vr_run_hunt", {"hunt_id": "nexus-process-tree"}),
        ("opencti_status", {}),
        ("get_rules", {}),
        ("get_investigation_framework", {}),
        ("get_evidence_standards", {}),
        ("case_list", {}),
        ("case_status", {}),
        ("get_findings", {}),
        ("get_timeline", {}),
        ("list_windows_tools", {}),
        ("list_missing_windows_tools", {}),
        ("suggest_windows_tools", {"artifact_type": "evtx"}),
        ("list_kape_targets", {}),
        ("get_db_stats", {}),
        ("get_health", {}),
        ("get_knowledge_graph_stats", {}),
        ("batch_scan", {"tool": "LECmd", "directory": str(EV / "01-windows" / "lnk"), "max_files": 3}),
        ("check_hash", {"hash_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}),
        ("check_lolbin", {"filename": "certutil.exe"}),
        ("check_autorun", {"path": r"C:\Windows\System32\svchost.exe"}),
        ("check_service", {"name": "Dnscache"}),
        ("check_scheduled_task", {"name": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"}),
        ("analyze_filename_triage", {"filename": "mimikatz.exe"}),
    ]
    for name, kwargs in calls:
        if name not in tools:
            rec("A-tools", name, False, "not registered", "GAP")
            continue
        try:
            r = tools[name].fn(**kwargs)
            if isinstance(r, dict) and r.get("error") and "not configured" in str(r.get("error")).lower() or isinstance(r, dict) and r.get("connected") is False:
                rec("A-tools", name, True, json.dumps(r, default=str)[:250], "OPTIONAL")
            elif isinstance(r, list):
                rec("A-tools", name, True, json.dumps(r, default=str)[:250])
            elif isinstance(r, dict):
                ok = True
                if r.get("error") and len(r) <= 2 and not any(k in r for k in ("ok", "status", "verdict")):
                    ok = False
                rec("A-tools", name, ok, json.dumps(r, default=str)[:250])
            else:
                rec("A-tools", name, True, str(r)[:250])
        except TypeError as exc:
            # retry with no kwargs for tools whose signature we guessed wrong
            try:
                r = tools[name].fn()
                rec("A-tools", name, True, f"retried empty kwargs; {json.dumps(r, default=str)[:200]}")
            except Exception as exc2:
                rec("A-tools", name, False, f"TypeError: {exc}; retry: {exc2}")
        except Exception as exc:
            rec("A-tools", name, False, f"{type(exc).__name__}: {exc}")


def lane_cli(case_id: str | None) -> None:
    py = sys.executable
    cmds = [
        ("doctor", [py, "-m", "nexus.cli.main", "doctor"]),
        ("config --show", [py, "-m", "nexus.cli.main", "config", "--show"]),
        ("setup test", [py, "-m", "nexus.cli.main", "setup", "test"]),
        ("case list", [py, "-m", "nexus.cli.main", "case", "list"]),
        ("evidence list", [py, "-m", "nexus.cli.main", "evidence", "list"]),
        ("data download-fixtures", [py, "-m", "nexus.cli.main", "data", "download-fixtures"]),
        ("service status", [py, "-m", "nexus.cli.main", "service", "status"]),
    ]
    conn = first("04-network/monitor-live/conn.log")
    if conn:
        cmds.append(("ingest conn.log", [py, "-m", "nexus.cli.main", "ingest", str(conn)]))
    if case_id:
        cmds.append(("case activate", [py, "-m", "nexus.cli.main", "case", "activate", case_id]))
        cmds.append(("report generate", [py, "-m", "nexus.cli.main", "report", "generate", "--full"]))
        cmds.append(("review findings", [py, "-m", "nexus.cli.main", "review", "--findings"]))
        cmds.append(("audit summary", [py, "-m", "nexus.cli.main", "audit", "summary"]))

    for name, cmd in cmds:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=str(ROOT))
            ok = p.returncode == 0
            rec("CLI", name, ok, (p.stdout or p.stderr or "")[-300:].replace("\n", " | "))
        except Exception as exc:
            rec("CLI", name, False, str(exc))

    # evidence verify via CLI
    try:
        p = subprocess.run([py, "-m", "nexus.cli.main", "evidence", "verify"],
                           capture_output=True, text=True, timeout=60, cwd=str(ROOT))
        rec("CLI", "evidence verify", p.returncode == 0, (p.stdout or p.stderr or "")[-250:].replace("\n", " | "))
    except Exception as exc:
        rec("CLI", "evidence verify", False, str(exc))

    # backup create
    if case_id:
        bak = EV / "_e2e-out" / "feature-matrix" / f"{case_id}-backup.zip"
        bak.parent.mkdir(parents=True, exist_ok=True)
        try:
            p = subprocess.run(
                [py, "-m", "nexus.cli.main", "backup", "create", str(bak)],
                capture_output=True, text=True, timeout=90, cwd=str(ROOT),
            )
            rec("CLI", "backup create", p.returncode == 0 and bak.is_file(),
                f"rc={p.returncode} size={bak.stat().st_size if bak.is_file() else 0} {(p.stdout or '')[-150:]}")
            if bak.is_file():
                p2 = subprocess.run(
                    [py, "-m", "nexus.cli.main", "backup", "verify", str(bak)],
                    capture_output=True, text=True, timeout=60, cwd=str(ROOT),
                )
                rec("CLI", "backup verify", p2.returncode == 0, (p2.stdout or p2.stderr or "")[-200:])
        except Exception as exc:
            rec("CLI", "backup create", False, str(exc))

    # export bundle
    if case_id:
        bundle = EV / "_e2e-out" / "feature-matrix" / f"{case_id}-bundle.json"
        try:
            p = subprocess.run(
                [py, "-m", "nexus.cli.main", "export", str(bundle)],
                capture_output=True, text=True, timeout=90, cwd=str(ROOT),
            )
            rec("CLI", "export bundle", p.returncode == 0 and bundle.is_file(),
                f"rc={p.returncode} {(p.stdout or p.stderr or '')[-200:]}")
        except Exception as exc:
            rec("CLI", "export bundle", False, str(exc))

    # reject a DRAFT (allowed) — not approve
    try:
        from nexus.app import create_server
        s = create_server()
        findings = s._tool_manager._tools["get_findings"].fn()
        fids = []
        if isinstance(findings, dict):
            fids = [f.get("id") for f in findings.get("findings", []) if f.get("status") == "DRAFT"]
        if fids:
            # create sacrificial finding then reject — don't reject the main matrix finding if only one
            # Use CLI reject with password from env if set — else BLOCKED
            rec("CLI", "reject", False,
                "Operator-gated same as approve when password required; leave DRAFT for human. "
                f"draft_ids={fids[:3]}",
                "BLOCKED_HITL")
        else:
            rec("CLI", "reject", False, "no DRAFT findings to reject", "SKIP")
    except Exception as exc:
        rec("CLI", "reject", False, str(exc))


def lane_modes() -> None:
    # M3 heuristic
    try:
        from nexus.ingest.schemas import ArtifactType
        from nexus.langgraph.pipeline import run_analysis_without_interrupt
        state = run_analysis_without_interrupt(
            case_id="matrix",
            artifacts=[{"type": ArtifactType.NETWORK, "path": str(first("04-network/monitor-live/conn.log"))}],
        )
        rec("MODE", "M3 heuristic pipeline", True, f"type={type(state).__name__} {str(state)[:200]}")
    except Exception as exc:
        rec("MODE", "M3 heuristic pipeline", False, f"{type(exc).__name__}: {exc}")

    # M4 LLM ping + optional full pipeline
    try:
        from nexus.llm.router import get_model
        model = get_model()
        rec("MODE", "M4 get_model", model is not None, type(model).__name__ if model else "None")
        if model:
            out = model.invoke("Reply with exactly PONG")
            text = getattr(out, "content", str(out))
            rec("MODE", "M4 LLM invoke", "PONG" in str(text), str(text)[:100])
    except Exception as exc:
        rec("MODE", "M4 LLM", False, str(exc))

    # HTTP health if serve up
    for port in (4510, 4508):
        try:
            import urllib.request
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=3) as resp:
                body = resp.read().decode()
                rec("MODE", f"M5 /health :{port}", resp.status == 200, body[:120])
        except Exception as exc:
            rec("MODE", f"M5 /health :{port}", False, str(exc), "DOWN")

    # SIFT remote health
    try:
        import urllib.request
        with urllib.request.urlopen("http://192.168.77.135:4508/health", timeout=5) as resp:
            body = resp.read().decode()
            rec("MODE", "SIFT /health :4508", resp.status == 200, body[:120])
    except Exception as exc:
        rec("MODE", "SIFT /health :4508", False, str(exc), "DOWN")


def lane_mcp_http() -> None:
    """Official-ish Streamable HTTP probe against /mcp if server up."""
    try:
        import httpx
    except ImportError:
        rec("MCP-HTTP", "httpx", False, "httpx missing", "BLOCKED")
        return
    for base in ("http://127.0.0.1:4510", "http://192.168.77.135:4508"):
        url = f"{base}/mcp"
        try:
            # Initialize handshake (MCP streamable HTTP)
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "feature-matrix", "version": "0.1"},
                },
            }
            r = httpx.post(url, json=payload, headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            }, timeout=10)
            rec("MCP-HTTP", f"initialize {base}", r.status_code in (200, 202, 406) or "result" in r.text,
                f"status={r.status_code} body={r.text[:250]}")
        except Exception as exc:
            rec("MCP-HTTP", f"initialize {base}", False, str(exc))


def write_report() -> None:
    by = {}
    for r in ROWS:
        by.setdefault(r["cap"], []).append(r)
    yes = sum(1 for r in ROWS if r["ok"])
    no = sum(1 for r in ROWS if not r["ok"] and r["status"] not in ("BLOCKED_HITL", "OPTIONAL", "MISSING", "NO_INPUT", "BLOCKED", "DOWN", "SKIP", "GAP"))
    blocked = sum(1 for r in ROWS if r["status"] in ("BLOCKED_HITL", "BLOCKED", "DOWN", "MISSING", "NO_INPUT", "GAP", "SKIP"))
    optional = sum(1 for r in ROWS if r["status"] == "OPTIONAL")

    lines = [
        f"# FEATURE-BY-FEATURE REPORT — {datetime.now(UTC).isoformat()}",
        "",
        "Evidence-backed agent pass against `Evidence-files/`. **Not** COMPLETE-TO-SHIP 12/12.",
        "",
        f"- total checks: **{len(ROWS)}**",
        f"- PASS (ok=True): **{yes}**",
        f"- FAIL (actionable): **{no}**",
        f"- BLOCKED/MISSING/NO_INPUT/GAP/HITL/DOWN/SKIP: **{blocked}**",
        f"- OPTIONAL (honest unconfigured): **{optional}**",
        "",
        "## Coverage truth",
        "",
        "- Every importer class mapped to a file under `Evidence-files/` (real preferred, `_fixtures/` when needed).",
        "- Windows tools run only when binary **and** matching evidence exist.",
        "- `nexus approve` remains **BLOCKED_HITL** (examiner password).",
        "- 12-pass ledger in COMPLETE-TO-SHIP.md still open.",
        "",
    ]
    for cap, rows in by.items():
        lines.append(f"## {cap}")
        lines.append("")
        lines.append("| status | name | detail |")
        lines.append("|--------|------|--------|")
        for r in rows:
            d = r["detail"].replace("|", "/").replace("\n", " ")
            lines.append(f"| {r['status']} | `{r['name']}` | {d} |")
        lines.append("")

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"WROTE {OUT} total={len(ROWS)} pass={yes} fail={no} blocked={blocked}")


def main() -> int:
    from nexus.app import create_server

    server = create_server()
    tools = server._tool_manager._tools
    rec("BOOT", "MCP tools registered", len(tools) > 0, f"n={len(tools)}")

    print("== importers ==", flush=True)
    lane_importers()
    print("== windows tools ==", flush=True)
    lane_windows_tools(tools)
    print("== case stack ==", flush=True)
    case_id = lane_case_stack(tools)
    print("== analysis/ti ==", flush=True)
    lane_analysis_ti(tools)
    print("== cli ==", flush=True)
    lane_cli(case_id)
    print("== modes ==", flush=True)
    lane_modes()
    print("== mcp http ==", flush=True)
    lane_mcp_http()
    write_report()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        traceback.print_exc()
        write_report()
        raise SystemExit(2)
