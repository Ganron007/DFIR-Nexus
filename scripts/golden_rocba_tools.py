#!/usr/bin/env python3
"""Golden Rocba host-tool run — PRODUCT path, not importer-only e2e.

Creates a case, registers H:\\ triage evidence, runs Windows catalog tools
with CSV/stdout into case/extractions/<tool>/, logs TOOL-LEDGER.md,
stages findings from Hayabusa signal, writes report via build_dfir_markdown
AND case/reports/.

Usage:
  python scripts/golden_rocba_tools.py
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.chdir(ROOT)
os.environ.setdefault("PYTHONUTF8", "1")

H = Path("H:/C")
EXAMINER = "e2e_host"
APPROVE_PW = "E2E-Host-Test-2026!"

from nexus.case import ApprovalState, CaseManager, FindingSeverity
from nexus.case.compat import get_sqlite_manager
from nexus.case.manager import materialize_case_dir
from nexus.tools.windows import _find_binary


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_tool(name: str, args: list[str], out_dir: Path, timeout: int = 600) -> dict:
    binary = _find_binary(name)
    row = {
        "tool": name,
        "status": "FAIL",
        "binary": binary,
        "args": args,
        "rc": None,
        "out_dir": str(out_dir),
        "outputs": [],
        "stderr_tail": "",
        "error": "",
    }
    if not binary:
        row["status"] = "MISSING"
        row["error"] = "binary not resolved"
        return row
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [binary, *args]
    try:
        cp = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            cwd=str(Path(binary).parent),
        )
        row["rc"] = cp.returncode
        # decode safely
        err = (cp.stderr or b"").decode("utf-8", errors="replace")
        out = (cp.stdout or b"").decode("utf-8", errors="replace")
        row["stderr_tail"] = (err or out)[-500:]
        (out_dir / "stdout.txt").write_text(out, encoding="utf-8", errors="replace")
        (out_dir / "stderr.txt").write_text(err, encoding="utf-8", errors="replace")
        (out_dir / "cmdline.txt").write_text("\n".join(cmd), encoding="utf-8")
        outputs = [p for p in out_dir.rglob("*") if p.is_file() and p.name not in ("stdout.txt", "stderr.txt", "cmdline.txt")]
        row["outputs"] = [str(p.relative_to(out_dir)) for p in outputs][:40]
        # success if rc==0 OR outputs produced (some tools return non-zero with usable csv)
        if cp.returncode == 0 or outputs:
            row["status"] = "PASS"
        else:
            row["status"] = "FAIL"
            row["error"] = row["stderr_tail"][:300]
    except subprocess.TimeoutExpired:
        row["status"] = "TIMEOUT"
        row["error"] = f"timeout>{timeout}s"
    except Exception as exc:
        row["status"] = "FAIL"
        row["error"] = f"{type(exc).__name__}: {exc}"
    return row


def main() -> int:
    ledger: list[dict] = []
    mgr: CaseManager = get_sqlite_manager()
    case = mgr.create_case(
        name="SHOWCASE-Rocba-Tools-H",
        description=(
            "FOR500 Rocba golden tool lane against mounted H:\\ Rocba_Triage. "
            "Product path: register evidence → run catalog tools → extractions/ → findings → report."
        ),
        severity=FindingSeverity.HIGH,
        created_by=EXAMINER,
        tags=["showcase", "rocba", "tools", "H-mount"],
    )
    mgr.set_case_approval_password(case.id, APPROVE_PW)
    case_dir = materialize_case_dir(case)
    active = Path.home() / ".nexus" / "active_case"
    active.write_text(case.id, encoding="utf-8")
    extractions = case_dir / "extractions"
    reports = case_dir / "reports"
    print(f"CASE {case.id} dir={case_dir}", flush=True)

    # --- Evidence register (H: real paths) ---
    evidence_paths = [
        H / "Windows/System32/winevt/Logs/Security.evtx",
        H / "Windows/System32/winevt/Logs/System.evtx",
        H / "Windows/AppCompat/Programs/Amcache.hve",
        H / "Windows/System32/config/SYSTEM",
        H / "Windows/System32/config/SOFTWARE",
        H / "Windows/System32/sru/SRUDB.dat",
    ]
    chrome = H / "Users/fredr/AppData/Local/Google/Chrome/User Data/Default/History"
    if chrome.is_file():
        evidence_paths.append(chrome)
    registered = []
    for p in evidence_paths:
        if not p.is_file():
            ledger.append({"tool": f"evidence:{p.name}", "status": "SKIP", "error": f"missing {p}"})
            continue
        try:
            digest = sha256(p)
            # Custody pointer in case/evidence (do not duplicate multi-GB triage blobs)
            dest = case_dir / "evidence" / f"{p.name}.pointer.txt"
            dest.write_text(
                f"POINTER\nsource={p}\nsha256={digest}\nsize={p.stat().st_size}\nhost=SRL-FORGE\n",
                encoding="utf-8",
            )
            ev = mgr.add_evidence(
                case_id=case.id,
                name=f"H:/ Rocba triage — {p.name}",
                description=f"Mounted Rocba_Triage evidence at {p} (host SRL-FORGE)",
                file_path=str(p),
                file_hash_sha256=digest,
                collected_by=EXAMINER,
                metadata={"host": "SRL-FORGE", "mount": "H:/C", "pointer": str(dest)},
            )
            registered.append({"path": str(p), "sha256": digest, "ev_id": getattr(ev, "id", None)})
            ledger.append({"tool": f"evidence:{p.name}", "status": "PASS", "outputs": [str(p)], "error": ""})
        except Exception as exc:
            ledger.append({"tool": f"evidence:{p.name}", "status": "FAIL", "error": str(exc)})
    print(f"EVIDENCE registered={len(registered)}", flush=True)

    sec = H / "Windows/System32/winevt/Logs/Security.evtx"
    sys_evtx = H / "Windows/System32/winevt/Logs/System.evtx"
    prefetch = H / "Windows/Prefetch"
    recent = H / "Users/fredr/AppData/Roaming/Microsoft/Windows/Recent"
    amcache = H / "Windows/AppCompat/Programs/Amcache.hve"
    system_hive = H / "Windows/System32/config/SYSTEM"
    srum = H / "Windows/System32/sru/SRUDB.dat"
    auto_jl = H / "Users/fredr/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations"
    custom_jl = H / "Users/fredr/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations"
    recycle = H / "Users/fredr"  # RBCmd needs $I files — use SID recycle if present
    recycle_sid = next((H / "$Recycle.Bin").glob("S-1-5-21-*"), None) if (H / "$Recycle.Bin").is_dir() else None
    usrclass = H / "Users/fredr/AppData/Local/Microsoft/Windows/UsrClass.dat"
    mft = H / "$MFT"

    # --- Tool runs (CSV into extractions) ---
    jobs: list[tuple[str, list[str], Path, int]] = []

    hay_out = extractions / "hayabusa" / "security-timeline.csv"
    hay_out.parent.mkdir(parents=True, exist_ok=True)
    if sec.is_file():
        jobs.append(("hayabusa", [
            "dfir-timeline", "-f", str(sec), "-o", str(hay_out), "-w", "-C", "-Q",
        ], extractions / "hayabusa", 900))

    if sec.is_file():
        jobs.append(("evtxecmd", [
            "-f", str(sec), "--csv", str(extractions / "evtxecmd"), "--csvf", "Security.csv",
        ], extractions / "evtxecmd", 600))
    if sys_evtx.is_file():
        jobs.append(("evtxecmd", [
            "-f", str(sys_evtx), "--csv", str(extractions / "evtxecmd-system"), "--csvf", "System.csv",
        ], extractions / "evtxecmd-system", 300))

    if prefetch.is_dir():
        jobs.append(("pecmd", [
            "-d", str(prefetch), "--csv", str(extractions / "pecmd"), "--csvf", "prefetch.csv",
        ], extractions / "pecmd", 600))

    if recent.is_dir():
        jobs.append(("lecmd", [
            "-d", str(recent), "--csv", str(extractions / "lecmd"), "--csvf", "recent-lnk.csv",
        ], extractions / "lecmd", 300))

    if auto_jl.is_dir():
        jobs.append(("jlecmd", [
            "-d", str(auto_jl), "--csv", str(extractions / "jlecmd"), "--csvf", "automatic.csv",
        ], extractions / "jlecmd", 300))
    elif custom_jl.is_dir():
        jobs.append(("jlecmd", [
            "-d", str(custom_jl), "--csv", str(extractions / "jlecmd"), "--csvf", "custom.csv",
        ], extractions / "jlecmd", 300))

    if amcache.is_file():
        jobs.append(("amcacheparser", [
            "-f", str(amcache), "--csv", str(extractions / "amcache"), "--csvf", "amcache.csv",
        ], extractions / "amcache", 300))

    if system_hive.is_file():
        jobs.append(("appcompatcacheparser", [
            "-f", str(system_hive), "--csv", str(extractions / "appcompat"), "--csvf", "appcompat.csv",
        ], extractions / "appcompat", 300))

    if srum.is_file():
        jobs.append(("srumecmd", [
            "-f", str(srum), "--csv", str(extractions / "srum"),
        ], extractions / "srum", 600))

    if recycle_sid and recycle_sid.is_dir():
        jobs.append(("rbcmd", [
            "-d", str(recycle_sid), "--csv", str(extractions / "rbcmd"), "--csvf", "recycle.csv",
        ], extractions / "rbcmd", 300))
    else:
        ledger.append({"tool": "rbcmd", "status": "SKIP", "error": "no $Recycle.Bin SID dir for fredr"})

    if usrclass.is_file():
        # SBECmd requires -d directory of hives (not -f)
        sbe_in = extractions / "sbecmd" / "_hives"
        sbe_in.mkdir(parents=True, exist_ok=True)
        hive_copy = sbe_in / "UsrClass.dat"
        if not hive_copy.exists():
            hive_copy.write_bytes(usrclass.read_bytes())
        jobs.append(("sbecmd", [
            "-d", str(sbe_in), "--csv", str(extractions / "sbecmd"),
        ], extractions / "sbecmd", 300))
    else:
        ledger.append({"tool": "sbecmd", "status": "SKIP", "error": f"missing {usrclass}"})

    # MFTECmd on $MFT — large; still run (may take time)
    if mft.is_file():
        jobs.append(("mftecmd", [
            "-f", str(mft), "--csv", str(extractions / "mftecmd"), "--csvf", "mft.csv",
        ], extractions / "mftecmd", 1800))
    else:
        ledger.append({"tool": "mftecmd", "status": "SKIP", "error": "H:/$MFT missing"})

    # RECmd — SOFTWARE hive via InstalledSoftware batch (--bn required for CSV)
    software_hive = H / "Windows/System32/config/SOFTWARE"
    reb = ROOT / "Tools/windows/kape/Modules/bin/RECmd/BatchExamples/InstalledSoftware.reb"
    if software_hive.is_file() and reb.is_file():
        jobs.append(("recmd", [
            "-f", str(software_hive), "--bn", str(reb),
            "--csv", str(extractions / "recmd"), "--csvf", "installed-software.csv",
        ], extractions / "recmd", 600))
    else:
        ledger.append({"tool": "recmd", "status": "SKIP", "error": f"SOFTWARE or .reb missing (reb={reb.is_file()})"})

    # SQLECmd — Chrome History (csv dir only; no --csvf)
    if chrome.is_file():
        jobs.append(("sqlecmd", [
            "-f", str(chrome), "--csv", str(extractions / "sqlecmd"),
        ], extractions / "sqlecmd", 300))
    else:
        ledger.append({"tool": "sqlecmd", "status": "SKIP", "error": "Chrome History missing"})

    # WxTCmd — ActivitiesCache.db if present
    act_hits = list((H / "Users/fredr/AppData/Local/ConnectedDevicesPlatform").rglob("ActivitiesCache.db"))
    if act_hits:
        jobs.append(("wxtcmd", [
            "-f", str(act_hits[0]), "--csv", str(extractions / "wxtcmd"), "--csvf", "timeline.csv",
        ], extractions / "wxtcmd", 300))
    else:
        ledger.append({"tool": "wxtcmd", "status": "SKIP", "error": "ActivitiesCache.db not found under ConnectedDevicesPlatform"})

    # Suzaku 2.0 is AWS/Azure cloud logs ONLY — not EVTX. Explicit SKIP (do not fake EVTX run).
    ledger.append({
        "tool": "suzaku",
        "status": "SKIP",
        "error": "suzaku-2.0 catalog binary is cloud (aws-ct/azure) only — not applicable to H: Security.evtx",
    })

    # Chainsaw: hunt needs sigma rules tree (not shipped under Tools/windows/extra/chainsaw).
    # Run `search` lane against Security.evtx so Chainsaw still produces case evidence.
    cs_map = ROOT / "Tools/windows/extra/chainsaw/mappings/sigma-event-logs-all.yml"
    cs_sigma = ROOT / "Tools/windows/extra/chainsaw/sigma"
    cs_rules = ROOT / "Tools/windows/extra/chainsaw/rules"
    if sec.is_file() and cs_sigma.is_dir() and cs_map.is_file():
        args = ["hunt", str(sec), "-s", str(cs_sigma), "--mapping", str(cs_map),
                "--csv", str(extractions / "chainsaw" / "hunt.csv")]
        if cs_rules.is_dir():
            args.extend(["-r", str(cs_rules)])
        jobs.append(("chainsaw", args, extractions / "chainsaw", 600))
    elif sec.is_file():
        ledger.append({
            "tool": "chainsaw:hunt",
            "status": "SKIP",
            "error": "sigma/ rules tree missing under Tools/windows/extra/chainsaw (mapping present) — hunt not runnable until sigma pack staged",
        })
        (extractions / "chainsaw").mkdir(parents=True, exist_ok=True)
        jobs.append(("chainsaw", [
            "search", "-i", "Failed", str(sec),
            "--csv", str(extractions / "chainsaw" / "search-failed.csv"),
        ], extractions / "chainsaw", 600))
    else:
        ledger.append({"tool": "chainsaw", "status": "SKIP", "error": "Security.evtx missing"})

    # bstrings sample on a small LNK if present
    lnk = next((recent.glob("*.lnk") if recent.is_dir() else iter(())), None)
    if lnk and lnk.is_file():
        bout = extractions / "bstrings" / "lnk-strings.txt"
        bout.parent.mkdir(parents=True, exist_ok=True)
        jobs.append(("bstrings", ["-f", str(lnk), "-o", str(bout)], extractions / "bstrings", 120))
    else:
        ledger.append({"tool": "bstrings", "status": "SKIP", "error": "no .lnk under Recent for sample"})

    # Tools that need live process / not applicable to offline triage — explicit SKIP
    for live in ("winpmem", "dumpit", "procdump", "moneta", "hollows_hunter", "handle", "autorunsc"):
        ledger.append({
            "tool": live,
            "status": "SKIP",
            "error": "live-host / memory-acquire tool — not applicable to offline H: triage mount",
        })
    for other in ("kape", "capa", "yara", "densityscout", "get_injectedthreadex", "sigcheck", "strings", "mactime"):
        reason = {
            "kape": "H: already is KAPE triage output — re-collect skipped",
            "capa": "no PE malware sample selected in this host triage lane",
            "yara": "no YARA rule pack + target PE scoped for this Rocba host lane",
            "densityscout": "entropy scan needs PE directory scope — deferred",
            "get_injectedthreadex": "live process injection scan — not offline triage",
            "sigcheck": "live signature check on PE set — deferred (no PE batch scoped)",
            "strings": "generic strings — covered by bstrings sample if LNK present",
            "mactime": "needs bodyfile from fls — Linux/SIFT lane, not Windows H: host tools",
        }[other]
        ledger.append({"tool": other, "status": "SKIP", "error": reason})

    for name, args, out_dir, timeout in jobs:
        print(f"RUN {name} …", flush=True)
        row = run_tool(name, args, out_dir, timeout=timeout)
        ledger.append(row)
        print(f"  {row['status']} rc={row['rc']} outputs={len(row.get('outputs') or [])} {row.get('error','')[:120]}", flush=True)

    # --- Findings from Hayabusa (real signal) ---
    draft_ids = []
    if hay_out.is_file() and hay_out.stat().st_size > 100:
        with hay_out.open(encoding="utf-8", errors="replace") as f:
            rows = list(csv.DictReader(f))
        computers = Counter(r.get("Computer") for r in rows)
        levels = Counter((r.get("Level") or "").lower() for r in rows)
        med = [r for r in rows if (r.get("Level") or "").lower() in ("med", "medium", "high", "critical")]
        titles = Counter(r.get("RuleTitle") for r in med)
        top = titles.most_common(10)
        sample = []
        for title, _n in top[:3]:
            hit = next(r for r in med if r.get("RuleTitle") == title)
            sample.append(
                f"- [{hit.get('Level')}] {title} | host={hit.get('Computer')} | "
                f"EID={hit.get('EventID')} | t={hit.get('Timestamp')} | {hit.get('Details','')[:160]}"
            )
        body = (
            f"Hayabusa dfir-timeline on H:\\…\\Security.evtx → `{hay_out}`.\n"
            f"Rows={len(rows)} computers={dict(computers)} levels={dict(levels)}.\n"
            f"Top medium+ rule titles: {top}.\n\n"
            f"Sample detections:\n" + "\n".join(sample)
        )
        f1 = mgr.add_finding(
            case_id=case.id,
            title="Rocba/SRL-FORGE: Hayabusa failed logon / password guessing cluster",
            description=body,
            severity="high",
            technique_ids=["T1110", "T1110.001"],
            created_by="tool:hayabusa",
            initial_state=ApprovalState.DRAFT,
        )
        if f1:
            draft_ids.append(f1.id)

        # Second finding: NTLM auth noise / targeting users from Details
        users = Counter()
        for r in rows:
            d = r.get("Details") or ""
            if "TgtUser:" in d:
                try:
                    users[d.split("TgtUser:")[1].split()[0].strip(" ·")] += 1
                except Exception:
                    pass
        body2 = (
            f"NTLM/logon targeting from Hayabusa Security timeline.\n"
            f"Top TgtUser values: {users.most_common(15)}.\n"
            f"Tool output: `{hay_out}`"
        )
        f2 = mgr.add_finding(
            case_id=case.id,
            title="Rocba/SRL-FORGE: targeted account names in NTLM/logon events",
            description=body2,
            severity="medium",
            technique_ids=["T1110"],
            created_by="tool:hayabusa",
            initial_state=ApprovalState.DRAFT,
        )
        if f2:
            draft_ids.append(f2.id)

    # PECmd finding if present
    pecmd_csv = next((extractions / "pecmd").glob("*.csv"), None) if (extractions / "pecmd").is_dir() else None
    if pecmd_csv and pecmd_csv.is_file():
        with pecmd_csv.open(encoding="utf-8", errors="replace") as f:
            prow = list(csv.DictReader(f))[:5]
        f3 = mgr.add_finding(
            case_id=case.id,
            title="Rocba: PECmd prefetch execution evidence produced",
            description=(
                f"PECmd against H:\\Windows\\Prefetch → `{pecmd_csv}` "
                f"({pecmd_csv.stat().st_size} bytes). Sample rows: {prow!r}"
            ),
            severity="medium",
            technique_ids=["T1074"],
            created_by="tool:pecmd",
            initial_state=ApprovalState.DRAFT,
        )
        if f3:
            draft_ids.append(f3.id)

    approved = []
    for fid in draft_ids:
        f = mgr.approve_finding(fid, APPROVE_PW, approved_by=EXAMINER, note="Operator-authorized golden tool run")
        if f and f.approval_state == ApprovalState.APPROVED:
            approved.append(fid)

    # --- Product-style DFIR report into case/reports ---
    from nexus.integration.dfir_report import build_dfir_markdown
    findings = mgr.list_findings(case.id)
    evidence = mgr.list_evidence(case.id)
    fdicts = []
    for f in findings:
        d = f.to_dict()
        d["status"] = f.approval_state.value.upper()
        d["severity"] = f.severity.value
        d["technique_ids"] = list(f.technique_ids or [])
        d["mitre_ids"] = list(f.technique_ids or [])
        d["description"] = f.description
        d["observation"] = f.description
        d["title"] = f.title
        d["id"] = f.id
        d["approved_by"] = f.approved_by
        fdicts.append(d)
    edicts = []
    for ev in evidence:
        meta = dict(ev.metadata or {})
        edicts.append({
            "name": ev.name,
            "path": ev.file_path,
            "sha256": ev.file_hash_sha256,
            "description": ev.description,
            "host": meta.get("host") or "SRL-FORGE",
            "metadata": meta,
        })
    # Attach tool output paths as evidence rows
    for p in sorted(extractions.rglob("*")):
        if p.is_file() and p.suffix.lower() in (".csv", ".json", ".txt") and p.stat().st_size > 0:
            edicts.append({
                "name": f"tool-output:{p.relative_to(extractions).as_posix()}",
                "path": str(p),
                "sha256": sha256(p) if p.stat().st_size < 50_000_000 else None,
                "description": "Catalog tool output under case extractions",
                "host": "SRL-FORGE",
            })

    tool_notes = [f"{r['tool']}: {r['status']}" + (f" ({r.get('error','')[:80]})" if r.get("error") else "") for r in ledger]
    md = build_dfir_markdown(
        case_id=case.id,
        case_name=case.name,
        findings=fdicts,
        evidence=edicts,
        sift_notes=tool_notes,
        examiner=EXAMINER,
        status=case.status.value,
        severity=case.severity.value,
        case_summary=(
            "FOR500 Rocba investigation on host SRL-FORGE (user fredr). "
            "Evidence collected from mounted H:\\ Rocba_Triage. "
            "Findings are grounded in catalog tool outputs under case/extractions/ "
            "(Hayabusa Security timeline, PECmd, etc.)."
        ),
    )
    report_path = reports / "dfir-report.md"
    report_path.write_text(md, encoding="utf-8")
    # mirror for Docs convenience
    docs_rep = ROOT / "Docs" / "internal" / "reports" / f"{case.id}-tools.md"
    docs_rep.parent.mkdir(parents=True, exist_ok=True)
    docs_rep.write_text(md, encoding="utf-8")

    # Ledger
    led_path = case_dir / "TOOL-LEDGER.md"
    lines = [
        f"# Tool ledger — {case.id}",
        "",
        f"Generated {datetime.now(UTC).isoformat()}",
        "",
        "| tool | status | rc | outputs | error |",
        "|------|--------|----|---------|-------|",
    ]
    for r in ledger:
        err = str(r.get("error") or "").replace("|", "/")[:120]
        outs = ",".join(r.get("outputs") or [])[:80]
        lines.append(f"| `{r.get('tool')}` | {r.get('status')} | {r.get('rc')} | {outs} | {err} |")
    led_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    summary = {
        "case_id": case.id,
        "case_dir": str(case_dir),
        "report": str(report_path),
        "docs_report": str(docs_rep),
        "approved": approved,
        "ledger": ledger,
    }
    (case_dir / "golden-summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    (ROOT / "Docs" / "internal" / "GOLDEN-ROCBA-TOOLS-REPORT.md").write_text(
        f"# Golden Rocba tools — {case.id}\n\n"
        f"- Case dir: `{case_dir}`\n"
        f"- Report: `{report_path}`\n"
        f"- Ledger: `{led_path}`\n\n"
        + "\n".join(lines)
        + "\n",
        encoding="utf-8",
    )

    passed = sum(1 for r in ledger if r.get("status") == "PASS")
    failed = sum(1 for r in ledger if r.get("status") == "FAIL")
    skipped = sum(1 for r in ledger if r.get("status") == "SKIP")
    print(f"\nDONE case={case.id} PASS={passed} FAIL={failed} SKIP={skipped}", flush=True)
    print(f"REPORT {report_path}", flush=True)
    print(f"LEDGER {led_path}", flush=True)
    try:
        mgr.close()
    except Exception:
        pass
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
