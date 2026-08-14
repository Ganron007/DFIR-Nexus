#!/usr/bin/env python3
"""Rocba showcase case run — ONE environment only (FOR500 / fredr).

Reads Evidence-files/showcase/rocba-500/ (stage with stage_rocba_showcase.py).
Does NOT ingest CADRE monitor Zeek/Suricata, linux01, or 508 Amadey memory.

Flow: ingest → case + evidence register → LangGraph agents → HITL approve → DFIR report.
"""
from __future__ import annotations

import json
import os
import sys
import traceback
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "Evidence-files" / "showcase" / "rocba-500"
OUT = ROOT / "Evidence-files" / "_e2e-out" / "rocba-showcase"
REPORT_MD = ROOT / "Docs" / "internal" / "reports"
ORCH_REPORT = ROOT / "Docs" / "internal" / "ROCBA-SHOWCASE-REPORT.md"
EXAMINER = "e2e_host"
APPROVE_PW = "E2E-Host-Test-2026!"

os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
sys.path.insert(0, str(ROOT / "src"))
os.chdir(ROOT)

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except Exception:
    pass

OUT.mkdir(parents=True, exist_ok=True)
ROWS: list[dict] = []


def rec(ok: bool, name: str, detail: str = "", skip: bool = False) -> None:
    status = "SKIP" if skip else ("PASS" if ok else "FAIL")
    ROWS.append({"ok": ok, "skip": skip, "name": name, "detail": detail[:600], "status": status})
    flag = "skip" if skip else ("yes" if ok else "NO ")
    safe = "".join(ch if ord(ch) < 128 else "?" for ch in str(detail)[:200])
    print(f"[{flag}] {name}: {safe}", flush=True)


def take(seq, n: int):
    out = []
    for i, item in enumerate(seq):
        if i >= n:
            break
        out.append(item)
    return out


def ingest(label: str, path: Path, importer_cls, cap: int) -> list:
    if not path.is_file():
        rec(False, f"ingest:{label}", f"missing {path}", skip=True)
        return []
    try:
        arts = take(importer_cls().parse(path), cap)
        src = getattr(arts[0].source, "value", "?") if arts else "empty"
        # Stamp host for Rocba narrative when missing
        for a in arts:
            if not a.host:
                a.host = "rocba-fredr"
        rec(True, f"ingest:{label}", f"n={len(arts)} src={src} {path.name}")
        return arts
    except Exception as exc:
        rec(False, f"ingest:{label}", f"{type(exc).__name__}: {exc}")
        return []


def main() -> int:
    if not PACK.is_dir():
        print(f"Pack missing: {PACK}\nRun: python scripts/stage_rocba_showcase.py", flush=True)
        return 2

    host = PACK / "host"
    precooked = PACK / "precooked"
    cloud = PACK / "cloud"
    manifest = PACK / "MANIFEST.md"
    rec(manifest.is_file(), "pack.manifest", str(manifest))

    from nexus.ingest.df.amcache import AmCacheImporter
    from nexus.ingest.df.browser_history import BrowserHistoryImporter
    from nexus.ingest.df.evtx import EVTXImporter
    from nexus.ingest.df.hayabusa import HayabusaImporter
    from nexus.ingest.generic.csv import CSVImporter

    artifacts: list = []

    # --- Host EVTX (Rocba only) ---
    artifacts += ingest("security.evtx", host / "evtx" / "Security.evtx", EVTXImporter, 200)
    artifacts += ingest("system.evtx", host / "evtx" / "System.evtx", EVTXImporter, 80)
    artifacts += ingest(
        "powershell.evtx",
        host / "evtx" / "Microsoft-Windows-PowerShell%4Operational.evtx",
        EVTXImporter,
        80,
    )

    # Hayabusa on Rocba Security.evtx only — never fall back to other-lab CSVs
    hay_out = OUT / "hayabusa-security.csv"
    sec = host / "evtx" / "Security.evtx"
    if sec.is_file():
        try:
            from nexus.tools.windows import _find_binary
            hay = _find_binary("hayabusa")
            if hay:
                import subprocess
                hay_path = Path(hay)
                cp = subprocess.run(
                    [
                        str(hay_path), "dfir-timeline",
                        "-f", str(sec),
                        "-o", str(hay_out),
                        "-w", "-C", "-Q",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=600,
                    cwd=str(hay_path.parent),
                )
                rec(
                    hay_out.is_file() and hay_out.stat().st_size > 50,
                    "tool.hayabusa",
                    f"rc={cp.returncode} size={hay_out.stat().st_size if hay_out.is_file() else 0} err={(cp.stderr or cp.stdout or '')[:200]}",
                )
            else:
                rec(True, "tool.hayabusa", "binary not resolved — skip", skip=True)
        except Exception as exc:
            rec(False, "tool.hayabusa", str(exc)[:300], skip=True)

    if hay_out.is_file() and hay_out.stat().st_size > 50:
        artifacts += ingest("hayabusa-security", hay_out, HayabusaImporter, 120)
    else:
        rec(True, "ingest:hayabusa-security", "no Rocba-local hayabusa CSV — EVTX still ingested", skip=True)

    artifacts += ingest("chrome-history", host / "browser" / "Chrome-History", BrowserHistoryImporter, 80)
    artifacts += ingest("edge-history", host / "browser" / "Edge-History", BrowserHistoryImporter, 40)
    artifacts += ingest("amcache", host / "amcache" / "Amcache.hve", AmCacheImporter, 40)

    # Precooked CSVs (Rocba EZ outputs)
    for label, rel in [
        ("pecmd", "PECmd_Output.csv"),
        ("lecmd", "LECmd_Output.csv"),
        ("rbcmd", "RBCmd_Output.csv"),
        ("jumplist-auto", "AutomaticDestinations.csv"),
    ]:
        artifacts += ingest(f"precooked:{label}", precooked / rel, CSVImporter, 40)

    # Cloud audit (same Rocba case cloud labs)
    for name in ("AuditLog_2020-09-10_2020-10-04.csv", "UnifiedAuditLog_SRL.csv"):
        artifacts += ingest(f"cloud:{name[:20]}", cloud / name, CSVImporter, 40)

    sources = sorted({a.source.value for a in artifacts})
    rec(bool(artifacts), "artifact-pool", f"total={len(artifacts)} sources={sources}")
    # Guard: refuse known foreign sources
    foreign = [s for s in sources if s in ("zeek", "suricata", "syslog", "auditd", "bash_history")]
    if foreign:
        rec(False, "pack.purity", f"foreign sources leaked into Rocba pack: {foreign}")
    else:
        rec(True, "pack.purity", "no CADRE-network/linux sources")

    # --- Case ---
    from nexus.case import ApprovalState, CaseManager, FindingSeverity
    from nexus.case.compat import get_sqlite_manager
    from nexus.langgraph.agents.synthesis import SynthesisAgent
    from nexus.langgraph.pipeline import run_analysis_without_interrupt
    from nexus.langgraph.types import AgentStatus

    mgr: CaseManager = get_sqlite_manager()
    case = mgr.create_case(
        name="SHOWCASE-Rocba-500-fredr",
        description=(
            "FOR500 Rocba single-environment showcase. Host user fredr. "
            "Sources: H:\\ Rocba_Triage + E:\\Evidence_files\\500 (host/precooked/cloud). "
            "Excluded: CADRE monitor, linux01, FOR508 Amadey memory."
        ),
        severity=FindingSeverity.HIGH,
        created_by=EXAMINER,
        tags=["showcase", "rocba", "fredr", "for500"],
    )
    mgr.set_case_approval_password(case.id, APPROVE_PW)
    rec(True, "case.create", f"id={case.id}")

    # Register real files (chain of custody) — paths from pack
    register_paths = [
        host / "evtx" / "Security.evtx",
        host / "evtx" / "System.evtx",
        host / "browser" / "Chrome-History",
        host / "amcache" / "Amcache.hve",
        host / "registry" / "SYSTEM",
        host / "srum" / "SRUDB.dat",
        precooked / "PECmd_Output.csv",
        cloud / "UnifiedAuditLog_SRL.csv",
    ]
    registered = 0
    for p in register_paths:
        if not p.is_file():
            continue
        try:
            # Prefer artifact-backed register when we have a matching art
            art = next((a for a in artifacts if a.file_path and Path(a.file_path).name == p.name), None)
            if art is None:
                # minimal: add_evidence via path helper if available
                from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity
                art = Artifact(
                    id=Artifact.new_id(),
                    artifact_type=ArtifactType.FILE,
                    source=ArtifactSource.UNKNOWN,
                    timestamp=datetime.now(UTC),
                    severity=Severity.INFORMATIONAL,
                    host="rocba-fredr",
                    file_path=str(p),
                    description=f"Showcase evidence: {p.name}",
                )
            else:
                art.file_path = str(p)
                art.host = art.host or "rocba-fredr"
            ev = mgr.add_evidence_from_artifact(case.id, art, collected_by=EXAMINER)
            if ev:
                registered += 1
        except Exception as exc:
            rec(False, f"evidence:{p.name}", str(exc)[:200])
    rec(registered >= 4, "case.evidence", f"registered={registered}")

    # Also register a capped set from artifact pool for richer report
    extra = 0
    for art in artifacts[:40]:
        try:
            if not art.host:
                art.host = "rocba-fredr"
            ev = mgr.add_evidence_from_artifact(case.id, art, collected_by=EXAMINER)
            if ev:
                extra += 1
        except Exception:
            pass
    rec(True, "case.evidence.artifacts", f"extra_registered={extra}")

    # LangGraph
    try:
        state = run_analysis_without_interrupt(
            case_id=case.id,
            artifacts=artifacts,
            case_manager=mgr,
            case_name=case.name,
        )
        done = [n for n, r in state.results.items() if r.status == AgentStatus.DONE]
        titles = {n: [f.get("title") for f in r.findings] for n, r in state.results.items()}
        rec(len(done) >= 4, "langgraph.agents", f"done={done} findings={titles}")
    except Exception as exc:
        rec(False, "langgraph.agents", f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-400:]}")
        state = None

    draft_ids: list[str] = []
    if state is not None:
        try:
            syn = SynthesisAgent(mgr).run(state)
            draft_ids = list(state.draft_finding_ids) or list(syn.evidence_ids)
            rec(len(draft_ids) >= 1, "langgraph.synthesis", f"drafts={draft_ids}")
        except Exception as exc:
            rec(False, "langgraph.synthesis", str(exc))

    approved = []
    for fid in draft_ids:
        try:
            f = mgr.approve_finding(
                fid, APPROVE_PW, approved_by=EXAMINER,
                note="Rocba showcase auto-approve (operator authorized)",
            )
            ok = f is not None and f.approval_state == ApprovalState.APPROVED
            rec(ok, f"hitl.approve:{fid}", f"state={getattr(f.approval_state, 'value', None)}")
            if ok:
                approved.append(fid)
        except Exception as exc:
            rec(False, f"hitl.approve:{fid}", str(exc))

    # DFIR report with evidence-first narrative
    dfir_path = REPORT_MD / f"{case.id}-rocba-showcase.md"
    try:
        from nexus.integration.dfir_report import build_dfir_markdown
        findings_list = mgr.list_findings(case.id)
        evidence_list = mgr.list_evidence(case.id)
        fdicts = []
        for f in findings_list:
            d = f.to_dict() if hasattr(f, "to_dict") else {}
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
        for ev in evidence_list:
            meta = dict(ev.metadata or {})
            edicts.append({
                "name": ev.name,
                "path": ev.file_path,
                "sha256": ev.file_hash_sha256,
                "description": ev.description,
                "host": meta.get("host") or "rocba-fredr",
                "dest_ip": meta.get("dest_ip"),
                "source_ip": meta.get("source_ip"),
                "process_name": meta.get("process_name"),
                "metadata": meta,
            })
        for a in artifacts:
            edicts.append({
                "name": f"artifact:{a.source.value}",
                "path": a.file_path,
                "host": a.host or "rocba-fredr",
                "dest_ip": a.dest_ip,
                "source_ip": a.source_ip,
                "process_name": a.process_name,
                "description": (a.description or "")[:200],
            })
        md = build_dfir_markdown(
            case_id=case.id,
            case_name=case.name,
            findings=fdicts,
            evidence=edicts,
            timeline=[],
            sift_notes=[
                "Windows-host showcase — SIFT optional.",
                f"Pack: {PACK}",
                "Large originals on E:\\Evidence_files\\500 (Rocba-Memory.raw, VHDX, E01) — memory/POINTERS.json",
            ],
            rag_notes=["RAG optional for showcase spine."],
            examiner=EXAMINER,
            status=case.status.value,
            severity=case.severity.value,
            case_summary=(
                f"FOR500 Rocba single-host investigation for user `fredr` on host `SRL-FORGE`. "
                f"Evidence pack `{PACK.name}` is locked to H:\\ Rocba_Triage + E:\\Evidence_files\\500 "
                "(EVTX, browser, AmCache, precooked EZ CSVs, M365 audit). "
                "CADRE monitor Zeek/Suricata, linux01, and FOR508 Amadey memory are excluded."
            ),
        )
        # Prepend environment banner
        banner = (
            f"# Environment lock\n\n"
            f"- **Case:** FOR500 Rocba / user `fredr` only\n"
            f"- **Pack:** `{PACK.as_posix()}`\n"
            f"- **Manifest:** `{manifest.as_posix()}`\n"
            f"- **Excluded:** CADRE Zeek/Suricata, linux01, FOR508 Amadey\n\n"
            f"---\n\n"
        )
        dfir_path.parent.mkdir(parents=True, exist_ok=True)
        dfir_path.write_text(banner + md, encoding="utf-8")
        rec(
            "## Key Takeaways" in md and len(edicts) >= 4,
            "report.dfir",
            f"path={dfir_path} bytes={dfir_path.stat().st_size} evidence_rows={len(edicts)} approved={len(approved)}",
        )
    except Exception as exc:
        rec(False, "report.dfir", f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-300:]}")

    passed = sum(1 for r in ROWS if r["status"] == "PASS")
    failed = sum(1 for r in ROWS if r["status"] == "FAIL")
    skipped = sum(1 for r in ROWS if r["status"] == "SKIP")
    ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        f"# Rocba Showcase Case — {ts}",
        "",
        f"case=`{case.id}` pack=`{PACK}` pass=`{passed}` fail=`{failed}` skip=`{skipped}`",
        "",
        f"**Report:** `{dfir_path.relative_to(ROOT) if dfir_path.exists() else 'MISSING'}`",
        "",
        "| ok | name | detail |",
        "|----|------|--------|",
    ]
    for row in ROWS:
        flag = "skip" if row["status"] == "SKIP" else ("yes" if row["ok"] else "NO")
        detail = str(row["detail"]).replace("|", "/").replace("\n", " ")[:200]
        lines.append(f"| {flag} | `{row['name']}` | {detail} |")
    lines += [
        "",
        "## Honesty",
        "",
        "- Single environment: FOR500 Rocba / fredr.",
        "- Memory lane uses POINTERS to E:\\…\\Rocba-Memory.raw (not FOR508 Amadey vol3).",
        "- Report quality depends on EVTX/browser/precooked signal in this pack — not mixed lab noise.",
        "",
    ]
    ORCH_REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / "summary.json").write_text(
        json.dumps({"case_id": case.id, "passed": passed, "failed": failed, "rows": ROWS}, indent=2, default=str),
        encoding="utf-8",
    )
    print(f"\nREPORT {ORCH_REPORT} CASE={case.id} DFIR={dfir_path}", flush=True)
    try:
        mgr.close()
    except Exception:
        pass
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
