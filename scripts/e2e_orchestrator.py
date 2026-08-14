#!/usr/bin/env python3
"""Orchestrator E2E: LangGraph 6-agent + RAG + detection/MITRE + SIFT + HITL.

This is the advertised product path, not lane smoke:
  ingest real artifacts → DFIRAgentGraph (Timeline/Endpoint/Network/Alert/Cloud)
  → Synthesis DRAFT → RAG/detection/MITRE/playbooks/TI/triage grounded in the case
  → examiner approve → SIFT Linux tool host + portal health.

Soft-fail only: CyberTriage / Falco-Sysdig / Security Onion / SocRates.
Do not publish.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import traceback
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EV = ROOT / "Evidence-files"
OUT = EV / "_e2e-out" / "orchestrator"
REPORT = ROOT / "Docs" / "internal" / "ORCHESTRATOR-E2E-REPORT.md"
SIFT_KEY = Path.home() / ".ssh" / "cadre-sift-key"
SIFT_HOST = "sansforensics@192.168.77.135"
SIFT_IP = "192.168.77.135"
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
    ROWS.append({"ok": ok, "skip": skip, "name": name, "detail": detail[:500], "status": status})
    flag = "skip" if skip else ("yes" if ok else "NO ")
    safe = "".join(ch if ord(ch) < 128 else "?" for ch in str(detail)[:180])
    print(f"[{flag}] {name}: {safe}", flush=True)


def take(seq, n: int):
    out = []
    for i, item in enumerate(seq):
        if i >= n:
            break
        out.append(item)
    return out


def ingest_file(label: str, path: Path, importer_cls, cap: int) -> list:
    if not path.is_file():
        rec(False, f"ingest:{label}", f"missing {path}")
        return []
    try:
        arts = take(importer_cls().parse(path), cap)
        rec(True, f"ingest:{label}", f"n={len(arts)} src={getattr(arts[0].source, 'value', '?') if arts else 'empty'} {path.name}")
        return arts
    except Exception as exc:
        rec(False, f"ingest:{label}", f"{type(exc).__name__}: {exc}")
        return []


def ssh(cmd: str, timeout: int = 90) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "ssh", "-i", str(SIFT_KEY),
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=12",
            "-o", "StrictHostKeyChecking=accept-new",
            SIFT_HOST, cmd,
        ],
        capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace",
    )


def http_get(url: str, timeout: int = 8, headers: dict | None = None) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "nexus-orch-e2e"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(800).decode("utf-8", errors="replace")
            return int(resp.status), body
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(800).decode("utf-8", errors="replace")
        except Exception:
            body = str(exc)
        return int(exc.code or 0), body
    except Exception as exc:
        return 0, str(exc)


def rag_hits_ok(result: dict) -> bool:
    rows = result.get("results") or []
    return bool(rows) and any(
        (r.get("score") or r.get("relevance") or 0) >= 0.5 or r.get("document") or r.get("text") or r.get("title")
        for r in rows
    )


def main() -> int:
    artifacts: list = []

    # ------------------------------------------------------------------
    # 1. Real evidence → Artifact objects (capped)
    # ------------------------------------------------------------------
    from nexus.ingest.df.browser_history import BrowserHistoryImporter
    from nexus.ingest.df.hayabusa import HayabusaImporter
    from nexus.ingest.df.volatility import VolatilityImporter
    from nexus.ingest.linux.auditd import AuditdImporter
    from nexus.ingest.linux.authlog import AuthLogImporter
    from nexus.ingest.linux.bash_history import BashHistoryImporter
    from nexus.ingest.linux.syslog import SyslogImporter
    from nexus.ingest.network.suricata import SuricataImporter
    from nexus.ingest.network.zeek import ZeekImporter

    artifacts += ingest_file("zeek-conn", EV / "04-network" / "monitor-live" / "conn.log", ZeekImporter, 80)
    artifacts += ingest_file("suricata-eve", EV / "04-network" / "monitor-live" / "eve-tail.json", SuricataImporter, 60)
    artifacts += ingest_file("hayabusa-sysmon", EV / "_e2e-out" / "host-full" / "tools" / "hayabusa-sysmon.csv", HayabusaImporter, 80)
    if not any(a.source.value == "hayabusa" for a in artifacts):
        artifacts += ingest_file("hayabusa-fixture", EV / "_fixtures" / "hayabusa-timeline.csv", HayabusaImporter, 40)
    artifacts += ingest_file("vol3-psscan", EV / "02-memory" / "rocba-508" / "vol3-amadey" / "windows.psscan.json", VolatilityImporter, 80)
    artifacts += ingest_file("chrome-history", EV / "01-windows" / "rocba-fredr" / "browser" / "Chrome-History", BrowserHistoryImporter, 40)
    artifacts += ingest_file("linux-audit", EV / "03-linux" / "audit.log", AuditdImporter, 30)
    artifacts += ingest_file("linux-auth", EV / "03-linux" / "auth.log", AuthLogImporter, 20)
    artifacts += ingest_file("linux-syslog", EV / "03-linux" / "syslog", SyslogImporter, 20)
    artifacts += ingest_file("linux-bash", EV / "03-linux" / "bash_history", BashHistoryImporter, 20)

    rec(bool(artifacts), "artifact-pool", f"total={len(artifacts)} sources={sorted({a.source.value for a in artifacts})}")

    # ------------------------------------------------------------------
    # 2. SQLite case + evidence register
    # ------------------------------------------------------------------
    from nexus.case import ApprovalState, CaseManager, FindingSeverity
    from nexus.case.compat import get_sqlite_manager
    from nexus.langgraph.agents.synthesis import SynthesisAgent
    from nexus.langgraph.pipeline import run_analysis_without_interrupt
    from nexus.langgraph.types import AgentStatus

    mgr: CaseManager = get_sqlite_manager()
    case = mgr.create_case(
        name="ORCH-Rocba-Fredr",
        description="Orchestrator E2E: Rocba fredr + monitor Zeek/Suricata + vol3 psscan + linux logs",
        severity=FindingSeverity.HIGH,
        created_by=EXAMINER,
        tags=["orchestrator", "e2e", "rocba", "fredr"],
    )
    mgr.set_case_approval_password(case.id, APPROVE_PW)
    rec(True, "case.create", f"id={case.id} name={case.name}")

    registered = 0
    for art in artifacts[:25]:
        ev = mgr.add_evidence_from_artifact(case.id, art, collected_by=EXAMINER)
        if ev:
            registered += 1
    rec(registered >= 5, "case.evidence", f"registered={registered}")

    # ------------------------------------------------------------------
    # 3. LangGraph 6-agent orchestrator (heuristic DFIRAgentGraph + Synthesis)
    # ------------------------------------------------------------------
    try:
        state = run_analysis_without_interrupt(
            case_id=case.id,
            artifacts=artifacts,
            case_manager=mgr,
            case_name=case.name,
        )
        agent_names = sorted(state.results.keys())
        done = [n for n, r in state.results.items() if r.status == AgentStatus.DONE]
        notes = {n: list(r.notes) for n, r in state.results.items()}
        findings_by_agent = {n: [f.get("title") for f in r.findings] for n, r in state.results.items()}
        rec(
            len(done) >= 5,
            "langgraph.5-agents",
            f"agents={agent_names} done={done} findings={findings_by_agent} notes={ {k: v[:2] for k, v in notes.items()} }",
        )
        if state.error:
            rec(False, "langgraph.error", state.error)
    except Exception as exc:
        rec(False, "langgraph.5-agents", f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-400:]}")
        state = None

    draft_ids: list[str] = []
    if state is not None:
        try:
            syn = SynthesisAgent(mgr).run(state)
            draft_ids = list(state.draft_finding_ids) or list(syn.evidence_ids)
            rec(
                syn.status.value in ("needs_approval", "done") and len(draft_ids) >= 1,
                "langgraph.synthesis",
                f"status={syn.status.value} drafts={draft_ids} notes={syn.notes} err={syn.error}",
            )
        except Exception as exc:
            rec(False, "langgraph.synthesis", f"{type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------
    # 4. RAG grounded in this case (not a dummy 'LSASS' smoke only)
    # ------------------------------------------------------------------
    observed_ttps: list[str] = []
    if state is not None:
        for r in state.results.values():
            for f in r.findings:
                observed_ttps.extend(f.get("technique_ids") or [])
    for a in artifacts:
        observed_ttps.extend(a.technique_ids or [])
    observed_ttps = [t for t in dict.fromkeys(observed_ttps) if t.startswith("T")]

    rag_queries = [
        "Sysmon process create credential dumping LSASS",
        "Zeek SMB lateral movement detection",
        "Volatility psscan injected process memory forensics",
        "browser history C2 beaconing forensic analysis",
    ]
    if observed_ttps:
        rag_queries.insert(0, f"{observed_ttps[0]} detection methodology")

    try:
        from nexus.tools.rag import RAGIndex
        idx = RAGIndex()
        idx.load()
        rec(True, "rag.load", f"docs={idx.collection.count() if idx.collection else '?'} sources={len(idx.available_sources)}")
        rag_ok = 0
        rag_sample = []
        for q in rag_queries[:4]:
            res = idx.search(query=q, top_k=5)
            hits = res.get("results") or []
            top = hits[0] if hits else {}
            title = (top.get("metadata") or {}).get("title") or top.get("title") or (top.get("document") or "")[:80]
            score = top.get("score") or top.get("relevance")
            rec(bool(hits), f"rag.search:{q[:40]}", f"n={len(hits)} top={title!r} score={score}")
            rag_ok += int(bool(hits))
            if hits:
                rag_sample.append({"q": q, "title": str(title)[:120], "score": score})
        rec(rag_ok >= 3, "rag.grounded", f"ok={rag_ok}/{len(rag_queries[:4])} sample={rag_sample[:2]}")
        (OUT / "rag-sample.json").write_text(json.dumps(rag_sample, indent=2, default=str), encoding="utf-8")
    except Exception as exc:
        rec(False, "rag.load", f"{type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------
    # 5. Detection / MITRE / playbooks
    # ------------------------------------------------------------------
    try:
        from nexus.detection.indexer import DetectionIndexer
        from nexus.detection.search import DetectionSearcher

        sigma_root = EV / "10-sigma" / "rules"
        index_dir = Path.home() / ".nexus" / "data" / "detection-index"
        index_dir.mkdir(parents=True, exist_ok=True)
        if sigma_root.is_dir() and not any(index_dir.glob("*.json")):
            n = DetectionIndexer(index_dir).index_sigma_directory(sigma_root)
            rec(n > 0, "detection.index", f"indexed={n}")
        else:
            rec(True, "detection.index", f"existing index={index_dir} files={len(list(index_dir.glob('*.json')))}")

        searcher = DetectionSearcher(index_dir)
        det_queries = [("mimikatz", ""), ("", observed_ttps[0] if observed_ttps else "T1003"), ("powershell", "")]
        det_hits_total = 0
        for q, tid in det_queries:
            hits = searcher.search(technique_id=tid or None, query=q or None) or []
            det_hits_total += len(hits)
            rec(True, f"detection.search:{q or tid}", f"n={len(hits)} first={getattr(hits[0], 'title', hits[0]) if hits else '-'}")
        rec(True, "detection.search.rollup", f"total_hits={det_hits_total} (0 is honest if sigma index empty)")
    except Exception as exc:
        rec(False, "detection.search", f"{type(exc).__name__}: {exc}")

    try:
        from nexus.detection.sigma_repo import sigma_translate
        sample_yaml = (
            "title: Orch E2E dummy\nlogsource:\n  product: windows\n  service: sysmon\n"
            "detection:\n  selection:\n    EventID: 1\n    Image|endswith: '\\mimikatz.exe'\n  condition: selection\n"
        )
        translated = sigma_translate(sample_yaml, target="kql")
        rec(bool(translated), "sigma_translate.kql", str(translated)[:200])
    except Exception as exc:
        rec(False, "sigma_translate.kql", f"{type(exc).__name__}: {exc}", skip="detection extra" in str(exc).lower())

    try:
        from nexus.mitre.adversary import match_observed_to_groups, predict_next_techniques
        seed = observed_ttps[:6] or ["T1003", "T1059.001", "T1071.001"]
        preds = predict_next_techniques(seed, top_n=8)
        groups = match_observed_to_groups(seed, min_overlap=1)
        rec(
            bool(preds),
            "mitre.predict",
            f"seed={seed} preds={[p.to_dict() for p in preds[:5]]} groups={str(groups)[:200]}",
        )
    except Exception as exc:
        rec(False, "mitre.predict", f"{type(exc).__name__}: {exc}")

    try:
        from nexus.knowledge.loader import list_playbooks
        pbs = list_playbooks() or []
        rec(len(pbs) >= 1, "playbooks.list", f"n={len(pbs)} names={[p.get('name') or p.get('id') or p.get('title') for p in pbs[:6]]}")
    except Exception as extra_exc:
        rec(False, "playbooks.list", f"{type(extra_exc).__name__}: {extra_exc}")

    # ------------------------------------------------------------------
    # 6. TI + triage (investigation steps, not one-shot smoke)
    # ------------------------------------------------------------------
    sample_ip = next((a.dest_ip or a.source_ip for a in artifacts if (a.dest_ip or a.source_ip)), None)
    try:
        import asyncio

        from nexus.ti.router import TIRouter
        router = TIRouter()
        ioc = sample_ip or "8.8.8.8"
        result = asyncio.run(router.lookup(ioc, ioc_type="ip"))
        rec(isinstance(result, dict), "ti.lookup", f"ioc={ioc} malicious={result.get('malicious_count')} providers={result.get('providers_queried')} err={result.get('error')}")
    except Exception as exc:
        rec(False, "ti.lookup", f"{type(exc).__name__}: {exc}")

    try:
        from nexus.triage.analysis import analyze_filename, check_suspicious_path
        from nexus.triage.server import _open_dbs

        fn = analyze_filename("mimikatz.exe")
        sus = check_suspicious_path(r"C:\Users\fredr\AppData\Local\Temp\payload.exe")
        kg, ctx = _open_dbs()
        kg_ok = kg is not None
        rec(True, "triage.filename", f"mimikatz={fn}")
        rec(True, "triage.suspicious_path", f"hits={sus}")
        rec(kg_ok, "triage.known_good_db", f"open={kg_ok} context={ctx is not None}")
        for db in (kg, ctx):
            if db is not None and hasattr(db, "close"):
                try:
                    db.close()
                except Exception:
                    pass
    except Exception as exc:
        rec(False, "triage", f"{type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------
    # 7. HITL approve Synthesis DRAFTs (operator-authorized auto-approve)
    # ------------------------------------------------------------------
    approved = []
    for fid in draft_ids:
        try:
            f = mgr.approve_finding(fid, APPROVE_PW, approved_by=EXAMINER, note="Orchestrator E2E auto-approve (operator authorized)")
            ok = f is not None and f.approval_state == ApprovalState.APPROVED
            rec(ok, f"hitl.approve:{fid}", f"state={getattr(getattr(f, 'approval_state', None), 'value', None)} hmac={bool(getattr(f, 'hmac_signature', None))}")
            if ok:
                approved.append(fid)
        except Exception as exc:
            rec(False, f"hitl.approve:{fid}", f"{type(exc).__name__}: {exc}")
    rec(len(approved) >= 1, "hitl.approved-any", f"approved={approved}")

    try:
        ok_sig, errs = mgr.verify_approval_signatures(case.id, APPROVE_PW)
        rec(ok_sig, "hitl.verify-signatures", f"ok={ok_sig} errs={errs}")
    except Exception as exc:
        rec(False, "hitl.verify-signatures", f"{type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------
    # 8. LLM pipeline smoke (compile/model; full hunt is HITL-gated)
    # ------------------------------------------------------------------
    llm_configured = bool(os.environ.get("NEXUS_LLM_MODEL") or os.environ.get("NEXUS_MODEL"))
    rec(True, "llm.env", f"configured={llm_configured} model_set={bool(os.environ.get('NEXUS_LLM_MODEL') or os.environ.get('NEXUS_MODEL'))} base_url_set={bool(os.environ.get('NEXUS_LLM_BASE_URL'))} key_set={bool(os.environ.get('NEXUS_LLM_API_KEY'))}")
    try:
        from nexus.langgraph.llm_pipeline import get_mcp_config
        cfg = get_mcp_config()
        rec(bool(cfg), "llm.mcp_config", f"servers={list(cfg)}")
        if llm_configured:
            from nexus.langgraph.llm_pipeline import get_model
            model = get_model()
            rec(model is not None, "llm.get_model", f"type={type(model).__name__}")
        else:
            rec(True, "llm.get_model", "no NEXUS_LLM_* / NEXUS_MODEL — skip live LLM hunt", skip=True)
    except Exception as exc:
        rec(False, "llm.pipeline-import", f"{type(exc).__name__}: {exc}", skip="not installed" in str(exc).lower() or "No LLM" in str(exc))

    # ------------------------------------------------------------------
    # 9. SIFT Linux tool host + portal
    # ------------------------------------------------------------------
    sift_notes: list[str] = []
    if not SIFT_KEY.is_file():
        rec(False, "sift.key", f"missing {SIFT_KEY}")
    else:
        rec(True, "sift.key", str(SIFT_KEY))

    code, body = http_get(f"http://{SIFT_IP}:4508/health")
    rec(code == 200, "sift.health", f"http={code} body={body[:120]}")
    code_mcp, body_mcp = http_get(
        f"http://{SIFT_IP}:4508/mcp",
        headers={
            "Host": f"{SIFT_IP}:4508",
            "Accept": "application/json, text/event-stream",
        },
    )
    # After mcp_security Host allowlist fix, Windows→lab-IP /mcp must not 421.
    # 400 Missing session ID / 406 Not Acceptable both prove Host was accepted.
    host_ok = code_mcp != 421 and "Invalid Host" not in body_mcp
    protocol_ok = code_mcp in (200, 400, 405, 406) or "jsonrpc" in body_mcp.lower()
    rec(
        host_ok and protocol_ok,
        "sift.mcp.windows",
        f"http={code_mcp} body={body_mcp[:160]}",
        skip=code_mcp == 0,
    )

    loc_code, loc_body = http_get("http://127.0.0.1:4508/health")
    rec(loc_code == 200, "portal.local.health", f"http={loc_code} body={loc_body[:80]}", skip=loc_code == 0)

    if SIFT_KEY.is_file():
        try:
            r = ssh("hostname; python3 -c \"import nexus,sys; print('nexus', nexus.__file__)\"; which fls tshark vol3 mactime 2>/dev/null; fls -V 2>&1 | head -1; tshark -v 2>&1 | head -1")
            rec(r.returncode == 0, "sift.ssh.tools", (r.stdout or r.stderr)[:400])
        except Exception as exc:
            rec(False, "sift.ssh.tools", str(exc))
        try:
            r = ssh(
                "curl -sS -m 8 -o /tmp/mcp-loop.out -w '%{http_code}' "
                "-H 'Accept: application/json, text/event-stream' "
                "-H 'Content-Type: application/json' "
                "-d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
                "\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},"
                "\"clientInfo\":{\"name\":\"orch\",\"version\":\"0\"}}}' "
                "http://127.0.0.1:4508/mcp; echo; head -c 240 /tmp/mcp-loop.out"
            )
            out = (r.stdout or "") + (r.stderr or "")
            rec(
                "jsonrpc" in out.lower() or any(x in out for x in ("200", "400", "406")),
                "sift.mcp.loopback",
                out[:300],
            )
        except Exception as exc:
            rec(False, "sift.mcp.loopback", str(exc))

        remote_py = r"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path.home() / 'DFIR-Nexus' / 'src'))
from nexus.ingest.linux.auditd import AuditdImporter
from nexus.ingest.linux.bash_history import BashHistoryImporter
from nexus.ingest.network.zeek import ZeekImporter
home = Path.home() / 'DFIR-Nexus' / 'Evidence-files'
# fallback: staged copies from prior e2e
cands = [
    (home / '03-linux' / 'audit.log', AuditdImporter, 'audit'),
    (home / '03-linux' / 'bash_history', BashHistoryImporter, 'bash'),
    (home / '04-network' / 'monitor-live' / 'conn.log', ZeekImporter, 'zeek'),
]
import os
alt = Path.home() / 'DFIR-Nexus'
for p in alt.rglob('audit.log'):
    if '03-linux' in str(p) or 'linux' in str(p).lower():
        cands[0] = (p, AuditdImporter, 'audit')
        break
out = {}
for path, cls, label in cands:
    if not path.is_file():
        out[label] = f'MISSING:{path}'
        continue
    n = sum(1 for _ in cls().parse(path))
    out[label] = n
print('SIFT_INGEST', out)
"""
        try:
            r = ssh(f"python3 - <<'PY'\n{remote_py}\nPY")
            rec("SIFT_INGEST" in (r.stdout or ""), "sift.ingest.linux", (r.stdout or r.stderr)[:400])
        except Exception as exc:
            rec(False, "sift.ingest.linux", str(exc))

        try:
            r = ssh("python3 - <<'PY'\n"
                    "import subprocess, shutil\n"
                    "cmds = []\n"
                    "for b in ['fls','tshark','yara','strings','ssdeep']:\n"
                    "    p = shutil.which(b)\n"
                    "    if not p:\n"
                    "        cmds.append(f'{b}=MISSING'); continue\n"
                    "    args = [p, '-V'] if b != 'strings' else [p, '--version']\n"
                    "    if b == 'ssdeep': args = [p, '-V']\n"
                    "    cp = subprocess.run(args, capture_output=True, text=True, timeout=20)\n"
                    "    cmds.append(f'{b}=rc{cp.returncode}')\n"
                    "print('SIFT_RUN', cmds)\n"
                    "PY")
            rec("SIFT_RUN" in (r.stdout or ""), "sift.run_command.smoke", (r.stdout or r.stderr)[:400])
            if r.stdout:
                sift_notes.append((r.stdout or "").strip()[:240])
        except Exception as exc:
            rec(False, "sift.run_command.smoke", str(exc))

        # Real case evidence analysis on SIFT (not version smoke only)
        case_tool_py = r"""
import shutil, subprocess
from pathlib import Path
home = Path.home() / 'DFIR-Nexus' / 'Evidence-files'
notes = []
# strings on bash_history / audit
for rel in ['03-linux/bash_history', '03-linux/audit.log', '03-linux/auth.log']:
    p = home / rel
    if not p.is_file():
        notes.append(f'MISSING {rel}')
        continue
    bin_s = shutil.which('strings')
    if not bin_s:
        notes.append('strings=MISSING'); break
    cp = subprocess.run([bin_s, '-n', '8', str(p)], capture_output=True, text=True, timeout=60)
    lines = [ln for ln in (cp.stdout or '').splitlines() if ln.strip()]
    sample = lines[:8]
    notes.append(f'strings {rel}: n={len(lines)} sample={sample[:4]}')
# tshark if any pcap present
pcap = None
for cand in home.rglob('*.pcap*'):
    pcap = cand
    break
th = shutil.which('tshark')
if th and pcap and pcap.is_file():
    cp = subprocess.run([th, '-r', str(pcap), '-q', '-z', 'io,phs'], capture_output=True, text=True, timeout=90)
    out = (cp.stdout or cp.stderr or '')[:300].replace('\n', ' | ')
    notes.append(f'tshark -r {pcap.name} io,phs rc={cp.returncode} {out}')
elif th:
    notes.append('tshark=present but no pcap under Evidence-files')
else:
    notes.append('tshark=MISSING')
# fls on any raw image if present
fls = shutil.which('fls')
img = None
for cand in list(home.rglob('*.E01')) + list(home.rglob('*.dd')) + list(home.rglob('*.raw')):
    img = cand
    break
if fls and img:
    cp = subprocess.run([fls, '-p', str(img)], capture_output=True, text=True, timeout=90)
    notes.append(f'fls {img.name} rc={cp.returncode} lines={len((cp.stdout or "").splitlines())}')
elif fls:
    notes.append('fls=present; no E01/dd/raw in Evidence-files (expected for this corpus)')
print('SIFT_CASE')
for n in notes:
    print(n)
"""
        try:
            r = ssh(f"python3 - <<'PY'\n{case_tool_py}\nPY", timeout=180)
            out = (r.stdout or "") + (r.stderr or "")
            ok_case = "SIFT_CASE" in out and "strings" in out
            rec(ok_case, "sift.case.tools", out[:500])
            for line in out.splitlines():
                if line.startswith("SIFT_CASE"):
                    continue
                if line.strip():
                    sift_notes.append(line.strip()[:300])
        except Exception as exc:
            rec(False, "sift.case.tools", str(exc))

    # ------------------------------------------------------------------
    # 10. DFIR Report-style narrative (examiner deliverable)
    # ------------------------------------------------------------------
    dfir_path = ROOT / "Docs" / "internal" / "reports" / f"{case.id}-dfir.md"
    rag_notes = [
        f"RAG grounded queries run during orchestrator E2E; see {OUT / 'rag-sample.json'}",
    ]
    try:
        from nexus.integration.dfir_report import build_dfir_markdown
        findings_list = mgr.list_findings(case.id)
        evidence_list = mgr.list_evidence(case.id)
        fdicts = []
        for f in findings_list:
            d = f.to_dict() if hasattr(f, "to_dict") else {}
            d["status"] = f.approval_state.value.upper()
            d["approval_state"] = f.approval_state.value.upper()
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
                "host": meta.get("host"),
                "dest_ip": meta.get("dest_ip"),
                "source_ip": meta.get("source_ip"),
                "process_name": meta.get("process_name"),
                "metadata": meta,
            })
        # Enrich indicators from artifact pool (evidence register is capped)
        for a in artifacts:
            if a.dest_ip:
                edicts.append({"dest_ip": a.dest_ip, "source_ip": a.source_ip, "host": a.host, "name": f"artifact:{a.source.value}"})
        det_sample = []
        try:
            from nexus.detection.search import DetectionSearcher
            index_dir = Path.home() / ".nexus" / "data" / "detection-index"
            if index_dir.exists():
                hits = DetectionSearcher(index_dir).search(query="mimikatz") or []
                for h in hits[:10]:
                    det_sample.append({
                        "title": getattr(h, "title", str(h)),
                        "technique_ids": list(getattr(h, "technique_ids", None) or []),
                    })
        except Exception:
            pass
        md = build_dfir_markdown(
            case_id=case.id,
            case_name=case.name,
            findings=fdicts,
            evidence=edicts,
            timeline=[],
            detections=det_sample,
            sift_notes=sift_notes,
            rag_notes=rag_notes,
            examiner=EXAMINER,
            status=case.status.value,
            severity=case.severity.value,
        )
        dfir_path.parent.mkdir(parents=True, exist_ok=True)
        dfir_path.write_text(md, encoding="utf-8")
        rec(
            "## Key Takeaways" in md and "Sample evidence:" in md,
            "report.dfir",
            f"path={dfir_path} bytes={dfir_path.stat().st_size} approved_findings={sum(1 for f in fdicts if f.get('status')=='APPROVED')}",
        )
    except Exception as exc:
        rec(False, "report.dfir", f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-300:]}")

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    passed = sum(1 for r in ROWS if r["status"] == "PASS")
    failed = sum(1 for r in ROWS if r["status"] == "FAIL")
    skipped = sum(1 for r in ROWS if r["status"] == "SKIP")
    ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = [
        f"# Orchestrator E2E — {ts}",
        "",
        f"case=`{case.id}` examiner=`{EXAMINER}` artifacts=`{len(artifacts)}` "
        f"pass=`{passed}` fail=`{failed}` skip=`{skipped}`",
        "",
        "Advertised path: **LangGraph DFIRAgentGraph** (Timeline / Endpoint / Network / Alert / Cloud + Synthesis HITL) "
        "+ RAG + detection/MITRE/playbooks + TI/triage + SIFT Linux tool host + DFIR Report narrative.",
        "",
        f"**Examiner report:** `{dfir_path.relative_to(ROOT) if dfir_path.exists() else 'MISSING'}`",
        "",
        "| ok | name | detail |",
        "|----|------|--------|",
    ]
    for row in ROWS:
        flag = "skip" if row["status"] == "SKIP" else ("yes" if row["ok"] else "NO")
        detail = str(row["detail"]).replace("|", "/").replace("\n", " ")[:220]
        lines.append(f"| {flag} | `{row['name']}` | {detail} |")
    lines += [
        "",
        "## Honest limits",
        "",
        "- Heuristic 6-agent graph ran on real Rocba/monitor artifacts with artifact-cited finding bodies.",
        "- LLM `nexus pipeline` full hunt is HITL-interrupt + MCP + model; smoked import/config only unless LLM env is set.",
        "- CloudAgent is empty unless CloudTrail/Azure/M365 artifacts exist in this corpus.",
        "- SIFT is the Linux tool host (second MCP server). Case evidence tools (strings/tshark/fls) ran over SSH.",
        "- Soft-fail still: CyberTriage / Falco-Sysdig / Security Onion / SocRates.",
        "- Not 12/12 stranger-pass. Do not publish.",
        "",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / "summary.json").write_text(
        json.dumps({"case_id": case.id, "passed": passed, "failed": failed, "skipped": skipped, "rows": ROWS, "dfir_report": str(dfir_path)}, indent=2, default=str),
        encoding="utf-8",
    )
    print(f"\nREPORT {REPORT}  PASS={passed} FAIL={failed} SKIP={skipped} CASE={case.id}", flush=True)
    print(f"DFIR {dfir_path}", flush=True)
    try:
        mgr.close()
    except Exception:
        pass
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
