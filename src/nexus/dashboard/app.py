"""Examiner Portal — browser-based case review + approval (HMAC commit).

Mounted automatically in HTTP mode at /portal.
Implements the original case-dashboard features: findings, timeline,
evidence, IOCs, todos, and the commit challenge-response workflow
for browser-based finding approval.
"""

import asyncio
import contextlib
import hashlib
import hmac as hmac_mod
import html
import json
import logging
import math
import os
import re
import secrets
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from starlette.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from starlette.routing import Route

logger = logging.getLogger(__name__)

_CHALLENGE_TTL = 300  # 5 minutes
_CHALLENGE_MAX = 1000
_challenges: dict[str, dict] = {}
_challenge_lock = threading.Lock()
_MAX_COMMIT_ATTEMPTS = 3
_COMMIT_LOCKOUT_SECONDS = 900
_LOCKOUT_FILE = Path.home() / ".nexus" / ".commit_lockout"


def _replace_with_retry(tmp: str, path: Path) -> None:
    """``os.replace`` with a short retry.

    On Windows, replacing a file that another thread/process (or an AV/indexer)
    momentarily holds open raises ``PermissionError``. The Mode 1 run record is
    written by both the POST handler and the background worker, so a transient
    collision must not fail the run.
    """
    last: Exception | None = None
    for attempt in range(6):
        try:
            os.replace(tmp, path)
            return
        except PermissionError as exc:  # transient on Windows
            last = exc
            time.sleep(0.05 * (attempt + 1))
    if last is not None:
        raise last


def _atomic_write_json(path: Path, data: Any) -> None:
    """Write JSON atomically to avoid corruption on crash."""
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        os.close(fd)
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2, default=str)
        _replace_with_retry(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _atomic_write_text(path: Path, text: str) -> None:
    """Write UTF-8 text atomically to avoid corruption on crash."""
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        os.close(fd)
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        _replace_with_retry(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _request_case_id(request=None) -> str:
    """Explicit case identity supplied by the SPA (header or query param).

    Returns "" when absent or invalid so callers fall back to the active-case
    pointer (CLI / MCP / legacy HTML keep working unchanged).
    """
    if request is None:
        return ""
    cid = ""
    try:
        cid = str(request.headers.get("X-Nexus-Case") or "").strip()
    except Exception:  # noqa: BLE001 — non-HTTP request objects
        cid = ""
    if not cid:
        try:
            cid = str(request.query_params.get("case_id") or "").strip()
        except Exception:  # noqa: BLE001
            cid = ""
    if not cid:
        return ""
    from nexus.discipline import validate_case_id

    if validate_case_id(cid):
        return ""
    return cid


def _get_case_dir(request=None) -> Path | None:
    """Resolve the case for a request.

    Explicit case identity (``X-Nexus-Case`` header or ``?case_id=``) always
    wins over the server-side active-case pointer. The pointer remains the
    fallback for CLI, MCP, and legacy HTML consumers.
    """
    cid = _request_case_id(request)
    if cid:
        from nexus.config import settings

        candidate = settings.cases_root / cid
        return candidate if candidate.is_dir() else None
    from nexus.case.outputs import resolve_active_case_dir

    return resolve_active_case_dir()


def _resolve_case_dir_for(case_id: str, request=None) -> Path | None:
    """Resolve an explicitly named case (body ``case_id`` preferred)."""
    from nexus.config import settings

    cid = (case_id or "").strip()
    if cid:
        from nexus.discipline import validate_case_id

        if validate_case_id(cid):
            return None
        candidate = settings.cases_root / cid
        return candidate if candidate.is_dir() else None
    return _get_case_dir(request)


def _transition_case_status(
    case_id: str,
    target: str,
    allowed_from: set[str] | None = None,
) -> None:
    """Best-effort audit-chained status transition (SQLite is the record).

    ``allowed_from`` gates the transition so e.g. registering late evidence
    cannot drag an ACTIVE case back to INTAKE. SEALED is never downgraded.
    """
    from nexus.case import CaseManager
    from nexus.case.schemas import CaseStatus
    from nexus.config import settings

    try:
        target_status = CaseStatus(target)
    except ValueError:
        return
    try:
        mgr = CaseManager(settings.cases_root / "cases.db")
    except Exception as exc:  # noqa: BLE001
        logger.warning("status transition: manager init failed: %s", exc)
        return
    try:
        case = mgr.get_case(case_id)
        if case is None:
            return
        if case.status == CaseStatus.SEALED and target_status != CaseStatus.SEALED:
            return
        if case.status == target_status:
            return
        if allowed_from is not None and case.status.value not in allowed_from:
            return
        mgr.update_status(case_id, target_status, actor="portal")
    except Exception as exc:  # noqa: BLE001 — status is best-effort
        logger.warning("status transition %s -> %s failed: %s", case_id, target, exc)
    finally:
        mgr.close()


def _sealed_case_error(case_id: str):
    """409 response when the case is sealed (completed) — reopen required."""
    if not case_id:
        return None
    from nexus.case import CaseManager
    from nexus.case.schemas import CaseStatus
    from nexus.config import settings

    try:
        mgr = CaseManager(settings.cases_root / "cases.db")
        try:
            case = mgr.get_case(case_id)
        finally:
            mgr.close()
    except Exception:  # noqa: BLE001 — never block on a lookup failure
        return None
    if case is not None and case.status == CaseStatus.SEALED:
        return JSONResponse(
            {"error": "Case is sealed (completed) — reopen it to run more actions"},
            status_code=409,
        )
    return None


def _pipeline_run_status_path(case_dir: Path, run_id: str) -> Path:
    return case_dir / "analysis" / "pipeline_runs" / f"{run_id}.json"


def _persist_pipeline_run(case_dir: Path, record: dict[str, Any]) -> None:
    """Write-through pipeline run state so status survives reload/restart."""
    try:
        path = _pipeline_run_status_path(case_dir, str(record.get("run_id") or ""))
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(path, record)
    except Exception as exc:  # noqa: BLE001
        logger.warning("pipeline run state persist failed: %s", exc)


def _load_json(name: str, request=None) -> list:
    case_dir = _get_case_dir(request)
    if not case_dir:
        return []
    path = case_dir / name
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _evidence_items(request=None, case_dir: Path | None = None) -> list:
    """Registered evidence for a case from the SQLite system of record.

    Falls back to the flat mirror only if the registry read fails, so legacy
    pages never break while the one true list is SQLite.
    """
    directory = case_dir or _get_case_dir(request)
    if not directory:
        return []
    from nexus.case import evidence_service

    try:
        return evidence_service.list_evidence(directory)
    except Exception as exc:  # noqa: BLE001 — legacy page must not 500
        logger.warning("evidence list failed for %s: %s", directory.name, exc)
        return _load_json("evidence.json", request)


def _load_password_entry(examiner: str) -> dict | None:
    """Load the examiner password entry from the shared nexus.auth store.

    Single source with `nexus config --setup-password` and
    `mode3.seal_case` — the previous dashboard-local store could diverge
    from the store the seal path reads.
    """
    from nexus.auth import _load_password_entry as _auth_load_password_entry

    return _auth_load_password_entry(examiner)


def _resolve_examiner(request) -> str:
    from nexus.audit import resolve_examiner
    return resolve_examiner()


def _commit_failure_count(examiner: str) -> int:
    if not _LOCKOUT_FILE.exists():
        return 0
    try:
        data = json.loads(_LOCKOUT_FILE.read_text())
        recent = [t for t in data.get(examiner, []) if time.time() - t < _COMMIT_LOCKOUT_SECONDS]
        return len(recent)
    except (OSError, json.JSONDecodeError):
        return 0


def _record_commit_failure(examiner: str) -> None:
    data = {}
    if _LOCKOUT_FILE.exists():
        with contextlib.suppress(OSError, json.JSONDecodeError):
            data = json.loads(_LOCKOUT_FILE.read_text())
    failures = data.get(examiner, [])
    failures.append(time.time())
    data[examiner] = failures
    _LOCKOUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _LOCKOUT_FILE.write_text(json.dumps(data))


def _clear_commit_failures(examiner: str) -> None:
    if not _LOCKOUT_FILE.exists():
        return
    try:
        data = json.loads(_LOCKOUT_FILE.read_text())
        data.pop(examiner, None)
        _LOCKOUT_FILE.write_text(json.dumps(data))
    except (OSError, json.JSONDecodeError):
        pass


def _check_commit_lockout(examiner: str) -> str | None:
    if _commit_failure_count(examiner) >= _MAX_COMMIT_ATTEMPTS:
        return f"Too many failed attempts. Locked for {_COMMIT_LOCKOUT_SECONDS // 60} minutes."
    return None


async def get_commit_challenge(request) -> JSONResponse:
    """Issue a challenge nonce + salt for password verification."""
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    lockout_msg = _check_commit_lockout(examiner)
    if lockout_msg:
        return JSONResponse({"error": lockout_msg}, status_code=429)

    entry = _load_password_entry(examiner)
    if not entry:
        return JSONResponse(
            {"error": "No password configured. Run: nexus config --setup-password"},
            status_code=403,
        )

    # Purge expired challenges
    now = time.time()
    with _challenge_lock:
        expired = [k for k, v in _challenges.items() if now - v["created_at"] > _CHALLENGE_TTL]
        for k in expired:
            del _challenges[k]
        if len(_challenges) >= _CHALLENGE_MAX:
            return JSONResponse({"error": "Too many active challenges"}, status_code=429)

        challenge_id = secrets.token_hex(16)
        nonce = secrets.token_hex(32)
        _challenges[challenge_id] = {
            "nonce": nonce,
            "examiner": examiner,
            "created_at": now,
        }

    return JSONResponse({
        "challenge_id": challenge_id,
        "nonce": nonce,
        "salt": entry["salt"],
        "iterations": 600000,
        "hash_algorithm": "SHA-256",
    })


async def get_commit_status(request) -> JSONResponse:
    """Probe approval readiness — no side effects (no challenge issued).

    Lets the UI explain up front whether the examiner password is configured
    and which identity it belongs to, instead of failing on Approve click.
    """
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"examiner": None, "password_configured": False})
    entry = _load_password_entry(examiner)
    return JSONResponse({
        "examiner": examiner,
        "password_configured": bool(entry),
        "setup_hint": None if entry else "nexus config --setup-password",
    })


async def post_commit(request) -> JSONResponse:
    """Apply finding approvals with challenge-response authentication."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    lockout_msg = _check_commit_lockout(examiner)
    if lockout_msg:
        return JSONResponse({"error": lockout_msg}, status_code=429)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    challenge_id = body.get("challenge_id")
    response_hmac = body.get("response")
    finding_ids = body.get("finding_ids", [])

    if not challenge_id or not response_hmac:
        return JSONResponse({"error": "Missing challenge_id or response"}, status_code=400)

    # Validate challenge
    with _challenge_lock:
        challenge = _challenges.pop(challenge_id, None)

    if not challenge:
        return JSONResponse({"error": "Invalid or expired challenge"}, status_code=401)

    now = time.time()
    if now - challenge["created_at"] > _CHALLENGE_TTL:
        return JSONResponse({"error": "Challenge expired"}, status_code=401)

    if challenge["examiner"] != examiner:
        return JSONResponse({"error": "Challenge/examiner mismatch"}, status_code=401)

    # Verify response: HMAC(stored_hash_bytes, nonce_bytes)
    entry = _load_password_entry(examiner)
    if not entry:
        return JSONResponse({"error": "No password configured"}, status_code=403)

    stored_hash_hex = entry.get("hash", "")
    try:
        stored_hash_bytes = bytes.fromhex(stored_hash_hex)
    except ValueError:
        return JSONResponse({"error": "Corrupted password entry"}, status_code=500)

    expected = hmac_mod.new(
        stored_hash_bytes,
        challenge["nonce"].encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac_mod.compare_digest(expected, response_hmac):
        _record_commit_failure(examiner)
        remaining = _MAX_COMMIT_ATTEMPTS - _commit_failure_count(examiner)
        if remaining <= 0:
            msg = f"Too many failed attempts. Locked for {_COMMIT_LOCKOUT_SECONDS // 60} minutes."
        else:
            msg = f"Incorrect password. {remaining} attempt(s) remaining."
        return JSONResponse({"error": msg}, status_code=401)

    _clear_commit_failures(examiner)

    # If finding_ids is empty, reject — do not auto-approve all DRAFTs
    if not finding_ids:
        return JSONResponse(
            {"error": "finding_ids is required — select at least one finding"},
            status_code=400,
        )

    # Approve findings and write HMAC verification ledger
    approved = []
    errors = []
    for fid in finding_ids:
        try:
            result = _approve_finding(case_dir, fid, examiner, stored_hash_hex, entry.get("salt", ""))
            if result.get("status") == "APPROVED":
                approved.append(fid)
            else:
                errors.append({"id": fid, "error": result.get("message", "Unknown error")})
        except Exception as e:
            errors.append({"id": fid, "error": str(e)})

    # Finding-sourced timeline events carry the finding's status — refresh
    # after commit so approved evidence flips DRAFT → APPROVED on the wire.
    timeline_events = 0
    if approved:
        with contextlib.suppress(Exception):
            from nexus.langgraph.timeline_merge import rebuild_case_timeline

            timeline_events = len(rebuild_case_timeline(case_dir))

    return JSONResponse({
        "status": "committed",
        "approved": approved,
        "errors": errors,
        "examiner": examiner,
        "timeline_events": timeline_events,
    })


def _approve_finding(case_dir: Path, finding_id: str, examiner: str, stored_hash_hex: str, salt: str) -> dict:
    """Approve a single finding and write HMAC verification ledger entry."""
    findings_path = case_dir / "findings.json"
    if not findings_path.exists():
        return {"status": "error", "message": "No findings file"}

    findings = json.loads(findings_path.read_text())
    for f in findings:
        fid = f.get("id") or f.get("finding_id", "")
        if fid == finding_id and f.get("status") == "DRAFT":
            f["status"] = "APPROVED"
            f["approved_by"] = examiner
            f["approved_at"] = datetime.now(UTC).isoformat()
            _atomic_write_json(findings_path, findings)

            from nexus.auth import (
                SIGNING_PURPOSE,
                compute_hmac,
                derive_purpose_key,
                write_verification_entry,
            )
            from nexus.transparency import transparency_append
            base_key = bytes.fromhex(stored_hash_hex)
            derived_key = derive_purpose_key(base_key, SIGNING_PURPOSE)
            content = json.dumps(f, sort_keys=True, default=str)
            hmac_val = compute_hmac(derived_key, content)
            case_id = case_dir.name
            write_verification_entry(case_id, {
                "finding_id": finding_id,
                "type": "finding",
                "approved_by": examiner,
                "approved_at": f["approved_at"],
                "content_snapshot": content,
                "hmac": hmac_val,
                "salt": salt,
            })
            transparency_append(case_id, {
                "action": "approve",
                "finding_id": finding_id,
                "approved_by": examiner,
            })
            return {"finding_id": finding_id, "status": "APPROVED"}

    return {"status": "error", "message": f"Finding {finding_id} not found or not DRAFT"}


# =============================================================================
# HTML pages (unchanged from previous)
# =============================================================================

_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<title>DFIR-Nexus — Examiner Portal</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #0d1117; color: #c9d1d9; }}
nav {{ background: #161b22; padding: 0.75rem 1.5rem; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }}
nav a {{ color: #58a6ff; text-decoration: none; padding: 0.25rem 0.75rem; border-radius: 4px; }}
nav a:hover {{ background: #1f2937; }}
nav a.active {{ background: #1f6feb; color: #fff; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 1.5rem; }}
h1 {{ font-size: 1.5rem; margin: 0 0 1rem 0; }}
h2 {{ font-size: 1.2rem; margin: 1.5rem 0 0.5rem 0; border-bottom: 1px solid #30363d; padding-bottom: 0.3rem; }}
table {{ width: 100%; border-collapse: collapse; margin: 0.5rem 0; }}
th, td {{ padding: 0.5rem; text-align: left; border-bottom: 1px solid #21262d; }}
th {{ background: #161b22; font-weight: 600; }}
tr:hover {{ background: #1c2128; }}
.status-DRAFT {{ color: #d29922; }}
.status-APPROVED {{ color: #3fb950; }}
.status-REJECTED {{ color: #f85149; }}
.badge {{ display: inline-block; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.75rem; font-weight: 600; }}
.badge-high {{ background: #f85149; color: #fff; }}
.badge-medium {{ background: #d29922; color: #fff; }}
.badge-low {{ background: #8b949e; color: #fff; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; }}
.summary-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; text-align: center; }}
.summary-card .num {{ font-size: 2rem; font-weight: 700; }}
.summary-card .label {{ font-size: 0.85rem; color: #8b949e; }}
.action-btn {{ background: #238636; color: #fff; border: none; padding: 0.4rem 1rem; border-radius: 4px; cursor: pointer; }}
.action-btn:hover {{ background: #2ea043; }}
.action-btn.danger {{ background: #da3633; }}
.action-btn.danger:hover {{ background: #f85149; }}
.evidence-path {{ font-family: monospace; font-size: 0.85rem; color: #8b949e; }}
pre {{ background: #161b22; padding: 0.5rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; }}
</style>
</head>
<body>
<nav>
<a href="/portal">Overview</a>
<a href="/portal/steer">Steer</a>
<a href="/portal/explore">Explore</a>
<a href="/portal/workbench">Workbench</a>
<a href="/portal/ask">Ask</a>
<a href="/portal/query">Query</a>
<a href="/portal/findings">Findings</a>
<a href="/portal/approve">Approve</a>
<a href="/portal/timeline">Timeline</a>
<a href="/portal/evidence">Evidence</a>
<a href="/portal/iocs">IOCs</a>
<a href="/portal/todos">TODOs</a>
</nav>
<div class="container">
{content}
</div>
</body>
</html>"""


def _e(value: str) -> str:
    """HTML-escape a string for safe embedding in HTML."""
    return html.escape(str(value), quote=True)


def _badge(confidence: str) -> str:
    c = confidence.lower()
    cls = "badge-high" if c in ("high", "critical") else "badge-medium" if c == "medium" else "badge-low"
    return f'<span class="badge {cls}">{_e(confidence)}</span>'


def _status_tag(status: str) -> str:
    safe = _e(status)
    return f'<span class="status-{safe}">{safe}</span>'


async def overview(request):
    findings = _load_json("findings.json", request)
    timeline = _load_json("timeline.json", request)
    evidence = _evidence_items(request)
    todos = _load_json("todos.json", request)

    draft = sum(1 for f in findings if f.get("status") == "DRAFT")
    approved = sum(1 for f in findings if f.get("status") == "APPROVED")
    rejected = sum(1 for f in findings if f.get("status") == "REJECTED")

    recent = sorted(findings, key=lambda f: f.get("ts", ""), reverse=True)[:5]
    recent_rows = ""
    for f in recent:
        title = _e(f.get("title", "")[:80])
        status = f.get("status", "DRAFT")
        conf = f.get("confidence", "MEDIUM")
        recent_rows += f"<tr><td>{_status_tag(status)}</td><td>{title}</td><td>{_badge(conf)}</td><td>{_e(f.get('ts', '')[:10])}</td></tr>"

    todo_open = sum(1 for t in todos if t.get("status") != "completed")
    tl_count = len(timeline)
    ev_count = len(evidence)

    content = f"""
<h1>Case Dashboard</h1>
<div class="summary">
<div class="summary-card"><div class="num">{approved}</div><div class="label">Approved</div></div>
<div class="summary-card"><div class="num" style="color:#d29922">{draft}</div><div class="label">DRAFT</div></div>
<div class="summary-card"><div class="num" style="color:#f85149">{rejected}</div><div class="label">Rejected</div></div>
<div class="summary-card"><div class="num">{tl_count}</div><div class="label">Timeline Events</div></div>
<div class="summary-card"><div class="num">{ev_count}</div><div class="label">Evidence Files</div></div>
<div class="summary-card"><div class="num">{todo_open}</div><div class="label">Open TODOs</div></div>
</div>
<h2>Recent Findings</h2>
<table><tr><th>Status</th><th>Title</th><th>Confidence</th><th>Date</th></tr>{recent_rows}</table>
"""
    return HTMLResponse(_TEMPLATE.format(content=content))


async def findings_page(request):
    findings = _load_json("findings.json", request)
    status_filter = request.query_params.get("status", "")

    rows = ""
    for f in sorted(findings, key=lambda x: x.get("ts", ""), reverse=True):
        status = f.get("status", "DRAFT")
        if status_filter and status != status_filter:
            continue
        title = _e(f.get("title", "")[:100])
        conf = f.get("confidence", "MEDIUM")
        host = _e(f.get("host", ""))
        finding_type = _e(f.get("type", ""))
        mitre = _e(", ".join(f.get("mitre_ids", [])))
        rows += f"<tr><td>{_status_tag(status)}</td><td>{title}</td><td>{_badge(conf)}</td><td>{finding_type}</td><td>{host}</td><td>{mitre}</td><td>{_e(f.get('ts', '')[:10])}</td></tr>"

    status_links = ''.join(f'<a href="/portal/findings?status={s}" style="margin-right:0.5rem">{s}</a>' for s in ["DRAFT", "APPROVED", "REJECTED"])
    content = f"""
<h1>Findings <span style="font-size:0.8rem;font-weight:normal">({len(findings)} total)</span></h1>
<p>Filter: <a href="/portal/findings">All</a> | {status_links}</p>
<table><tr><th>Status</th><th>Title</th><th>Confidence</th><th>Type</th><th>Host</th><th>MITRE</th><th>Date</th></tr>{rows}</table>
"""
    return HTMLResponse(_TEMPLATE.format(content=content))


async def approve_page(request):
    """HTML page for browser-based finding approval with password."""
    findings = _load_json("findings.json", request)
    drafts = [f for f in findings if f.get("status") == "DRAFT"]

    rows = ""
    for f in drafts:
        fid = _e(f.get("id") or f.get("finding_id", ""))
        title = _e(f.get("title", "")[:80])
        conf = f.get("confidence", "MEDIUM")
        finding_type = _e(f.get("type", ""))
        host = _e(f.get("host", ""))
        rows += f'''
<tr>
  <td><input type="checkbox" class="finding-check" value="{fid}" checked></td>
  <td>{fid}</td>
  <td>{title}</td>
  <td>{_badge(conf)}</td>
  <td>{finding_type}</td>
  <td>{host}</td>
</tr>'''

    approve_js = """
<script>
const SALT = null, ITERATIONS = 600000;

async function pbkdf2(password, salt, iterations) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations, hash: "SHA-256" },
    keyMaterial, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256(keyHex, data) {
  const keyBytes = new Uint8Array(keyHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function approveSelected() {
  const checkboxes = document.querySelectorAll('.finding-check:checked');
  const findingIds = Array.from(checkboxes).map(cb => cb.value);
  if (findingIds.length === 0) return alert('No findings selected');

  const password = prompt('Enter approval password:');
  if (!password) return;

  const statusEl = document.getElementById('status');
  statusEl.textContent = 'Getting challenge...';

  try {
    const chalResp = await fetch('/portal/api/commit/challenge');
    const chal = await chalResp.json();
    if (chal.error) { statusEl.textContent = 'Error: ' + chal.error; return; }

    statusEl.textContent = 'Computing HMAC...';
    const pbkdf2Hash = await pbkdf2(password, chal.salt, chal.iterations);
    const responseHmac = await hmacSha256(pbkdf2Hash, chal.nonce);

    statusEl.textContent = 'Submitting approval...';
    const commitResp = await fetch('/portal/api/commit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge_id: chal.challenge_id,
        response: responseHmac,
        finding_ids: findingIds,
      })
    });
    const result = await commitResp.json();
    if (result.status === 'committed') {
      statusEl.textContent = `Approved ${result.approved.length} finding(s)`;
      setTimeout(() => location.reload(), 1500);
    } else {
      statusEl.textContent = 'Error: ' + JSON.stringify(result);
    }
  } catch (e) {
    statusEl.textContent = 'Error: ' + e.message;
  }
}
</script>
"""

    content = f"""
<h1>Approve Findings</h1>
{approve_js}
<p>Select DRAFT findings to approve using your approval password:</p>
<div style="margin-bottom:1rem">
  <button class="action-btn" onclick="approveSelected()">Approve Selected</button>
  <span id="status" style="margin-left:1rem"></span>
</div>
<table>
<tr><th></th><th>ID</th><th>Title</th><th>Confidence</th><th>Type</th><th>Host</th></tr>
{rows or '<tr><td colspan="6" style="text-align:center;color:#8b949e">No DRAFT findings</td></tr>'}
</table>
"""
    return HTMLResponse(_TEMPLATE.format(content=content))


async def timeline_page(request):
    events = _load_json("timeline.json", request)
    rows = ""
    for e in sorted(events, key=lambda x: x.get("timestamp", "")):
        ts = _e(e.get("timestamp", "")[:19])
        desc = _e(e.get("description", "")[:120])
        ev_type = _e(e.get("event_type", ""))
        host = _e(e.get("host", ""))
        source = _e(e.get("source", ""))
        rows += f"<tr><td>{ts}</td><td>{desc}</td><td>{ev_type}</td><td>{host}</td><td>{source}</td></tr>"
    content = f"""
<h1>Timeline <span style="font-size:0.8rem;font-weight:normal">({len(events)} events)</span></h1>
<table><tr><th>Timestamp</th><th>Description</th><th>Type</th><th>Host</th><th>Source</th></tr>{rows}</table>
"""
    return HTMLResponse(_TEMPLATE.format(content=content))


async def evidence_page(request):
    ev = _evidence_items(request)
    rows = ""
    for e in ev:
        path = _e(e.get("path", ""))[:80]
        sha = _e((e.get("sha256", "") or e.get("hash", ""))[:16])
        desc = _e(e.get("description", "")[:60])
        ts = _e(e.get("registered_at", e.get("ts", ""))[:10])
        rows += f"<tr><td class='evidence-path'>{path}</td><td><code>{sha}...</code></td><td>{desc}</td><td>{ts}</td></tr>"
    content = f"""
<h1>Evidence Registry <span style="font-size:0.8rem;font-weight:normal">({len(ev)} files)</span></h1>
<table><tr><th>Path</th><th>SHA-256</th><th>Description</th><th>Registered</th></tr>{rows}</table>
"""
    return HTMLResponse(_TEMPLATE.format(content=content))


async def iocs_page(request):
    findings = _load_json("findings.json", request)
    iocs = []
    for f in findings:
        for ioc in f.get("iocs", []):
            ioc["finding_title"] = f.get("title", "")
            ioc["finding_status"] = f.get("status", "DRAFT")
            iocs.append(ioc)

    rows = ""
    for ioc in iocs:
        value = _e(ioc.get("value", ioc.get("indicator", "")))
        ioc_type = _e(ioc.get("type", ""))
        context = _e(ioc.get("context", ""))
        rows += f"<tr><td><code>{value}</code></td><td>{ioc_type}</td><td>{context}</td><td>{_status_tag(ioc.get('finding_status', ''))}</td></tr>"
    content = f"""
<h1>Indicators of Compromise <span style="font-size:0.8rem;font-weight:normal">({len(iocs)} total)</span></h1>
<table><tr><th>Value</th><th>Type</th><th>Context</th><th>Status</th></tr>{rows}</table>
"""
    return HTMLResponse(_TEMPLATE.format(content=content))


async def todos_page(request):
    todos = _load_json("todos.json", request)
    rows = ""
    for t in todos:
        tid = _e(t.get("todo_id", t.get("id", "")))
        desc = _e(t.get("description", "")[:80])
        status = _e(t.get("status", "open"))
        prio = _e(t.get("priority", "medium"))
        assignee = _e(t.get("assignee", ""))
        rows += f"<tr><td>{tid}</td><td>{desc}</td><td>{_badge(prio.capitalize())}</td><td>{status}</td><td>{assignee}</td></tr>"
    content = f"""
<h1>TODOs <span style="font-size:0.8rem;font-weight:normal">({len(todos)} items)</span></h1>
<table><tr><th>ID</th><th>Description</th><th>Priority</th><th>Status</th><th>Assignee</th></tr>{rows}</table>
"""
    return HTMLResponse(_TEMPLATE.format(content=content))


def _list_case_ids() -> list[str]:
    from nexus.config import settings
    root = settings.cases_root
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir() and (p / "CASE.yaml").is_file())


def _active_case_id() -> str:
    # Deliberately pointer-only: "active" means the server-side current case.
    case_dir = _get_case_dir()
    return case_dir.name if case_dir else ""


async def steer_page(request):
    """N1 intake + case switch + add evidence + N4 rerun (HITL redirect)."""
    import yaml

    cases = _list_case_ids()
    active = _active_case_id()
    intake = {}
    case_dir = _get_case_dir(request)
    if case_dir and (case_dir / "CASE.yaml").is_file():
        meta = yaml.safe_load((case_dir / "CASE.yaml").read_text(encoding="utf-8")) or {}
        if isinstance(meta.get("intake"), dict):
            intake = meta["intake"]
    options = "".join(
        f'<option value="{_e(c)}"{" selected" if c == active else ""}>{_e(c)}</option>'
        for c in cases
    )
    q = _e(str(intake.get("question") or ""))
    window = _e(str(intake.get("window") or ""))
    extras = _e(str(intake.get("extras") or ""))
    content = f"""
<h1>Steer case</h1>
<p>Active: <code>{_e(active) or '(none)'}</code>. HITL redirect re-runs N4 without re-parsing.</p>
<h2>Pick case</h2>
<p><select id="case">{options}</select>
<button class="action-btn" onclick="post('/portal/api/case/activate', {{case_id: document.getElementById('case').value}})">Activate</button></p>
<h2>N1 intake</h2>
<p>Question<br><textarea id="question" rows="3" style="width:100%;background:#161b22;color:#c9d1d9">{q}</textarea></p>
<p>Window<br><input id="window" style="width:100%;background:#161b22;color:#c9d1d9" value="{window}"></p>
<p>Extras (chrome_profiles,drivefs,email,usb_serial)<br>
<input id="extras" style="width:100%;background:#161b22;color:#c9d1d9" value="{extras}"></p>
<p><button class="action-btn" onclick="post('/portal/api/intake', {{question: qv('question'), window: qv('window'), extras: qv('extras')}})">Save intake</button></p>
<h2>Add evidence root</h2>
<p><input id="evpath" style="width:70%;background:#161b22;color:#c9d1d9" placeholder="C:\\\\path\\\\to\\\\pack or conn.log">
<button class="action-btn" onclick="post('/portal/api/evidence', {{path: qv('evpath')}})">Register</button></p>
<h2>Redirect N4</h2>
<p><button class="action-btn" onclick="post('/portal/api/query-rerun', {{}})">Re-run query pack</button></p>
<pre id="out"></pre>
<script>
function qv(id) {{ return document.getElementById(id).value; }}
async function post(url, body) {{
  const r = await fetch(url, {{method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify(body)}});
  document.getElementById('out').textContent = await r.text();
}}
</script>
"""
    return HTMLResponse(_TEMPLATE.format(content=content))


async def query_page(request):
    """N4 hit browser — examiner searches processed output, not raw evidence."""
    needles = str(request.query_params.get("needles") or "")
    persist_flag = str(request.query_params.get("persist") or "") in {"1", "true", "yes"}
    case_dir = _get_case_dir(request)
    hits: list[dict] = []
    meta: dict = {}
    if case_dir:
        from nexus.langgraph.query_pack import _parse_needles, run_ad_hoc_query

        meta = run_ad_hoc_query(
            case_dir,
            extra_needles=_parse_needles(needles),
            persist=persist_flag and bool(needles.strip()),
            limit=80,
        )
        hits = list(meta.get("hits") or [])
    if hits:
        rows = "".join(
            "<tr>"
            f"<td>{_e(h.get('family', ''))}</td>"
            f"<td>{_e(h.get('file', ''))}:{_e(h.get('line', ''))}</td>"
            f"<td>{_e(h.get('terms', ''))}</td>"
            f"<td class='evidence-path'>{_e(h.get('text', ''))}</td>"
            "</tr>"
            for h in hits
        )
    else:
        rows = (
            "<tr><td colspan='4'>No rows matched. INSUFFICIENT — "
            "do not invent findings. Add needles or check playbook query_terms.</td></tr>"
        )
    backend = _e(str(meta.get("backend") or "(no case)"))
    count = meta.get("count", 0)
    persist_attr = "checked" if persist_flag else ""
    content = f"""
<h1>Query processed evidence (N4)</h1>
<p>This searches <strong>parsed CSVs / the case index</strong>, not Evidence-files.
Empty hits mean INSUFFICIENT. Persist needles, then re-run interpret
(<code>nexus pipeline --mode interpret --from-case …</code>).</p>
<form method="get" action="/portal/query">
<p>Needles (comma-separated)<br>
<input name="needles" style="width:70%;background:#161b22;color:#c9d1d9" value="{_e(needles)}" placeholder="sdelete,.pst,USBSTOR">
<label><input type="checkbox" name="persist" value="1" {persist_attr}> persist on intake</label>
<button class="action-btn" type="submit">Search</button></p>
</form>
<p>backend=<code>{backend}</code> showing {len(hits)} / {count} hits.</p>
<table>
<tr><th>Family</th><th>File:line</th><th>Terms</th><th>Row</th></tr>
{rows}
</table>
"""
    return HTMLResponse(_TEMPLATE.format(content=content))


def _case_summary(case_id: str, mgr) -> dict[str, Any]:
    """Dashboard row summary: name/status/mode/counts/pipeline/report."""
    from nexus.config import settings

    case_dir = settings.cases_root / case_id
    summary: dict[str, Any] = {"case_id": case_id, "name": case_id, "status": "", "mode": ""}

    case = None
    if mgr is not None:
        try:
            case = mgr.get_case(case_id)
        except Exception:  # noqa: BLE001
            case = None
    if case is not None:
        summary["name"] = case.name or case_id
        summary["status"] = case.status.value
        summary["synthetic"] = bool((case.metadata or {}).get("synthetic"))
    else:
        summary["status"] = "unknown"
        summary["synthetic"] = False

    case_yaml = case_dir / "CASE.yaml"
    if case_yaml.is_file():
        try:
            import yaml

            meta = yaml.safe_load(case_yaml.read_text(encoding="utf-8")) or {}
            if isinstance(meta, dict):
                summary["name"] = str(meta.get("name") or summary["name"])
                if not summary["status"] or summary["status"] == "unknown":
                    summary["status"] = str(meta.get("status") or "")
                summary["mode"] = str(meta.get("investigation_mode") or "")
        except Exception:  # noqa: BLE001
            pass

    evidence_count = 0
    findings_count = 0
    approved_count = 0
    if mgr is not None:
        try:
            evidence_count = len(mgr.list_evidence(case_id))
            findings = mgr.list_findings(case_id)
            findings_count = len(findings)
            approved_count = sum(1 for f in findings if f.approval_state.value == "approved")
        except Exception:  # noqa: BLE001
            pass
    if evidence_count == 0:
        # Legacy flat-only case: go through the one evidence service so the
        # legacy registry is imported once and SQLite stays authoritative.
        from nexus.case import evidence_service

        try:
            evidence_count = len(evidence_service.list_evidence(case_dir))
        except Exception:  # noqa: BLE001 — dashboard must still render
            evidence_count = 0

    summary["evidence_count"] = evidence_count
    summary["findings_count"] = findings_count
    summary["approved_count"] = approved_count
    summary.update(_case_artifact_flags(case_dir))
    return summary


def _case_artifact_flags(case_dir: Path) -> dict[str, bool]:
    """N2/N8 presence flags that match where the writers actually write.

    Reports land in ``reports/REPORT.md`` (the legacy ``REPORT.md`` is only
    a demo-seed artifact) and TOOL-RUN.md lives in the active run directory —
    checking the legacy paths made the cockpit stepper disagree with a
    completed pipeline/report on every real case.
    """
    report = (case_dir / "reports" / "REPORT.md").is_file() or (
        case_dir / "REPORT.md"
    ).is_file()
    pipeline = (case_dir / "analysis" / "TOOL-RUN.md").is_file()
    if not pipeline:
        runs_dir = case_dir / "runs"
        try:
            if runs_dir.is_dir():
                for run_dir in runs_dir.iterdir():
                    if not run_dir.is_dir():
                        continue
                    if (run_dir / "reports" / "TOOL-RUN.md").is_file() or (
                        run_dir / "manifest.json"
                    ).is_file():
                        pipeline = True
                        break
        except OSError:
            pass
    return {
        "pipeline_complete": pipeline,
        "report_exists": report,
        "digest_exists": (case_dir / "analysis" / "case_digest.json").is_file(),
    }


def _slim_chat_hits(hits: list) -> list[dict]:
    """Compact hits for the persisted transcript — the chat file must not grow
    by ~40 KB per turn (full rows stay available via Explore/ES)."""
    out: list[dict] = []
    for h in hits or []:
        if not isinstance(h, dict):
            continue
        item: dict = {}
        for key in ("family", "file", "line", "host", "user", "event_id", "ts", "terms"):
            value = h.get(key)
            if value not in (None, ""):
                item[key] = str(value)[:200]
        item["text"] = str(h.get("text") or "")[:400]
        out.append(item)
    return out


async def api_cases(request):
    cases = _list_case_ids()
    active = _active_case_id()
    details: dict[str, Any] = {}
    mgr = None
    try:
        from nexus.case import CaseManager
        from nexus.config import settings

        mgr = CaseManager(settings.cases_root / "cases.db")
        for case_id in cases:
            details[case_id] = _case_summary(case_id, mgr)
    except Exception as exc:  # noqa: BLE001 — dashboard must still render
        logger.warning("case summaries failed: %s", exc)
        for case_id in cases:
            details.setdefault(
                case_id,
                {"case_id": case_id, "name": case_id, "status": "", "mode": ""},
            )
    finally:
        if mgr is not None:
            mgr.close()
    return JSONResponse({"cases": cases, "active": active, "details": details})


async def api_activate_case(request):
    body = await request.json()
    case_id = str(body.get("case_id") or "").strip()
    from nexus.discipline import validate_case_id

    if validate_case_id(case_id):
        return JSONResponse({"ok": False, "error": "invalid case id"}, status_code=400)
    from nexus.config import settings
    path = settings.cases_root / case_id
    if not path.is_dir():
        return JSONResponse({"ok": False, "error": "case not found"}, status_code=404)
    import os

    active = Path(
        os.environ.get("NEXUS_ACTIVE_CASE_FILE", str(Path.home() / ".nexus" / "active_case"))
    )
    active.parent.mkdir(parents=True, exist_ok=True)
    active.write_text(case_id, encoding="utf-8")
    return JSONResponse({"ok": True, "active": case_id})


async def api_intake(request):
    body = await request.json()
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"ok": False, "error": "no active case"}, status_code=400)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    from nexus.langgraph.case_intake import persist_case_intake
    written = persist_case_intake(case_dir, {
        k: str(body.get(k) or "")
        for k in ("question", "window", "extras", "playbooks", "subjects", "hypothesis", "query_extra")
        if body.get(k)
    })
    return JSONResponse({"ok": True, "intake": written})


async def api_register_evidence(request):
    body = await request.json()
    # Strip surrounding quotes — examiners often paste "C:\path with spaces"
    path = str(body.get("path") or "").strip().strip('"').strip()
    case_dir = _resolve_case_dir_for(str(body.get("case_id") or ""), request)
    if not case_dir:
        return JSONResponse(
            {"ok": False, "error": "no case specified - create a case or select an active one"},
            status_code=400,
        )
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    if not path:
        return JSONResponse({"ok": False, "error": "path missing"}, status_code=400)

    from nexus.audit import resolve_examiner
    from nexus.case import evidence_service

    try:
        # B10: full-tree SHA-256 hashing is blocking IO — off the event loop.
        result = await asyncio.to_thread(
            evidence_service.register_evidence,
            case_dir,
            path,
            description=str(body.get("description") or "portal register"),
            examiner=resolve_examiner(),
        )
    except FileNotFoundError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=409)

    # Evidence registered → intake. Never downgrades an ACTIVE case.
    _transition_case_status(case_dir.name, "intake", allowed_from={"created", "open"})
    return JSONResponse({"ok": True, "case_id": case_dir.name, **result})


async def api_query_rerun(request):
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"ok": False, "error": "no active case"}, status_code=400)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    from nexus.langgraph.query_pack import _parse_needles, run_ad_hoc_query, write_query_pack

    try:
        body = await request.json()
    except Exception:
        body = {}
    needles = _parse_needles(str(body.get("needles") or ""))
    persist = bool(body.get("persist")) if needles else False
    if needles:
        result = run_ad_hoc_query(
            case_dir, extra_needles=needles, persist=persist, limit=int(body.get("limit") or 80)
        )
        return JSONResponse({"ok": True, **result})
    path = write_query_pack(case_dir)
    return JSONResponse({"ok": True, "query_pack": str(path)})


async def api_findings(request):
    """GET /portal/api/findings?status=DRAFT&limit=20"""
    findings = _load_json("findings.json", request)
    status = request.query_params.get("status")
    limit = int(request.query_params.get("limit", "0"))
    if status:
        findings = [f for f in findings if f.get("status", "").upper() == status.upper()]
    if limit > 0:
        findings = findings[:limit]
    return JSONResponse({"findings": findings, "total": len(findings)})


async def api_timeline(request):
    """GET /portal/api/timeline?event_type=execution&limit=50"""
    events = _load_json("timeline.json", request)
    ev_type = request.query_params.get("event_type")
    limit = int(request.query_params.get("limit", "0"))
    if ev_type:
        events = [e for e in events if e.get("event_type", "") == ev_type]
    if limit > 0:
        events = events[:limit]
    return JSONResponse({"events": events, "total": len(events)})


async def api_evidence(request):
    """GET /portal/api/evidence"""
    ev = _evidence_items(request)
    return JSONResponse({"evidence": ev, "total": len(ev)})


async def api_iocs(request):
    """GET /portal/api/iocs — unified case IOC store.

    iocs.json is the canonical store: evidence-registered indicators (via
    the SQLite→flat mirror) plus finding IOCs merged at stage time
    (auto-extracted hashes/IPs/URLs/domains/emails + explicit entries).
    Explicit finding-level IOCs not yet in the store are merged in here so
    the page always shows the full picture.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    from nexus.case_manager import CaseManager as FlatCaseManager

    iocs = FlatCaseManager()._load_iocs(case_dir)
    findings = _load_json("findings.json", request)
    findings_by_id = {f.get("id"): f for f in findings}

    seen = {str(i.get("value") or "").lower() for i in iocs}
    for f in findings:
        for ioc in f.get("iocs") or []:
            if not isinstance(ioc, dict):
                continue
            val = str(ioc.get("value", ioc.get("indicator", ""))).lower()
            if not val or val in seen:
                continue
            seen.add(val)
            rec = dict(ioc)
            rec["source_findings"] = list(
                dict.fromkeys((rec.get("source_findings") or []) + [f.get("id")])
            )
            iocs.append(rec)

    for ioc in iocs:
        linked = [
            findings_by_id[fid] for fid in (ioc.get("source_findings") or [])
            if fid in findings_by_id
        ]
        ioc["finding_title"] = "; ".join(f.get("title", "") for f in linked)
        ioc["finding_status"] = "; ".join(
            sorted({f.get("status", "DRAFT") for f in linked})
        )
    return JSONResponse({"iocs": iocs, "total": len(iocs)})


async def api_todos(request):
    """GET /portal/api/todos?status=open"""
    todos = _load_json("todos.json", request)
    status = request.query_params.get("status", "")
    if status:
        todos = [t for t in todos if t.get("status", "open") == status]
    return JSONResponse({"todos": todos, "total": len(todos)})


async def api_todos_add(request):
    """POST /portal/api/todos — {description, assignee?, priority?,
    related_findings?}. Examiner follow-ups; not signed — same trust level
    as workbench bookmarks."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    desc = str(body.get("description") or "").strip()
    if not desc:
        return JSONResponse({"error": "Missing description"}, status_code=400)
    related = body.get("related_findings")
    if related is not None and not (
        isinstance(related, list) and all(isinstance(r, str) for r in related)
    ):
        return JSONResponse(
            {"error": "related_findings must be a list of finding IDs"},
            status_code=400,
        )
    from nexus.case_manager import CaseManager as FlatCaseManager

    try:
        result = FlatCaseManager().add_todo(
            desc,
            assignee=str(body.get("assignee") or ""),
            priority=str(body.get("priority") or "medium"),
            related_findings=related,
            examiner_override=_resolve_examiner(request),
            case_dir=case_dir,
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse(result)


async def api_todos_update(request):
    """POST /portal/api/todos/update — {todo_id, status?, note?, assignee?,
    priority?}. Status 'completed' stamps completed_at; 'open' reopens."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    todo_id = str(body.get("todo_id") or body.get("id") or "").strip()
    if not todo_id:
        return JSONResponse({"error": "Missing todo_id"}, status_code=400)
    status = str(body.get("status") or "").strip().lower()
    if status and status not in ("open", "in_progress", "completed"):
        return JSONResponse(
            {"error": "status must be open|in_progress|completed"},
            status_code=400,
        )
    if not status and not str(body.get("note") or "").strip() \
            and not str(body.get("assignee") or "").strip() \
            and not str(body.get("priority") or "").strip():
        return JSONResponse({"error": "Nothing to update"}, status_code=400)
    from nexus.case_manager import CaseManager as FlatCaseManager

    try:
        result = FlatCaseManager().update_todo(
            todo_id,
            status=status,
            note=str(body.get("note") or ""),
            assignee=str(body.get("assignee") or ""),
            priority=str(body.get("priority") or ""),
            examiner_override=_resolve_examiner(request),
            case_dir=case_dir,
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    if result.get("status") == "not_found":
        return JSONResponse({"error": f"TODO not found: {todo_id}"}, status_code=404)
    return JSONResponse(result)


async def api_audit_for_finding(request):
    """GET /portal/api/audit/{finding_id}"""
    finding_id = request.path_params.get("finding_id", "")
    if not finding_id:
        return JSONResponse({"error": "Missing finding_id"}, status_code=400)
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    audit_dir = case_dir / "audit"
    if not audit_dir.exists():
        return JSONResponse({"entries": [], "finding_id": finding_id})
    entries = []
    for jsonl_file in sorted(audit_dir.glob("*.jsonl")):
        for line in jsonl_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if finding_id in json.dumps(entry):
                    entries.append(entry)
            except json.JSONDecodeError:
                continue
    return JSONResponse({"entries": entries, "finding_id": finding_id, "total": len(entries)})


async def api_summary(request):
    """GET /portal/api/summary"""
    findings = _load_json("findings.json", request)
    timeline = _load_json("timeline.json", request)
    evidence = _evidence_items(request)
    todos = _load_json("todos.json", request)
    return JSONResponse({
        "findings": {"total": len(findings), "draft": sum(1 for f in findings if f.get("status") == "DRAFT"),
                      "approved": sum(1 for f in findings if f.get("status") == "APPROVED"),
                      "rejected": sum(1 for f in findings if f.get("status") == "REJECTED")},
        "timeline": len(timeline),
        "evidence": len(evidence),
        "todos": {"total": len(todos), "open": sum(1 for t in todos if t.get("status") != "completed")},
    })


async def api_transparency(request):
    """GET /portal/api/transparency"""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    from nexus.transparency import transparency_verify
    result = transparency_verify(case_dir.name)
    return JSONResponse(result)


async def ask_page(request):
    """Mode 1 examiner query desk: natural language -> needles -> hits -> select."""
    case_dir = _get_case_dir(request)
    question = str(request.query_params.get("question") or "").strip()
    hits: list[dict] = []
    needles: list[str] = []
    window = ""
    backend = "(no case)"
    count = 0
    error = ""

    if case_dir and question:
        from nexus.langgraph.llm_pipeline import get_model
        from nexus.langgraph.mode1 import nl_to_needles
        from nexus.langgraph.query_pack import run_ad_hoc_query

        try:
            model = get_model()
        except Exception:
            model = None

        try:
            parsed = nl_to_needles(question, model=model)
            needles = parsed.get("needles", [])
            window = parsed.get("window", "")
            if not needles:
                error = "No needles extracted from the question. Refine it."
            else:
                n4_result = run_ad_hoc_query(
                    case_dir,
                    extra_needles=needles,
                    persist=True,
                    limit=80,
                )
                hits = list(n4_result.get("hits") or [])
                count = n4_result.get("count", 0)
                backend = str(n4_result.get("backend") or "")
                if not hits:
                    error = "No rows matched. INSUFFICIENT — do not invent findings."
        except Exception as exc:
            error = f"Query failed: {exc}"

    # Render hit rows with checkboxes for selection
    if hits:
        rows = ""
        for i, h in enumerate(hits, 1):
            rows += f"""
<tr>
  <td><input type="checkbox" class="hit-check" value="{i}" data-family="{_e(h.get('family', ''))}" data-file="{_e(h.get('file', ''))}" data-line="{_e(h.get('line', ''))}"></td>
  <td>{_e(h.get('family', ''))}</td>
  <td>{_e(h.get('file', ''))}:{_e(h.get('line', ''))}</td>
  <td>{_e(h.get('terms', ''))}</td>
  <td class="evidence-path">{_e(h.get('text', ''))}</td>
</tr>"""
    else:
        rows = (
            "<tr><td colspan='5' style='text-align:center;color:#8b949e'>"
            "No hits yet. Enter a question above and click Ask."
            "</td></tr>"
        )

    error_div = f'<p style="color:#f85149">{_e(error)}</p>' if error else ""
    content = f"""
<h1>Mode 1 — Ask the Case</h1>
<p>Natural language → needles → N4 query. The examiner then selects hits to promote to DRAFT.</p>
<form method="get" action="/portal/ask" style="margin-bottom:1rem">
<p>Question<br>
<input name="question" style="width:70%;background:#161b22;color:#c9d1d9" value="{_e(question)}" placeholder="Was sdelete used to wipe files around 2026-08-10?">
<button class="action-btn" type="submit">Ask</button></p>
</form>
{error_div}
<p>Extracted needles: <code>{_e(', '.join(needles) or '(none)')}</code>
{(' · Window: ' + _e(window)) if window else ''}
{(' · backend: ' + _e(backend)) if question else ''}
· hits: {len(hits)} / {count}</p>
<h2>Select hits and promote to DRAFT</h2>
<p>Title <input id="draft_title" style="width:50%;background:#161b22;color:#c9d1d9" placeholder="sdelete file wipe on WS01"></p>
<p><label><input type="checkbox" id="use_scribe" checked> Run LLM scribe (methodology + RAG)</label></p>
<p><button class="action-btn" onclick="promoteSelected()">Promote selected to DRAFT</button>
<span id="status" style="margin-left:1rem"></span></p>
<table>
<tr><th></th><th>Family</th><th>File:line</th><th>Terms</th><th>Row</th></tr>
{rows}
</table>
<script>
async function promoteSelected() {{
  const checkboxes = document.querySelectorAll('.hit-check:checked');
  const hitIds = Array.from(checkboxes).map(cb => cb.value);
  if (hitIds.length === 0) return alert('Select at least one hit');
  const title = document.getElementById('draft_title').value.trim();
  if (!title) return alert('Enter a finding title');
  const scribe = document.getElementById('use_scribe').checked;
  document.getElementById('status').textContent = 'Promoting...';
  const r = await fetch('/portal/api/mode1/select', {{
    method: 'POST',
    headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{rows: hitIds.map(function(i){{var cb=checkboxes[i-1];return {{family:cb.dataset.family, file:cb.dataset.file, line:cb.dataset.line}};}}), title: title, scribe: scribe}})
  }});
  const result = await r.json();
  if (result.finding_id) {{
    document.getElementById('status').textContent = 'DRAFT: ' + result.finding_id;
    setTimeout(() => window.location = '/portal/findings?status=DRAFT', 1000);
  }} else {{
    document.getElementById('status').textContent = 'Error: ' + (result.error || JSON.stringify(result));
  }}
}}
</script>
"""
    return HTMLResponse(_TEMPLATE.format(content=content))


def _capa_rule_names_from_case(case_dir: Path, limit: int = 200) -> list[str]:
    """capa/YARA rule names from this case's capa extraction files (bounded).

    Best-effort: JSON/JSONL rows (``rule``/``name``/``rule_name`` keys) and
    plain-text/csv rule lines. Returns [] when no capa output exists.
    """
    case = Path(case_dir)
    names: list[str] = []
    seen: set[str] = set()
    token = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\- ]{3,80}$")
    for root in (case / "extractions", case / "runs"):
        if not root.is_dir():
            continue
        for path in root.rglob("*capa*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".txt", ".log", ".csv", ".json", ".jsonl", ".out"}:
                continue
            try:
                with path.open(encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh):
                        if i > 4000 or len(names) >= limit:
                            break
                        line = line.strip()
                        if not line:
                            continue
                        candidate = ""
                        if line.startswith("{"):
                            try:
                                obj = json.loads(line)
                            except ValueError:
                                continue
                            if isinstance(obj, dict):
                                for key in ("rule", "name", "rule_name"):
                                    value = obj.get(key)
                                    if isinstance(value, str) and value.strip():
                                        candidate = value.strip()
                                        break
                        elif "," in line:
                            candidate = line.split(",", 1)[0].strip()
                        else:
                            candidate = line
                        if candidate and token.match(candidate):
                            key = candidate.lower()
                            if key not in seen:
                                seen.add(key)
                                names.append(candidate)
            except OSError:
                continue
            if len(names) >= limit:
                break
    return names


def _mode1_ask_context(case_dir: Path, question: str) -> dict[str, Any]:
    """Ground the Mode 1 scribe with case material (WP 4g-A).

    Evidence families present, playbook terms + caveats for those families,
    RAG methodology, already-searched needles, and the case intake. Every
    item is best-effort — a missing index just yields a thinner prompt.
    """
    from nexus.langgraph.query_pack import (
        _parse_needles,
        load_case_intake,
        n4_aggregate,
        playbook_techniques_for_families,
        playbook_terms_for_families,
    )

    context: dict[str, Any] = {"sources": []}
    try:
        intake = load_case_intake(case_dir)
    except Exception:  # noqa: BLE001
        intake = {}
    context["searched"] = _parse_needles(str(intake.get("query_extra") or ""))
    context["intake"] = {
        key: str(intake.get(key) or "").strip()
        for key in ("question", "subjects", "hypothesis")
        if str(intake.get(key) or "").strip()
    }

    families: set[str] = set()
    try:
        agg = n4_aggregate(case_dir, group_by="family")
        families = {str(k) for k in (agg.get("buckets") or {}) if str(k).strip()}
        if families:
            context["sources"].append("n4-families")
    except Exception:  # noqa: BLE001
        families = set()
    context["families"] = sorted(families)

    if families:
        try:
            terms = playbook_terms_for_families(families)
            if terms:
                context["playbook_terms"] = terms
                context["sources"].append("playbooks")
        except Exception:  # noqa: BLE001
            pass
        try:
            from nexus.langgraph.mode2 import (
                _playbook_context_for_families,
                _rag_methodology_for_proposal,
            )

            playbook_context = _playbook_context_for_families(families)
            if playbook_context:
                context["playbook_context"] = playbook_context
                context["sources"].append("playbook-caveats")
            rag_text, rag_provenance = _rag_methodology_for_proposal(families)
            if rag_text:
                context["rag"] = rag_text
                context["rag_provenance"] = rag_provenance
                context["sources"].append("rag")
        except Exception:  # noqa: BLE001
            pass

    # MITRE ATT&CK packs (WP 4g-B): techniques named in intake or implied by
    # the playbooks matched to the evidence families present.
    from nexus.knowledge.attack_needles import (
        attack_context_for,
        attack_needles_for,
        attack_packs_for,
        extract_techniques,
    )

    technique_text = " ".join(
        [question]
        + [str(intake.get(k) or "") for k in ("question", "subjects", "hypothesis")]
    )
    techniques = set(extract_techniques(technique_text))
    if families:
        with contextlib.suppress(Exception):
            techniques.update(playbook_techniques_for_families(families))
    context["techniques"] = sorted(techniques)
    if families or techniques:
        try:
            packs = attack_packs_for(families, techniques, limit=4)
            if packs:
                context["attack_packs"] = packs
                context["attack_needles"] = attack_needles_for(
                    families, techniques, limit=4
                )
                context["attack_context"] = attack_context_for(packs)
                context["sources"].append("attack-packs")
        except Exception:  # noqa: BLE001
            pass

    # Insider Threat Matrix lens (registry-validated ids) + the AI/malware
    # registries (ATLAS/MBC) matched against the same case text.
    try:
        from nexus.langgraph.itm import itm_prompt_block

        itm_ctx = itm_prompt_block(
            question=question, families=families, limit=5, full_taxonomy=False
        )
        if itm_ctx:
            context["itm_context"] = itm_ctx
            context["sources"].append("itm")
    except Exception:  # noqa: BLE001
        pass
    try:
        from nexus.knowledge.registry_context import (
            atlas_context_for,
            mbc_context_for,
        )

        atlas_ctx = atlas_context_for(technique_text)
        if atlas_ctx:
            context["atlas_context"] = atlas_ctx
            context["sources"].append("atlas")
        mbc_ctx = mbc_context_for(technique_text)
        if mbc_ctx:
            context["mbc_context"] = mbc_ctx
            context["sources"].append("mbc")
    except Exception:  # noqa: BLE001
        pass
    # capa output -> MBC behaviors (ties the malware-capability tool to the
    # registry; only when the case actually holds capa rule hits).
    try:
        from nexus.knowledge.mbc import mbc_capa_context

        capa_names = _capa_rule_names_from_case(case_dir, limit=200)
        capa_ctx = mbc_capa_context(capa_names, cap=6) if capa_names else ""
        if capa_ctx:
            context["mbc_capa_context"] = capa_ctx
            context["sources"].append("mbc-capa")
    except Exception:  # noqa: BLE001
        pass

    # Phase 4g-D/C/F: SigmaHQ-derived patterns + the examiner's local overlay.
    try:
        from nexus.knowledge.needle_overlay import overlay_terms_for_families
        from nexus.knowledge.sigma_needles import (
            sigma_context_for,
            sigma_needles_for,
            sigma_packs_for,
        )

        sigma_packs = sigma_packs_for(families, limit=4)
        if sigma_packs:
            context["sigma_needles"] = sigma_needles_for(families, limit=4)
            context["sigma_context"] = sigma_context_for(sigma_packs)
            context["sources"].append("sigma")
        overlay = overlay_terms_for_families(families)
        if overlay:
            context["overlay_needles"] = overlay
            context["sources"].append("needle-overlay")
    except Exception as exc:  # noqa: BLE001
        logger.debug("sigma/overlay context skipped: %s", exc)

    # WP 3.27a: LOLBAS + Atomic Red Team needle packs.
    try:
        from nexus.knowledge.loader import get_atomic_red_team, get_lolbas_needles

        lolbas_packs = get_lolbas_needles()
        if lolbas_packs:
            # Filter LOLBAS packs to families present in the case
            relevant = [
                p for p in lolbas_packs
                if any(f.lower() in (p.get("binary") or "").lower() for f in families)
                or any(m.lower() in (p.get("binary") or "").lower() for m in techniques)
            ]
            if relevant:
                context["lolbas_needles"] = [
                    str(n) for p in relevant[:6]
                    for n in (p.get("needles") or [])
                ]
                context["lolbas_context"] = "\n".join(
                    f"- {p.get('name', '')}: {', '.join(p.get('needles', [])[:5])}"
                    for p in relevant[:4]
                )
                context["sources"].append("lolbas")
        atomic_packs = get_atomic_red_team()
        if atomic_packs:
            relevant_atomic = [
                p for p in atomic_packs
                if any(t.lower() in (p.get("technique") or "").lower() for t in techniques)
            ]
            if relevant_atomic:
                context["atomic_needles"] = [
                    str(a) for p in relevant_atomic[:6]
                    for t in (p.get("tests") or [])
                    for a in (t.get("artifacts") or [])
                ]
                context["atomic_context"] = "\n".join(
                    f"- {p.get('name', '')}: {p.get('technique', '')}"
                    for p in relevant_atomic[:4]
                )
                context["sources"].append("atomic-red-team")
    except Exception as exc:  # noqa: BLE001
        logger.debug("lolbas/atomic context skipped: %s", exc)

    # WP 3.27c: CAR analytics + OSSEM + EVTX-ATTACK-SAMPLES.
    try:
        from nexus.knowledge.loader import (
            get_car_analytics,
            get_evtx_attack_samples,
            get_ossem_events,
        )

        car_packs = get_car_analytics()
        if car_packs:
            relevant_car = [
                p for p in car_packs
                if any(t.lower() in (p.get("technique") or "").lower() for t in techniques)
                or any(f.lower() in (p.get("data_model") or []) for f in families)
            ]
            if relevant_car:
                context["car_needles"] = [
                    str(n) for p in relevant_car[:6]
                    for n in (p.get("needles") or [])
                ]
                context["car_context"] = "\n".join(
                    f"- {p.get('name', '')}: {', '.join(p.get('data_model', [])[:5])}"
                    for p in relevant_car[:4]
                )
                context["sources"].append("car")
        ossem_events = get_ossem_events()
        if ossem_events:
            relevant_ossem = [
                e for e in ossem_events
                if any(f.lower() in (e.get("name") or "").lower() for f in families)
            ]
            if relevant_ossem:
                context["ossem_needles"] = [
                    str(f.get("name")) for e in relevant_ossem[:6]
                    for f in (e.get("fields") or [])
                ]
                context["ossem_context"] = "\n".join(
                    f"- {e.get('name', '')}: {', '.join(str(f.get('name', '')) for f in (e.get('fields') or [])[:5])}"
                    for e in relevant_ossem[:4]
                )
                context["sources"].append("ossem")
        evtx_packs = get_evtx_attack_samples()
        if evtx_packs:
            relevant_evtx = [
                p for p in evtx_packs
                if any(t.lower() in (p.get("technique") or "").lower() for t in techniques)
            ]
            if relevant_evtx:
                context["evtx_needles"] = [
                    str(v) for p in relevant_evtx[:6]
                    for e in (p.get("events") or [])
                    for v in (e.get("fields") or {}).values()
                ]
                context["evtx_context"] = "\n".join(
                    f"- {p.get('name', '')}: {p.get('technique', '')}"
                    for p in relevant_evtx[:4]
                )
                context["sources"].append("evtx-attack-samples")
    except Exception as exc:  # noqa: BLE001
        logger.debug("car/ossem/evtx context skipped: %s", exc)

    # WP 3.27d: Incident reports + threat feeds + vendor guides + Sysmon + YARA + KEV + MISP.
    try:
        from nexus.knowledge.loader import (
            get_cisa_kev,
            get_incident_reports,
            get_misp_opencti,
            get_sysmon_configs,
            get_threat_feeds,
            get_vendor_guides,
            get_yara_rules,
        )

        # Incident reports — APT group IOCs and TTPs
        incident_packs = get_incident_reports()
        if incident_packs:
            relevant_incidents = [
                p for p in incident_packs
                if any(t.lower() in (p.get("group") or "").lower() for t in techniques)
                or any(m.lower() in (p.get("group") or "").lower() for m in techniques)
            ]
            if relevant_incidents:
                context["incident_needles"] = [
                    str(n) for p in relevant_incidents[:6]
                    for n in (p.get("needles") or [])
                ]
                context["incident_context"] = "\n".join(
                    f"- {p.get('group', '')}: {', '.join(p.get('needles', [])[:5])}"
                    for p in relevant_incidents[:4]
                )
                context["sources"].append("incident-reports")

        # Threat feeds — current known-bad IOCs
        threat_feeds = get_threat_feeds()
        if threat_feeds:
            context["threat_feeds"] = [
                f.get("name") for f in threat_feeds[:8]
            ]
            context["threat_needles"] = [
                str(n) for f in threat_feeds[:8]
                for n in (f.get("needles") or [])
            ]
            context["sources"].append("threat-feeds")

        # Vendor guides — detection logic and field names
        vendor_guides = get_vendor_guides()
        if vendor_guides:
            context["vendor_guides"] = [
                v.get("vendor") for v in vendor_guides[:6]
            ]
            context["vendor_needles"] = [
                str(n) for v in vendor_guides[:6]
                for d in (v.get("detection_logic") or [])
                for n in (d.get("needles") or [])
            ]
            context["sources"].append("vendor-guides")

        # Sysmon configs — event coverage and field names
        sysmon_configs = get_sysmon_configs()
        if sysmon_configs:
            context["sysmon_configs"] = [
                c.get("name") for c in sysmon_configs[:4]
            ]
            context["sysmon_needles"] = [
                str(n) for c in sysmon_configs[:4]
                for e in (c.get("events") or [])
                for n in (e.get("needles") or [])
            ]
            context["sources"].append("sysmon")

        # YARA rules — malware family detection
        yara_rules = get_yara_rules()
        if yara_rules:
            context["yara_rules"] = [
                r.get("family") for r in yara_rules[:6]
            ]
            context["yara_needles"] = [
                str(s) for r in yara_rules[:6]
                for ru in (r.get("rules") or [])
                for s in (ru.get("strings") or [])
            ]
            context["sources"].append("yara")

        # CISA KEV — actively exploited CVEs
        cisa_kev = get_cisa_kev()
        if cisa_kev:
            context["cisa_kev"] = [
                c.get("cve") for c in cisa_kev[:8]
            ]
            context["cisa_needles"] = [
                str(n) for c in cisa_kev[:8]
                for n in (c.get("needles") or [])
            ]
            context["sources"].append("cisa-kev")

        # MISP / OpenCTI — structured threat intel
        misp_opencti = get_misp_opencti()
        if misp_opencti:
            context["misp_opencti"] = [
                p.get("name") for p in misp_opencti[:4]
            ]
            context["misp_needles"] = [
                str(n) for p in misp_opencti[:4]
                for f in (p.get("feed_types") or [])
                for n in (f.get("needles") or [])
            ]
            context["sources"].append("misp-opencti")
    except Exception as exc:  # noqa: BLE001
        logger.debug("incident/threat/vendor/sysmon/yara/kev/misp context skipped: %s", exc)

    return context


async def api_ask(request):
    """POST /portal/api/mode1/ask — NL → needles + N4 hits."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    body = await request.json()
    question = str(body.get("question") or "").strip()
    if not question:
        return JSONResponse({"error": "Missing question"}, status_code=400)

    from nexus.langgraph.llm_pipeline import get_model
    from nexus.langgraph.mode1 import nl_to_needles
    from nexus.langgraph.query_pack import run_ad_hoc_query

    try:
        model = get_model()
    except Exception:
        model = None

    context = _mode1_ask_context(case_dir, question)
    parsed = nl_to_needles(question, model=model, context=context)
    needles = parsed.get("needles", [])
    window = parsed.get("window", "")
    dsl_query = str(parsed.get("dsl_query") or "").strip()
    if not needles and not dsl_query:
        return JSONResponse({"needles": [], "window": window, "error": "No needles extracted"})

    # WP 4j.11: prefer the structured query verbatim; degrade to terms.
    query_text = dsl_query or " ".join(needles)
    n4_result = run_ad_hoc_query(
        case_dir,
        extra_needles=needles,
        query_override=query_text,
        persist=True,
        limit=int(body.get("limit") or 80),
    )
    return JSONResponse({
        "needles": needles,
        "query": query_text,
        "dsl": bool(dsl_query),
        "dsl_fallback": (parsed.get("dsl") or {}).get("fallback", False),
        "window": window,
        "hits": n4_result.get("hits", []),
        "count": n4_result.get("count", 0),
        "backend": n4_result.get("backend", ""),
        "rationale": parsed.get("rationale", ""),
        "entities": parsed.get("entities", {}),
        "families": context.get("families", []),
        "techniques": context.get("techniques", []),
        "context_sources": context.get("sources", []),
        "source": parsed.get("source", ""),
    })


async def api_select(request):
    """POST /portal/api/mode1/select — promote selected hit indices to DRAFT."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed

    body = await request.json()
    raw_indices = body.get("hits", [])
    raw_rows = body.get("rows")
    has_rows = isinstance(raw_rows, list) and bool(raw_rows)
    title = str(body.get("title") or "").strip()
    use_scribe = bool(body.get("scribe", True))

    if not title:
        return JSONResponse({"error": "Missing title"}, status_code=400)
    if not raw_indices and not has_rows:
        return JSONResponse({"error": "No hits selected"}, status_code=400)

    from nexus.langgraph.llm_pipeline import get_model
    from nexus.langgraph.mode1 import promote_hits_to_draft, save_draft_finding, scribe_finding
    from nexus.langgraph.query_pack import (
        _parse_needles,
        collect_playbook_query_terms,
        collect_query_terms,
        load_case_intake,
        n4_hits,
        parse_intake_window,
    )

    intake = load_case_intake(case_dir)
    pb_terms = collect_playbook_query_terms(intake)

    # If the client sent the current explore filters, run the same query
    # so that indices are stable against the displayed hit list.
    explore_needles = _parse_needles(str(body.get("needles") or ""))
    if body.get("family") or body.get("start") or body.get("end") or explore_needles:
        if explore_needles:
            from nexus.langgraph.query_pack import persistable_needles

            merged = persistable_needles(
                _parse_needles(intake.get("query_extra", "")) + explore_needles
            )
            intake["query_extra"] = "\n".join(merged) + ("\n" if merged else "")
        start = str(body.get("start") or "").strip()
        end = str(body.get("end") or "").strip()
        if start or end:
            parts = []
            if start:
                parts.append(start)
            if end:
                parts.append(end)
            intake["window"] = "..".join(parts)
        terms = collect_query_terms(intake)
        window = parse_intake_window(intake)
        all_hits, _ = n4_hits(case_dir, terms, window, priority_terms=pb_terms)
        family_filter = [f.strip() for f in str(body.get("family") or "").split(",") if f.strip()]
        if family_filter:
            want = {f.lower() for f in family_filter}
            all_hits = [h for h in all_hits if (h.get("family") or "").lower() in want]
    else:
        # Fallback to the persisted intake query (ask flow)
        terms = collect_query_terms(intake)
        window = parse_intake_window(intake)
        all_hits, _ = n4_hits(case_dir, terms, window, priority_terms=pb_terms)

    if not all_hits:
        return JSONResponse({"error": "No hits loaded. Run ask first."}, status_code=400)

    def _hit_key(h: dict) -> tuple[str, str, str]:
        return (
            str(h.get("family") or ""),
            str(h.get("file") or "").replace("\\", "/"),
            str(h.get("line") or ""),
        )

    if has_rows:
        # EH-6: select by STABLE row identity. The displayed list came from the
        # search path; index-based selection could attach a different row after
        # any drift. Missing identities are reported (409), never substituted.
        wanted = {
            (
                str(r.get("family") or ""),
                str(r.get("file") or "").replace("\\", "/"),
                str(r.get("line") or ""),
            )
            for r in raw_rows if isinstance(r, dict)
        }
        selected = [h for h in all_hits if _hit_key(h) in wanted]
        found = {_hit_key(h) for h in selected}
        missing = [f"{f}:{ln}" for _fam, f, ln in wanted - found]
        if missing:
            return JSONResponse({
                "error": "selected rows are not in the current result — re-run the search",
                "missing": sorted(missing)[:10],
            }, status_code=409)
    else:
        try:
            indices = sorted({int(i) - 1 for i in raw_indices if str(i).strip()})
        except (ValueError, TypeError):
            return JSONResponse({"error": "Invalid hit indices"}, status_code=400)

        bad = [i + 1 for i in indices if i < 0 or i >= len(all_hits)]
        if bad:
            return JSONResponse({"error": f"Hit indices out of range: {bad}"}, status_code=400)

        selected = [all_hits[i] for i in indices]
    from nexus.audit import resolve_examiner
    from nexus.langgraph.query_pack import attach_hit_fields
    selected = attach_hit_fields(case_dir, selected)  # re-parse fields for the report
    examiner = resolve_examiner()
    draft = promote_hits_to_draft(
        case_dir,
        hits=selected,
        title=title,
        examiner=examiner,
        interpretation_hint=str(body.get("interpretation") or ""),
    )

    if use_scribe:
        try:
            model = get_model()
        except Exception:
            model = None
        draft = scribe_finding(draft, hits=selected, model=model, case_dir=case_dir)
    else:
        # scribe=false = fast deterministic fill, not "no scribe" — a bare
        # skeleton with empty observation used to reach findings.json.
        from nexus.langgraph.mode1 import _heuristic_scribe

        draft = _heuristic_scribe(draft, selected, case_dir=case_dir)

    result = save_draft_finding(case_dir, draft)
    if result.get("status") == "STAGED":
        resp: dict = {
            "finding_id": result.get("finding_id"),
            "title": title,
            "status": "DRAFT",
            "audit_ids": draft.get("audit_ids", []),
        }
        if result.get("confidence_adjusted"):
            resp["confidence_adjusted"] = result["confidence_adjusted"]
        return JSONResponse(resp)
    # Surface the real rejection reason (validation errors, provenance
    # detail, missing audit_ids) instead of a bare status code.
    detail: list = list(result.get("errors") or [])
    if result.get("error"):
        detail.append(str(result["error"]))
    if result.get("missing_audit_ids"):
        detail.append("missing audit_ids: " + ", ".join(str(a) for a in result["missing_audit_ids"][:5]))
    if not detail:
        detail = [str(result.get("status", "failed"))]
    return JSONResponse({"error": detail})




# ---------------------------------------------------------------------------
# Mode 1 Cockpit: Explore + Steer Chat + Histogram
# ---------------------------------------------------------------------------


def _available_families(case_dir: Path) -> list[str]:
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions
    extractions = resolve_tools_extractions(case_dir)
    if not extractions.is_dir():
        return []
    return sorted({p.parent.name for p in extractions.rglob("*.csv")})


def _bucket_times(hits: list[dict], bucket_minutes: int = 60) -> dict[str, int]:
    from nexus.langgraph.query_pack import _DATE_RE
    buckets: dict[str, int] = {}
    for h in hits:
        text = str(h.get('text', ''))
        for m in _DATE_RE.finditer(text):
            ts = m.group(1)
            try:
                d = datetime.strptime(ts, '%Y-%m-%d').replace(tzinfo=UTC)
            except ValueError:
                continue
            key = ts if bucket_minutes == 1440 else f'{ts}T{d.hour:02d}:00'
            buckets[key] = buckets.get(key, 0) + 1
    return dict(sorted(buckets.items()))


def _case_default_needles(case_dir, cap: int = 120) -> list[str]:
    """The 'no query given' vocabulary: what the investigation flagged.

    Order: needles the Mode 1 full-run actually scanned (persisted in the
    run record — the honest set for this case), else the briefing scan
    vocabulary for the case's families. Lets the Timeline show matched
    events for portal cases whose intake is empty.
    """
    try:
        rec = _mode1_run_record(case_dir)
    except Exception:  # noqa: BLE001
        rec = None
    if rec and rec.get("needles"):
        return [str(n) for n in rec["needles"] if str(n).strip()][:cap]
    try:
        from nexus.langgraph.briefing import _family_inventory, _scan_needles

        return list(_scan_needles(case_dir, sorted(_family_inventory(case_dir))))[:cap]
    except Exception:  # noqa: BLE001
        return []


def _needle_dsl(needle: str) -> str:
    """Render one needle for the N4 DSL.

    A comma/space inside a needle ("sc.exe, net.exe") would re-tokenize as
    several OR terms — quote it so Explore/workbench search exactly the term
    the examiner or LLM supplied (EH-8).
    """
    term = str(needle or "").strip()
    if not term:
        return ""
    if any(ch in term for ch in (",", " ", "\t")):
        return '"' + term.replace('"', " ").strip() + '"'
    return term


def _explore_query_from_body(case_dir, body):
    """Shared needle→DSL construction for /explore/search and
    /workbench/add_many — both endpoints must see the identical result set.

    Returns (query_text, window, family_filter, host_filter). Single-value
    family + host are pushed INTO the DSL (true totals); multi-family lists
    and host stay for post-filtering.
    """
    from nexus.langgraph.query_pack import (
        _parse_needles,
        load_case_intake,
        parse_intake_window,
        persistable_needles,
    )

    needles = _parse_needles(str(body.get('needles') or ''))
    query_text = str(body.get('query') or '').strip()
    family_filter = [f.strip() for f in str(body.get('family') or '').split(',') if f.strip()]
    start = str(body.get('start') or '').strip()
    end = str(body.get('end') or '').strip()

    intake = load_case_intake(case_dir)
    if needles:
        merged = persistable_needles(_parse_needles(intake.get('query_extra', '')) + needles)
        intake['query_extra'] = '\n'.join(merged) + ('\n' if merged else '')
    window = parse_intake_window(intake)
    if start or end:
        parts = [p for p in (start, end) if p]
        intake['window'] = '..'.join(parts)
        window = parse_intake_window(intake)

    # Merge plain needles into the DSL text so n4_query sees both
    # (it reloads CASE.yaml internally and would otherwise drop them).
    if needles and query_text:
        query_text = query_text + ' ' + ' '.join(
            _needle_dsl(n) for n in needles if _needle_dsl(n)
        )
    elif needles and not query_text:
        query_text = ' OR '.join(_needle_dsl(n) for n in needles if _needle_dsl(n))

    # Push single-value family + host filters into the DSL so n4_query's
    # `count` is the TRUE filtered total — post-filtering a 400-row page
    # under-reports and breaks pagination vs. the briefing's chip counts.
    host_filter = str(body.get('host') or '').strip().lower()
    if len(family_filter) == 1:
        query_text = f"{query_text} family:{family_filter[0].lower()}".strip()
        family_filter = []
    if host_filter:
        query_text = f"{query_text} host:{host_filter}".strip()

    return query_text, window, family_filter, host_filter


def _post_filter_hits(hits, family_filter, host_filter):
    """Apply the residual filters the DSL push-down left behind
    (multi-family lists, host re-check on attached fields)."""
    if family_filter:
        want = {f.lower() for f in family_filter}
        hits = [h for h in hits if (h.get('family') or '').lower() in want]
    if host_filter:
        hits = [h for h in hits if (h.get('host') or '').lower() == host_filter]
    return hits


async def api_explore_search(request):
    """POST /portal/api/explore/search — faceted N4 search.

    Body: {query?: "<DSL>", needles?: "a,b", family?: "evtx,prefetch",
           start?, end?, limit?, offset?}. When ``query`` (DSL) is provided
    it takes precedence over plain needles.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({'error': 'No active case'}, status_code=404)

    from nexus.langgraph.query_pack import (
        attach_hit_fields,
        collect_query_terms,
        load_case_intake,
        n4_query,
    )

    body = await request.json()
    try:
        limit = max(1, min(int(body.get('limit') or 80), 400))
        offset = max(0, int(body.get('offset') or 0))
    except (TypeError, ValueError):
        return JSONResponse({'error': 'limit/offset must be integers'}, status_code=400)

    query_text, window, family_filter, host_filter = _explore_query_from_body(case_dir, body)

    defaulted = 0
    if not query_text and body.get('default_needles'):
        # Timeline events panel opt-in: no query = "rows the investigation
        # flagged". Term lists go straight to n4_hits — the DSL's 24-term
        # OR cap is for examiner queries, not internal vocabulary.
        vocab = _case_default_needles(case_dir)
        if vocab:
            from nexus.langgraph.query_pack import n4_hits

            all_hits, backend_used = n4_hits(
                case_dir, vocab, window, priority_terms=vocab)
            result = {
                'count': len(all_hits),
                'hits': all_hits[offset:offset + 400],
                'backend': backend_used,
                'query': f'{len(vocab)} case needles (auto)',
            }
            defaulted = len(vocab)
        else:
            result = {'count': 0, 'hits': [], 'backend': '', 'query': ''}
    else:
        result = n4_query(case_dir, query_text, window=window, limit=400, offset=offset)
    if result.get('error'):
        return JSONResponse({'error': result['error']}, status_code=400)
    hits = list(result.get('hits') or [])
    total = int(result.get('count') or 0)

    hits = _post_filter_hits(hits, family_filter, "")
    if family_filter:
        # Multi-family lists are page-level post-filtered: the count is a
        # lower bound, and the UI must say so (review fix).
        total = len(hits)
        result["count_lower_bound"] = True

    # WP 4d.1: parsed CSV fields + best-effort host per hit for type-aware UI.
    # The host re-check runs AFTER attach (raw hits may not carry `host`).
    hits = attach_hit_fields(case_dir, hits)
    hits = _post_filter_hits(hits, [], host_filter)

    return JSONResponse({
        'hits': hits[:limit],
        'count': total,
        'count_exact': bool(result.get('count_exact')),
        'count_lower_bound': bool(result.get('count_lower_bound')),
        'capped_reasons': list(result.get('capped_reasons') or []),
        'total_before_family_filter': total,
        'backend': result.get('backend', ''),
        'families': _available_families(case_dir),
        'needles': collect_query_terms(load_case_intake(case_dir)),
        'query': result.get('query', ''),
        'offset': offset,
        'default_needles': defaulted,
    })


async def api_explore_aggregate(request):
    """POST /portal/api/explore/aggregate — hit counts by family/host/hour/day.

    Body: {query?: "<DSL>", group_by: family|host|hour|day|file}
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({'error': 'No active case'}, status_code=404)
    body = await request.json()
    from nexus.langgraph.query_pack import n4_aggregate

    result = n4_aggregate(
        case_dir,
        str(body.get('query') or ''),
        group_by=str(body.get('group_by') or 'family'),
    )
    if result.get('error'):
        return JSONResponse({'error': result['error']}, status_code=400)
    return JSONResponse(result)


async def api_explore_histogram(request):
    """POST /portal/api/explore/histogram — time buckets for current hits."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({'error': 'No active case'}, status_code=404)
    body = await request.json()
    from nexus.langgraph.query_pack import (
        _parse_needles,
        collect_query_terms,
        load_case_intake,
        n4_hits,
        parse_intake_window,
        persistable_needles,
    )
    needles = _parse_needles(str(body.get('needles') or ''))
    family_filter = [f.strip() for f in str(body.get('family') or '').split(',') if f.strip()]
    start = str(body.get('start') or '').strip()
    end = str(body.get('end') or '').strip()
    intake = load_case_intake(case_dir)
    if needles:
        merged = persistable_needles(_parse_needles(intake.get('query_extra', '')) + needles)
        intake['query_extra'] = '\n'.join(merged)
    if start or end:
        parts = []
        if start:
            parts.append(start)
        if end:
            parts.append(end)
        intake['window'] = '..'.join(parts)
    window = parse_intake_window(intake)
    hits, _ = n4_hits(case_dir, collect_query_terms(intake), window)
    if family_filter:
        want = {f.lower() for f in family_filter}
        hits = [h for h in hits if (h.get('family') or '').lower() in want]
    buckets = _bucket_times(hits, bucket_minutes=int(body.get('bucket') or 60))
    return JSONResponse({'buckets': buckets, 'count': len(hits)})


async def explore_page(request):
    """Mode 1 Cockpit — faceted explore + steer chat + histogram."""
    case_dir = _get_case_dir(request)
    families = _available_families(case_dir) if case_dir else []
    fam_options = ''.join(f'<option value="{_e(f)}">{_e(f)}</option>' for f in families)
    content = f"""
<h1>Explore Evidence</h1>
<p>Faceted N4 search over parsed evidence. The chat can translate English to needles and return hits inline.</p>
<div style="display:grid;grid-template-columns:260px 1fr;gap:1rem">
  <div>
    <h3>Filters</h3>
    <p>Query (DSL)<br><input id="dsl" style="width:100%;background:#161b22;color:#c9d1d9" placeholder='error AND family:evtx NOT defender'></p>
    <p style="font-size:0.75rem;color:#8b949e">AND / OR / NOT &middot; family: host: user: event: file: &middot; regex:&lt;pattern&gt;</p>
    <p>Needles<br><input id="needles" style="width:100%;background:#161b22;color:#c9d1d9" placeholder="sdelete,.pst,USBSTOR"></p>
    <p>Family<br><select id="family" multiple style="width:100%;background:#161b22;color:#c9d1d9;height:6rem">{fam_options}</select></p>
    <p>Start<br><input id="start" type="date" style="width:100%;background:#161b22;color:#c9d1d9"></p>
    <p>End<br><input id="end" type="date" style="width:100%;background:#161b22;color:#c9d1d9"></p>
    <p><button class="action-btn" onclick="searchHits()">Search</button></p>
    <p><button class="action-btn" style="background:#1f6feb" onclick="loadAggregates()">Aggregations</button></p>
    <div id="agg" style="font-size:0.8rem;color:#8b949e"></div>
    <p><button class="action-btn" style="background:#8957e5" onclick="loadEntities()">Entities</button></p>
    <div id="entities" style="font-size:0.8rem;color:#8b949e;max-height:14rem;overflow:auto"></div>
    <hr style="border-color:#30363d">
    <h3>Steer Chat</h3>
    <div id="chat" style="background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:0.5rem;height:12rem;overflow:auto;font-size:0.85rem;margin-bottom:0.5rem"></div>
    <input id="chat_input" style="width:100%;background:#161b22;color:#c9d1d9" placeholder="Ask the case..." onkeydown="if(event.key==='Enter') chatAsk()">
    <p>
      <button class="action-btn" onclick="chatAsk()">Ask LLM</button>
      <button class="action-btn" style="background:#8957e5" onclick="mode2Iterate()">Iterate (Mode 2)</button>
      <span id="mode2_status" style="margin-left:0.5rem;font-size:0.8rem;color:#8b949e"></span>
    </p>
  </div>
  <div>
    <h3>Hits <span id="hit_count" style="font-size:0.8rem;font-weight:normal"></span></h3>
    <div id="hist" style="height:120px;background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:0.5rem;margin-bottom:1rem;overflow:hidden"></div>
    <p>
      <input id="draft_title" style="width:50%;background:#161b22;color:#c9d1d9" placeholder="Finding title">
      <label style="margin-left:0.5rem"><input type="checkbox" id="use_scribe" checked> Scribe</label>
      <button class="action-btn" onclick="promoteSelected()" style="margin-left:0.5rem">Promote to DRAFT</button>
      <button class="action-btn" style="background:#1f6feb" onclick="addSelectedToWorkbench()">Add to Workbench</button>
      <span id="status" style="margin-left:1rem"></span>
    </p>
    <table>
      <tr><th></th><th>Family</th><th>File:line</th><th>Terms</th><th>Row</th></tr>
      <tbody id="hit_rows"></tbody>
    </table>
  </div>
</div>
<script>
let currentHits = [];
function selectedFamily() {{
  const s = document.getElementById('family');
  return Array.from(s.selectedOptions).map(o => o.value).join(',');
}}
async function searchHits() {{
  const dslEl = document.getElementById('dsl');
  const dsl = dslEl ? dslEl.value.trim() : '';
  const body = {{
    needles: document.getElementById('needles').value,
    family: selectedFamily(),
    start: document.getElementById('start').value,
    end: document.getElementById('end').value,
  }};
  if (dsl) body.query = dsl;
  const r = await fetch('/portal/api/explore/search', {{
    method: 'POST', headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify(body)
  }});
  const data = await r.json();
  if (data.error) {{
    document.getElementById('hit_count').textContent = 'query error: ' + data.error;
    renderHits();
    return;
  }}
  currentHits = data.hits || [];
  document.getElementById('hit_count').textContent = `showing ${{currentHits.length}} / ${{data.count}}` + (data.query && data.query !== '(match all)' ? ' | ' + data.query : '');
  renderHits();
  await updateTimelineLanes();
  await loadAggregates();
}}
async function loadAggregates() {{
  const dslEl = document.getElementById('dsl');
  const r = await fetch('/portal/api/explore/aggregate', {{
    method: 'POST', headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{ query: dslEl ? dslEl.value.trim() : '', group_by: 'family' }})
  }});
  const data = await r.json();
  const el = document.getElementById('agg');
  if (data.error) {{
    el.innerHTML = '<span style="color:#f85149">' + escapeHtml(data.error) + '</span>';
    return;
  }}
  const buckets = data.buckets || {{}};
  document.getElementById('agg').innerHTML = Object.keys(buckets).length
    ? '<b>hits by family</b><br>' + Object.entries(buckets).map(([k, v]) => escapeHtml(k) + ': <b>' + v + '</b>').join('<br>')
    : 'No hits to aggregate.';
}}
async function loadEntities() {{
  const dslEl = document.getElementById('dsl');
  const r = await fetch('/portal/api/entities', {{
    method: 'POST', headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{ query: dslEl ? dslEl.value.trim() : '' }})
  }});
  const data = await r.json();
  const el = document.getElementById('entities');
  if (data.error) {{
    el.innerHTML = '<span style="color:#f85149">' + escapeHtml(data.error) + '</span>';
    return;
  }}
  const ent = data.entities || {{}};
  let html = '';
  for (const [key, label] of [['users', 'Users'], ['ips', 'IPs'], ['processes', 'Processes'], ['paths', 'Paths']]) {{
    const entries = Object.entries(ent[key] || {{}}).slice(0, 8);
    if (!entries.length) continue;
    html += '<b>' + label + '</b><br>' + entries.map(([k, v]) =>
      '<span style="cursor:pointer;color:#58a6ff" title="click to pivot" '
      + 'onclick="pivotEntity(this.textContent)">' + escapeHtml(k) + '</span>: ' + v
    ).join('<br>');
  }}
  el.innerHTML = html || 'No entities found.';
}}
function pivotEntity(value) {{
  const dslEl = document.getElementById('dsl');
  if (dslEl) {{
    dslEl.value = '"' + value + '"';
    searchHits();
  }}
}}
function renderHits() {{
  const tb = document.getElementById('hit_rows');
  if (!currentHits.length) {{
    tb.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#8b949e">No hits. Adjust filters or chat.</td></tr>';
    return;
  }}
  tb.innerHTML = currentHits.map((h, i) => '<tr>' +
    '<td><input type="checkbox" class="hit-check" value="' + (i+1) + '"' +
      ' data-family="' + escapeHtml(h.family || '') + '"' +
      ' data-file="' + escapeHtml(h.file || '') + '"' +
      ' data-line="' + escapeHtml(String(h.line || '')) + '"></td>' +
    '<td>' + escapeHtml(h.family) + '</td>' +
    '<td>' + escapeHtml(h.file) + ':' + escapeHtml(h.line) + '</td>' +
    '<td>' + escapeHtml(h.terms) + '</td>' +
    '<td class="evidence-path">' + escapeHtml(h.text) + '</td>' +
  '</tr>').join('');
}}
function famColor(fam) {{
  let h = 0;
  for (const c of String(fam)) h = (h * 31 + c.charCodeAt(0)) % 360;
  return 'hsl(' + h + ',60%,45%)';
}}
async function updateTimelineLanes() {{
  const dslEl = document.getElementById('dsl');
  const r = await fetch('/portal/api/timeline/lanes', {{
    method: 'POST', headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{
      query: dslEl ? dslEl.value.trim() : '',
      needles: document.getElementById('needles').value,
      bucket: 'hour'
    }})
  }});
  const data = await r.json();
  const el = document.getElementById('hist');
  const families = data.families || [];
  if (!families.length) {{
    el.innerHTML = '<span style="color:#8b949e">No timestamped hits</span>';
    return;
  }}
  const max = Math.max(1, ...families.flatMap(f => Object.values(f.buckets)));
  let html = '';
  for (const f of families.slice(0, 8)) {{
    html += '<div style="display:flex;align-items:flex-end;height:22px;gap:1px;margin-bottom:2px" title="' + escapeHtml(f.family) + '">';
    html += '<div style="width:90px;font-size:0.7rem;color:#8b949e;overflow:hidden;white-space:nowrap">' + escapeHtml(f.family) + '</div>';
    const keys = Object.keys(f.buckets);
    for (const [k, v] of Object.entries(f.buckets)) {{
      html += '<div data-day="' + escapeHtml(k.slice(0, 10)) + '" title="' + escapeHtml(f.family + ' ' + k + ': ' + v) + '"'
        + ' onclick="zoomTo(this.dataset.day)"'
        + ' style="flex:1;background:' + famColor(f.family) + ';height:' + (v/max*100) + '%;min-width:3px;cursor:pointer"></div>';
    }}
    html += '</div>';
  }}
  el.innerHTML = html;
}}
function zoomTo(day) {{
  const startEl = document.getElementById('start');
  const endEl = document.getElementById('end');
  if (startEl && endEl) {{ startEl.value = day; endEl.value = day; searchHits(); }}
}}
function updateHistogram(hd) {{
  const buckets = hd.buckets || {{}};
  const max = Math.max(1, ...Object.values(buckets));
  const el = document.getElementById('hist');
  const keys = Object.keys(buckets);
  if (!keys.length) {{
    el.innerHTML = '<span style="color:#8b949e">No timestamped hits</span>';
    return;
  }}
  let html = '<div style="display:flex;align-items:flex-end;height:100%;gap:2px">';
  for (const [k, v] of Object.entries(buckets)) {{
    html += '<div title="' + escapeHtml(k + ': ' + v) + '" style="flex:1;background:#1f6feb;height:' + (v/max*100) + '%;min-width:4px"></div>';
  }}
  html += '</div>';
  el.innerHTML = html;
}}
async function chatAsk() {{
  const input = document.getElementById('chat_input');
  const q = input.value.trim();
  if (!q) return;
  input.value = '';
  appendChat('you', q);
  appendChat('llm', 'Thinking...');
  try {{
    const r = await fetch('/portal/api/chat', {{
      method: 'POST', headers: {{'Content-Type':'application/json'}},
      body: JSON.stringify({{message: q}})
    }});
    const data = await r.json();
    if (data.error) {{
      replaceLast('llm', 'Error: ' + data.error);
      return;
    }}
    replaceLast('llm', data.reply);
    if (data.hits && data.hits.length) {{
      currentHits = data.hits;
      document.getElementById('needles').value = data.needles.join(',');
      document.getElementById('hit_count').textContent = 'showing ' + currentHits.length + ' / ' + data.count;
      renderHits();
      const rh = await fetch('/portal/api/explore/histogram', {{
        method: 'POST', headers: {{'Content-Type':'application/json'}},
        body: JSON.stringify({{needles: data.needles.join(',')}})
      }});
      updateTimelineLanes();
    }}
  }} catch (e) {{
    replaceLast('llm', 'Error: ' + e.message);
  }}
}}
async function loadChatHistory() {{
  try {{
    const r = await fetch('/portal/api/chat');
    if (!r.ok) return;
    const data = await r.json();
    const msgs = data.messages || [];
    for (const m of msgs) {{
      appendChat(m.role === 'examiner' ? 'you' : 'llm', m.text);
    }}
  }} catch (e) {{ /* transcript load is best-effort */ }}
}}
document.addEventListener('DOMContentLoaded', loadChatHistory);
document.addEventListener('DOMContentLoaded', loadChatHistory);
async function mode2Iterate() {{
  const q = document.getElementById('chat_input').value.trim()
    || (currentHits.length ? 'Corroborate and expand on the current hits' : '');
  if (!q && !currentHits.length) return alert('Ask a question first or run a search');
  const statusEl = document.getElementById('mode2_status');
  statusEl.textContent = 'iterating...';
  appendChat('you', '[Mode 2] iterate on: ' + (q || 'current hits'));
  try {{
    const r = await fetch('/portal/api/mode2/iterate', {{
      method: 'POST', headers: {{'Content-Type':'application/json'}},
      body: JSON.stringify({{ question: q || 'corroborate the current hits', max_iterations: 2 }})
    }});
    const data = await r.json();
    if (data.error) {{
      appendChat('llm', 'Mode 2 error: ' + data.error);
      document.getElementById('mode2_status').textContent = 'error';
      return;
    }}
    for (const it of data.iterations || []) {{
      if (it.action === 'proposed_and_run') {{
        appendChat('llm', 'Iteration ' + it.iteration + ': proposed ' + (it.needles || []).join(', ') + ' -> ' + it.hits + ' hits');
      }} else if (it.action === 'no_new_proposals') {{
        appendChat('llm', 'Iteration ' + it.iteration + ': no new needles to propose');
      }}
    }}
    appendChat('llm', 'Mode 2 loop complete: ' + (data.total_hits || 0) + ' total hits' + (data.capped ? ' (capped)' : ''));
    if (data.needles_run) {{
      document.getElementById('needles').value = (data.needles_run || []).join(',');
      await searchHits();
    }}
    statusEl.textContent = 'done';
  }} catch (e) {{
    document.getElementById('mode2_status').textContent = 'error: ' + e.message;
  }}
}}
function appendChat(who, text) {{
  const d = document.getElementById('chat');
  const cls = who === 'you' ? 'color:#58a6ff' : 'color:#3fb950';
  d.innerHTML += '<div style="' + cls + '">' + who + ': ' + escapeHtml(text) + '</div>';
  d.scrollTop = d.scrollHeight;
}}
function replaceLast(who, text) {{
  const d = document.getElementById('chat');
  const divs = d.querySelectorAll('div');
  if (divs.length) {{
    const last = divs[divs.length-1];
    if (last.textContent.startsWith(who + ':')) {{
      last.textContent = who + ': ' + text;
      return;
    }}
  }}
  appendChat(who, text);
}}
async function promoteSelected() {{
  const checkboxes = document.querySelectorAll('.hit-check:checked');
  const hitIds = Array.from(checkboxes).map(cb => cb.value);
  if (hitIds.length === 0) return alert('Select at least one hit');
  const title = document.getElementById('draft_title').value.trim();
  if (!title) return alert('Enter a finding title');
  const scribe = document.getElementById('use_scribe').checked;
  document.getElementById('status').textContent = 'Promoting...';
  const r = await fetch('/portal/api/mode1/select', {{
    method: 'POST',
    headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{
      rows: Array.from(checkboxes).map(cb => ({{family: cb.dataset.family, file: cb.dataset.file, line: cb.dataset.line}})),
      title: title,
      scribe: scribe,
      needles: document.getElementById('needles').value,
      family: selectedFamily(),
      start: document.getElementById('start').value,
      end: document.getElementById('end').value
    }})
  }});
  const result = await r.json();
  if (result.finding_id) {{
    document.getElementById('status').textContent = 'DRAFT: ' + result.finding_id;
    setTimeout(() => window.location = '/portal/findings?status=DRAFT', 1000);
  }} else {{
    document.getElementById('status').textContent = 'Error: ' + (result.error || JSON.stringify(result));
  }}
}}
async function addSelectedToWorkbench() {{
  const checkboxes = document.querySelectorAll('.hit-check:checked');
  if (checkboxes.length === 0) return alert('Select at least one hit');
  let added = 0, lastErr = '';
  for (const cb of checkboxes) {{
    const cells = cb.closest('tr').querySelectorAll('td');
    const hit = {{
      family: cells[1] ? cells[1].textContent : '',
      file: (cells[2] ? cells[2].textContent : '').split(':')[0],
      line: (cells[2] ? cells[2].textContent : '').split(':')[1] || '',
      terms: cells[3] ? cells[3].textContent : '',
      text: cells[4] ? cells[4].textContent : '',
    }};
    const r = await fetch('/portal/api/workbench/add', {{
      method: 'POST', headers: {{'Content-Type':'application/json'}},
      body: JSON.stringify({{ hit }})
    }});
    const res = await r.json();
    if (res.status === 'added') {{ added += 1; }}
    else {{ lastErr = res.error || 'failed'; }}
  }}
  document.getElementById('status').textContent = added
    ? 'Added ' + added + ' hit(s) to Workbench'
    : 'Error: ' + (lastErr || 'nothing added');
}}
function escapeHtml(s) {{
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}}
</script>
"""
    return HTMLResponse(_TEMPLATE.format(content=content))


async def api_workbench(request):
    """GET /portal/api/workbench — list bookmarked hits."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    from nexus.case.workbench import load_bookmarks

    return JSONResponse({"bookmarks": load_bookmarks(case_dir), "total": len(load_bookmarks(case_dir))})


async def api_workbench_add(request):
    """POST /portal/api/workbench/add — bookmark one hit {hit: {...}, note?}."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    body = await request.json()
    hit = body.get("hit") or {}
    if not isinstance(hit, dict) or not (hit.get("file") or hit.get("text")):
        return JSONResponse({"error": "Missing hit data"}, status_code=400)
    from nexus.case.workbench import add_bookmark

    return JSONResponse(add_bookmark(case_dir, hit, note=str(body.get("note") or "")))


async def api_workbench_add_many(request):
    """POST /portal/api/workbench/add_many — bookmark every hit matching the
    current Explore query. Body takes the same fields as /explore/search
    {needles?, query?, family?, host?, start?, end?, note?} so "bookmark all"
    means the FULL result set, not just the rendered page. Re-runs the N4
    query server-side; bounded at 5000 rows with an honest truncated flag.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed

    from nexus.case.workbench import add_bookmarks
    from nexus.langgraph.query_pack import attach_hit_fields, n4_query

    body = await request.json()
    cap = 5000
    query_text, window, family_filter, host_filter = _explore_query_from_body(case_dir, body)

    result = n4_query(case_dir, query_text, window=window, limit=cap, offset=0)
    if result.get('error'):
        return JSONResponse({'error': result['error']}, status_code=400)
    hits = _post_filter_hits(list(result.get('hits') or []), family_filter, "")
    matched = int(result.get('count') or 0)
    if family_filter:
        # multi-family residual post-filter — count only covers query+host,
        # so the page-filtered length is the honest (lower-bound) matched.
        matched = len(hits)

    hits = attach_hit_fields(case_dir, hits)
    hits = _post_filter_hits(hits, [], host_filter)
    # host is ALWAYS pushed into the DSL — result["count"] is already the
    # true host-filtered total; overwriting with len(hits) would hide page
    # truncation. The post-filter above is only a belt re-check on attached
    # fields.

    r = add_bookmarks(case_dir, hits, note=str(body.get("note") or ""))
    r["matched"] = matched
    r["truncated"] = matched > len(hits)
    return JSONResponse(r)


def _case_key(case_dir: Path | None) -> str:
    """Stable per-case key for in-memory state (run lock, briefing cache).

    Uses the resolved path, not the basename: two case stores can hold a case
    with the same id (e.g. separate roots / pytest tmp dirs), and a basename
    key would wrongly share locks and cached payloads between them.
    """
    if case_dir is None:
        return ""
    try:
        return str(Path(case_dir).resolve())
    except OSError:
        return str(case_dir)


_MODE1_RUN_FILE = "mode1_full_run.json"
_mode1_run_threads: dict[str, threading.Thread] = {}
_mode1_run_starting: set[str] = set()
_mode1_run_lock = threading.Lock()

# Briefing cache — case_briefing scans every playbook needle over the evidence
# (~seconds on small cases, worse on massive ones) and is re-requested on every
# Briefing mount + again by the directions endpoint. Short TTL keeps
# re-navigation instant; mutations invalidate explicitly.
_briefing_cache: dict[str, tuple[float, dict]] = {}
_briefing_lock = threading.Lock()
_BRIEFING_TTL = 45.0  # seconds


def _cached_briefing(case_dir: Path) -> dict:
    from nexus.langgraph.briefing import case_briefing
    key = _case_key(case_dir)
    with _briefing_lock:
        hit = _briefing_cache.get(key)
        if hit and time.time() - hit[0] < _BRIEFING_TTL:
            return hit[1]
    payload = case_briefing(case_dir)
    with _briefing_lock:
        _briefing_cache[key] = (time.time(), payload)
    return payload


def _invalidate_briefing(case_id: str) -> None:
    with _briefing_lock:
        _briefing_cache.pop(case_id, None)


def _mode1_run_path(case_dir: Path) -> Path:
    return case_dir / "analysis" / _MODE1_RUN_FILE


def _full_run_scribe_policy() -> tuple[str, int]:
    """Full-run scribe mode (WP 10.53 decision, Option B).

    Default ``heuristic`` keeps the one-click run fast. ``signal`` runs the
    LLM scribe only for needles whose hit count clears the threshold;
    ``llm`` runs it for every staged draft. Env-overridable.
    """
    mode = os.environ.get("NEXUS_FULL_RUN_SCRIBE", "heuristic").strip().lower()
    if mode not in ("heuristic", "signal", "llm"):
        mode = "heuristic"
    try:
        min_hits = int(os.environ.get("NEXUS_FULL_RUN_SCRIBE_MIN_HITS", "3"))
    except ValueError:
        min_hits = 3
    return mode, max(1, min_hits)


def _mode1_run_record(case_dir: Path) -> dict | None:
    """Read the persisted full-run record, marking dead runs as interrupted."""
    path = _mode1_run_path(case_dir)
    if not path.is_file():
        return None
    try:
        rec = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if rec.get("status") == "running":
        with _mode1_run_lock:
            alive = _mode1_run_threads.get(_case_key(case_dir))
            alive = bool(alive and alive.is_alive())
        rec["thread_alive"] = alive
        if not alive:
            # Server restarted (or the worker died) mid-run — the record is a
            # tombstone, not a live run. New POSTs may proceed.
            rec["status"] = "interrupted"
            rec["error"] = "Run interrupted — server restarted or worker stopped"
            _atomic_write_json(path, rec)
    return rec


def _supersede_drafts(case_dir: Path, finding_ids: list[str], *,
                      run_id: str, replaced_by: str) -> list[str]:
    """Retire DRAFT findings superseded by a reprocess re-run.

    Marked REJECTED with a superseded_by link rather than deleted — the audit
    trail keeps the old draft, the reason, and its replacement. Only drafts
    reach here (the caller skips approved needles first); APPROVED findings
    are signed and never superseded programmatically.
    Returns the ids actually updated.
    """
    done: list[str] = []
    findings_path = case_dir / "findings.json"
    if not findings_path.is_file():
        return done
    try:
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        changed = False
        for f in findings:
            fid = str(f.get("id") or f.get("finding_id") or "")
            if fid in finding_ids and str(f.get("status") or "").upper() == "DRAFT":
                f["status"] = "REJECTED"
                f["rejected_by"] = "mode1-full-run"
                f["rejected_at"] = datetime.now(UTC).isoformat()
                f["rejection_reason"] = (
                    f"Superseded by re-run {run_id}"
                    + (f" — replaced by {replaced_by}" if replaced_by else "")
                )
                f["superseded_by"] = replaced_by
                done.append(fid)
                changed = True
        if changed:
            _atomic_write_json(findings_path, findings)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed superseding drafts in findings.json: %s", exc)
    # Best-effort SQLite sync — same dual-store pattern as the reject endpoint
    try:
        from nexus.case import CaseManager
        from nexus.case.schemas import ApprovalState
        from nexus.config import settings
        mgr = CaseManager(settings.cases_root / "cases.db")
        for fid in done:
            f_obj = mgr.store.get_finding(fid, case_id=case_dir.name)
            if f_obj and f_obj.approval_state == ApprovalState.DRAFT:
                f_obj.approval_state = ApprovalState.REJECTED
                f_obj.rejected_by = "mode1-full-run"
                f_obj.rejected_at = datetime.now(UTC)
                f_obj.rejection_reason = f"Superseded by re-run {run_id}"
                mgr.store.save_finding(f_obj)
        mgr.close()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed syncing superseded drafts to SQLite: %s", exc)
    return done


def _mode1_full_run_worker(case_dir: Path, record_path: Path, record: dict,
                           max_needles: int, only: set[str],
                           reprocess: bool = False) -> None:
    """Background Mode 1 full-run worker.

    Writes the run record after every needle so navigation/reload/poll always
    sees live state. Stops at DRAFTs — examiner approval stays manual (HMAC).
    The briefing scan runs here, not in the POST — the endpoint returns 202
    instantly; the UI shows stage "scanning briefing" while the vocabulary
    and hit counts are computed.

    reprocess=True supersedes existing DRAFTs for covered needles and re-stages
    them fresh (drafts are unsigned machine output — safe to replace). APPROVED
    findings are never overwritten or rejected: they are signed examiner
    decisions — reprocess instead stages a fresh DRAFT revision alongside them
    (recorded under revised_approved) for examiner comparison and approval.
    """
    from nexus.audit import AuditWriter, resolve_examiner
    from nexus.case.workbench import add_bookmarks
    from nexus.langgraph.briefing import case_briefing
    from nexus.langgraph.mode1 import (
        _heuristic_scribe,
        promote_hits_to_draft,
        save_draft_finding,
        scribe_finding,
    )
    from nexus.langgraph.query_pack import (
        attach_hit_fields,
        load_case_intake,
        n4_hits,
        parse_intake_window,
    )

    write_lock = threading.Lock()
    scribe_mode, scribe_min_hits = _full_run_scribe_policy()
    scribe_state: dict[str, Any] = {"model": None, "resolved": False}

    def _persist() -> None:
        record["updated_at"] = time.time()
        with write_lock:
            _atomic_write_json(record_path, record)

    try:
        # Stage 1 — deterministic scan of every playbook/ATT&CK/Sigma needle.
        # This is the expensive step (~seconds on big evidence) — it lives in
        # the worker so the POST returns instantly.
        record["stage"] = "scanning briefing"
        _persist()
        brief = case_briefing(case_dir)
        scan = list(brief.get("needle_scan") or [])
        if only:
            scan = [s for s in scan if str(s.get("needle", "")).lower() in only]
        # F1: ubiquitous terms are background - reported, never staged.
        record.setdefault("skipped", [])
        ubiquitous = [s for s in scan if s.get("ubiquitous")]
        if ubiquitous:
            record["skipped"].extend(
                {
                    "needle": str(s.get("needle") or ""),
                    "reason": (
                        f"ubiquitous term ({int(s.get('hits') or 0)} hits - "
                        "matches a large share of the case; background, not staged)"
                    ),
                }
                for s in ubiquitous[:50]
            )
            scan = [s for s in scan if not s.get("ubiquitous")]
        needles_hit_total = len(scan)  # before the max_needles cap — report honestly
        scan = scan[:max_needles]
        record["needles"] = [str(s.get("needle") or "") for s in scan]
        record["needles_total"] = len(scan)
        record["needles_scanned"] = int(brief.get("scanned_needles") or 0)
        record["needles_hit_total"] = needles_hit_total
        record["needles_capped"] = needles_hit_total - len(scan)
        record["scan_truncated"] = bool(brief.get("scan_truncated"))
        _persist()
        if not scan:
            record["stage"] = "nothing to promote"
            record["needles_hit"] = 0
            record["skipped"] = [{"reason": "no playbook needles matched any evidence"}]
            record["drafts_staged"] = 0
            record["completed_at"] = time.time()
            record["next"] = "Nothing to promote - no needle hits in this case."
            record["status"] = "complete"  # publish LAST (pollers fire on status)
            _persist()
            return
        # Existing DRAFT/APPROVED needles — re-runs must not duplicate staged
        # findings (titles embed hit counts, so match the needle, not the
        # string). REJECTED/superseded needles are NOT skipped: the examiner may
        # legitimately re-stage a signal after rejecting a first attempt.
        existing: set[str] = set()
        drafts_by_needle: dict[str, list[str]] = {}
        approved_by_needle: dict[str, list[str]] = {}
        findings_path = case_dir / "findings.json"
        if findings_path.is_file():
            try:
                for f in json.loads(findings_path.read_text(encoding="utf-8")):
                    st = str(f.get("status") or "").upper()
                    title = str(f.get("title") or "")
                    m = re.match(r"Signal:\s*(.+?)\s*—", title)
                    if st in {"DRAFT", "APPROVED"} and m:
                        needle_key = m.group(1).strip().lower()
                        existing.add(needle_key)
                        fid = str(f.get("id") or f.get("finding_id") or "")
                        (approved_by_needle if st == "APPROVED" else drafts_by_needle
                         ).setdefault(needle_key, []).append(fid)
            except (OSError, json.JSONDecodeError):
                pass
        record["reprocess"] = reprocess
        record["superseded"] = []
        record["revised_approved"] = []

        examiner = resolve_examiner()
        window = parse_intake_window(load_case_intake(case_dir))
        record["stage"] = "scanning"
        _persist()

        # EH-6: ONE batched chunked scan per 25 needles (was one full-case
        # query per needle — up to 120 sequential rescans). Per-needle rows
        # are attributed from each hit's structured ``terms_list``, so no
        # intake terms leak in and no needle needs its own re-query.
        needles_ordered: list[str] = []
        for s in scan:
            needle = str(s.get("needle") or "").strip()
            if not needle:
                continue
            # Low-signal guard: pure digits / single chars match everything and
            # produce garbage drafts ("Signal: 21 — 37 hits"). Report, don't stage.
            if len(needle) < 3 or needle.isdigit():
                record["skipped"].append(
                    {"needle": needle, "reason": "low-signal needle (numeric/too short)"})
                continue
            needles_ordered.append(needle)
        needle_keys = {n.lower() for n in needles_ordered}
        hits_by_needle: dict[str, list[dict]] = {}
        # FD-001: the scan IS a tool call that produced these rows, but it runs
        # in-process (n4_hits), so nothing audited it — every staged draft was
        # rejected for a missing evidence trail and Approve stayed empty.
        # Record one case audit entry per batch and let drafts cite it.
        scan_audit = AuditWriter("nexus", audit_dir=case_dir / "audit")
        scan_aid_by_needle: dict[str, str] = {}
        scan_audit_ids: list[str] = []
        scan_batches = 0
        scan_capped = False
        scan_coverage = {"terms_requested": 0, "terms_queried": 0, "terms_failed": 0}
        for start_at in range(0, len(needles_ordered), 25):
            chunk = needles_ordered[start_at:start_at + 25]
            chunk_stats: dict = {}
            chunk_hits, _chunk_backend = n4_hits(
                case_dir, chunk, window, priority_terms=chunk, stats=chunk_stats,
            )
            chunk_aid = scan_audit.log(
                tool="mode1_scan",
                params={"case_id": case_dir.name, "needles": list(chunk),
                        "batch": scan_batches},
                result_summary={"hits": len(chunk_hits),
                                "backend": str(_chunk_backend or "")},
                extra={"case_id": case_dir.name},
            )
            if chunk_aid:
                scan_audit_ids.append(chunk_aid)
                for needle in chunk:
                    scan_aid_by_needle[str(needle).strip().lower()] = chunk_aid
            scan_batches += 1
            if (chunk_stats.get("hits_capped") or chunk_stats.get("files_capped")
                    or chunk_stats.get("files_skipped_family_cap")
                    or chunk_stats.get("files_skipped_size")
                    or chunk_stats.get("terms_failed")):
                scan_capped = True
            scan_coverage["terms_requested"] += int(chunk_stats.get("terms_requested") or 0)
            scan_coverage["terms_queried"] += int(chunk_stats.get("terms_queried") or 0)
            scan_coverage["terms_failed"] += len(chunk_stats.get("terms_failed") or [])
            for h in attach_hit_fields(case_dir, list(chunk_hits)):
                matched = h.get("terms_list")
                if not isinstance(matched, list):
                    matched = [t.strip() for t in str(h.get("terms") or "").split(",")]
                for t in matched:
                    key = str(t).strip().lower()
                    if key in needle_keys:
                        hits_by_needle.setdefault(key, []).append(h)
        record["scan_batches"] = scan_batches
        record["scan_coverage"] = scan_coverage
        record["scan_audit_ids"] = scan_audit_ids[:20]
        record["scan_truncated"] = bool(record.get("scan_truncated")) or scan_capped
        _persist()

        all_hits: list[dict] = []
        seen_hit_keys: set[tuple[str, str, str]] = set()
        for i, s in enumerate(scan):
            needle = str(s.get("needle") or "").strip()
            record["needles_done"] = i
            record["current"] = needle
            _persist()
            if not needle or len(needle) < 3 or needle.isdigit():
                continue
            hits = hits_by_needle.get(needle.lower()) or []
            if not hits:
                record["skipped"].append({"needle": needle, "reason": "no hits matched this needle"})
                continue
            for h in hits:
                hit_key = (str(h.get("family") or ""), str(h.get("file") or ""), str(h.get("line") or ""))
                if hit_key not in seen_hit_keys:
                    seen_hit_keys.add(hit_key)
                    all_hits.append(h)
            record["stage"] = "bookmarking"
            record["bookmarks_added"] += int(add_bookmarks(case_dir, hits).get("added") or 0)

            # One DRAFT per needle (candidate signal, not a verdict).
            # len(hits) is a lower bound: the 500-row page may not hold every
            # needle-matched row, and intake terms inflate result["count"].
            record["stage"] = "staging draft"
            families = sorted({str(h.get("family") or "?") for h in hits})
            more = "+" if scan_capped else ""
            title = f"Signal: {needle} — {len(hits)}{more} hit(s) across {', '.join(families)}"
            needle_key = needle.lower()
            approved_ids = approved_by_needle.get(needle_key) or []
            if needle_key in existing:
                if approved_ids and not reprocess:
                    record["skipped"].append({
                        "needle": needle,
                        "reason": (
                            f"approved finding(s) exist ({', '.join(approved_ids)}) — "
                            "signed examiner decisions are never overwritten; "
                            "use reprocess to stage a fresh revision"
                        ),
                    })
                    continue
                if not approved_ids and not reprocess:
                    record["skipped"].append(
                        {"needle": needle, "reason": "draft already staged/approved"})
                    continue
                # reprocess — fall through: stage fresh, then supersede drafts
            draft = promote_hits_to_draft(
                case_dir,
                hits=hits,
                title=title,
                examiner=examiner,
                interpretation_hint=(
                    f"Needle '{needle}' ({s.get('source', 'playbook')}) matched "
                    f"{len(hits)} row(s) — candidate signal pending examiner review."
                ),
            )
            # FD-001 provenance: linked tool-lane audits when they exist,
            # otherwise the audited scan that produced these rows.
            scan_aid = scan_aid_by_needle.get(needle_key)
            if scan_aid:
                existing_aids = [str(a) for a in (draft.get("audit_ids") or [])]
                if scan_aid not in existing_aids:
                    draft["audit_ids"] = [*existing_aids, scan_aid]
                    arts = [a for a in (draft.get("artifacts") or [])
                            if isinstance(a, dict)]
                    if not any(a.get("audit_id") == scan_aid for a in arts):
                        arts.append({"audit_id": scan_aid, "type": "scan"})
                    draft["artifacts"] = arts
            draft = _heuristic_scribe(draft, hits, case_dir=case_dir)
            # WP 10.53 Option B: full-run default stays heuristic; ``signal``
            # upgrades only drafts clearing the hit threshold, ``llm`` upgrades
            # every draft. Any model failure falls back to the heuristic fill.
            if scribe_mode != "heuristic" and (
                scribe_mode == "llm" or len(hits) >= scribe_min_hits
            ):
                if not scribe_state["resolved"]:
                    try:
                        from nexus.langgraph.llm_pipeline import get_model

                        scribe_state["model"] = get_model()
                    except Exception:  # noqa: BLE001 — heuristic fallback stands
                        scribe_state["model"] = None
                    scribe_state["resolved"] = True
                if scribe_state["model"] is not None:
                    with contextlib.suppress(Exception):
                        draft = scribe_finding(
                            draft, hits, model=scribe_state["model"],
                            case_dir=case_dir,
                        )
            if approved_ids:
                draft["related_findings"] = approved_ids
            res = save_draft_finding(case_dir, draft)
            if res.get("status") == "STAGED":
                d: dict = {
                    "finding_id": res.get("finding_id"),
                    "title": title,
                    "hits": len(hits),
                    "families": families,
                }
                if res.get("confidence_adjusted"):
                    d["confidence_adjusted"] = res["confidence_adjusted"]
                record["drafts"].append(d)
                if approved_ids:
                    record["revised_approved"].append({
                        "needle": needle,
                        "finding_id": res.get("finding_id"),
                        "prior_approved_ids": approved_ids,
                    })
                # Reprocess: the fresh draft landed — retire the old DRAFTs.
                # Rejected (not deleted) keeps the audit trail; the reason names
                # the replacement so the chain is self-documenting.
                old_drafts = drafts_by_needle.pop(needle_key, [])
                if reprocess and old_drafts:
                    sup = _supersede_drafts(
                        case_dir, old_drafts,
                        run_id=str(record.get("run_id") or ""),
                        replaced_by=str(res.get("finding_id") or ""),
                    )
                    record["superseded"].extend(
                        {"needle": needle, "finding_id": fid,
                         "replaced_by": res.get("finding_id")}
                        for fid in sup
                    )
                existing.add(needle_key)
            else:
                detail = res.get("errors") or [str(res.get("error") or "stage failed")]
                record["skipped"].append(
                    {"needle": needle, "reason": "; ".join(str(d) for d in detail)})

        # N7: every matched row is timeline-worthy BEFORE approval — the
        # examiner needs the chronology to review the drafts against.
        record["stage"] = "building timeline"
        _persist()
        try:
            from nexus.langgraph.timeline_merge import rebuild_case_timeline

            record["timeline_events"] = len(rebuild_case_timeline(case_dir, hits=all_hits))
        except Exception as exc:  # noqa: BLE001 — drafts are already staged; report, don't fail
            record["timeline_error"] = str(exc)

        record["needles_done"] = len(scan)
        record["current"] = ""
        record["stage"] = "awaiting examiner approval"
        record["drafts_staged"] = len(record["drafts"])
        record["completed_at"] = time.time()
        record["next"] = (
            "Review DRAFT findings in Approve (manual HMAC), then generate the report (N8)."
        )
        # Publish the terminal status LAST: pollers fire as soon as status is
        # terminal, so every derived field must already be populated.
        record["status"] = "complete"
        _persist()
    except Exception as exc:  # noqa: BLE001 — record must always reach terminal state
        logger.exception("Mode 1 full-run failed for %s", case_dir.name)
        record["status"] = "error"
        record["stage"] = "failed"
        record["error"] = str(exc)
        record["completed_at"] = time.time()
        _persist()
    finally:
        with _mode1_run_lock:
            # A re-run may already have replaced this entry — only the thread
            # that OWNS the mapping may remove it (popping unconditionally
            # marked the fresh live run as interrupted).
            key = _case_key(case_dir)
            if _mode1_run_threads.get(key) is threading.current_thread():
                _mode1_run_threads.pop(key, None)
        _invalidate_briefing(_case_key(case_dir))  # run changed drafts/bookmarks


async def api_mode1_full_run(request):
    """POST /portal/api/mode1/full-run — start a tracked Mode 1 'full run' (WP 4j.5d).

    Runs in a background thread with a persisted record at
    analysis/mode1_full_run.json so the cockpit can reconnect after
    navigation/reload. One run per case at a time — a second POST while a
    run is live returns 409 with the existing record.

    Body: {max_needles?: 40, needle_filter?: "a,b" (subset),
           reprocess?: bool — supersede existing DRAFTs for hit needles and
           re-stage them fresh. APPROVED findings are never overwritten or
           rejected (signed examiner decisions); reprocess stages a fresh
           DRAFT revision alongside them for examiner comparison}.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed

    body: dict = {}
    with contextlib.suppress(Exception):
        body = await request.json()

    try:
        max_needles = max(1, min(int(body.get("max_needles") or 40), 120))
    except (TypeError, ValueError):
        return JSONResponse({"error": "max_needles must be an integer"}, status_code=400)
    reprocess = bool(body.get("reprocess"))
    only = {n.strip().lower() for n in str(body.get("needle_filter") or "").split(",") if n.strip()}

    # Concurrency guard — one live run per case. The record file survives
    # navigation/reload; "interrupted" records (thread dead) don't block.
    key = _case_key(case_dir)
    with _mode1_run_lock:
        live_thread = _mode1_run_threads.get(key)
        live = (key in _mode1_run_starting
                or bool(live_thread and live_thread.is_alive()))
    if live:
        # A terminal persisted record means the worker finished the run and is
        # only unwinding its thread — not a live run. Closes the completion
        # race where is_alive() is still true for a few ms after "complete".
        done = _mode1_run_record(case_dir)
        if isinstance(done, dict) and done.get("status") in ("complete", "error", "interrupted"):
            live = False
    if not live:
        with _mode1_run_lock:
            _mode1_run_starting.add(key)
    if live:
        existing_run = _mode1_run_record(case_dir)
        payload = dict(existing_run) if isinstance(existing_run, dict) else {"status": "running"}
        payload["error"] = "Mode 1 full run already in progress"
        return JSONResponse(payload, status_code=409)
    try:
        existing_run = _mode1_run_record(case_dir)
        if existing_run and existing_run.get("status") == "running":
            return JSONResponse(
                {**existing_run, "error": "Mode 1 full run already in progress"},
                status_code=409,
            )

        # The needle scan runs inside the worker — this POST returns instantly so
        # the click always produces immediate feedback. The worker fills in
        # needles_total / needles_scanned once the briefing lands.
        record: dict = {
            "run_id": f"M1-{int(time.time())}",
            "case_id": case_dir.name,
            "mode": "mode1_full_run",
            "status": "running",
            "stage": "starting",
            "current": "",
            "started_at": time.time(),
            "updated_at": time.time(),
            "needles_done": 0,
            "needles_total": 0,
            "needles_scanned": 0,
            "needles_hit_total": 0,
            "needles_capped": 0,
            "scan_truncated": False,
            "reprocess": reprocess,
            "bookmarks_added": 0,
            "drafts": [],
            "skipped": [],
            "superseded": [],
            "revised_approved": [],
        }
        record_path = _mode1_run_path(case_dir)
        record_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(record_path, record)

        worker = threading.Thread(
            target=_mode1_full_run_worker,
            args=(case_dir, record_path, record, max_needles, only, reprocess),
            name=f"mode1-full-run-{case_dir.name}",
            daemon=True,
        )
        with _mode1_run_lock:
            _mode1_run_threads[_case_key(case_dir)] = worker
            worker.start()
            _mode1_run_starting.discard(_case_key(case_dir))
        return JSONResponse(record, status_code=202)
    finally:
        with _mode1_run_lock:
            _mode1_run_starting.discard(_case_key(case_dir))


async def api_mode1_full_run_status(request):
    """GET /portal/api/mode1/full-run/status — latest run record for the case."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    rec = _mode1_run_record(case_dir)
    if rec is None:
        return JSONResponse({"status": "never_run"})
    return JSONResponse(rec)


async def api_workbench_remove(request):
    """POST /portal/api/workbench/remove — {bookmark_id}."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    body = await request.json()
    from nexus.case.workbench import remove_bookmark

    return JSONResponse(remove_bookmark(case_dir, str(body.get("bookmark_id") or "")))


async def api_workbench_clear(request):
    """POST /portal/api/workbench/clear."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    from nexus.case.workbench import clear_bookmarks

    return JSONResponse(clear_bookmarks(case_dir))


async def api_workbench_promote(request):
    """POST /portal/api/workbench/promote - bookmarked hits -> DRAFT finding.

    Body: {bookmark_ids: ["B-001", ...], title, scribe?, interpretation?,
           confidence?, confidence_justification?}
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    body = await request.json()
    title = str(body.get("title") or "").strip()
    wanted = [str(b) for b in (body.get("bookmark_ids") or []) if str(b).strip()]
    confidence = str(body.get("confidence") or "").strip().upper()
    if confidence and confidence not in {"LOW", "MEDIUM", "HIGH", "SPECULATIVE"}:
        return JSONResponse(
            {"error": "confidence must be one of LOW|MEDIUM|HIGH|SPECULATIVE"},
            status_code=400)
    confidence_justification = str(body.get("confidence_justification") or "").strip()
    if not title:
        return JSONResponse({"error": "Missing title"}, status_code=400)
    if not wanted:
        return JSONResponse({"error": "No bookmarks selected"}, status_code=400)

    from nexus.case.workbench import load_bookmarks
    from nexus.langgraph.llm_pipeline import get_model
    from nexus.langgraph.mode1 import promote_hits_to_draft, save_draft_finding, scribe_finding

    bookmarks = load_bookmarks(case_dir)
    by_id = {str(b.get("id")): b for b in bookmarks}
    selected = []
    for bid in wanted:
        if hit := by_id.get(bid):
            selected.append(hit)
    if not selected:
        return JSONResponse({"error": "Bookmark IDs not found"}, status_code=400)

    # Bookmarks store only raw text — re-attach parsed fields so the draft
    # evidence rows render 'RuleTitle: X · Details: Y' instead of CSV lines.
    from nexus.langgraph.query_pack import attach_hit_fields

    selected = attach_hit_fields(case_dir, selected)

    from nexus.audit import resolve_examiner

    examiner = resolve_examiner()
    draft = promote_hits_to_draft(
        case_dir,
        hits=selected,
        title=title,
        examiner=examiner,
        interpretation_hint=str(body.get("interpretation") or ""),
    )
    if body.get("scribe", True):
        try:
            model = get_model()
        except Exception:
            model = None
        draft = scribe_finding(draft, hits=selected, model=model, case_dir=case_dir)
    else:
        # WP 4j.5d: scribe=false is the fast path — deterministic heuristic
        # fill, no LLM. Never leave the draft empty: a skipped scribe used
        # to produce a bare skeleton with no observation.
        from nexus.langgraph.mode1 import _heuristic_scribe

        draft = _heuristic_scribe(draft, selected, case_dir=case_dir)

    if confidence:
        draft["confidence"] = confidence
    if confidence_justification:
        draft["confidence_justification"] = confidence_justification

    result = save_draft_finding(case_dir, draft)
    if result.get("status") == "STAGED":
        resp: dict = {
            "finding_id": result.get("finding_id"),
            "status": "DRAFT",
            "title": title,
            "bookmark_count": len(selected),
        }
        if result.get("confidence_adjusted"):
            resp["confidence_adjusted"] = result["confidence_adjusted"]
        # Promoted evidence belongs on the timeline the moment it becomes a
        # DRAFT — approval changes state, not existence.
        with contextlib.suppress(Exception):
            from nexus.langgraph.timeline_merge import rebuild_case_timeline

            resp["timeline_events"] = len(rebuild_case_timeline(case_dir))
        return JSONResponse(resp)
    detail: list = list(result.get("errors") or [])
    if result.get("error"):
        detail.append(str(result["error"]))
    if result.get("missing_audit_ids"):
        detail.append("missing audit_ids: " + ", ".join(str(a) for a in result["missing_audit_ids"][:5]))
    if not detail:
        detail = [str(result.get("status", "failed"))]
    return JSONResponse({"error": detail})


async def workbench_page(request):
    """Mode 1 workbench — bookmarked hits -> DRAFT builder."""
    case_dir = _get_case_dir(request)
    from nexus.case.workbench import load_bookmarks

    bookmarks = load_bookmarks(case_dir) if case_dir else []
    rows = ""
    for b in bookmarks:
        rows += (
            "<tr>"
            f"<td><input type='checkbox' class='bm-check' value='{_e(b.get('id', ''))}'></td>"
            f"<td>{_e(b.get('id', ''))}</td>"
            f"<td>{_e(b.get('family', ''))}</td>"
            f"<td>{_e(b.get('file', ''))}:{_e(b.get('line', ''))}</td>"
            f"<td class='evidence-path'>{_e(b.get('text', ''))}</td>"
            "</tr>"
        )
    if not rows:
        rows = "<tr><td colspan='5' style='text-align:center;color:#8b949e'>No bookmarks. Select hits in Explore and click 'Add to Workbench'.</td></tr>"

    content = f"""
<h1>Finding Workbench</h1>
<p>Bookmarked hits collected during exploration. Select bookmarks, give the finding a title, promote to DRAFT.</p>
<p style="font-size:0.85rem;color:#8b949e">{len(bookmarks)} bookmark(s) in the workbench.</p>
<p>
  <input id="wb_title" style="width:45%;background:#161b22;color:#c9d1d9" placeholder="Finding title">
  <label style="margin-left:0.5rem"><input type="checkbox" id="wb_scribe" checked> Scribe</label>
  <button class="action-btn" onclick="promoteBookmarks()">Promote to DRAFT</button>
  <button class="action-btn danger" onclick="clearWb()">Clear all</button>
  <span id="wb_status" style="margin-left:1rem"></span>
</p>
<table>
<tr><th></th><th>ID</th><th>Family</th><th>File:line</th><th>Row</th></tr>
{rows or '<tr><td colspan="5" style="text-align:center;color:#8b949e">Workbench empty — bookmark hits from Explore.</td></tr>'}
</table>
<script>
async function promoteBookmarks() {{
  const ids = Array.from(document.querySelectorAll('.bm-check:checked')).map(cb => cb.value);
  if (!ids.length) return alert('Select bookmarks first');
  const title = document.getElementById('wb_title').value.trim();
  if (!title) return alert('Enter a finding title');
  const scribe = document.getElementById('wb_scribe').checked;
  document.getElementById('wb_status').textContent = 'Promoting...';
  const r = await fetch('/portal/api/workbench/promote', {{
    method: 'POST', headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{ bookmark_ids: ids, title, scribe }})
  }});
  const result = await r.json();
  if (result.finding_id) {{
    document.getElementById('wb_status').textContent = 'DRAFT: ' + result.finding_id;
    setTimeout(() => window.location = '/portal/findings?status=DRAFT', 1000);
  }} else {{
    document.getElementById('wb_status').textContent = 'Error: ' + (result.error || 'failed');
  }}
}}
async function clearWb() {{
  if (!confirm('Clear ALL bookmarks?')) return;
  await fetch('/portal/api/workbench/clear', {{method:'POST'}});
  location.reload();
}}
</script>
"""
    return HTMLResponse(_TEMPLATE.format(content=content))


async def api_workbook(request):
    """GET /portal/api/workbench — list bookmarks."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    from nexus.case.workbench import load_bookmarks

    bookmarks = load_bookmarks(case_dir)
    return JSONResponse({"bookmarks": bookmarks, "total": len(bookmarks)})


async def api_chat_get(request):
    """GET /portal/api/chat — steer-chat transcript for the active case."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    from nexus.case.chat import load_chat

    messages = load_chat(case_dir)
    return JSONResponse({"messages": messages, "total": len(messages)})


async def api_chat_post(request):
    """POST /portal/api/chat — examiner message -> Mode 1 ask flow -> logged reply."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    body = await request.json()
    message = str(body.get("message") or "").strip()
    if not message:
        return JSONResponse({"error": "Empty message"}, status_code=400)

    from nexus.case.chat import append_chat
    from nexus.langgraph.llm_pipeline import get_model
    from nexus.langgraph.mode1 import nl_to_needles
    from nexus.langgraph.query_pack import load_case_intake, n4_query, parse_intake_window

    append_chat(case_dir, "examiner", "ask", message)

    try:
        model = get_model()
    except Exception:
        model = None

    parsed = nl_to_needles(message, model=model)
    needles = parsed.get("needles", [])
    window_str = parsed.get("window", "")
    # WP 4j.11: prefer the structured query from the entry point
    dsl_query = str(parsed.get("dsl_query") or "").strip()
    query_text = dsl_query or " ".join(needles)

    if not needles and not dsl_query:
        reply = "No needles extracted. Refine the question (name an artifact, tool, or event ID)."
        append_chat(case_dir, "llm", "needles_empty", reply, {"source": parsed.get("source", "")})
        return JSONResponse({"reply": reply, "needles": [], "count": 0})

    window = parse_intake_window(load_case_intake(case_dir))
    result = n4_query(case_dir, query_text, window=window, limit=80)
    if result.get("error"):
        append_chat(case_dir, "llm", "error", result["error"])
        return JSONResponse({"reply": f"Query error: {result['error']}"}, status_code=400)

    query_note = f"Query: {query_text} | " if dsl_query else ""
    reply = (
        f"{query_note}Needles: {', '.join(needles)} | hits: {result.get('count', 0)}"
        + (f" | {result.get('query')}" if result.get("query") else "")
    )
    append_chat(case_dir, "llm", "query_run", reply, {
        "needles": ",".join(needles),
        "query": query_text,
        "dsl": bool(dsl_query),
        "hits": result.get("count", 0),
        "backend": result.get("backend", ""),
        "window": window_str,
    })
    return JSONResponse({
        "reply": reply,
        "needles": needles,
        "window": window_str,
        "hits": result.get("hits", []),
        "count": result.get("count", 0),
        "backend": result.get("backend", ""),
    })


async def api_chat_clear(request):
    """POST /portal/api/chat/clear — wipe the transcript."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    from nexus.case.chat import clear_chat

    return JSONResponse(clear_chat(case_dir))


_CHAT_STREAM_MAX_HITS = 12


def _hits_for_transcript(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cap + trim hits persisted into the chat transcript (WP 4d.3)."""
    out = []
    for h in hits[:_CHAT_STREAM_MAX_HITS]:
        out.append({
            "family": str(h.get("family", ""))[:60],
            "file": str(h.get("file", ""))[:200],
            "line": str(h.get("line", ""))[:12],
            "terms": str(h.get("terms", ""))[:120],
            "text": str(h.get("text", ""))[:240],
            "fields": {str(k)[:60]: str(v)[:160] for k, v in list((h.get("fields") or {}).items())[:12]},
            "host": str(h.get("host", ""))[:60],
        })
    return out


def _slim_tool_calls(calls: list[dict[str, Any]], limit: int = 12) -> list[dict[str, Any]]:
    """Transcript-safe tool-call view: never persist full schemas/row sets."""
    out: list[dict[str, Any]] = []
    for call in (calls or [])[:limit]:
        if not isinstance(call, dict):
            continue
        summary = call.get("summary") if isinstance(call.get("summary"), dict) else {}
        keep = {
            key: summary.get(key)
            for key in ("total", "returned", "matched", "sampled", "error",
                        "available", "bucket_count", "counts", "family_count",
                        "parsed_columns_count")
            if summary.get(key) is not None
        }
        out.append({
            "tool": str(call.get("tool") or "")[:60],
            "why": str(call.get("why") or "")[:200],
            "audit_id": str(call.get("audit_id") or "")[:80],
            "elapsed_ms": call.get("elapsed_ms"),
            "summary": keep,
        })
    return out


def _mode2_turn_budget() -> float:
    # Must stay strictly above the loop's own soft budget (default 360 s) +
    # one model call; 900 s is the documented production default.
    try:
        value = float(os.environ.get("NEXUS_MODE2_TURN_TIMEOUT", "900"))
    except ValueError:
        return 900.0
    if not math.isfinite(value):
        return 900.0
    return max(1.0, min(value, 1800.0))


# One Mode 2 turn per case at a time — a retry must never overlap an orphaned
# (timed-out but still running) turn. Released by the worker, not the handler.
_mode2_turn_active: set[str] = set()
_mode2_turn_lock = threading.Lock()


async def api_mode2_chat(request):
    """POST /portal/api/mode2/chat — the Mode 2 conversational evidence agent (WP 4j.13).

    Body: {message, history?: [{role, text}]}
    The agent: reads the evidence landscape → formulates N4 DSL queries →
    executes through the case-gated backbone → reads results → iterates
    (bounded) → returns a natural-language answer with the queries it ran.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    message = str(body.get("message") or "").strip()
    history = body.get("history") or []
    if not message:
        return JSONResponse({"error": "message is required"}, status_code=400)

    from nexus.case.chat import append_chat
    from nexus.langgraph.steer_agent import run_steer_agent

    case_key = case_dir.name
    with _mode2_turn_lock:
        if case_key in _mode2_turn_active:
            return JSONResponse(
                {
                    "error": "a steering turn is already running for this case",
                    "reply": (
                        "A steering turn is already running for this case — wait "
                        "for it to finish before asking again."
                    ),
                    "queries_executed": [], "total_hits": 0, "confidence": "low",
                    "timings_ms": {}, "stages": [],
                },
                status_code=409,
            )
        _mode2_turn_active.add(case_key)

    # Persist the examiner's message BEFORE the turn runs — a slow or failed
    # turn must never make the question vanish from the transcript.
    append_chat(case_dir, "examiner", "steer_question", message[:2000])

    # WP 4j.33: never block the event loop on the LLM turn — run the agent in
    # a worker thread with a hard turn budget (the LLM client itself carries
    # NEXUS_LLM_TIMEOUT; this is the backstop).
    import asyncio

    def _run_turn() -> dict:
        try:
            return run_steer_agent(case_dir, message, history=history)
        finally:
            # Released when the WORK finishes, so a retry cannot overlap an
            # orphaned (timed-out) turn still writing to the case.
            with _mode2_turn_lock:
                _mode2_turn_active.discard(case_key)

    turn_budget = _mode2_turn_budget()
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_run_turn),
            timeout=turn_budget,
        )
    except TimeoutError:
        result = {
            "error": f"turn exceeded {turn_budget:.0f}s",
            "reply": (
                f"Steering turn timed out after {turn_budget:.0f}s — the model "
                "or a data provider stalled. Try again or narrow the question."
            ),
            "queries_executed": [], "total_hits": 0, "confidence": "low",
            "timings_ms": {}, "stages": [],
        }
    except Exception:  # noqa: BLE001
        logger.exception("Mode 2 steering turn failed")
        result = {
            "error": "steering turn failed",
            "reply": (
                "The steering turn failed before an answer was produced. "
                "The examiner question remains in the transcript; retry or narrow it."
            ),
            "queries_executed": [], "total_hits": 0, "confidence": "low",
            "timings_ms": {}, "stages": [],
        }

    timings = result.get("timings_ms") or {}
    append_chat(case_dir, "llm", "steer_answer", result.get("reply", "")[:3000], {
        "total_hits": str(result.get("total_hits", 0)),
        "confidence": result.get("confidence", ""),
        "timings": " ".join(f"{k}={round(v / 1000, 1)}s" for k, v in timings.items()),
    }, {
        "queries": result.get("queries_executed", [])[:8],
        "aggregations": result.get("aggregations", [])[:5],
        # Cited rows + drill-down chips persist so the transcript stays
        # bookmarkable/explorable after reload (hits slimmed — Explore owns
        # the full rows).
        "hits": _slim_chat_hits(result.get("hits", [])[:10]),
        "followups": result.get("followups", []),
    })

    return JSONResponse(result)


async def api_chat_stream(request):
    """POST /portal/api/chat/stream — live steer-chat (WP 4d.3).

    Body: {message, mode: "mode1"|"mode2", max_iterations?}
    Returns text/event-stream with events:
      status   — {stage: "translating"|"querying", ...}
      iteration — Mode 2 loop step (needles, hits, rationale)
      hits     — {hits: [...]} top hits for the transcript
      done     — {reply, needles, count, backend}
      error    — {error}
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    message = str(body.get("message") or "").strip()
    mode = str(body.get("mode") or "mode1").strip()
    history = body.get("history") if isinstance(body.get("history"), list) else []
    if not message:
        return JSONResponse({"error": "Empty message"}, status_code=400)
    if mode not in ("mode1", "mode2"):
        return JSONResponse({"error": f"Unsupported stream mode: {mode}"}, status_code=400)
    # ``max_iterations`` is accepted for API compatibility; the new tool loop
    # is bounded by NEXUS_CONTEXT_LOOP_* instead.
    _ = body.get("max_iterations")

    import queue as _queue

    from nexus.case.chat import append_chat

    append_chat(case_dir, "examiner", "ask", message)
    q: _queue.Queue = _queue.Queue()

    def _worker_mode1() -> tuple[str, dict[str, Any]]:
        from nexus.langgraph.mode1 import nl_to_needles
        from nexus.langgraph.query_pack import (
            attach_hit_fields,
            load_case_intake,
            n4_query,
            parse_intake_window,
        )

        q.put(("status", {"stage": "translating", "detail": "translating question to needles"}))
        try:
            from nexus.langgraph.llm_pipeline import get_model
            model = get_model()
        except Exception:
            model = None
        # Phase 4g: the UI chat path gets the same grounded context as /mode1/ask.
        context = _mode1_ask_context(case_dir, message)
        parsed = nl_to_needles(message, model=model, context=context)
        needles = parsed.get("needles", [])
        # WP 4j.11: prefer the structured query from the entry point
        dsl_query = str(parsed.get("dsl_query") or "").strip()
        query_text = dsl_query or " ".join(needles)
        if not needles and not dsl_query:
            q.put(("done", {"reply": "No needles extracted. Refine the question (name an artifact, tool, or event ID).", "needles": [], "count": 0}))
            return "needles_empty", {}
        window = parse_intake_window(load_case_intake(case_dir))
        q.put(("status", {"stage": "querying", "needles": needles, "query": query_text}))
        result = n4_query(case_dir, query_text, window=window, limit=80)
        if result.get("error"):
            q.put(("error", {"error": result["error"]}))
            return "error", {}
        hits = attach_hit_fields(case_dir, result.get("hits", []))
        rationale = str(parsed.get("rationale") or "").strip()
        query_note = f"Query: {query_text} | " if dsl_query else ""
        reply = (
            f"{query_note}Needles: {', '.join(needles)} | hits: {result.get('count', 0)}"
            + (f" | {result.get('query')}" if result.get("query") else "")
            + (f" | why: {rationale}" if rationale else "")
        )
        q.put(("hits", {"hits": _hits_for_transcript(hits), "count": result.get("count", 0)}))
        return "query_run", {
            "reply": reply,
            "needles": needles,
            "count": result.get("count", 0),
            "backend": result.get("backend", ""),
            "hits": hits,
            "rationale": rationale,
            "techniques": context.get("techniques", []),
            "families": context.get("families", []),
        }

    def _finalize(action: str, final: dict[str, Any]) -> None:
        if action == "error":
            q.put(("error", final))
            q.put((None, None))
            return
        hits = final.get("hits", [])
        reply = final.get("reply", "")
        if action == "steer_answer":
            # WP 10.53: keep the tool chain + partial state in the transcript,
            # so a budget stop is visible and revisitable after reload.
            timings = final.get("timings_ms") or {}
            append_chat(case_dir, "llm", "steer_answer", reply[:3000], {
                "total_hits": str(final.get("total_hits", 0)),
                "confidence": str(final.get("confidence", "")),
                "partial": str(bool(final.get("partial"))),
                "timings": " ".join(
                    f"{k}={round(float(v) / 1000, 1)}s"
                    for k, v in timings.items()
                    if isinstance(v, (int, float))
                ),
            }, {
                "queries": final.get("queries_executed", [])[:8],
                "tool_calls": _slim_tool_calls(final.get("tool_calls") or []),
                "aggregations": final.get("aggregations", [])[:5],
                "hits": _hits_for_transcript(hits[:10]),
                "followups": final.get("followups", []),
                "partial": bool(final.get("partial")),
            })
            q.put(("done", {
                "reply": reply,
                "queries_executed": final.get("queries_executed", []),
                "tool_calls": _slim_tool_calls(final.get("tool_calls") or []),
                "total_hits": final.get("total_hits", 0),
                "partial": bool(final.get("partial")),
                "partial_reason": str(final.get("partial_reason") or ""),
                "timings_ms": final.get("timings_ms", {}),
                "hits": _hits_for_transcript(hits),
                "followups": final.get("followups", []),
            }))
            q.put((None, None))
            return
        if action == "mode2_done":
            reply = f"Iterative run complete: {final.get('total_hits', 0)} total hits across {len(final.get('needles_run', []))} needle(s)."
            from nexus.case.chat import append_chat as _ac
            _ac(case_dir, "llm", "mode2_done",
                f"Run complete: {final.get('total_hits', 0)} total hits",
                {"needles": ",".join(final.get("needles_run", [])[:12])})
        append_chat(case_dir, "llm", action, reply, {
            "needles": ",".join(final.get("needles", [])[:12]),
            "hits": str(final.get("count", len(hits))),
            "rationale": str(final.get("rationale") or "")[:400],
            "techniques": ",".join(final.get("techniques", [])[:8]),
        }, data={"hits": _hits_for_transcript(hits)})
        q.put(("done", {
            "reply": reply,
            "needles": final.get("needles", []),
            "count": final.get("count", 0) or len(hits),
            "backend": final.get("backend", ""),
            "hits": _hits_for_transcript(hits),
            "rationale": final.get("rationale", ""),
            "techniques": final.get("techniques", []),
            "families": final.get("families", []),
        }))
        q.put((None, None))

    async def _run():
        try:
            if mode == "mode1":
                action, final = await asyncio.to_thread(_worker_mode1)
                if action != "error":
                    final["backend"] = final.get("backend", "")
                _finalize(action, final)
            else:
                # WP 10.53/10.54: the model-driven bounded tool loop. The
                # same one-turn-per-case guard as /mode2/chat applies here;
                # tool events stream through the queue and the final result
                # is still a normal chat answer (partial on budget).
                case_key = case_dir.name
                with _mode2_turn_lock:
                    if case_key in _mode2_turn_active:
                        q.put(("error", {
                            "error": "a steering turn is already running "
                                     "for this case",
                        }))
                        q.put((None, None))
                        return
                    _mode2_turn_active.add(case_key)

                def _mode2_worker():
                    try:
                        from nexus.langgraph.steer_agent import run_steer_agent

                        return run_steer_agent(
                            case_dir, message, history=history,
                            on_event=lambda event: q.put(
                                (str(event.get("event") or "context"), event)),
                        )
                    finally:
                        with _mode2_turn_lock:
                            _mode2_turn_active.discard(case_key)

                try:
                    result = await asyncio.wait_for(
                        asyncio.to_thread(_mode2_worker),
                        timeout=_mode2_turn_budget(),
                    )
                except TimeoutError:
                    q.put(("error", {
                        "error": f"turn exceeded {_mode2_turn_budget():.0f}s",
                    }))
                    q.put((None, None))
                    return
                if result.get("error"):
                    q.put(("error", {"error": result["error"]}))
                    q.put((None, None))
                else:
                    hits = result.get("hits", [])
                    q.put(("hits", {"hits": _hits_for_transcript(hits[:_CHAT_STREAM_MAX_HITS])}))
                    _finalize("steer_answer", result)
        except Exception as exc:
            q.put(("error", {"error": str(exc)}))
            q.put((None, None))

    async def _stream():
        task = asyncio.create_task(_run())
        while True:
            try:
                kind, payload = await asyncio.to_thread(q.get, timeout=30)
            except _queue.Empty:
                yield "event: ping\ndata: {}\n\n"
                continue
            if kind is None:
                break
            yield f"event: {kind}\ndata: {json.dumps(payload, default=str)}\n\n"
        with contextlib.suppress(Exception):
            await task

    return StreamingResponse(_stream(), media_type="text/event-stream")


async def api_timeline_lanes(request):
    """POST /portal/api/timeline/lanes — per-family time buckets for lanes.

    Body: {query?: "<DSL>", needles?, family?, start?, end?, bucket?: hour|day}
    Returns {families: [{family, buckets: {ts: count}}], total}
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    body = await request.json()
    from nexus.langgraph.query_pack import _DATE_RE, n4_query

    query_text = str(body.get("query") or "")
    hits: list[dict] = []
    count = 0
    defaulted = 0
    if query_text.strip():
        result = n4_query(case_dir, query_text, limit=400)
        if result.get("error"):
            return JSONResponse({"error": result["error"]}, status_code=400)
        hits = list(result.get("hits") or [])
        count = int(result.get("count") or 0)
    else:
        # Empty query = "everything the investigation flagged" — full-run
        # needles, else the case's scan vocabulary. Term lists go straight
        # to n4_hits — the DSL's 24-term OR cap is for examiner queries,
        # not internal vocabulary. Without this a portal case with empty
        # intake renders a blank timeline.
        from nexus.langgraph.query_pack import _parse_needles

        user_vocab = _parse_needles(str(body.get("needles") or ""))
        vocab = user_vocab or _case_default_needles(case_dir)
        if vocab:
            from nexus.langgraph.query_pack import (
                load_case_intake,
                n4_hits,
                parse_intake_window,
            )

            window = parse_intake_window(load_case_intake(case_dir))
            all_hits, _be = n4_hits(case_dir, vocab, window)
            count = len(all_hits)
            hits = all_hits[:400]
            defaulted = 0 if user_vocab else len(vocab)
    from nexus.langgraph.mode1 import _SEV_ORDER, _severity_from_hits
    from nexus.langgraph.query_pack import attach_hit_fields

    hits = attach_hit_fields(case_dir, hits)
    bucket = "day" if str(body.get("bucket") or "hour") == "day" else "hour"

    families: dict[str, dict[str, int]] = {}
    sev_lanes: dict[str, dict[str, str]] = {}
    for h in hits:
        fam = h.get("family") or "other"
        m = _DATE_RE.search(h.get("text", ""))
        if not m:
            key = "(no timestamp)"
        elif bucket == "day":
            key = m.group(1)
        else:
            key = f"{m.group(1)}T{(m.group(2) or '00:00:00')[:2]}:00"
        lanes = families.setdefault(fam, {})
        lanes[key] = lanes.get(key, 0) + 1
        # Bucket severity = highest detection level seen in the bucket —
        # examiner reads "worst thing in this hour" at a glance.
        sev = _severity_from_hits([h])
        sb = sev_lanes.setdefault(fam, {})
        prev = sb.get(key, "informational")
        if sev in _SEV_ORDER and _SEV_ORDER.index(sev) < _SEV_ORDER.index(prev):
            sb[key] = sev

    ordered = [
        {
            "family": fam,
            "buckets": dict(sorted(lanes.items())),
            "buckets_sev": sev_lanes.get(fam, {}),
        }
        for fam, lanes in sorted(families.items(), key=lambda kv: -sum(kv[1].values()))
    ]
    return JSONResponse({
        "families": ordered,
        "total": count,
        "bucket": bucket,
        "default_needles": defaulted,
    })


async def api_timeline_rebuild(request):
    """POST /portal/api/timeline/rebuild — regenerate timeline.json (N7).

    Merges N4 hits (intake terms, or the persisted full-run needle list for
    portal cases), finding evidence rows, ingest artifacts, and existing
    ledger events (T-*) — which are never dropped. Bookmarks are the
    examiner's curated subset of those hits, so this is what "approving
    bookmarks" is expected to surface.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    from nexus.langgraph.timeline_merge import rebuild_case_timeline

    events = rebuild_case_timeline(case_dir)
    return JSONResponse({"events": len(events), "status": "rebuilt"})


async def api_entities(request):
    """POST /portal/api/entities — extract entities from current N4 hits.

    Body: {query?: "<DSL>", needles?: "a,b,c"} — needles merge into the DSL
    like /explore/search. An empty request scans all in-window hits
    (match-all) so the pivot page populates on arrival.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    body = await request.json()
    from nexus.analysis.entities import extract_entities
    from nexus.langgraph.query_pack import _parse_needles, n4_query

    query_text = str(body.get("query") or "").strip()
    needles = _parse_needles(str(body.get("needles") or ""))
    if needles and query_text:
        query_text = query_text + " " + " ".join(needles)
    elif needles:
        query_text = " OR ".join(needles)

    result = n4_query(case_dir, query_text, limit=400, match_all=True)
    if result.get("error"):
        return JSONResponse({"error": result["error"]}, status_code=400)
    texts = [h.get("text", "") for h in result.get("hits", [])]
    return JSONResponse({"entities": extract_entities(texts), "total": result.get("count", 0)})


# Mode 2 suggested questions — LLM-generated (validated, grounded in the case)
# with a deterministic fallback so the panel always populates. Cached per case
# so the chat never pays for it twice and a slow model can't block the UI.
_MODE2_SUGGEST_TTL = 120.0
_mode2_suggest_cache: dict[str, tuple[float, dict]] = {}
_mode2_suggest_lock = threading.Lock()


def _mode2_chat_entries(case_dir: Path) -> list[dict]:
    """Read chat.jsonl (append-only transcript) — best-effort, never raises."""
    out: list[dict] = []
    try:
        lines = (Path(case_dir) / "chat.jsonl").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return out
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            out.append(entry)
    return out


def _mode2_suggest_context(case_dir: Path) -> dict[str, Any]:
    """Small, cheap case context for question suggestions (no needle scan)."""
    ctx: dict[str, Any] = {
        "families": [], "hosts": [], "users": [], "processes": [], "last_question": "",
    }
    try:
        from nexus.tools.evidence_index import do_index_mappings

        mappings = do_index_mappings(case_id=Path(case_dir).name)
        ctx["families"] = [str(f) for f in (mappings.get("families") or [])][:12]
    except Exception:  # noqa: BLE001 — suggestions are best-effort
        pass
    try:
        inv = json.loads(
            (Path(case_dir) / "analysis" / "entity_inventory.json").read_text(
                encoding="utf-8"
            )
        )
        for key in ("hosts", "users", "processes"):
            values = inv.get(key) or {}
            if isinstance(values, dict):
                ranked = sorted(values.items(), key=lambda kv: -int(kv[1] or 0))
                ctx[key] = [str(k) for k, _v in ranked[:5]]
    except Exception:  # noqa: BLE001
        pass
    for entry in reversed(_mode2_chat_entries(case_dir)):
        if entry.get("role") == "examiner" and entry.get("text"):
            ctx["last_question"] = str(entry["text"])[:200]
            break
    try:
        from nexus.knowledge.itm_needles import itm_packs_for

        ctx["itm_sections"] = [
            f"{p.get('itm')} {p.get('name')}".strip()
            for p in itm_packs_for(set(ctx.get("families") or []), limit=4)
        ]
    except Exception:  # noqa: BLE001 — suggestions are best-effort
        pass
    return ctx


def _mode2_deterministic_suggestions(ctx: dict[str, Any]) -> list[dict[str, str]]:
    """Question ideas from what the case actually holds (never guesswork)."""
    out: list[dict[str, str]] = []

    def add(text: str) -> None:
        text = text.strip()
        if text and all(text.lower() != s["text"].lower() for s in out):
            out.append({"text": text, "source": "case"})

    if ctx.get("hosts"):
        add(f"What else happened on host {ctx['hosts'][0]}?")
    if ctx.get("users"):
        add(f"What did user {ctx['users'][0]} do in this case?")
    if ctx.get("processes"):
        add(f"Trace {ctx['processes'][0]} across the case")
    if ctx.get("families"):
        add(f"What are the top detections in {ctx['families'][0]} evidence?")
    if ctx.get("itm_sections"):
        add(
            "Check insider preparation evidence: "
            f"{ctx['itm_sections'][0]} - any rows?"
        )
    add("List all hosts seen in this case")
    add("List all users seen in this case")
    add("Show the highest-severity detections")
    return out[:6]


def _validate_mode2_suggestions(
    raw: Any, ctx: dict[str, Any], last_q: str = ""
) -> list[dict[str, str]]:
    """Keep only grounded, sane questions (LLM output is untrusted input)."""
    out: list[dict[str, str]] = []
    tokens = {
        str(t).lower()
        for key in ("hosts", "users", "processes", "families")
        for t in (ctx.get(key) or [])
        if str(t).strip()
    }
    generic = re.compile(
        r"\b(list|show|which|what|who|count|trace|summari[sz]e|find|seen|involved|happened)\b",
        re.IGNORECASE,
    )
    for item in raw if isinstance(raw, list) else []:
        text = str(item.get("text") if isinstance(item, dict) else item or "").strip().strip("-•*")
        if not text or len(text) > 140:
            continue
        if last_q and text.lower() == last_q.lower():
            continue
        if any(text.lower() == s["text"].lower() for s in out):
            continue
        low = text.lower()
        if not (any(tok in low for tok in tokens) or generic.search(text)):
            continue
        out.append({"text": text, "source": "llm"})
        if len(out) >= 6:
            break
    return out


async def api_mode2_suggestions(request):
    """POST /portal/api/mode2/suggestions — examiner question ideas for the chat.

    The LLM proposes questions grounded in the case's families/entities; every
    suggestion is validated and the deterministic set fills any gap (or the
    whole panel when no model is configured). Cached per case for 120 s.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)

    key = case_dir.name
    now = time.time()
    with _mode2_suggest_lock:
        hit = _mode2_suggest_cache.get(key)
        if hit and (now - hit[0]) < _MODE2_SUGGEST_TTL:
            payload = dict(hit[1])
            payload["cached"] = True
            return JSONResponse(payload)

    ctx = await asyncio.to_thread(_mode2_suggest_context, case_dir)
    fallback = _mode2_deterministic_suggestions(ctx)
    suggestions: list[dict[str, str]] = []
    generated_by = "deterministic"
    try:
        from nexus.langgraph.llm_pipeline import get_model

        model = get_model()
        prompt = (
            "You help a DFIR examiner interrogate a case index.\n"
            f"Evidence families present: {', '.join(ctx['families']) or 'none'}.\n"
            f"Top hosts: {', '.join(ctx['hosts']) or 'none'}. "
            f"Top users: {', '.join(ctx['users']) or 'none'}. "
            f"Top processes: {', '.join(ctx['processes']) or 'none'}.\n"
            f"Insider Threat Matrix sections relevant to these families: "
            f"{', '.join(ctx.get('itm_sections') or ['none'])}\n"
            f"Last examiner question: {ctx['last_question'] or 'none'}\n\n"
            "Propose 4 to 6 SHORT investigation questions (max 120 chars each) that "
            "the examiner could ask this case next. Use only entities from the lists "
            "above; prefer pivots (drill into a host/user/process, list hosts or users, "
            "highest-severity detections, activity around a family, and an "
            "insider-preparation check when ITM sections are listed). "
            'Reply ONLY with JSON: {"questions": ["...", "..."]}'
        )

        def _ask() -> str:
            response = model.invoke([{"role": "user", "content": prompt}])
            return str(getattr(response, "content", response))

        raw_text = await asyncio.wait_for(asyncio.to_thread(_ask), timeout=45.0)
        match = re.search(r"\{.*\}", raw_text, re.DOTALL)
        parsed = json.loads(match.group(0)) if match else {}
        candidates = parsed.get("questions") if isinstance(parsed, dict) else parsed
        suggestions = _validate_mode2_suggestions(
            candidates, ctx, str(ctx["last_question"])
        )
        if len(suggestions) >= 3:
            generated_by = "llm"
            for extra in fallback:  # top up coverage without duplicates
                if len(suggestions) >= 6:
                    break
                if all(extra["text"].lower() != s["text"].lower() for s in suggestions):
                    suggestions.append(extra)
        else:
            suggestions = []
    except Exception:  # noqa: BLE001 — deterministic panel is the fallback
        suggestions = []

    if not suggestions:
        suggestions = fallback
    payload = {"suggestions": suggestions, "generated_by": generated_by, "cached": False}
    with _mode2_suggest_lock:
        _mode2_suggest_cache[key] = (now, payload)
    return JSONResponse(payload)


async def api_mode2_save_answer(request):
    """POST /portal/api/mode2/save-answer — bookmark a Mode 2 answer for the report.

    Body: {entry_ts, note?}. Bookmarks the answer's cited rows to the Workbench,
    appends an ``answer_saved`` transcript entry, and records the answer in
    ``analysis/mode2_saved_answers.json`` (the report's Saved-answers section).
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    entry_ts = str(body.get("entry_ts") or "").strip()
    if not entry_ts:
        return JSONResponse({"error": "entry_ts is required"}, status_code=400)

    entries = _mode2_chat_entries(case_dir)
    target = next(
        (e for e in entries if str(e.get("ts") or "") == entry_ts and e.get("role") == "llm"),
        None,
    )
    if target is None:
        return JSONResponse({"error": "chat entry not found"}, status_code=404)
    question = ""
    for entry in entries:
        if str(entry.get("ts") or "") == entry_ts:
            break
        if entry.get("role") == "examiner" and entry.get("text"):
            question = str(entry["text"])[:500]

    data = target.get("data") or {}
    hits = [h for h in (data.get("hits") or []) if isinstance(h, dict)][:20]
    note = str(body.get("note") or "").strip()[:200]
    added = skipped = total = 0
    if hits:
        from nexus.case.workbench import add_bookmarks

        bm = add_bookmarks(
            case_dir, hits,
            note=note or f"Mode 2 answer: {question[:120]}"[:300],
        )
        added = int(bm.get("added") or 0)
        skipped = int(bm.get("skipped") or 0)
        total = int(bm.get("total") or 0)

    from datetime import UTC, datetime

    saved_path = Path(case_dir) / "analysis" / "mode2_saved_answers.json"
    existing: list[dict] = []
    try:
        loaded = json.loads(saved_path.read_text(encoding="utf-8"))
        if isinstance(loaded, list):
            existing = [e for e in loaded if isinstance(e, dict)]
    except (OSError, ValueError):
        existing = []
    if all(str(e.get("ts") or "") != entry_ts for e in existing):
        existing.append({
            "ts": entry_ts,
            "saved_at": datetime.now(UTC).isoformat(),
            "question": question,
            "reply": str(target.get("text") or "")[:2000],
            "queries": [q for q in (data.get("queries") or []) if isinstance(q, dict)][:8],
            "cited_rows": len(hits),
        })
        _atomic_write_json(saved_path, existing)

    from nexus.case.chat import append_chat

    append_chat(
        case_dir, "system", "answer_saved",
        f"Mode 2 answer saved for the report ({len(hits)} cited row(s) bookmarked)",
        {"entry_ts": entry_ts},
        {"entry_ts": entry_ts},
    )
    return JSONResponse({
        "saved": True,
        "entry_ts": entry_ts,
        "bookmarked": added,
        "existed": skipped,
        "total": total,
        "saved_answers": len(existing),
    })


async def api_mode2_iterate(request):
    """POST /portal/api/mode2/iterate - Mode 2 iterative loop (logged).

    Body: {question, max_iterations? (default 2, hard cap 4), limit?}
    Every iteration is logged to chat.jsonl. Returns the iteration log;
    the examiner reviews proposals - nothing is auto-staged.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    body = await request.json()
    question = str(body.get("question") or "").strip()
    if not question:
        return JSONResponse({"error": "Missing question"}, status_code=400)
    try:
        max_iterations = max(1, min(int(body.get("max_iterations") or 2), 4))
    except (TypeError, ValueError):
        return JSONResponse({"error": "max_iterations must be an integer"}, status_code=400)
    try:
        limit = max(1, min(int(body.get("limit") or 80), 400))
    except (TypeError, ValueError):
        return JSONResponse({"error": "limit must be an integer"}, status_code=400)

    from nexus.case.chat import append_chat
    from nexus.langgraph.llm_pipeline import get_model
    from nexus.langgraph.mode2 import run_iterative_loop

    try:
        model = get_model()
    except Exception:
        model = None

    case_key = case_dir.name
    with _mode2_turn_lock:
        if case_key in _mode2_turn_active:
            return JSONResponse(
                {"error": "a Mode 2 turn is already running for this case"},
                status_code=409,
            )
        _mode2_turn_active.add(case_key)

    def _run_iterative() -> dict:
        try:
            return run_iterative_loop(
                case_dir, question,
                model=model, max_iterations=max_iterations, limit=limit,
            )
        finally:
            # Release when the WORK finishes — a timed-out handler must not
            # unlock while the orphaned thread is still running.
            with _mode2_turn_lock:
                _mode2_turn_active.discard(case_key)

    append_chat(case_dir, "examiner", "mode2_start", question, {"max_iterations": max_iterations})
    turn_budget = _mode2_turn_budget()
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_run_iterative),
            timeout=turn_budget,
        )
    except TimeoutError:
        message = f"iterative loop timed out after {turn_budget:.0f}s"
        append_chat(case_dir, "llm", "mode2_error", message)
        return JSONResponse({"error": message}, status_code=504)
    except Exception:  # noqa: BLE001
        logger.exception("Mode 2 iterative loop failed")
        message = "iterative loop failed"
        append_chat(case_dir, "llm", "mode2_error", message)
        return JSONResponse({"error": message}, status_code=500)
    if result.get("error"):
        append_chat(case_dir, "llm", "mode2_error", result["error"])
        return JSONResponse({"error": result["error"]}, status_code=400)
    # Per-iteration transcript entries are written by run_iterative_loop itself
    # (single writer) — only the summary is added here.
    append_chat(case_dir, "llm", "mode2_done", f"Iterative loop complete: {result.get('total_hits', 0)} total hits.", {
        "iterations": len(result.get("iterations", [])),
        "capped": result.get("capped", False),
    })
    return JSONResponse(result)


async def api_mode2_corroborate(request):
    """POST /portal/api/mode2/corroborate — FD-006/007 check on a finding.

    Body: {finding_id} or a full {finding} dict.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    body = await request.json()
    from nexus.langgraph.mode2 import corroboration_check

    finding = body.get("finding")
    if not finding and body.get("finding_id"):
        fid = str(body.get("finding_id"))
        findings_path = case_dir / "findings.json"
        if findings_path.is_file():
            try:
                all_f = json.loads(findings_path.read_text(encoding="utf-8"))
                finding = next((f for f in all_f if f.get("id") == fid), None)
            except (OSError, ValueError):
                finding = None
    if not finding:
        return JSONResponse({"error": "Finding not found"}, status_code=404)
    return JSONResponse(corroboration_check(finding))


async def api_mode2_propose_draft(request):
    """POST /portal/api/mode2/propose-draft - LLM drafts a finding from hits.

    Body: {title, hits: [...]} or {title, query} (hits from the query).
    The draft stages as DRAFT (examiner_selected=False); HMAC approval
    stays with the examiner.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    body = await request.json()
    title = str(body.get("title") or "").strip()
    if not title:
        return JSONResponse({"error": "Missing title"}, status_code=400)

    from nexus.case.chat import append_chat
    from nexus.langgraph.llm_pipeline import get_model
    from nexus.langgraph.mode2 import propose_draft_finding
    from nexus.langgraph.query_pack import n4_query

    # WP 4j.33: sync ES query + LLM scribe must not block the event loop.
    def _draft() -> dict:
        hits = body.get("hits")
        if not hits and body.get("query") is not None:
            hits = n4_query(case_dir, str(body.get("query")), limit=12).get("hits", [])
        if not hits:
            return {"error": "No hits to draft from", "http": 400}
        try:
            model = get_model()
        except Exception:
            model = None
        outcome = propose_draft_finding(case_dir, hits, title, model=model)
        if outcome.get("error"):
            return {"error": outcome["error"], "http": 400}
        draft = outcome["draft"]
        from nexus.langgraph.mode1 import save_draft_finding

        saved = save_draft_finding(case_dir, draft)
        if saved.get("status") == "STAGED":
            append_chat(case_dir, "llm", "mode2_draft", f"Proposed DRAFT '{title}' from {len(hits)} hits (examiner approval required)", {
                "finding_id": saved.get("finding_id", ""),
                "confidence": draft.get("confidence", ""),
            })
            resp: dict = {
                "finding_id": saved.get("finding_id"),
                "status": "DRAFT",
                "corroboration": outcome.get("corroboration", {}),
            }
            if saved.get("confidence_adjusted"):
                resp["confidence_adjusted"] = saved["confidence_adjusted"]
            return resp
        detail: list = list(saved.get("errors") or [])
        if saved.get("error"):
            detail.append(str(saved["error"]))
        if not detail:
            detail = [str(saved.get("status", "failed"))]
        return {"error": detail, "http": 400}

    result = await asyncio.to_thread(_draft)
    if result.get("error"):
        return JSONResponse({"error": result["error"]}, status_code=int(result.get("http") or 400))
    return JSONResponse(result)


async def api_rag_status(request):
    """GET /portal/api/rag/status — RAG preflight: embedder + Chroma + test query.

    WP 3.13: Exposes RAG readiness to the UI and API clients. Mode 3
    orchestrator and any RAG-dependent workflow should check this before
    starting. Returns {ready, embedding_model, document_count, ...}.
    """
    from nexus.tools.rag_preflight import rag_preflight

    try:
        result = rag_preflight()
        return JSONResponse(result)
    except Exception as exc:
        return JSONResponse(
            {"ready": False, "error": str(exc), "errors": [str(exc)]},
            status_code=500,
        )


async def api_mode3_plan(request):
    """POST /portal/api/mode3/plan - agent proposes the investigation plan.

    Reads the tool-lane ledger (SKIPs), unrequested extras, and FD-006
    corroboration needs. Logged to agent_runs.jsonl + chat. The examiner
    approves items before anything executes.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    from nexus.langgraph.llm_pipeline import get_model
    from nexus.langgraph.mode3 import plan_extras

    try:
        model = get_model()
    except Exception:
        model = None
    plan = plan_extras(case_dir, model=model)
    return JSONResponse(plan)


async def api_mode3_execute(request):
    """POST /portal/api/mode3/execute - run examiner-approved plan items.

    Body: {extras: ["usb_serial", ...], queries: ["...", ...]}
    Extras persist to intake (next lane run parses them; mandatory lane
    first). Queries run immediately (read-only N4).
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    extras = body.get("extras") or []
    queries = body.get("queries") or []
    if not isinstance(extras, list) or not isinstance(queries, list):
        return JSONResponse({"error": "extras and queries must be lists"}, status_code=400)

    from nexus.langgraph.llm_pipeline import get_model
    from nexus.langgraph.mode3 import execute_plan

    try:
        model = get_model()
    except Exception:
        model = None

    result = execute_plan(
        case_dir,
        [str(e) for e in extras],
        [str(q) for q in queries],
        model=model,
    )
    if result.get("error"):
        return JSONResponse(result, status_code=400)
    return JSONResponse(result)


async def api_mode3_draft_finding(request):
    """POST /portal/api/mode3/draft-finding - agent proposes a DRAFT finding (WP 3.7).

    Body: {hits, title, interpretation_hint?}
    Stages a DRAFT finding with examiner_selected=False. The examiner
    reviews and approves via the normal HMAC flow. The agent NEVER approves.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    hits = body.get("hits") or []
    title = body.get("title") or "Agent-proposed finding"
    hint = body.get("interpretation_hint") or ""

    from nexus.langgraph.llm_pipeline import get_model
    from nexus.langgraph.mode3 import propose_agent_finding

    try:
        model = get_model()
    except Exception:
        model = None

    result = propose_agent_finding(case_dir, hits, title, model=model, interpretation_hint=hint)
    if result.get("error"):
        return JSONResponse(result, status_code=400)
    return JSONResponse(result)


async def api_case_seal(request):
    """POST /portal/api/case/seal — case-file HMAC via challenge-response.

    Body: {challenge_id, response, examiner?}
    Reuses the same challenge-response flow as per-finding approval —
    the password never travels in plaintext. This is the general case-close
    action for every mode (registered at /mode3/seal as a back-compat alias).
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    challenge_id = body.get("challenge_id")
    response_hmac = body.get("response")
    if not challenge_id or not response_hmac:
        return JSONResponse(
            {"error": "Missing challenge_id or response — get a challenge from /portal/api/commit/challenge"},
            status_code=400,
        )

    examiner = str(body.get("examiner") or "") or _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    # Validate the challenge (same flow as post_commit)
    import hashlib
    import hmac as hmac_mod
    import time as _time

    with _challenge_lock:
        challenge = _challenges.pop(challenge_id, None)
    if not challenge:
        return JSONResponse({"error": "Invalid or expired challenge"}, status_code=401)
    if _time.time() - challenge["created_at"] > _CHALLENGE_TTL:
        return JSONResponse({"error": "Challenge expired"}, status_code=401)
    if challenge["examiner"] != examiner:
        return JSONResponse({"error": "Challenge/examiner mismatch"}, status_code=401)

    entry = _load_password_entry(examiner)
    if not entry:
        return JSONResponse({"error": "No password configured"}, status_code=403)

    stored_hash_bytes = bytes.fromhex(entry.get("hash", ""))
    expected = hmac_mod.new(stored_hash_bytes, challenge["nonce"].encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac_mod.compare_digest(expected, response_hmac):
        return JSONResponse({"error": "Challenge response mismatch"}, status_code=401)

    # Challenge proved the examiner knows the password. Derive the
    # signing key from the stored hash (same as per-finding approval).
    from nexus.langgraph.mode3 import seal_case

    result = seal_case(case_dir, examiner, "", skip_verify=True)
    if result.get("error"):
        return JSONResponse(result, status_code=400)
    # Case-file seal → lifecycle SEALED (SQLite is the record).
    _transition_case_status(case_dir.name, "sealed")
    return JSONResponse(result)


async def health(request):
    """Lightweight health endpoint for load balancers and Docker healthchecks."""
    return JSONResponse({"status": "ok", "service": "dfir-nexus"})


async def api_mode3_orchestrator(request):
    """POST /portal/api/mode3/orchestrator — run real multi-agent orchestrator (WP 3.21).

    Body: {hits? (optional — agents run their own queries if not provided)}
    Dispatches EvidenceAgents that run real N4 queries on assigned families,
    extract entities, correlate across families, detect attack patterns, and
    build a narrative. Examiner reviews proposals — nothing is auto-staged.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    from nexus.langgraph.llm_pipeline import get_model
    from nexus.langgraph.orchestrator import run_orchestrator

    try:
        model = get_model()
    except Exception:
        model = None

    try:
        body = await request.json()
    except Exception:
        body = {}

    hits = body.get("hits") or None
    result = run_orchestrator(case_dir, model=model, hits=hits)
    return JSONResponse(result)


async def api_mode_mapping(request):
    """GET /portal/api/mode-mapping?product_mode=1 — map product mode to pipeline mode (WP 3.8).

    Query params: product_mode (1, 2, or 3)
    Returns: {pipeline_mode, pipeline_modes, description}
    """
    from urllib.parse import parse_qs

    qs = parse_qs(request.url.query)
    mode_str = qs.get("product_mode", [""])[0]
    try:
        mode = int(mode_str)
    except (TypeError, ValueError):
        return JSONResponse({"error": "product_mode must be 1, 2, or 3"}, status_code=400)

    from nexus.langgraph.mode_mapping import map_product_mode_to_pipeline

    result = map_product_mode_to_pipeline(mode)
    if "error" in result:
        return JSONResponse(result, status_code=400)
    return JSONResponse(result)


# --- Phase 4: React SPA serving ---
# The built React SPA lives in frontend/dist/. Starlette serves it at /portal/app/*
# and the index.html catch-all handles client-side routing. The root URL "/"
# serves a professional landing page that links into the cockpit.

_SPA_DIST = Path(__file__).resolve().parent.parent.parent.parent / "frontend" / "dist"
_SPA_INDEX = _SPA_DIST / "index.html"
_LANDING_HTML = Path(__file__).resolve().parent / "landing.html"


_LANDING_HTML = Path(__file__).resolve().parent / "landing.html"
_CASE_DASHBOARD_HTML = Path(__file__).resolve().parent / "case_dashboard.html"


async def landing_page(request) -> Response:
    """Serve the DFIR-Nexus landing page at /."""
    if _LANDING_HTML.is_file():
        return HTMLResponse(_LANDING_HTML.read_text(encoding="utf-8"))
    # Fallback if landing.html is missing — redirect to the cockpit
    return RedirectResponse(url="/portal/app", status_code=302)


async def case_dashboard_page(request) -> Response:
    """Legacy /dashboard — retired; the SPA Overview is the one case home."""
    return RedirectResponse(url="/portal/app/", status_code=302)


async def spa_index(request) -> HTMLResponse:
    """Serve the React SPA index.html for client-side routing."""
    if _SPA_INDEX.is_file():
        return HTMLResponse(_SPA_INDEX.read_text(encoding="utf-8"))
    # Fallback: SPA not built yet — show a helpful message
    return HTMLResponse(
        "<html><body style='background:#0d1117;color:#e6edf3;font-family:sans-serif;padding:40px'>"
        "<h2>DFIR-Nexus UI not built</h2>"
        "<p>Run <code>cd frontend && npm run build</code> to build the React UI.</p>"
        "</body></html>",
        status_code=503,
    )


async def spa_asset(request) -> Response:
    """Serve a static asset (JS/CSS/images) from the SPA dist directory."""
    path = request.path_params.get("path", "")
    # Defense-in-depth: block obvious traversal attempts
    if ".." in path or path.startswith("/"):
        return Response(status_code=404)
    # The route is /portal/app/assets/{path} — files live in dist/assets/{path}
    try:
        spa_root = _SPA_DIST.resolve()
        file_path = (_SPA_DIST / "assets" / path).resolve()
        if not str(file_path).startswith(str(spa_root)):
            return Response(status_code=404)
    except (ValueError, RuntimeError):
        return Response(status_code=404)
    if file_path.is_file():
        return FileResponse(file_path)
    return Response(status_code=404)


_LOGO_SVG = Path(__file__).resolve().parent.parent.parent.parent / "frontend" / "public" / "logo.svg"


# ── Phase 4b: Workflow-driven cockpit APIs ──────────────────────────────


async def api_case_create(request):
    """POST /portal/api/case/create — create a new investigation case.

    Body: {name, description?, examiner?, mode?, activate?}
    Creates the case via CaseManager. Does NOT switch the active-case pointer
    unless ``activate: true`` is explicitly passed — the case-setup wizard
    registers evidence/mode against the returned ``case_id`` and activates on
    "Enter Cockpit". CLI ``nexus case init`` / MCP ``case_init`` keep their
    create+activate behavior (they are separate paths).
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    name = str(body.get("name") or "").strip()
    if not name:
        return JSONResponse({"error": "name is required"}, status_code=400)

    description = str(body.get("description") or f"Case: {name}")
    examiner = str(body.get("examiner") or "system")
    mode = str(body.get("mode") or "").strip()

    from nexus.case import CaseManager
    from nexus.config import settings

    db_path = settings.cases_root / "cases.db"
    mgr = CaseManager(db_path)
    try:
        case = mgr.create_case(name=name, description=description, created_by=examiner)
    except ValueError as exc:
        mgr.close()
        return JSONResponse({"error": str(exc)}, status_code=400)
    mgr.close()

    # Activate only when explicitly requested (legacy/machine callers).
    activate = bool(body.get("activate") or False)
    if activate:
        import os

        active = Path(
            os.environ.get("NEXUS_ACTIVE_CASE_FILE", str(Path.home() / ".nexus" / "active_case"))
        )
        active.parent.mkdir(parents=True, exist_ok=True)
        active.write_text(case.id, encoding="utf-8")

    # Store mode in CASE.yaml if provided
    if mode in ("1", "2", "3"):
        try:
            case_dir = settings.cases_root / case.id
            case_yaml = case_dir / "CASE.yaml"
            if case_yaml.is_file():
                import yaml
                meta = yaml.safe_load(case_yaml.read_text(encoding="utf-8")) or {}
                if not isinstance(meta, dict):
                    meta = {}
                meta["investigation_mode"] = mode
                case_yaml.write_text(yaml.safe_dump(meta, sort_keys=False), encoding="utf-8")
        except Exception:
            pass

    return JSONResponse({
        "ok": True,
        "case_id": case.id,
        "name": case.name,
        "active": _active_case_id(),
    })


async def api_case_deactivate(request):
    """POST /portal/api/case/deactivate — clear the active-case pointer.

    "Exit to Dashboard": the case stays on disk untouched; the cockpit simply
    detaches so the dashboard can preview/enter cases without ambiguity.
    """
    import os

    active = Path(
        os.environ.get("NEXUS_ACTIVE_CASE_FILE", str(Path.home() / ".nexus" / "active_case"))
    )
    active.parent.mkdir(parents=True, exist_ok=True)
    active.write_text("", encoding="utf-8")
    return JSONResponse({"ok": True, "active": ""})


async def api_case_reopen(request):
    """POST /portal/api/case/reopen — reopen a sealed/closed case for more work.

    Sealing is the completion gate: sealed cases reject mutating actions
    (409) until the examiner explicitly reopens them. Reopen is
    audit-chained and returns the case to ACTIVE.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    case_dir = _resolve_case_dir_for(str(body.get("case_id") or ""), request)
    if not case_dir:
        return JSONResponse({"error": "No case specified"}, status_code=404)

    from nexus.case import CaseManager
    from nexus.case.schemas import CaseStatus
    from nexus.config import settings

    mgr = CaseManager(settings.cases_root / "cases.db")
    try:
        case = mgr.get_case(case_dir.name)
        if case is None:
            return JSONResponse({"error": "Case not found"}, status_code=404)
        if case.status not in (CaseStatus.SEALED, CaseStatus.CLOSED, CaseStatus.ARCHIVED):
            return JSONResponse(
                {"ok": True, "status": case.status.value, "note": "already open"}
            )
        reopened_from = case.status.value
        updated = mgr.update_status(case_dir.name, CaseStatus.ACTIVE, actor="portal")
        return JSONResponse({
            "ok": True,
            "status": updated.status.value if updated else CaseStatus.ACTIVE.value,
            "reopened_from": reopened_from,
        })
    finally:
        mgr.close()


async def api_case_details(request):
    """GET /portal/api/case/details[?case_id=ID] or /case/{id}/details.

    Returns case info from CASE.yaml, evidence count, findings count,
    the investigation mode, and the SQLite status (system of record).
    Without an explicit id it falls back to the active case.
    """
    import yaml

    from nexus.config import settings

    case_id = str(
        request.path_params.get("case_id")
        or request.query_params.get("case_id")
        or ""
    ).strip()
    if case_id:
        case_dir = _resolve_case_dir_for(case_id)
        if case_dir is None:
            return JSONResponse({"error": "Case not found"}, status_code=404)
    else:
        case_dir = _get_case_dir(request)
        if case_dir is None:
            return JSONResponse({"error": "No case specified"}, status_code=404)
        case_id = case_dir.name

    details: dict[str, Any] = {"case_id": case_id}
    case_yaml = case_dir / "CASE.yaml"
    if case_yaml.is_file():
        try:
            meta = yaml.safe_load(case_yaml.read_text(encoding="utf-8")) or {}
            if isinstance(meta, dict):
                details["name"] = meta.get("name", "")
                details["description"] = meta.get("description", "")
                details["status"] = meta.get("status", "")
                details["investigation_mode"] = str(meta.get("investigation_mode", ""))
        except Exception:
            pass

    # Status: SQLite is the system of record; CASE.yaml is only the mirror.
    try:
        from nexus.case import CaseManager

        mgr = CaseManager(settings.cases_root / "cases.db")
        try:
            case = mgr.get_case(case_id)
            if case is not None:
                details["status"] = case.status.value
                details["synthetic"] = bool((case.metadata or {}).get("synthetic"))
                if not details.get("name"):
                    details["name"] = case.name
        finally:
            mgr.close()
    except Exception:  # noqa: BLE001 — details must still render
        pass

    # Evidence count from the SQLite registry (system of record).
    details["evidence_count"] = len(_evidence_items(request, case_dir))

    # Findings count + approval split (WP 4d.5 stage states)
    findings_file = case_dir / "findings.json"
    details["findings_count"] = 0
    details["approved_count"] = 0
    if findings_file.is_file():
        try:
            f = json.loads(findings_file.read_text(encoding="utf-8"))
            if isinstance(f, list):
                details["findings_count"] = len(f)
                details["approved_count"] = len(
                    [x for x in f if str(x.get("status", "")).upper() == "APPROVED"]
                )
        except Exception:
            pass

    # N8/N2 presence — matches the real writer paths (runs/…/reports, reports/)
    details.update(_case_artifact_flags(case_dir))

    return JSONResponse(details)


async def api_pipeline_run(request):
    """POST /portal/api/pipeline/run — trigger the N2 processing lane.

    Body: {mode: "tools"|"interpret"|"coverage"|"design", case_id?,
           question?, window?, host?, notes?}
    Runs the pipeline asynchronously and returns a run_id.
    The pipeline runs in a background thread; status is polled via
    GET /portal/api/pipeline/status.

    Examiner intake (question / incident window) flows into the pipeline's
    ``case_context`` — without it the N1 gate degrades coverage/design to
    TOOL-RUN only and the LLM interpret node never runs. When the request
    carries no intake, the case's own description is used as the question.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    pipeline_mode = str(body.get("mode") or "tools").strip().lower()
    if pipeline_mode not in ("tools", "interpret", "coverage", "design"):
        return JSONResponse({"error": f"Invalid mode: {pipeline_mode}"}, status_code=400)

    case_id = str(body.get("case_id") or "").strip() or _active_case_id()
    if not case_id:
        return JSONResponse({"error": "No active case"}, status_code=404)
    from nexus.discipline import validate_case_id

    if validate_case_id(case_id):
        return JSONResponse({"error": "invalid case id"}, status_code=400)

    from nexus.config import settings
    case_dir = settings.cases_root / case_id
    if not case_dir.is_dir():
        return JSONResponse({"error": "Case not found"}, status_code=404)
    sealed = _sealed_case_error(case_id)
    if sealed:
        return sealed

    # Mode 2/3 hard-gate: the LLM works against the N3 Elasticsearch index, so
    # a case processed while ES is down would silently run on the CSV pack and
    # leave the index empty — hollow Mode 2. Refuse before any work starts.
    import yaml
    case_mode = ""
    case_yaml = case_dir / "CASE.yaml"
    if case_yaml.is_file():
        try:
            _meta = yaml.safe_load(case_yaml.read_text(encoding="utf-8")) or {}
            if isinstance(_meta, dict):
                case_mode = str(_meta.get("investigation_mode") or "")
        except Exception:
            case_mode = ""
    # Case-mode gate: the pipeline stage must belong to the case's chosen
    # investigation mode — a Mode 1 case must never run design/coverage.
    _allowed_by_case_mode = {
        "1": {"tools", "interpret"},
        "2": {"tools", "coverage", "interpret"},
        "3": {"tools", "design", "interpret"},
    }
    if case_mode and pipeline_mode not in _allowed_by_case_mode.get(case_mode, set()):
        return JSONResponse(
            {"error": (
                f"pipeline mode {pipeline_mode!r} does not belong to Mode {case_mode} "
                "— create a new case in that mode from the same evidence."
            )},
            status_code=409,
        )

    if case_mode in ("2", "3"):
        from nexus.langgraph.case_index import es_available

        if not (os.environ.get("NEXUS_ES_URL") or "").strip():
            return JSONResponse({
                "error": (
                    f"Mode {case_mode} requires Elasticsearch — set NEXUS_ES_URL so parsed "
                    "evidence lands in the N3 index the LLM queries, or run this case in Mode 1."
                )
            }, status_code=409)
        if not es_available():
            return JSONResponse({
                "error": (
                    f"Mode {case_mode} requires Elasticsearch — NEXUS_ES_URL is set but the "
                    "cluster is unreachable. Start ES and retry, or run this case in Mode 1."
                )
            }, status_code=409)

    # Resolve the case's registered evidence so the N2 lane has data to parse.
    # Without this the pipeline would run against an empty evidence list.
    evidence_paths: list[str] = []
    from nexus.case import CaseManager
    mgr = CaseManager(settings.cases_root / "cases.db")
    try:
        for rec in mgr.list_evidence(case_id):
            fp = (rec.file_path or "").strip()
            if fp and Path(fp).exists():
                evidence_paths.append(fp)
    finally:
        mgr.close()
    if not evidence_paths:
        return JSONResponse({
            "error": "No registered evidence for this case — register evidence first (wizard step 2)"
        }, status_code=400)

    # ── Examiner intake → pipeline case_context (N1 gate) ──
    # Coverage/design only reach the LLM interpret node when a real question
    # or incident window is present (llm_pipeline._route_after_tool_lane).
    case_context: dict[str, str] = {}
    for key in ("question", "window", "host", "notes", "hypothesis", "subjects"):
        value = str(body.get(key) or "").strip()
        if value:
            case_context[key] = value
    meta: dict = {}
    if case_yaml.is_file():
        try:
            loaded = yaml.safe_load(case_yaml.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                meta = loaded
        except Exception:
            meta = {}
    if "question" not in case_context:
        # Fall back to the case's own narrative so existing cases get the
        # LLM interpretation instead of a silent TOOL-RUN-only degrade.
        description = str(meta.get("description") or "").strip()
        if description:
            case_context["question"] = f"{description} — triage this case"
    if str(meta.get("name") or "").strip():
        case_context.setdefault("name", str(meta["name"]).strip())
    if str(meta.get("created_by") or "").strip():
        case_context.setdefault("examiner", str(meta["created_by"]).strip())

    # ── Mode 2 run options (operator decides BEFORE the run) ──
    # interpret_rounds: how many interpretation rounds the loop runs (1–5,
    # default 3). context_window: the model's max context window — the budget
    # allocator packs window × fill (NEXUS_CONTEXT_FILL_RATIO, default 0.7).
    try:
        rounds = int(body.get("interpret_rounds") or 0)
    except (TypeError, ValueError):
        rounds = 0
    if not rounds:
        try:
            rounds = int(os.environ.get("NEXUS_INTERPRET_ROUNDS") or 3)
        except ValueError:
            rounds = 3
    rounds = max(1, min(rounds, 5))
    try:
        window = int(body.get("context_window") or 0)
    except (TypeError, ValueError):
        window = 0
    from nexus.langgraph.prompt_budget import context_window as _ctx_window

    if not window:
        window = _ctx_window()
    window = max(8_000, window)
    case_context["interpret_rounds"] = str(rounds)
    case_context["context_window"] = str(window)
    run_options = {"interpret_rounds": rounds, "context_window": window}
    # NOTE: deliberately NOT written to os.environ — the allocator reads the
    # per-case options file (prompt_budget.case_window), so two cases with
    # different windows can never race over a process-wide value.
    with contextlib.suppress(OSError):
        (case_dir / "analysis").mkdir(parents=True, exist_ok=True)
        (case_dir / "analysis" / "mode2_run_options.json").write_text(
            json.dumps(run_options, indent=2), encoding="utf-8"
        )

    import threading
    import uuid

    run_id = str(uuid.uuid4())[:8]

    # Store run state (memory cache + write-through to the case dir)
    _pipeline_runs[run_id] = {
        "run_id": run_id,
        "case_id": case_id,
        "mode": pipeline_mode,
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "completed_at": "",
        "error": "",
        "stages": [],
        "intake": bool(case_context.get("question") or case_context.get("window")),
        "options": run_options,
    }
    _persist_pipeline_run(case_dir, _pipeline_runs[run_id])
    # Fresh stage feed for this run (a re-run must not replay old stages)
    with contextlib.suppress(OSError):
        _pipeline_run_status_path(case_dir, run_id).with_suffix(
            ".progress.jsonl"
        ).unlink(missing_ok=True)
    _transition_case_status(
        case_id,
        "processing",
        allowed_from={"created", "open", "intake", "active", "in_progress"},
    )

    def _run_in_thread():
        import asyncio

        record = _pipeline_runs[run_id]
        try:
            from nexus.langgraph.llm_pipeline import run_pipeline

            progress_path = _pipeline_run_status_path(case_dir, run_id).with_suffix(
                ".progress.jsonl"
            )
            asyncio.run(run_pipeline(
                evidence_path=evidence_paths[0],
                mode=pipeline_mode,
                case_id=case_id,
                evidence_paths=evidence_paths,
                case_context=case_context,
                progress_path=str(progress_path),
            ))
            record["status"] = "complete"
            record["completed_at"] = datetime.now(UTC).isoformat()
            _transition_case_status(case_id, "active", allowed_from={"processing"})
        except Exception as exc:
            record["status"] = "error"
            record["error"] = str(exc)
            record["completed_at"] = datetime.now(UTC).isoformat()
            _transition_case_status(case_id, "intake", allowed_from={"processing"})
        finally:
            _persist_pipeline_run(case_dir, record)
            _invalidate_briefing(_case_key(case_dir))

    thread = threading.Thread(target=_run_in_thread, daemon=True)
    thread.start()

    return JSONResponse({
        "run_id": run_id,
        "case_id": case_id,
        "mode": pipeline_mode,
        "status": "running",
        "options": run_options,
    })


_pipeline_runs: dict[str, dict[str, Any]] = {}


def _parse_iso_ts(value: object):
    """Parse an ISO timestamp to an aware datetime; None when unparseable."""
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _latest_pipeline_run_id(case_dir: Path | None) -> str:
    """Newest pipeline run for a case (prefers a still-running one).

    Used when the UI re-attaches after a reload: the run id lives in React
    state client-side, but the server still knows the active/last run.
    """
    if case_dir is None:
        return ""
    runs_dir = Path(case_dir) / "analysis" / "pipeline_runs"
    if not runs_dir.is_dir():
        return ""
    newest = ""
    newest_mtime = -1.0
    running = ""
    for path in runs_dir.glob("*.json"):
        if path.name.endswith(".progress.jsonl"):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        rid = str(data.get("run_id") or path.stem)
        if str(data.get("status") or "") == "running" and not running:
            running = rid
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if mtime > newest_mtime:
            newest_mtime = mtime
            newest = rid
    return running or newest


async def api_pipeline_status(request):
    """GET /portal/api/pipeline/status?run_id=ID — poll pipeline run status.

    Memory cache first; falls back to the write-through record under
    ``<case>/analysis/pipeline_runs/<run_id>.json`` so a reload or server
    restart keeps the examiner's run state. Without ``run_id`` the newest
    (or still-running) record for the case is used — that is how the UI
    re-attaches to an in-flight run after a page reload.
    """
    run_id = request.query_params.get("run_id") or ""
    case_dir = _get_case_dir(request)
    if not run_id:
        run_id = _latest_pipeline_run_id(case_dir)
    if not run_id:
        return JSONResponse({"error": "run_id not found"}, status_code=404)

    record = _pipeline_runs.get(run_id)

    if record is None:
        candidates: list[Path] = []
        if case_dir is not None:
            candidates.append(_pipeline_run_status_path(case_dir, run_id))
        else:
            from nexus.config import settings

            root = settings.cases_root
            if root.is_dir():
                for child in root.iterdir():
                    if not child.is_dir():
                        continue
                    candidate = _pipeline_run_status_path(child, run_id)
                    if candidate.is_file():
                        candidates.append(candidate)
        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                loaded = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(loaded, dict):
                record = loaded
                if case_dir is None:
                    case_dir = candidate.parent.parent.parent
                break

    if record is None:
        return JSONResponse({"error": "run_id not found"}, status_code=404)

    # Reconcile a stale "running" record against the pipeline's own manifest
    # (server restart mid-run: the thread is gone, the run dir is not).
    # Guard: only a manifest created at/after THIS record's start time may
    # speak for it — a previous run for the same mode must never mark a
    # live run complete (the "status lies complete" bug).
    if record.get("status") == "running" and case_dir is not None:
        try:
            from nexus.langgraph.pipeline_runs import resolve_run

            run = resolve_run(case_dir, str(record.get("mode") or "tools"))
            manifest = json.loads((run.path / "manifest.json").read_text(encoding="utf-8"))
            manifest_started = _parse_iso_ts(manifest.get("created_at"))
            record_started = _parse_iso_ts(record.get("started_at"))
            stale_manifest = bool(
                manifest_started and record_started and manifest_started < record_started
            )
            if not stale_manifest:
                manifest_status = str(manifest.get("status") or "")
                if manifest_status == "completed":
                    record["status"] = "complete"
                    record["completed_at"] = str(manifest.get("completed_at") or "")
                elif manifest_status == "failed":
                    record["status"] = "error"
                    record["error"] = str(manifest.get("error") or "pipeline failed")
                    record["completed_at"] = str(manifest.get("completed_at") or "")
        except Exception:  # noqa: BLE001 — reconciliation is best-effort
            pass

    # WP 4j.13: live pipeline stage feed — every graph node announces
    # running/done/error to analysis/pipeline_runs/<run_id>.progress.jsonl.
    if case_dir is not None:
        stage_path = case_dir / "analysis" / "pipeline_runs" / f"{run_id}.progress.jsonl"
        if stage_path.is_file():
            try:
                entries: list[dict[str, Any]] = []
                for line in stage_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(entry, dict):
                        entries.append(entry)
                seen = int(record.get("_stages_loaded") or 0)
                if len(entries) > seen:
                    record["stages"] = (record.get("stages") or []) + entries[seen:]
                    record["_stages_loaded"] = len(entries)
            except OSError:
                pass

    # WP 4j.5d: live per-tool progress — the tool lane writes
    # _tool_lane_progress.json after every job; surface it while running.
    # The file lives under runs/<run_id>/extractions/ (per-run dir), so
    # resolve it through resolve_run — the case-level paths are a legacy
    # fallback only.
    if record.get("status") == "running" and case_dir is not None:
        prog_paths: list[Path] = []
        with contextlib.suppress(Exception):
            from nexus.langgraph.pipeline_runs import resolve_run

            prog_paths.append(
                resolve_run(
                    case_dir, str(record.get("mode") or "tools"), run_id=run_id
                ).extractions / "_tool_lane_progress.json"
            )
        prog_paths += [
            case_dir / "extractions" / "_tool_lane_progress.json",
            case_dir / "ledger" / "_tool_lane_progress.json",
        ]
        # The record carries the SHORT run id ('51cf63cc') while run dirs are
        # 'RUN-…-<short>': resolve_run rejects the short form, so the tool feed
        # silently vanished. Match the run dir by suffix as the reliable path.
        runs_dir = case_dir / "runs"
        if runs_dir.is_dir() and run_id:
            with contextlib.suppress(OSError):
                for rdir in sorted(runs_dir.iterdir(), reverse=True):
                    if rdir.is_dir() and rdir.name.endswith(f"-{run_id}"):
                        prog_paths.insert(
                            0, rdir / "extractions" / "_tool_lane_progress.json"
                        )
                        break
        for prog_path in prog_paths:
            if not prog_path.is_file():
                continue
            try:
                prog = json.loads(prog_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(prog, dict):
                progress: dict[str, Any] = {
                    "done": prog.get("done", 0),
                    "total": prog.get("total", 0),
                    "current": prog.get("current", ""),
                }
                running = prog.get("running")
                if isinstance(running, dict) and running.get("tool"):
                    progress["running"] = {
                        "tool": str(running.get("tool") or ""),
                        "host": str(running.get("host") or ""),
                        "purpose": str(running.get("purpose") or "")[:200],
                        "command": str(running.get("command") or "")[:400],
                    }
                record["progress"] = progress
                tool_entries = list(prog.get("entries") or [])
                seen_tool = int(record.get("_tool_stages_loaded") or 0)
                if len(tool_entries) > seen_tool:
                    record["stages"] = (record.get("stages") or []) + tool_entries[seen_tool:]
                    record["_tool_stages_loaded"] = len(tool_entries)
            break

    return JSONResponse(record)


async def api_pipeline_ledger(request):
    """GET /portal/api/pipeline/ledger — tool-lane ledger for the active case.

    Returns the per-parser run status from the active tools run ledger so
    the UI can show exactly which parsers ran, were skipped, or failed.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    from nexus.langgraph.pipeline_runs import resolve_run, resolve_tools_extractions

    ledger: list[dict[str, Any]] = []
    run_id = ""
    evidence_paths: list[str] = []
    run_status = ""
    try:
        run = resolve_run(case_dir, "tools")
        run_id = run.run_id
        candidates = [
            run.extractions / "_tool_lane_ledger.json",
            run.path / "ledger" / "_tool_lane_ledger.json",
        ]
        for lp in candidates:
            if lp.is_file():
                try:
                    parsed = json.loads(lp.read_text(encoding="utf-8"))
                    if isinstance(parsed, list):
                        ledger = parsed
                    break
                except (json.JSONDecodeError, OSError):
                    continue
        try:
            manifest = json.loads((run.path / "manifest.json").read_text(encoding="utf-8"))
            evidence_paths = [str(p) for p in (manifest.get("evidence_paths") or [])]
            run_status = str(manifest.get("status") or "")
        except (OSError, json.JSONDecodeError):
            pass
    except ValueError:
        pass
    return JSONResponse({
        "run_id": run_id,
        "run_status": run_status,
        "evidence_paths": evidence_paths,
        "ledger": ledger,
        "total": len(ledger),
        "extractions": str(resolve_tools_extractions(case_dir)),
    })


async def api_case_briefing(request):
    """GET /portal/api/case/briefing — WP 4i.1 deterministic case briefing.

    What was processed (inventory + parser ledger), what the signatures
    already caught (alert surface), where the signal density is (playbook
    auto-scan needle→hit counts), top entities, hosts, time range, and the
    intake echo. One bounded extraction scan powers it; no LLM required.

    WP 4i.5: when an LLM is configured, an optional `directions` block adds
    plain-English investigation starting points grounded in the deterministic
    numbers. Directions moved to a lazy endpoint (``/case/briefing/directions``)
    so a slow local LLM never blocks the deterministic briefing.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)

    try:
        # EH-10: the first (cache-miss) build scans every extraction file —
        # never on the event loop, or a big case stalls every other request.
        return JSONResponse(await asyncio.to_thread(_cached_briefing, case_dir))
    except Exception as exc:  # noqa: BLE001
        logger.exception("briefing failed")
        return JSONResponse({"error": f"briefing failed: {exc}"}, status_code=500)


async def api_case_briefing_directions(request):
    """GET /portal/api/case/briefing/directions — optional LLM layer.

    Runs ``llm_directions`` on demand so the deterministic briefing returns
    immediately and the LLM block loads lazily. A slow/absent local model
    returns an empty list rather than holding the page hostage.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    from nexus.langgraph.briefing import llm_directions

    def _resolve_model():
        try:
            from nexus.langgraph.llm_pipeline import get_model

            return get_model()
        except Exception:  # noqa: BLE001
            return None

    try:
        # The briefing build AND the LLM call are blocking — never on the loop.
        model = await asyncio.to_thread(_resolve_model)
        if model is None:
            return JSONResponse({"directions": []})
        brief = await asyncio.to_thread(_cached_briefing, case_dir)
        directions = await asyncio.to_thread(llm_directions, case_dir, brief, model)
        if directions and not sealed:
            # Persist so REPORT.md can carry the same directions as next steps
            # without regenerating them (report generation may run offline).
            # Sealed cases are read-only: generate/return but never write.
            await asyncio.to_thread(
                _atomic_write_json,
                case_dir / "analysis" / "briefing_directions.json",
                {
                    "generated_at": datetime.now(UTC).isoformat(),
                    "source": "llm",
                    "directions": directions,
                },
            )
    except Exception as exc:  # noqa: BLE001
        logger.exception("briefing directions failed")
        return JSONResponse({"error": f"directions failed: {exc}"}, status_code=500)
    return JSONResponse({"directions": directions})


async def api_case_digest(request):
    """GET /portal/api/case/digest — deterministic Case Digest (Mode 2/3).

    Everything the interpretation loop consumes: scope (what IS and is NOT in
    evidence), inventory + ledger, signal map incl. 0-hit needles, alerts,
    entities with first/last seen, timeline shape, TI context. Built fresh if
    the persisted digest is missing.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    digest_path = case_dir / "analysis" / "case_digest.json"

    def _load_digest() -> dict:
        if digest_path.is_file():
            return json.loads(digest_path.read_text(encoding="utf-8"))
        from nexus.langgraph.case_digest import build_case_digest, write_case_digest

        brief = None
        with contextlib.suppress(Exception):
            brief = _cached_briefing(case_dir)  # 45 s cache — no full re-scan
        payload = build_case_digest(case_dir, brief=brief)
        write_case_digest(case_dir, payload)
        return payload

    try:
        # Building the digest can run a full extraction scan — never on the
        # event loop (a big Mode 2 case would stall every request).
        payload = await asyncio.to_thread(_load_digest)
        md_path = case_dir / "analysis" / "case_digest.md"
        return JSONResponse({
            "digest": payload,
            "markdown": md_path.read_text(encoding="utf-8", errors="replace")
            if md_path.is_file() else "",
        })
    except Exception as exc:  # noqa: BLE001
        logger.exception("case digest failed")
        return JSONResponse({"error": f"digest failed: {exc}"}, status_code=500)


async def api_case_export(request):
    """GET /portal/api/case/export — stream EVERY matching row (EH-12).

    Query params mirror the Explore search body (``query`` DSL, ``needles``,
    ``family``, ``host``, ``start``, ``end``) plus ``format=csv|jsonl``.
    Unlike /explore/search this endpoint has NO result caps — it streams the
    exhaustive enumeration (ES ``search_after`` / CSV row stream) so "export
    all" actually exports all. Evidence-complete by construction.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)

    from nexus.langgraph.query_pack import (
        collect_playbook_query_terms,
        collect_query_terms,
        iter_all_hits,
        load_case_intake,
    )

    params = {k: request.query_params.get(k, "") for k in
              ("query", "needles", "family", "host", "start", "end")}
    params["match_all"] = request.query_params.get("match_all", "")
    query_text, window, family_filter, _host_filter = _explore_query_from_body(
        case_dir, params
    )
    fmt = (request.query_params.get("format") or "csv").strip().lower()
    if fmt not in {"csv", "jsonl"}:
        return JSONResponse({"error": "format must be csv or jsonl"}, status_code=400)

    from nexus.langgraph.query_dsl import QuerySyntaxError, parse_query

    parsed = None
    if query_text:
        try:
            from nexus.langgraph.field_catalog import case_field_catalog

            _cat = case_field_catalog(case_dir)
        except Exception:  # noqa: BLE001 — catalog is best-effort
            _cat = None
        try:
            parsed = parse_query(query_text, catalog=_cat)
        except QuerySyntaxError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
    intake = load_case_intake(case_dir)
    do_match_all = bool(params["match_all"]) and (parsed is None or parsed.is_empty())
    dsl_terms = parsed.all_needles() if parsed else []
    terms = [] if do_match_all else list(
        dict.fromkeys(list(dsl_terms) + collect_query_terms(intake))
    )
    priority = list(dict.fromkeys(
        collect_playbook_query_terms(intake) + list(dsl_terms)
    ))
    query_arg = parsed if (parsed is not None and not parsed.is_empty()) else None
    want_families = {f.lower() for f in family_filter}

    def _stream():
        yielded = 0
        header = ["family", "file", "line", "terms", "host", "user", "event_id", "ts", "text"]
        if fmt == "csv":
            import csv
            import io

            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(header)
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)
            for hit in iter_all_hits(
                case_dir, terms, window, priority_terms=priority,
                query=query_arg, match_all=do_match_all,
            ):
                if want_families and str(hit.get("family") or "").lower() not in want_families:
                    continue
                writer.writerow([hit.get(k, "") for k in header])
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate(0)
                yielded += 1
        else:
            import json

            for hit in iter_all_hits(
                case_dir, terms, window, priority_terms=priority,
                query=query_arg, match_all=do_match_all,
            ):
                if want_families and str(hit.get("family") or "").lower() not in want_families:
                    continue
                yield json.dumps(hit, ensure_ascii=False) + "\n"
                yielded += 1
        logger.info("case export streamed %d rows", yielded)

    filename = f"{case_dir.name}-export.{'csv' if fmt == 'csv' else 'jsonl'}"
    return StreamingResponse(
        _stream(),
        media_type="text/csv" if fmt == "csv" else "application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


async def api_case_rounds(request):
    """GET /portal/api/case/rounds — GATE-B interpret round log.

    Returns the loop summary + every persisted round artifact
    (``analysis/interpret_rounds/*.json``) so the examiner can replay how the
    interpretation reached its conclusions.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    rounds_dir = case_dir / "analysis" / "interpret_rounds"
    if not rounds_dir.is_dir():
        return JSONResponse({"summary": None, "rounds": []})
    summary: dict | None = None
    rounds: list[dict] = []
    try:
        for path in sorted(rounds_dir.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if path.name == "summary.json":
                summary = payload
            else:
                rounds.append(payload)
    except OSError as exc:
        return JSONResponse({"error": f"rounds unavailable: {exc}"}, status_code=500)
    return JSONResponse({"summary": summary, "rounds": rounds})


async def api_hit_interpret(request):
    """POST /portal/api/hit/interpret — WP 4j.1 hit interpretation layer.

    Body: {hit: {family, file, line, terms, text, fields?, host?}, rag?: bool}.
    Returns what the row means + what to check next — matched skills
    (look_for / corroborate / negative / caveats / confidence_rules),
    playbook caveats for the family, and a RAG methodology chunk when
    ``rag`` is true (default) and the index is available.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "invalid JSON body"}, status_code=400)
    hit = body.get("hit")
    if not isinstance(hit, dict) or not str(hit.get("family") or hit.get("file") or "").strip():
        return JSONResponse({"error": "hit object required (family/file)"}, status_code=400)
    include_rag = bool(body.get("rag", True))
    from nexus.langgraph.interpret import interpret_hit

    return JSONResponse(interpret_hit(case_dir, hit, include_rag=include_rag))


async def api_fs_list(request):
    """GET /portal/api/fs/list?path=... — filesystem browsing for the
    evidence picker (WP: evidence path selection UI).

    No path → list drives (Windows) or root (POSIX). Read-only listing;
    never returns file contents.
    """
    import string as _string

    raw = (request.query_params.get("path") or "").strip().strip('"').strip()
    try:
        if not raw.strip():
            if os.name == "nt":
                drives = []
                for letter in _string.ascii_uppercase:
                    drive = f"{letter}:\\"
                    if Path(drive).exists():
                        drives.append(drive)
                entries = [
                    {"name": f"{d} Drive", "path": d, "is_dir": True, "size": None}
                    for d in drives
                ]
                return JSONResponse({"path": "", "parent": "", "drives": True, "entries": entries})
            return _list_dir(Path("/"))
        p = Path(raw)
        if not p.exists():
            return JSONResponse({"error": "path not found"}, status_code=404)
        if p.is_file():
            # Return file info so the picker can offer to add it directly
            return JSONResponse({
                "path": str(p.parent),
                "parent": str(p.parent.parent) if p.parent.parent != p.parent else "",
                "drives": False,
                "is_file": True,
                "file_entry": {"name": p.name, "path": str(p), "is_dir": False, "size": p.stat().st_size},
                "entries": [],
            })
        return _list_dir(p)
    except (OSError, ValueError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


def _list_dir(p: Path) -> Response:
    """List one directory for the evidence picker (read-only)."""
    try:
        entries_raw = list(p.iterdir())
    except OSError as exc:
        return JSONResponse({"error": f"cannot list: {exc}"}, status_code=400)
    dirs, files = [], []
    for entry in entries_raw:
        try:
            is_dir = entry.is_dir()
        except OSError:
            continue
        if is_dir:
            dirs.append(entry)
        else:
            files.append(entry)
    dirs.sort(key=lambda x: x.name.lower())
    files.sort(key=lambda x: x.name.lower())

    def _size(path: Path) -> int | None:
        try:
            return path.stat().st_size
        except OSError:
            return None

    out = [
        {"name": d.name, "path": str(d), "is_dir": True, "size": None}
        for d in dirs
    ] + [
        {"name": f.name, "path": str(f), "is_dir": False, "size": _size(f)}
        for f in files
    ]
    parent = str(p.parent) if p.parent != p else ""
    return JSONResponse({"path": str(p), "parent": parent, "drives": False, "entries": out})


def _gate_suggestion_vocabulary(suggestion: dict[str, Any]) -> None:
    """Split raw suggestion needles into scannable terms + typed hints (F6).

    The Explore suggestion list is the promotable needle surface: bare numbers
    (event IDs) and container file names must not be offered as needles. They
    ride along as ``event_ids`` / ``artifacts`` so nothing is lost.
    """
    from nexus.knowledge.needle_terms import split_terms

    event_ids: list[str] = []
    artifacts: list[str] = []
    for key, cap in (("needles", 20), ("strong_needles", 12)):
        scan, context = split_terms(suggestion.get(key) or [])
        suggestion[key] = scan[:cap]
        event_ids.extend(context["event_ids"])
        artifacts.extend(context["artifacts"])
    if event_ids:
        suggestion["event_ids"] = list(dict.fromkeys(event_ids))
    if artifacts:
        suggestion["artifacts"] = list(dict.fromkeys(artifacts))


async def api_playbook_needles(request):
    """GET /portal/api/playbook/needles?families=fam1,fam2 — suggested needles from playbooks.

    Returns playbook-suggested search needles for the given evidence families
    (or all playbooks if no families specified).
    """
    from nexus.knowledge.loader import get_playbook, list_playbook_slugs

    families_param = request.query_params.get("families") or ""
    families_filter = {f.strip().lower() for f in families_param.split(",") if f.strip()}

    slugs = list_playbook_slugs()
    suggestions: list[dict[str, Any]] = []

    for slug in slugs:
        pb = get_playbook(slug)
        if not isinstance(pb, dict):
            continue
        terms = pb.get("query_terms") or []
        if not isinstance(terms, list):
            continue

        # Filter by family if specified
        if families_filter:
            term_lower = {str(t).lower() for t in terms}
            pb_text = (
                str(pb.get("name", "")) + " " + str(pb.get("description", ""))
            ).lower()
            if not any(f in term_lower or f in pb_text for f in families_filter):
                continue

        suggestions.append({
            "playbook": pb.get("name", slug),
            "slug": slug,
            "needles": [str(t) for t in terms[:20]],
            "strong_needles": [str(t) for t in (pb.get("query_terms_strong") or [])[:12]],
            "caveats": [str(c)[:200] for c in (pb.get("caveats") or [])[:3]],
            "triggers": [str(t)[:200] for t in (pb.get("triggers") or [])[:3]],
            "source": "playbook",
        })

    # Phase 4g: MITRE ATT&CK packs for the case's evidence families (and the
    # techniques those families' playbooks declare). Same needle vocabulary the
    # grounded scribe uses, so Explore and the chat agree.
    attack_suggestions: list[dict[str, Any]] = []
    try:
        from nexus.knowledge.attack_needles import attack_packs_for
        from nexus.langgraph.query_pack import playbook_techniques_for_families

        techniques = (
            set(playbook_techniques_for_families(families_filter))
            if families_filter
            else set()
        )
        for pack in attack_packs_for(families_filter, techniques, limit=6):
            attack_suggestions.append({
                "playbook": f"{pack.get('technique', '')} {pack.get('name', '')}".strip(),
                "slug": f"mitre:{pack.get('technique', '')}",
                "needles": [str(n) for n in (pack.get("needles") or [])[:20]],
                "caveats": [str(c)[:200] for c in (pack.get("caveats") or [])[:2]],
                "triggers": [],
                "source": "mitre",
            })
    except Exception as exc:  # noqa: BLE001
        logger.debug("attack needle suggestions skipped: %s", exc)

    # Phase 4g-C: SigmaHQ-derived patterns for the families present.
    sigma_suggestions: list[dict[str, Any]] = []
    try:
        from nexus.knowledge.sigma_needles import sigma_packs_for

        for pack in sigma_packs_for(families_filter, limit=5):
            sigma_suggestions.append({
                "playbook": f"Sigma: {pack.get('name', '')}".strip(),
                "slug": f"sigma:{pack.get('id', '')}",
                "needles": [str(n) for n in (pack.get("needles") or [])[:20]],
                "strong_needles": [],
                "caveats": [str(c)[:200] for c in (pack.get("caveats") or [])[:2]],
                "triggers": [],
                "source": "sigma",
            })
    except Exception as exc:  # noqa: BLE001
        logger.debug("sigma needle suggestions skipped: %s", exc)

    # Phase 4g-F: examiner-promoted local overlay for the families present.
    overlay_suggestions: list[dict[str, Any]] = []
    try:
        from nexus.knowledge.needle_overlay import load_overlay

        overlay = load_overlay()
        for family in sorted(families_filter):
            terms = overlay.get(family) or []
            if terms:
                overlay_suggestions.append({
                    "playbook": f"Your promoted needles ({family})",
                    "slug": f"overlay:{family}",
                    "needles": [str(t) for t in terms[:20]],
                    "strong_needles": [str(t) for t in terms[:20]],
                    "caveats": ["Promoted by the examiner from case feedback."],
                    "triggers": [],
                    "source": "overlay",
                })
    except Exception as exc:  # noqa: BLE001
        logger.debug("overlay needle suggestions skipped: %s", exc)

    # Insider Threat Matrix packs (registry-validated hard artifacts) - the
    # insider counterpart of the ATT&CK packs above.
    itm_suggestions: list[dict[str, Any]] = []
    if families_filter:
        try:
            from nexus.knowledge.itm_needles import itm_packs_for

            for pack in itm_packs_for(families_filter, limit=6):
                itm_suggestions.append({
                    "playbook": f"ITM {pack.get('itm')} {pack.get('name')}".strip(),
                    "slug": f"itm:{pack.get('itm')}",
                    "needles": [str(t) for t in (pack.get("needles") or [])[:20]],
                    "strong_needles": [str(t) for t in (pack.get("strong") or [])[:12]],
                    "caveats": [str(pack.get("caveat") or "")[:200]],
                    "triggers": [],
                    "source": "itm",
                })
        except Exception as exc:  # noqa: BLE001
            logger.debug("itm needle suggestions skipped: %s", exc)

    # External-threat hard artifacts (ATT&CK-grounded packs).
    external_suggestions: list[dict[str, Any]] = []
    if families_filter:
        try:
            from nexus.knowledge.external_needles import external_packs_for

            for pack in external_packs_for(families_filter, limit=6):
                external_suggestions.append({
                    "playbook": f"ATT&CK {pack.get('attack')} {pack.get('name')}".strip(),
                    "slug": f"attack-ext:{pack.get('attack')}",
                    "needles": [str(t) for t in (pack.get("needles") or [])[:20]],
                    "strong_needles": [str(t) for t in (pack.get("strong") or [])[:12]],
                    "caveats": [str(pack.get("caveat") or "")[:200]],
                    "triggers": [],
                    "source": "external",
                })
        except Exception as exc:  # noqa: BLE001
            logger.debug("external needle suggestions skipped: %s", exc)

    combined = (
        overlay_suggestions + attack_suggestions + sigma_suggestions
        + itm_suggestions + external_suggestions + suggestions
    )
    # F6: no promotable suggestion may offer a bare number or container name.
    for suggestion in combined:
        _gate_suggestion_vocabulary(suggestion)
    return JSONResponse({
        "suggestions": combined,
        "total": len(combined),
        "families": sorted(families_filter),
    })


async def api_needle_feedback(request):
    """POST /portal/api/needles/feedback — examiner verdict on suggested needles.

    Body: {needle?: str, needles?: [str], family?, source?, verdict: "accept"|"reject"|"promote"}
    Records the verdict in ``<case>/needle_feedback.jsonl`` (when a case is
    resolved). ``promote`` additionally merges the terms into the examiner's
    LOCAL overlay (~/.nexus/knowledge/needles/overlay.yaml) — never the repo.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    verdict = str(body.get("verdict") or "").strip().lower()
    if verdict not in ("accept", "reject", "promote"):
        return JSONResponse({"error": "verdict must be accept|reject|promote"}, status_code=400)

    family = str(body.get("family") or "").strip().lower()
    source = str(body.get("source") or "").strip()
    raw_terms = body.get("needles")
    if not isinstance(raw_terms, list):
        single = str(body.get("needle") or "").strip()
        raw_terms = [single] if single else []
    terms = [str(t).strip() for t in raw_terms if str(t).strip()]
    if not terms:
        return JSONResponse({"error": "needle or needles is required"}, status_code=400)

    case_dir = _get_case_dir(request)
    if case_dir is not None:
        from nexus.audit import resolve_examiner

        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "examiner": resolve_examiner(),
            "verdict": verdict,
            "family": family,
            "source": source,
            "needles": terms,
        }
        try:
            with (case_dir / "needle_feedback.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            logger.warning("needle feedback write failed: %s", exc)

    promoted: dict[str, Any] = {}
    if verdict == "promote":
        from nexus.knowledge.needle_overlay import promote_needles

        promoted = promote_needles(family or "general", terms)

    return JSONResponse({"ok": True, "verdict": verdict, "terms": terms, "promoted": promoted})


async def api_case_mode(request):
    """POST /portal/api/case/mode — set the investigation mode for a case.

    Body: {mode: "1"|"2"|"3", case_id?}. Explicit case_id (or the SPA
    X-Nexus-Case header) wins over the active-case pointer, so the wizard can
    configure a case that is not active yet.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    mode = str(body.get("mode") or "").strip()
    if mode not in ("1", "2", "3"):
        return JSONResponse({"error": "mode must be 1, 2, or 3"}, status_code=400)

    case_dir = _resolve_case_dir_for(str(body.get("case_id") or ""), request)
    if not case_dir:
        return JSONResponse({"error": "No case specified"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed

    # Segregation: once the case has been PROCESSED (a run exists) or has
    # findings, its mode is FIXED. Evidence registration alone still allows
    # the wizard's register-then-choose-mode order. Changing the mode later
    # would flip the Briefing surface, the pipeline gate and the steering
    # semantics mid-investigation — new mode = new case (same evidence).
    has_work = False
    runs_dir = case_dir / "runs"
    if runs_dir.is_dir():
        has_work = any(runs_dir.iterdir())
    if not has_work:
        try:
            findings_file = case_dir / "findings.json"
            if findings_file.is_file():
                has_work = bool(json.loads(findings_file.read_text(encoding="utf-8")))
        except Exception:
            has_work = False
    if has_work:
        return JSONResponse(
            {"error": "The investigation mode is fixed once the case has been "
                      "processed — create a new case from the same evidence to "
                      "run another mode."},
            status_code=409,
        )

    import yaml
    case_yaml = case_dir / "CASE.yaml"
    try:
        meta = {}
        if case_yaml.is_file():
            meta = yaml.safe_load(case_yaml.read_text(encoding="utf-8")) or {}
            if not isinstance(meta, dict):
                meta = {}
        meta["investigation_mode"] = mode
        case_yaml.write_text(yaml.safe_dump(meta, sort_keys=False), encoding="utf-8")
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)

    return JSONResponse({"ok": True, "mode": mode})


async def api_get_case_mode(request):
    """GET /portal/api/case/mode — get the investigation mode for the active case."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)

    import yaml
    case_yaml = case_dir / "CASE.yaml"
    if not case_yaml.is_file():
        return JSONResponse({"mode": ""})

    try:
        meta = yaml.safe_load(case_yaml.read_text(encoding="utf-8")) or {}
        mode = str(meta.get("investigation_mode", "")) if isinstance(meta, dict) else ""
    except Exception:
        mode = ""

    return JSONResponse({"mode": mode})


async def api_system_health(request):
    """GET /portal/api/system/health — cheap backend/ES/RAG/LLM/parser status.

    Reports configured/reachable status without heavy preflight (no model
    loads). Deep verification stays in `nexus doctor` / `GET /rag/status`.
    """
    health: dict[str, Any] = {"backend": "ok"}

    # Elasticsearch (N3 backend) — same check as nexus doctor
    es_url = (os.environ.get("NEXUS_ES_URL") or "").strip()
    if not es_url:
        health["es"] = {"configured": False, "reachable": False, "note": "CSV pack backend"}
    else:
        try:
            import httpx
            r = httpx.get(es_url.rstrip("/") + "/", timeout=3)
            ok = r.status_code == 200 and "version" in r.json()
            health["es"] = {"configured": True, "reachable": ok, "url": es_url}
        except Exception:
            health["es"] = {"configured": True, "reachable": False, "url": es_url}

    # RAG index presence (cheap — no model load; deep check via /rag/status)
    rag_entry: dict[str, Any] = {"configured": False}
    try:
        from nexus.tools.rag import _get_index_dir
        chroma_dir = _get_index_dir() / "chroma"
        rag_entry = {"configured": chroma_dir.is_dir(), "path": str(_get_index_dir())}
    except Exception:
        pass
    health["rag"] = rag_entry

    # LLM configuration (not reachability — that needs a live call)
    llm_model = (os.environ.get("NEXUS_LLM_MODEL") or "").strip()
    llm_base = (os.environ.get("NEXUS_LLM_BASE_URL") or "").strip()
    health["llm"] = {"configured": bool(llm_model and llm_base), "model": llm_model}

    # Parser lane availability (tool-lane deps importable)
    try:
        from nexus.langgraph.tool_lane import run_tool_lane  # noqa: F401
        health["parser"] = "ok"
    except Exception as exc:
        health["parser"] = "missing"
        health["parser_error"] = str(exc)[:200]

    # Actionable detail for the preflight panel — where to fix each item.
    health["fixes"] = {
        "es": "POST /portal/api/setup/env {NEXUS_ES_URL} or `nexus config env NEXUS_ES_URL=...`",
        "rag": "POST /portal/api/setup/rag or `nexus data download-rag`",
        "llm": "POST /portal/api/setup/env {NEXUS_LLM_*} or `nexus config env ...`",
        "parser": "fix the import error shown in parser_error (usually a missing extra)",
    }
    if llm_base:
        health["llm"] = {**health["llm"], "base_url": llm_base}
    return JSONResponse(health)


_SETUP_TASKS: dict[str, dict[str, Any]] = {}


async def api_setup_status(request):
    """GET /portal/api/setup/status — in-flight/finished setup task states."""
    return JSONResponse({"tasks": _SETUP_TASKS})


async def api_setup_env(request):
    """POST /portal/api/setup/env — write allowlisted NEXUS_* keys to .env.

    Body: {"NEXUS_ES_URL": "http://...", "NEXUS_LLM_MODEL": "...", ...}
    Empty value removes the key. Applied to os.environ immediately — no
    restart needed. Secret values are masked in the response.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "Body must be a JSON object of key=value"}, status_code=400)
    from nexus.envfile import apply_env, env_file_path
    try:
        applied = apply_env(body)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse({"ok": True, "applied": applied, "env_file": str(env_file_path())})


async def api_setup_rag(request):
    """POST /portal/api/setup/rag — download the RAG index in the background.

    202 while running; 409 if a download is already in flight. Poll
    GET /portal/api/setup/status for progress, then re-GET system/health.
    """
    task = _SETUP_TASKS.get("rag")
    if task and task.get("status") == "running":
        return JSONResponse({"error": "RAG download already running", "task": task},
                            status_code=409)
    _SETUP_TASKS["rag"] = {"status": "running", "detail": "downloading…",
                           "started_at": datetime.now(UTC).isoformat()}

    def _run() -> None:
        try:
            from mcp.server.fastmcp import FastMCP

            from nexus.audit import AuditWriter
            from nexus.tools.rag import register_tools

            server = FastMCP("setup")
            register_tools(server, AuditWriter("setup"))
            fn = server._tool_manager._tools["forensic_rag_download"].fn
            result = fn(tag="latest")
            _SETUP_TASKS["rag"] = {
                "status": "done", "detail": str(result)[:300],
                "finished_at": datetime.now(UTC).isoformat(),
            }
        except Exception as exc:
            _SETUP_TASKS["rag"] = {
                "status": "error", "detail": str(exc)[:300],
                "finished_at": datetime.now(UTC).isoformat(),
            }

    import threading
    threading.Thread(target=_run, daemon=True, name="setup-rag").start()
    return JSONResponse({"status": "started", "task": _SETUP_TASKS["rag"]},
                        status_code=202)


async def api_case_seed_demo(request):
    """POST /portal/api/case/seed-demo — seed a populated demo investigation.

    Body: {name?, activate?}. By default the demo is created without switching
    the active case; the dashboard previews it and offers an explicit Enter.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    name = str(body.get("name") or "Demo Investigation").strip()
    activate = bool(body.get("activate") or False)
    from nexus.case.seed import seed_demo_case

    try:
        res = seed_demo_case(case_name=name, activate=activate)
        return JSONResponse({**res, "active": _active_case_id()})
    except Exception as exc:
        logger.exception("Demo seed failed: %s", exc)
        return JSONResponse({"error": str(exc)}, status_code=500)


async def api_findings_reject(request):
    """POST /portal/api/findings/reject — reject DRAFT findings with a reason.

    Intentionally does NOT require HMAC challenge-response: rejection is a
    non-cryptographic state transition (DRAFT → REJECTED), not an attestation.
    Approval (DRAFT → APPROVED) always requires HMAC via POST /portal/api/commit.
    Rejection is logged with examiner identity, timestamp, and reason in both
    findings.json and the SQLite store for audit traceability.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    raw_ids = body.get("finding_ids", [])
    if not isinstance(raw_ids, list):
        return JSONResponse({"error": "finding_ids must be a list"}, status_code=400)
    finding_ids = list(dict.fromkeys(
        s for s in (str(fid).strip() for fid in raw_ids) if s))
    reason = str(body.get("reason") or "").strip()
    if not finding_ids:
        return JSONResponse({"error": "finding_ids is required"}, status_code=400)
    if not reason:
        return JSONResponse({"error": "reason is required"}, status_code=400)

    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed

    examiner = str(body.get("examiner") or "").strip() or _resolve_examiner(request)

    findings_path = case_dir / "findings.json"
    findings: list[dict[str, Any]] = []
    if findings_path.is_file():
        try:
            data = json.loads(findings_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                findings = data
        except Exception:
            findings = []
    by_id = {}
    for f in findings:
        fid = f.get("id") or f.get("finding_id", "")
        if fid:
            by_id[fid] = f
    missing = [fid for fid in finding_ids if fid not in by_id]
    if missing:
        return JSONResponse(
            {"error": "finding_ids not found", "missing": missing},
            status_code=404)
    blocked = [
        {
            "finding_id": fid,
            "status": str(by_id[fid].get("status") or ""),
        }
        for fid in finding_ids
        if str(by_id[fid].get("status") or "").upper() != "DRAFT"
    ]
    try:
        from nexus.case import CaseManager
        from nexus.case.schemas import ApprovalState
        from nexus.config import settings
        mgr = CaseManager(settings.cases_root / "cases.db")
        try:
            for fid in finding_ids:
                if any(b["finding_id"] == fid for b in blocked):
                    continue
                f_obj = mgr.store.get_finding(fid, case_id=case_dir.name)
                if (f_obj is not None
                        and f_obj.approval_state != ApprovalState.DRAFT):
                    blocked.append({
                        "finding_id": fid,
                        "status": str(f_obj.approval_state).upper(),
                    })
        finally:
            mgr.close()
    except Exception as exc:
        logger.warning("Failed prevalidating SQLite states on reject: %s", exc)
    if blocked:
        return JSONResponse(
            {"error": "only DRAFT findings can be rejected", "blocked": blocked},
            status_code=409)

    rejected = []
    # Update findings.json
    try:
        for f in findings:
            fid = f.get("id") or f.get("finding_id", "")
            if fid in finding_ids:
                f["status"] = "REJECTED"
                f["rejected_by"] = examiner
                f["rejected_at"] = datetime.now(UTC).isoformat()
                f["rejection_reason"] = reason
                rejected.append(fid)
        _atomic_write_json(findings_path, findings)
    except Exception as exc:
        logger.warning("Failed updating findings.json on reject: %s", exc)
        return JSONResponse(
            {"error": f"could not update findings.json: {exc}"},
            status_code=500)

    # Best-effort sync to SQLite store
    try:
        from nexus.case import CaseManager
        from nexus.case.schemas import ApprovalState
        from nexus.config import settings
        mgr = CaseManager(settings.cases_root / "cases.db")
        for fid in rejected:
            f_obj = mgr.store.get_finding(fid, case_id=case_dir.name)
            if f_obj and f_obj.approval_state == ApprovalState.DRAFT:
                f_obj.approval_state = ApprovalState.REJECTED
                f_obj.rejected_by = examiner
                f_obj.rejected_at = datetime.now(UTC)
                f_obj.rejection_reason = reason
                mgr.store.save_finding(f_obj)
            elif f_obj:
                logger.warning(
                    "Skipping SQLite reject for %s: state %s is not DRAFT",
                    fid, f_obj.approval_state)
        mgr.close()
    except Exception as exc:
        logger.warning("Failed updating SQLite on reject: %s", exc)

    return JSONResponse({"ok": True, "rejected": rejected})


def _write_case_report(case_dir, *, llm: bool = True, steer: str = ""):
    """Shared report build — findings/timeline/meta loaded from the case
    dir, markdown written to reports/REPORT.md. Returns the response
    payload or raises."""
    from nexus.cli.report import _load_flat_evidence
    from nexus.integration.dfir_report import (
        _split_questions,
        build_dfir_markdown,
        load_case_ledger,
        sift_notes_from_ledger,
    )

    findings = []
    if (case_dir / "findings.json").is_file():
        try:
            findings = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
        except Exception:
            findings = []

    evidence = _load_flat_evidence(case_dir)
    timeline = []
    if (case_dir / "timeline.json").is_file():
        try:
            timeline = json.loads((case_dir / "timeline.json").read_text(encoding="utf-8"))
        except Exception:
            timeline = []

    import yaml
    meta = {}
    if (case_dir / "CASE.yaml").is_file():
        try:
            meta = yaml.safe_load((case_dir / "CASE.yaml").read_text(encoding="utf-8")) or {}
        except Exception:
            meta = {}

    raw_intake = meta.get("intake")
    intake: dict[str, Any] = raw_intake if isinstance(raw_intake, dict) else {}
    questions = _split_questions(str(intake.get("question") or meta.get("question") or ""))
    ledger = load_case_ledger(case_dir)

    report_text = build_dfir_markdown(
        case_id=case_dir.name,
        case_name=meta.get("name") or case_dir.name,
        findings=findings,
        evidence=evidence,
        timeline=timeline if isinstance(timeline, list) else [],
        sift_notes=sift_notes_from_ledger(ledger),
        examiner=meta.get("examiner") or meta.get("created_by") or "examiner",
        status=str(meta.get("status") or "open"),
        severity=str(meta.get("severity") or "unrated"),
        case_summary=str(meta.get("description") or ""),
        tool_ledger=ledger,
        questions=questions,
        case_dir=case_dir,
        llm=llm,
        steer=steer,
    )
    reports_dir = case_dir / "reports"
    reports_dir.mkdir(exist_ok=True)
    out_file = reports_dir / "REPORT.md"
    _atomic_write_text(out_file, report_text)
    approved_count = len([f for f in findings if str(f.get("status") or "").upper() == "APPROVED"])
    return {
        "ok": True,
        "report_path": str(out_file),
        "findings_count": approved_count,
    }


async def api_report_generate(request):
    """POST /portal/api/report/generate — trigger official case report generation."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed

    body: dict = {}
    with contextlib.suppress(Exception):
        body = await request.json() or {}

    try:
        # N8 analysis layer on by default; {"llm": false} forces the
        # deterministic render (fast regen, offline, tests).
        # B4: report analysis runs sequential LLM calls — never on the loop.
        return JSONResponse(await asyncio.to_thread(
            _write_case_report,
            case_dir,
            llm=bool(body.get("llm", True)),
            steer=_report_steer_context(_load_report_rounds(case_dir)),
        ))
    except Exception as exc:
        logger.exception("Report generation failed: %s", exc)
        return JSONResponse({"error": str(exc)}, status_code=500)


def _report_rounds_file(case_dir):
    return case_dir / "analysis" / "report_rounds.json"


def _load_report_rounds(case_dir) -> list[dict[str, Any]]:
    f = _report_rounds_file(case_dir)
    if not f.is_file():
        return []
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _report_steer_context(rounds: list[dict[str, Any]]) -> str:
    parts = []
    for row in rounds[-8:]:
        part = f"(r{row.get('round', '?')}) {str(row.get('instruction') or '').strip()}"
        if row.get('finding_id'):
            part += f" [focus: {row['finding_id']}]"
        parts.append(part)
    return " ; ".join(p for p in parts if p.strip())


async def api_report_steer(request):
    """POST /portal/api/report/steer — the Mode 1 narrative loop.

    The examiner steers the report's analysis ("dig into mshta", "focus on
    lateral movement", "that inference is wrong — explain"). Each round is
    persisted (instruction + timestamp + model + findings state hash), the
    accumulated steering is injected into the analysis prompts, and the
    report regenerates — examiner ↔ LLM until satisfied. Facts still come
    only from the evidence rows; the LLM never approves anything.
    """
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    sealed = _sealed_case_error(case_dir.name)
    if sealed:
        return sealed
    try:
        body = await request.json() or {}
    except Exception:
        body = {}
    instruction = str(body.get("instruction") or "").strip()
    if not instruction:
        return JSONResponse({"error": "instruction required"}, status_code=400)

    import hashlib
    rounds = _load_report_rounds(case_dir)
    findings_file = case_dir / "findings.json"
    f_hash = ""
    if findings_file.is_file():
        f_hash = hashlib.sha256(
            findings_file.read_bytes()).hexdigest()[:12]
    model_name = ""
    try:
        from nexus.langgraph.report_analysis import resolve_model

        m = resolve_model()
        model_name = getattr(m, "model_name", None) or getattr(m, "model", "") or ""
    except Exception:
        model_name = ""

    rnd = {
        "round": max([int(r.get("round") or 0) for r in rounds] + [0]) + 1,
        "ts": datetime.now(UTC).isoformat(),
        "instruction": instruction[:500],
        "finding_id": str(body.get("finding_id") or ""),
        "model": model_name or "heuristic",
        "findings_hash": f_hash,
    }
    snap_rel = f"analysis/report_rounds/round-{rnd['round']:04d}.md"
    snap_path = case_dir / snap_rel
    if snap_path.exists():
        return JSONResponse(
            {"error": "report round snapshot already exists; repair "
                      "report_rounds.json before retrying"},
            status_code=409)

    # Accumulated steering — every prior round stays in effect; the latest
    # instruction refines, it doesn't reset. Last 8 rounds bound the prompt.
    steer = _report_steer_context(rounds + [rnd])

    try:
        # B4: same as generate — off the event loop.
        result = await asyncio.to_thread(
            _write_case_report, case_dir,
            llm=bool(body.get("llm", True)), steer=steer,
        )
    except Exception as exc:
        logger.exception("Steered report generation failed: %s", exc)
        return JSONResponse({"error": str(exc)}, status_code=500)

    report_file = case_dir / "reports" / "REPORT.md"
    report_bytes = report_file.read_bytes() if report_file.is_file() else b""
    rnd["report_sha256"] = hashlib.sha256(report_bytes).hexdigest()
    rnd["snapshot_path"] = snap_rel
    prev_sha = next(
        (r.get("report_sha256") for r in reversed(rounds)
         if r.get("report_sha256")),
        None)
    if prev_sha:
        rnd["previous_report_sha256"] = prev_sha

    rounds.append(rnd)
    try:
        _atomic_write_text(snap_path, report_bytes.decode("utf-8"))
        _atomic_write_json(_report_rounds_file(case_dir), rounds)
    except Exception as exc:
        logger.warning("Could not persist report round: %s", exc)
        return JSONResponse(
            {"error": f"could not persist report round: {exc}"},
            status_code=500)

    return JSONResponse({
        **result,
        "round": rnd["round"],
        "instructions_applied": len(rounds),
        "steer_preview": steer[:300],
        "report_sha256": rnd["report_sha256"],
        "snapshot_path": rnd["snapshot_path"],
    })


async def api_report_rounds(request):
    """GET /portal/api/report/rounds — steering history for the case."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    return JSONResponse({"rounds": _load_report_rounds(case_dir)})


async def api_report_view(request):
    """GET /portal/api/report/view — view the case's generated REPORT.md."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    report_file = case_dir / "reports" / "REPORT.md"
    if not report_file.is_file():
        report_file = case_dir / "reports" / "dfir-report.md"
    if not report_file.is_file():
        return JSONResponse({"ok": False, "markdown": "", "error": "Report not yet generated. Click 'Generate Official Report'."})
    return JSONResponse({
        "ok": True,
        "markdown": report_file.read_text(encoding="utf-8"),
        "title": f"Report: {case_dir.name}",
    })


async def api_evidence_verify(request):
    """POST /portal/api/evidence/verify — re-verify SHA-256 hashes of registered evidence."""
    case_dir = _get_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)

    from nexus.case import CaseManager
    from nexus.config import settings
    mgr = CaseManager(settings.cases_root / "cases.db")
    evidence_list = mgr.list_evidence(case_dir.name)
    mgr.close()

    def _verify_all() -> list[dict]:
        out: list[dict] = []
        for ev in evidence_list:
            fpath = Path(ev.file_path) if ev.file_path else None
            if not fpath or not fpath.exists():
                out.append({"name": ev.name, "file_path": ev.file_path or "", "valid": False, "error": "File not found on disk"})
                continue
            try:
                sha256 = hashlib.sha256()
                with open(fpath, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        sha256.update(chunk)
                digest = sha256.hexdigest()
                valid = digest == ev.file_hash_sha256
                out.append({
                    "name": ev.name,
                    "file_path": str(fpath),
                    "valid": valid,
                    "expected_hash": ev.file_hash_sha256,
                    "actual_hash": digest,
                })
            except Exception as exc:
                out.append({"name": ev.name, "file_path": str(fpath), "valid": False, "error": str(exc)})
        return out

    # B10: re-hashing the whole evidence set is blocking IO — off the loop.
    results = await asyncio.to_thread(_verify_all)
    return JSONResponse({"ok": True, "results": results})


# ── End Phase 4b APIs ─────────────────────────────────────────────────────


async def logo(request) -> Response:
    """Serve the DFIR-Nexus logo SVG. Works before and after SPA build."""
    # Try built dist first, then public/ source
    for candidate in [_SPA_DIST / "logo.svg", _LOGO_SVG]:
        if candidate.is_file():
            return FileResponse(
                str(candidate),
                media_type="image/svg+xml",
                headers={"Cache-Control": "public, max-age=3600"},
            )
    return Response(status_code=404)


def create_dashboard():
    return [
        Route("/health", endpoint=health, methods=["GET"]),
        # Logo (works before and after SPA build)
        Route("/logo.svg", endpoint=logo),
        # Landing page + SPA
        Route("/", endpoint=landing_page),
        Route("/dashboard", endpoint=case_dashboard_page),
        Route("/portal", endpoint=landing_page),
        Route("/portal/", endpoint=landing_page),
        Route("/portal/ask", endpoint=ask_page),
        Route("/portal/findings", endpoint=findings_page),
        Route("/portal/approve", endpoint=approve_page),
        Route("/portal/timeline", endpoint=timeline_page),
        Route("/portal/evidence", endpoint=evidence_page),
        Route("/portal/iocs", endpoint=iocs_page),
        Route("/portal/todos", endpoint=todos_page),
        Route("/portal/steer", endpoint=steer_page),
        Route("/portal/query", endpoint=query_page),
        # API endpoints
        Route("/portal/api/commit/challenge", get_commit_challenge, methods=["GET"]),
        Route("/portal/api/commit/status", get_commit_status, methods=["GET"]),
        Route("/portal/api/commit", post_commit, methods=["POST"]),
        Route("/portal/api/findings", api_findings, methods=["GET"]),
        Route("/portal/api/timeline", api_timeline, methods=["GET"]),
        Route("/portal/api/evidence", api_evidence, methods=["GET"]),
        Route("/portal/api/evidence", api_register_evidence, methods=["POST"]),
        Route("/portal/api/iocs", api_iocs, methods=["GET"]),
        Route("/portal/api/todos", api_todos, methods=["GET"]),
        Route("/portal/api/todos", api_todos_add, methods=["POST"]),
        Route("/portal/api/todos/update", api_todos_update, methods=["POST"]),
        Route("/portal/api/audit/{finding_id}", api_audit_for_finding, methods=["GET"]),
        Route("/portal/api/summary", api_summary, methods=["GET"]),
        Route("/portal/api/transparency", api_transparency, methods=["GET"]),
        Route("/portal/api/cases", api_cases, methods=["GET"]),
        Route("/portal/api/case/activate", api_activate_case, methods=["POST"]),
        Route("/portal/api/intake", api_intake, methods=["POST"]),
        Route("/portal/api/query-rerun", api_query_rerun, methods=["POST"]),
        # Mode 1 API endpoints
        Route("/portal/api/mode1/ask", api_ask, methods=["POST"]),
        Route("/portal/api/mode1/select", api_select, methods=["POST"]),
        # Mode 1 Cockpit
        Route("/portal/explore", explore_page),
        Route("/portal/workbench", workbench_page),
        Route("/portal/api/explore/search", api_explore_search, methods=["POST"]),
        Route("/portal/api/explore/histogram", api_explore_histogram, methods=["POST"]),
        Route("/portal/api/explore/aggregate", api_explore_aggregate, methods=["POST"]),
        Route("/portal/api/workbench", api_workbench, methods=["GET"]),
        Route("/portal/api/workbench/add", api_workbench_add, methods=["POST"]),
        Route("/portal/api/workbench/add_many", api_workbench_add_many, methods=["POST"]),
        Route("/portal/api/mode1/full-run", api_mode1_full_run, methods=["POST"]),
        Route("/portal/api/mode1/full-run/status", api_mode1_full_run_status, methods=["GET"]),
        Route("/portal/api/workbench/remove", api_workbench_remove, methods=["POST"]),
        Route("/portal/api/workbench/clear", api_workbench_clear, methods=["POST"]),
        Route("/portal/api/workbench/promote", api_workbench_promote, methods=["POST"]),
        # Steer chat (persistent transcript)
        Route("/portal/api/chat", api_chat_get, methods=["GET"]),
        Route("/portal/api/chat", api_chat_post, methods=["POST"]),
        Route("/portal/api/chat/clear", api_chat_clear, methods=["POST"]),
        # Live steer-chat stream (WP 4d.3)
        Route("/portal/api/chat/stream", api_chat_stream, methods=["POST"]),
        Route("/portal/api/mode2/chat", api_mode2_chat, methods=["POST"]),
        # Timeline lanes
        Route("/portal/api/timeline/lanes", api_timeline_lanes, methods=["POST"]),
        Route("/portal/api/timeline/rebuild", api_timeline_rebuild, methods=["POST"]),
        # Entity pivot
        Route("/portal/api/entities", api_entities, methods=["POST"]),
        # Mode 2 (LLM-guided)
        Route("/portal/api/mode2/chat", api_mode2_chat, methods=["POST"]),
        Route("/portal/api/mode2/suggestions", api_mode2_suggestions, methods=["POST"]),
        Route("/portal/api/mode2/save-answer", api_mode2_save_answer, methods=["POST"]),
        Route("/portal/api/mode2/iterate", api_mode2_iterate, methods=["POST"]),
        Route("/portal/api/mode2/corroborate", api_mode2_corroborate, methods=["POST"]),
        Route("/portal/api/mode2/propose-draft", api_mode2_propose_draft, methods=["POST"]),
        # Mode 3 (agentic)
        Route("/portal/api/mode3/plan", api_mode3_plan, methods=["POST"]),
        Route("/portal/api/mode3/execute", api_mode3_execute, methods=["POST"]),
        Route("/portal/api/case/seal", api_case_seal, methods=["POST"]),
        Route("/portal/api/mode3/seal", api_case_seal, methods=["POST"]),
        # RAG preflight (WP 3.13)
        Route("/portal/api/rag/status", api_rag_status, methods=["GET"]),
        # Mode 3 orchestrator (WP 3.10)
        Route("/portal/api/mode3/orchestrator", api_mode3_orchestrator, methods=["POST"]),
        # Mode 3 agent DRAFT finding (WP 3.7)
        Route("/portal/api/mode3/draft-finding", api_mode3_draft_finding, methods=["POST"]),
        # Product mode ↔ pipeline mode mapping (WP 3.8)
        Route("/portal/api/mode-mapping", api_mode_mapping, methods=["GET"]),
        # Phase 4b: Workflow-driven cockpit APIs
        Route("/portal/api/case/create", api_case_create, methods=["POST"]),
        Route("/portal/api/case/details", api_case_details, methods=["GET"]),
        Route("/portal/api/case/deactivate", api_case_deactivate, methods=["POST"]),
        Route("/portal/api/case/reopen", api_case_reopen, methods=["POST"]),
        Route("/portal/api/case/{case_id}/details", api_case_details, methods=["GET"]),
        Route("/portal/api/pipeline/run", api_pipeline_run, methods=["POST"]),
        Route("/portal/api/pipeline/status", api_pipeline_status, methods=["GET"]),
        Route("/portal/api/pipeline/ledger", api_pipeline_ledger, methods=["GET"]),
        Route("/portal/api/case/briefing", api_case_briefing, methods=["GET"]),
        Route("/portal/api/case/digest", api_case_digest, methods=["GET"]),
        Route("/portal/api/case/export", api_case_export, methods=["GET"]),
        Route("/portal/api/case/rounds", api_case_rounds, methods=["GET"]),
        Route("/portal/api/case/briefing/directions", api_case_briefing_directions, methods=["GET"]),
        Route("/portal/api/hit/interpret", api_hit_interpret, methods=["POST"]),
        Route("/portal/api/needles/feedback", api_needle_feedback, methods=["POST"]),
        Route("/portal/api/fs/list", api_fs_list, methods=["GET"]),
        Route("/portal/api/playbook/needles", api_playbook_needles, methods=["GET"]),
        Route("/portal/api/case/mode", api_case_mode, methods=["POST"]),
        Route("/portal/api/case/mode", api_get_case_mode, methods=["GET"]),
        Route("/portal/api/system/health", api_system_health, methods=["GET"]),
        Route("/portal/api/setup/env", api_setup_env, methods=["POST"]),
        Route("/portal/api/setup/rag", api_setup_rag, methods=["POST"]),
        Route("/portal/api/setup/status", api_setup_status, methods=["GET"]),
        Route("/portal/api/case/seed-demo", api_case_seed_demo, methods=["POST"]),
        Route("/portal/api/findings/reject", api_findings_reject, methods=["POST"]),
        Route("/portal/api/report/generate", api_report_generate, methods=["POST"]),
        Route("/portal/api/report/view", api_report_view, methods=["GET"]),
        Route("/portal/api/report/steer", api_report_steer, methods=["POST"]),
        Route("/portal/api/report/rounds", api_report_rounds, methods=["GET"]),
        Route("/portal/api/evidence/verify", api_evidence_verify, methods=["POST"]),
        # Phase 4: React SPA (served after API + legacy HTML routes)
        Route("/portal/app/assets/{path:path}", spa_asset),
        Route("/portal/app/logo.svg", logo),
        Route("/portal/app/{path:path}", spa_index),
        Route("/portal/app", spa_index),
    ]
