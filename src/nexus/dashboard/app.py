"""Examiner Portal — browser-based case review + approval (HMAC commit).

Mounted automatically in HTTP mode at /portal.
Implements the original case-dashboard features: findings, timeline,
evidence, IOCs, todos, and the commit challenge-response workflow
for browser-based finding approval.
"""

import contextlib
import hashlib
import hmac as hmac_mod
import html
import json
import logging
import os
import secrets
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from starlette.responses import FileResponse, HTMLResponse, JSONResponse, Response
from starlette.routing import Route

logger = logging.getLogger(__name__)

_CHALLENGE_TTL = 300  # 5 minutes
_CHALLENGE_MAX = 1000
_challenges: dict[str, dict] = {}
_challenge_lock = threading.Lock()
_MAX_COMMIT_ATTEMPTS = 3
_COMMIT_LOCKOUT_SECONDS = 900
_LOCKOUT_FILE = Path.home() / ".nexus" / ".commit_lockout"

_PASSWORDS_DIR = Path.home() / ".nexus" / "passwords"


def _atomic_write_json(path: Path, data: Any) -> None:
    """Write JSON atomically to avoid corruption on crash."""
    import tempfile
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        os.close(fd)
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _get_case_dir() -> Path | None:
    from nexus.case.outputs import resolve_active_case_dir

    return resolve_active_case_dir()


def _load_json(name: str) -> list:
    case_dir = _get_case_dir()
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


def _load_password_entry(examiner: str) -> dict | None:
    path = _PASSWORDS_DIR / f"{examiner}.json"
    try:
        data = json.loads(path.read_text())
        if isinstance(data, dict) and "hash" in data and "salt" in data:
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return None


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


async def post_commit(request) -> JSONResponse:
    """Apply finding approvals with challenge-response authentication."""
    case_dir = _get_case_dir()
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

    return JSONResponse({
        "status": "committed",
        "approved": approved,
        "errors": errors,
        "examiner": examiner,
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
    findings = _load_json("findings.json")
    timeline = _load_json("timeline.json")
    evidence = _load_json("evidence_registry.json")
    todos = _load_json("todos.json")

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
    findings = _load_json("findings.json")
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
    findings = _load_json("findings.json")
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
    events = _load_json("timeline.json")
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
    ev = _load_json("evidence_registry.json")
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
    findings = _load_json("findings.json")
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
    todos = _load_json("todos.json")
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
    case_dir = _get_case_dir()
    return case_dir.name if case_dir else ""


async def steer_page(request):
    """N1 intake + case switch + add evidence + N4 rerun (HITL redirect)."""
    import yaml

    cases = _list_case_ids()
    active = _active_case_id()
    intake = {}
    case_dir = _get_case_dir()
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
    case_dir = _get_case_dir()
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


async def api_cases(request):
    return JSONResponse({"cases": _list_case_ids(), "active": _active_case_id()})


async def api_activate_case(request):
    body = await request.json()
    case_id = str(body.get("case_id") or "").strip()
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
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"ok": False, "error": "no active case"}, status_code=400)
    from nexus.langgraph.case_intake import persist_case_intake
    written = persist_case_intake(case_dir, {
        k: str(body.get(k) or "")
        for k in ("question", "window", "extras", "playbooks", "subjects", "hypothesis", "query_extra")
        if body.get(k)
    })
    return JSONResponse({"ok": True, "intake": written})


async def api_register_evidence(request):
    body = await request.json()
    path = str(body.get("path") or "").strip()
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"ok": False, "error": "no active case"}, status_code=400)
    if not path or not Path(path).exists():
        return JSONResponse({"ok": False, "error": "path missing"}, status_code=400)
    import hashlib

    from nexus.audit import resolve_examiner
    from nexus.case import CaseManager
    from nexus.config import settings
    fpath = Path(path)
    h = hashlib.sha256()
    if fpath.is_dir():
        h.update(str(fpath.resolve()).encode())
        digest = h.hexdigest()
    else:
        with open(fpath, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        digest = h.hexdigest()
    mgr = CaseManager(settings.cases_root / "cases.db")
    mgr.add_evidence(
        case_id=case_dir.name,
        name=fpath.name,
        description="portal register",
        file_path=str(fpath.resolve()),
        file_hash_sha256=digest,
        collected_by=resolve_examiner(),
    )
    return JSONResponse({"ok": True, "path": str(fpath), "sha256": digest})


async def api_query_rerun(request):
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"ok": False, "error": "no active case"}, status_code=400)
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
    findings = _load_json("findings.json")
    status = request.query_params.get("status")
    limit = int(request.query_params.get("limit", "0"))
    if status:
        findings = [f for f in findings if f.get("status", "").upper() == status.upper()]
    if limit > 0:
        findings = findings[:limit]
    return JSONResponse({"findings": findings, "total": len(findings)})


async def api_timeline(request):
    """GET /portal/api/timeline?event_type=execution&limit=50"""
    events = _load_json("timeline.json")
    ev_type = request.query_params.get("event_type")
    limit = int(request.query_params.get("limit", "0"))
    if ev_type:
        events = [e for e in events if e.get("event_type", "") == ev_type]
    if limit > 0:
        events = events[:limit]
    return JSONResponse({"events": events, "total": len(events)})


async def api_evidence(request):
    """GET /portal/api/evidence"""
    ev = _load_json("evidence_registry.json")
    return JSONResponse({"evidence": ev, "total": len(ev)})


async def api_iocs(request):
    """GET /portal/api/iocs"""
    findings = _load_json("findings.json")
    iocs = []
    for f in findings:
        for ioc in f.get("iocs", []):
            ioc["finding_title"] = f.get("title", "")
            ioc["finding_status"] = f.get("status", "DRAFT")
            iocs.append(ioc)
    return JSONResponse({"iocs": iocs, "total": len(iocs)})


async def api_todos(request):
    """GET /portal/api/todos?status=open"""
    todos = _load_json("todos.json")
    status = request.query_params.get("status", "")
    if status:
        todos = [t for t in todos if t.get("status", "open") == status]
    return JSONResponse({"todos": todos, "total": len(todos)})


async def api_audit_for_finding(request):
    """GET /portal/api/audit/{finding_id}"""
    finding_id = request.path_params.get("finding_id", "")
    if not finding_id:
        return JSONResponse({"error": "Missing finding_id"}, status_code=400)
    case_dir = _get_case_dir()
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
    findings = _load_json("findings.json")
    timeline = _load_json("timeline.json")
    evidence = _load_json("evidence_registry.json")
    todos = _load_json("todos.json")
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
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    from nexus.transparency import transparency_verify
    result = transparency_verify(case_dir.name)
    return JSONResponse(result)


async def ask_page(request):
    """Mode 1 examiner query desk: natural language -> needles -> hits -> select."""
    case_dir = _get_case_dir()
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
  <td><input type="checkbox" class="hit-check" value="{i}"></td>
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
    body: JSON.stringify({{hits: hitIds, title: title, scribe: scribe}})
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


async def api_ask(request):
    """POST /portal/api/mode1/ask — NL → needles + N4 hits."""
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
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

    parsed = nl_to_needles(question, model=model)
    needles = parsed.get("needles", [])
    window = parsed.get("window", "")
    if not needles:
        return JSONResponse({"needles": [], "window": window, "error": "No needles extracted"})

    n4_result = run_ad_hoc_query(
        case_dir,
        extra_needles=needles,
        persist=True,
        limit=int(body.get("limit") or 80),
    )
    return JSONResponse({
        "needles": needles,
        "window": window,
        "hits": n4_result.get("hits", []),
        "count": n4_result.get("count", 0),
        "backend": n4_result.get("backend", ""),
    })


async def api_select(request):
    """POST /portal/api/mode1/select — promote selected hit indices to DRAFT."""
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)

    body = await request.json()
    raw_indices = body.get("hits", [])
    title = str(body.get("title") or "").strip()
    use_scribe = bool(body.get("scribe", True))

    if not title:
        return JSONResponse({"error": "Missing title"}, status_code=400)
    if not raw_indices:
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
            merged = _parse_needles(intake.get("query_extra", "")) + explore_needles
            intake["query_extra"] = ",".join(merged)
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

    try:
        indices = sorted({int(i) - 1 for i in raw_indices if str(i).strip()})
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid hit indices"}, status_code=400)

    bad = [i + 1 for i in indices if i < 0 or i >= len(all_hits)]
    if bad:
        return JSONResponse({"error": f"Hit indices out of range: {bad}"}, status_code=400)

    selected = [all_hits[i] for i in indices]
    from nexus.audit import resolve_examiner
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
        draft = scribe_finding(draft, hits=selected, model=model)

    result = save_draft_finding(case_dir, draft)
    if result.get("status") == "STAGED":
        return JSONResponse({
            "finding_id": result.get("finding_id"),
            "title": title,
            "status": "DRAFT",
            "audit_ids": draft.get("audit_ids", []),
        })
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


async def api_explore_search(request):
    """POST /portal/api/explore/search — faceted N4 search.

    Body: {query?: "<DSL>", needles?: "a,b", family?: "evtx,prefetch",
           start?, end?, limit?, offset?}. When ``query`` (DSL) is provided
    it takes precedence over plain needles.
    """
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({'error': 'No active case'}, status_code=404)

    from nexus.langgraph.query_pack import (
        _parse_needles,
        collect_query_terms,
        load_case_intake,
        n4_query,
        parse_intake_window,
    )

    body = await request.json()
    needles = _parse_needles(str(body.get('needles') or ''))
    query_text = str(body.get('query') or '').strip()
    family_filter = [f.strip() for f in str(body.get('family') or '').split(',') if f.strip()]
    start = str(body.get('start') or '').strip()
    end = str(body.get('end') or '').strip()
    try:
        limit = max(1, min(int(body.get('limit') or 80), 400))
        offset = max(0, int(body.get('offset') or 0))
    except (TypeError, ValueError):
        return JSONResponse({'error': 'limit/offset must be integers'}, status_code=400)

    intake = load_case_intake(case_dir)
    if needles:
        merged = _parse_needles(intake.get('query_extra', '')) + needles
        intake['query_extra'] = ','.join(merged)
    window = parse_intake_window(intake)
    if start or end:
        parts = [p for p in (start, end) if p]
        intake['window'] = '..'.join(parts)
        window = parse_intake_window(intake)

    # Merge plain needles into the DSL text so n4_query sees both
    # (it reloads CASE.yaml internally and would otherwise drop them).
    if needles and query_text:
        query_text = query_text + ' ' + ' '.join(needles)
    elif needles and not query_text:
        query_text = ' OR '.join(needles)

    result = n4_query(case_dir, query_text, window=window, limit=400, offset=offset)
    if result.get('error'):
        return JSONResponse({'error': result['error']}, status_code=400)
    hits = list(result.get('hits') or [])
    total_before_filter = int(result.get('count') or 0)

    if family_filter:
        want = {f.lower() for f in family_filter}
        hits = [h for h in hits if (h.get('family') or '').lower() in want]

    return JSONResponse({
        'hits': hits[:limit],
        'count': len(hits),
        'total_before_family_filter': total_before_filter,
        'backend': result.get('backend', ''),
        'families': _available_families(case_dir),
        'needles': collect_query_terms(intake),
        'query': result.get('query', ''),
        'offset': offset,
    })


async def api_explore_aggregate(request):
    """POST /portal/api/explore/aggregate — hit counts by family/hour/day.

    Body: {query?: "<DSL>", group_by: family|hour|day|file}
    """
    case_dir = _get_case_dir()
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
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({'error': 'No active case'}, status_code=404)
    body = await request.json()
    from nexus.langgraph.query_pack import (
        _parse_needles,
        collect_query_terms,
        load_case_intake,
        n4_hits,
        parse_intake_window,
    )
    needles = _parse_needles(str(body.get('needles') or ''))
    family_filter = [f.strip() for f in str(body.get('family') or '').split(',') if f.strip()]
    start = str(body.get('start') or '').strip()
    end = str(body.get('end') or '').strip()
    intake = load_case_intake(case_dir)
    if needles:
        merged = _parse_needles(intake.get('query_extra', '')) + needles
        intake['query_extra'] = ','.join(merged)
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
    case_dir = _get_case_dir()
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
    '<td><input type="checkbox" class="hit-check" value="' + (i+1) + '"></td>' +
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
      hits: hitIds,
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
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    from nexus.case.workbench import load_bookmarks

    return JSONResponse({"bookmarks": load_bookmarks(case_dir), "total": len(load_bookmarks(case_dir))})


async def api_workbench_add(request):
    """POST /portal/api/workbench/add — bookmark one hit {hit: {...}, note?}."""
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    body = await request.json()
    hit = body.get("hit") or {}
    if not isinstance(hit, dict) or not (hit.get("file") or hit.get("text")):
        return JSONResponse({"error": "Missing hit data"}, status_code=400)
    from nexus.case.workbench import add_bookmark

    return JSONResponse(add_bookmark(case_dir, hit, note=str(body.get("note") or "")))


async def api_workbench_remove(request):
    """POST /portal/api/workbench/remove — {bookmark_id}."""
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    body = await request.json()
    from nexus.case.workbench import remove_bookmark

    return JSONResponse(remove_bookmark(case_dir, str(body.get("bookmark_id") or "")))


async def api_workbench_clear(request):
    """POST /portal/api/workbench/clear."""
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    from nexus.case.workbench import clear_bookmarks

    return JSONResponse(clear_bookmarks(case_dir))


async def api_workbench_promote(request):
    """POST /portal/api/workbench/promote — bookmarked hits -> DRAFT finding.

    Body: {bookmark_ids: ["B-001", ...], title, scribe?, interpretation?}
    """
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    body = await request.json()
    title = str(body.get("title") or "").strip()
    wanted = [str(b) for b in (body.get("bookmark_ids") or []) if str(b).strip()]
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
        draft = scribe_finding(draft, hits=selected, model=model)

    result = save_draft_finding(case_dir, draft)
    if result.get("status") == "STAGED":
        return JSONResponse({
            "finding_id": result.get("finding_id"),
            "status": "DRAFT",
            "title": title,
            "bookmark_count": len(selected),
        })
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
    case_dir = _get_case_dir()
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
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    from nexus.case.workbench import load_bookmarks

    bookmarks = load_bookmarks(case_dir)
    return JSONResponse({"bookmarks": bookmarks, "total": len(bookmarks)})


async def api_chat_get(request):
    """GET /portal/api/chat — steer-chat transcript for the active case."""
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    from nexus.case.chat import load_chat

    messages = load_chat(case_dir)
    return JSONResponse({"messages": messages, "total": len(messages)})


async def api_chat_post(request):
    """POST /portal/api/chat — examiner message -> Mode 1 ask flow -> logged reply."""
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
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

    if not needles:
        reply = "No needles extracted. Refine the question (name an artifact, tool, or event ID)."
        append_chat(case_dir, "llm", "needles_empty", reply, {"source": parsed.get("source", "")})
        return JSONResponse({"reply": reply, "needles": [], "count": 0})

    window = parse_intake_window(load_case_intake(case_dir))
    result = n4_query(case_dir, " ".join(needles), window=window, limit=80)
    if result.get("error"):
        append_chat(case_dir, "llm", "error", result["error"])
        return JSONResponse({"reply": f"Query error: {result['error']}"}, status_code=400)

    reply = (
        f"Needles: {', '.join(needles)} | hits: {result.get('count', 0)}"
        + (f" | {result.get('query')}" if result.get("query") else "")
    )
    append_chat(case_dir, "llm", "query_run", reply, {
        "needles": ",".join(needles),
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
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    from nexus.case.chat import clear_chat

    return JSONResponse(clear_chat(case_dir))


async def api_timeline_lanes(request):
    """POST /portal/api/timeline/lanes — per-family time buckets for lanes.

    Body: {query?: "<DSL>", needles?, family?, start?, end?, bucket?: hour|day}
    Returns {families: [{family, buckets: {ts: count}}], total}
    """
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    body = await request.json()
    from nexus.langgraph.query_pack import _DATE_RE, n4_query

    result = n4_query(case_dir, str(body.get("query") or ""), limit=400)
    if result.get("error"):
        return JSONResponse({"error": result["error"]}, status_code=400)
    hits = result.get("hits", [])
    bucket = "day" if str(body.get("bucket") or "hour") == "day" else "hour"

    families: dict[str, dict[str, int]] = {}
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

    ordered = [
        {"family": fam, "buckets": dict(sorted(lanes.items()))}
        for fam, lanes in sorted(families.items(), key=lambda kv: -sum(kv[1].values()))
    ]
    return JSONResponse({"families": ordered, "total": result.get("count", 0), "bucket": bucket})


async def api_entities(request):
    """POST /portal/api/entities — extract entities from current N4 hits.

    Body: {query?: "<DSL>", needles?} — same search as explore/search.
    """
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    body = await request.json()
    from nexus.analysis.entities import extract_entities
    from nexus.langgraph.query_pack import n4_query

    result = n4_query(case_dir, str(body.get("query") or ""), limit=400)
    if result.get("error"):
        return JSONResponse({"error": result["error"]}, status_code=400)
    texts = [h.get("text", "") for h in result.get("hits", [])]
    return JSONResponse({"entities": extract_entities(texts), "total": result.get("count", 0)})


async def api_mode2_iterate(request):
    """POST /portal/api/mode2/iterate — Mode 2 iterative loop (logged).

    Body: {question, max_iterations? (default 2, hard cap 4), limit?}
    Every iteration is logged to chat.jsonl. Returns the iteration log;
    the examiner reviews proposals — nothing is auto-staged.
    """
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    body = await request.json()
    question = str(body.get("question") or "").strip()
    if not question:
        return JSONResponse({"error": "Missing question"}, status_code=400)
    try:
        max_iterations = max(1, min(int(body.get("max_iterations") or 2), 4))
    except (TypeError, ValueError):
        return JSONResponse({"error": "max_iterations must be an integer"}, status_code=400)

    from nexus.case.chat import append_chat
    from nexus.langgraph.llm_pipeline import get_model
    from nexus.langgraph.mode2 import run_iterative_loop

    try:
        model = get_model()
    except Exception:
        model = None

    append_chat(case_dir, "examiner", "mode2_start", question, {"max_iterations": max_iterations})
    result = run_iterative_loop(case_dir, question, model=model, max_iterations=max_iterations)
    if result.get("error"):
        append_chat(case_dir, "llm", "mode2_error", result["error"])
        return JSONResponse({"error": result["error"]}, status_code=400)
    for it in result.get("iterations", []):
        action = it.get("action", "")
        if action == "proposed_and_run":
            append_chat(case_dir, "llm", "mode2_proposal", (
                f"Iteration {it.get('iteration')}: proposed {', '.join(it.get('needles', []))} "
                f"-> {it.get('hits', 0)} hits. {it.get('rationale', '')}"
            ), {"needles": ",".join(it.get("needles", [])), "hits": it.get("hits", 0)})
        elif action == "no_new_proposals":
            append_chat(case_dir, "llm", "mode2_no_proposals", "No new needles to propose.", {"iteration": it.get("iteration")})
    append_chat(case_dir, "llm", "mode2_done", f"Iterative loop complete: {result.get('total_hits', 0)} total hits.", {
        "iterations": len(result.get("iterations", [])),
        "capped": result.get("capped", False),
    })
    return JSONResponse(result)


async def api_mode2_corroborate(request):
    """POST /portal/api/mode2/corroborate — FD-006/007 check on a finding.

    Body: {finding_id} or a full {finding} dict.
    """
    case_dir = _get_case_dir()
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
    """POST /portal/api/mode2/propose-draft — LLM drafts a finding from hits.

    Body: {title, hits: [...]} or {title, query} (hits from the query).
    The draft stages as DRAFT (examiner_selected=False); HMAC approval
    stays with the examiner.
    """
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    body = await request.json()
    title = str(body.get("title") or "").strip()
    if not title:
        return JSONResponse({"error": "Missing title"}, status_code=400)
    hits = body.get("hits")
    if not hits and body.get("query") is not None:
        from nexus.langgraph.query_pack import n4_query

        result = n4_query(case_dir, str(body.get("query")), limit=12)
        hits = result.get("hits", [])
    if not hits:
        return JSONResponse({"error": "No hits to draft from"}, status_code=400)

    from nexus.case.chat import append_chat
    from nexus.langgraph.llm_pipeline import get_model
    from nexus.langgraph.mode2 import propose_draft_finding

    try:
        model = get_model()
    except Exception:
        model = None

    outcome = propose_draft_finding(case_dir, hits, title, model=model)
    if outcome.get("error"):
        return JSONResponse({"error": outcome["error"]}, status_code=400)
    draft = outcome["draft"]
    from nexus.langgraph.mode1 import save_draft_finding

    saved = save_draft_finding(case_dir, draft)
    if saved.get("status") == "STAGED":
        append_chat(case_dir, "llm", "mode2_draft", f"Proposed DRAFT '{title}' from {len(hits)} hits (examiner approval required)", {
            "finding_id": saved.get("finding_id", ""),
            "confidence": draft.get("confidence", ""),
        })
        return JSONResponse({
            "finding_id": saved.get("finding_id"),
            "status": "DRAFT",
            "corroboration": outcome.get("corroboration", {}),
        })
    detail: list = list(saved.get("errors") or [])
    if saved.get("error"):
        detail.append(str(saved["error"]))
    if not detail:
        detail = [str(saved.get("status", "failed"))]
    return JSONResponse({"error": detail})


async def api_mode3_plan(request):
    """POST /portal/api/mode3/plan — agent proposes the investigation plan.

    Reads the tool-lane ledger (SKIPs), unrequested extras, and FD-006
    corroboration needs. Logged to agent_runs.jsonl + chat. The examiner
    approves items before anything executes.
    """
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    from nexus.langgraph.llm_pipeline import get_model
    from nexus.langgraph.mode3 import plan_extras

    try:
        model = get_model()
    except Exception:
        model = None
    plan = plan_extras(case_dir, model=model)
    return JSONResponse(plan)


async def api_mode3_execute(request):
    """POST /portal/api/mode3/execute — run examiner-approved plan items.

    Body: {extras: ["usb_serial", ...], queries: ["...", ...]}
    Extras persist to intake (next lane run parses them; mandatory lane
    first). Queries run immediately (read-only N4).
    """
    case_dir = _get_case_dir()
    if not case_dir:
        return JSONResponse({"error": "No active case"}, status_code=404)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    extras = body.get("extras") or []
    queries = body.get("queries") or []
    if not isinstance(extras, list) or not isinstance(queries, list):
        return JSONResponse({"error": "extras and queries must be lists"}, status_code=400)

    from nexus.langgraph.mode3 import execute_plan

    result = execute_plan(
        case_dir,
        [str(e) for e in extras],
        [str(q) for q in queries],
    )
    if result.get("error"):
        return JSONResponse(result, status_code=400)
    return JSONResponse(result)


async def api_mode3_seal(request):
    """POST /portal/api/mode3/seal — case-file HMAC via challenge-response.

    Body: {challenge_id, response, examiner?}
    Reuses the same challenge-response flow as per-finding approval —
    the password never travels in plaintext.
    """
    case_dir = _get_case_dir()
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
    return JSONResponse(result)


async def health(request):
    """Lightweight health endpoint for load balancers and Docker healthchecks."""
    return JSONResponse({"status": "ok", "service": "dfir-nexus"})


# --- Phase 4: React SPA serving ---
# The built React SPA lives in frontend/dist/. Starlette serves it at /portal/app/*
# and the index.html catch-all handles client-side routing. The old HTML pages
# remain available at their original paths until the parity checklist is signed.

_SPA_DIST = Path(__file__).resolve().parent.parent.parent.parent / "frontend" / "dist"
_SPA_INDEX = _SPA_DIST / "index.html"


async def spa_index(request) -> HTMLResponse:
    """Serve the React SPA index.html for client-side routing."""
    if _SPA_INDEX.is_file():
        return HTMLResponse(_SPA_INDEX.read_text(encoding="utf-8"))
    # Fallback: SPA not built yet — show a helpful message
    return HTMLResponse(
        "<html><body style='background:#0d1117;color:#e6edf3;font-family:sans-serif;padding:40px'>"
        "<h2>Phase 4 SPA not built</h2>"
        "<p>Run <code>cd frontend && npm run build</code> to build the React UI.</p>"
        "<p>The legacy HTML pages are still available at their original /portal/* paths.</p>"
        "</body></html>",
        status_code=503,
    )


async def spa_asset(request) -> Response:
    """Serve a static asset (JS/CSS/images) from the SPA dist directory."""
    path = request.path_params.get("path", "")
    # Defense-in-depth: block obvious traversal attempts
    if ".." in path or path.startswith("/"):
        return Response(status_code=404)
    # Resolve and verify the path stays within _SPA_DIST
    try:
        spa_root = _SPA_DIST.resolve()
        file_path = (_SPA_DIST / path).resolve()
        if not str(file_path).startswith(str(spa_root)):
            return Response(status_code=404)
    except (ValueError, RuntimeError):
        return Response(status_code=404)
    if file_path.is_file():
        return FileResponse(file_path)
    return Response(status_code=404)


def create_dashboard():
    return [
        Route("/health", endpoint=health, methods=["GET"]),
        Route("/portal", endpoint=overview),
        Route("/portal/", endpoint=overview),
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
        Route("/portal/api/commit", post_commit, methods=["POST"]),
        Route("/portal/api/findings", api_findings, methods=["GET"]),
        Route("/portal/api/timeline", api_timeline, methods=["GET"]),
        Route("/portal/api/evidence", api_evidence, methods=["GET"]),
        Route("/portal/api/evidence", api_register_evidence, methods=["POST"]),
        Route("/portal/api/iocs", api_iocs, methods=["GET"]),
        Route("/portal/api/todos", api_todos, methods=["GET"]),
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
        Route("/portal/api/workbench/remove", api_workbench_remove, methods=["POST"]),
        Route("/portal/api/workbench/clear", api_workbench_clear, methods=["POST"]),
        Route("/portal/api/workbench/promote", api_workbench_promote, methods=["POST"]),
        # Steer chat (persistent transcript)
        Route("/portal/api/chat", api_chat_get, methods=["GET"]),
        Route("/portal/api/chat", api_chat_post, methods=["POST"]),
        Route("/portal/api/chat/clear", api_chat_clear, methods=["POST"]),
        # Timeline lanes
        Route("/portal/api/timeline/lanes", api_timeline_lanes, methods=["POST"]),
        # Entity pivot
        Route("/portal/api/entities", api_entities, methods=["POST"]),
        # Mode 2 (LLM-guided)
        Route("/portal/api/mode2/iterate", api_mode2_iterate, methods=["POST"]),
        Route("/portal/api/mode2/corroborate", api_mode2_corroborate, methods=["POST"]),
        Route("/portal/api/mode2/propose-draft", api_mode2_propose_draft, methods=["POST"]),
        # Mode 3 (agentic)
        Route("/portal/api/mode3/plan", api_mode3_plan, methods=["POST"]),
        Route("/portal/api/mode3/execute", api_mode3_execute, methods=["POST"]),
        Route("/portal/api/mode3/seal", api_mode3_seal, methods=["POST"]),
        # Phase 4: React SPA (served after API + legacy HTML routes)
        Route("/portal/app/assets/{path:path}", spa_asset),
        Route("/portal/app/{path:path}", spa_index),
        Route("/portal/app", spa_index),
    ]
