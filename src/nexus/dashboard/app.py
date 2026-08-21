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

from starlette.responses import HTMLResponse, JSONResponse
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
    active = Path.home() / ".nexus" / "active_case"
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


async def health(request):
    """Lightweight health endpoint for load balancers and Docker healthchecks."""
    return JSONResponse({"status": "ok", "service": "dfir-nexus"})


def create_dashboard():
    return [
        Route("/health", endpoint=health, methods=["GET"]),
        Route("/portal", endpoint=overview),
        Route("/portal/", endpoint=overview),
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
    ]
