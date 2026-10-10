"""DFIR-Nexus CLI — human-only operations.

The full CLI surface. For background on which
operations are human-only and why, see Docs/ARCHITECTURE.md.

Usage:
    nexus serve [--http] [--port]          Start MCP server
    nexus approve [ids...] [--note]        Approve DRAFT findings (password required)
    nexus reject <ids...> [--reason]       Reject findings
    nexus report generate [--profile dfir] Generate report (APPROVED only)
    nexus backup create /path              Backup case
    nexus backup restore /path             Restore case
    nexus case init "Name"                 Create case
    nexus case activate CASE-001           Activate case
    nexus case close CASE-001              Close case
    nexus case reopen CASE-001             Reopen case
    nexus case list                        List cases
    nexus evidence register /path          Register evidence
    nexus evidence list                    List evidence
    nexus evidence verify                  Verify evidence integrity
    nexus evidence lock                    Lock evidence (read-only)
    nexus evidence unlock                  Unlock evidence
    nexus review findings                  Review case state (findings/timeline/...)
    nexus config [--examiner] [--setup-password]  Configure
    nexus export bundle.json               Export case bundle
    nexus merge bundle.json                Import case bundle
    nexus exec run --purpose "reason" cmd  Run command with audit
    nexus audit log                        View audit trail
    nexus audit summary                    Audit summary
    nexus todo list                        List TODOs
    nexus todo add "description"           Add TODO
    nexus todo complete TODO-001           Complete TODO
    nexus portal                           Open Examiner Portal
    nexus setup client                     Generate LLM client config
    nexus setup test                       Test connectivity
    nexus ingest <path> [--source] [--case]  Auto-detect (or force source) and ingest
    nexus doctor [--health-url]            Report extras / tools / indexes / /health
    nexus collect tools|plan|run|import    Stage 0 live IR collect (SSH/WinRM/local)
    nexus data download-rag|triage|fixtures  Indexes / fixture pointer
    nexus service status                   Check service status
    nexus service start                    Start service
    nexus service stop                     Stop service
    nexus service restart                  Restart service
    nexus update                           Pull latest code
"""

import os
import subprocess
import sys
from pathlib import Path

import typer

from nexus.case.locks import lock_case_writes
from nexus.cli.audit_cmd import app as audit_app
from nexus.cli.backup import app as backup_app
from nexus.cli.case_cmd import app as case_app
from nexus.cli.collect_cmd import app as collect_app
from nexus.cli.config_cmd import app as config_app
from nexus.cli.data_cmd import app as data_app
from nexus.cli.evidence import app as evidence_app
from nexus.cli.exec_cmd import app as exec_app
from nexus.cli.finding_cmd import app as finding_app
from nexus.cli.index_cmd import app as index_app
from nexus.cli.init_cmd import init as init_cmd
from nexus.cli.lane_cmd import app as lane_app
from nexus.cli.mode2_cmd import app as mode2_app
from nexus.cli.mode3_cmd import app as mode3_app
from nexus.cli.report import app as report_app
from nexus.cli.review import app as review_app
from nexus.cli.service import app as service_app
from nexus.cli.sift_cmd import app as sift_app
from nexus.cli.timeline_cmd import app as timeline_app
from nexus.cli.todo import app as todo_app

app = typer.Typer(name="nexus", help="DFIR-Nexus — unified DFIR investigation platform")

app.add_typer(report_app, name="report", help="Generate investigation reports")
app.add_typer(backup_app, name="backup", help="Backup and restore cases")
app.add_typer(case_app, name="case", help="Manage investigation cases")
app.add_typer(evidence_app, name="evidence", help="Manage evidence")
app.add_typer(finding_app, name="finding", help="Inspect findings (exhibit bundle)")
app.add_typer(review_app, name="review", help="Review case state")
app.add_typer(config_app, name="config", help="Manage examiner configuration")
app.add_typer(service_app, name="service", help="Manage MCP services")
app.add_typer(lane_app, name="lane", help="Evidence gate (N2): never skip evidence processing")
app.add_typer(sift_app, name="sift", help="SIFT lane: selection, reachability, and SIFT-output ingest")
# export/merge registered as DIRECT commands below so the documented
# `nexus export bundle.json` / `nexus merge bundle.json` forms work
# (sync_app's own sub-commands would double-nest: `nexus export export`).
from nexus.cli.sync import export as _sync_export
from nexus.cli.sync import merge as _sync_merge

app.command(name="export", help="Export case bundle")(_sync_export)
app.command(name="merge", help="Merge case bundle")(_sync_merge)
app.add_typer(exec_app, name="exec", help="Execute forensic command with audit trail")
app.add_typer(audit_app, name="audit", help="View audit trail")
app.add_typer(mode2_app, name="mode2",
              help="Mode 2 — Multi-role pipeline")
app.add_typer(mode3_app, name="mode3",
              help="Mode 3 — Multi-agent team")
app.add_typer(todo_app, name="todo", help="Manage TODO items")
app.add_typer(data_app, name="data", help="Download RAG / triage / fixtures")
app.add_typer(timeline_app, name="timeline",
               help="Queryable timeline on Elasticsearch (build|query|export)")
app.add_typer(index_app, name="index", help="Rebuild the per-case ES index (schema v2)")
app.add_typer(collect_app, name="collect", help="Stage 0 IR orchestrator — live collect with auth")
# Registered as a direct command (not a sub-group) so the documented
# `nexus init "Case" --evidence ...` form works.
app.command(name="init", help="Quickstart — one-command onboarding")(init_cmd)

from nexus.cli.coverage_cmd import coverage_audit as _coverage_cmd
from nexus.cli.doctor_cmd import doctor as doctor_cmd
from nexus.cli.ingest_cmd import ingest as ingest_cmd
from nexus.cli.investigate import brief as _brief_cmd
from nexus.cli.investigate import hit_cmd as _hit_cmd
from nexus.cli.investigate import hits_cmd as _hits_cmd

app.command(name="ingest", help="Auto-detect and ingest a forensic file or tree")(ingest_cmd)
app.command(name="doctor", help="Report extras, catalog binaries, indexes, optional keys")(doctor_cmd)
# WP 10.2: the coverage audit answers "what did this investigation NOT cover?".
app.command(name="coverage-audit", help="Case coverage audit: tools not run, sources not cited, needles not scanned")(_coverage_cmd)

# Level 1: verify every claim the case made, mechanically, with UNVERIFIABLE
# kept distinct from a pass.
from nexus.cli.verify_cmd import verify_claims as _verify_cmd

app.command(name="verify-claims", help="Level 1 claim check: citations, entities, techniques, timestamps, counts")(_verify_cmd)

# WP 4i.10: headless investigation verbs — the UI stays primary, these keep
# the spine usable without a browser.
app.command(name="brief", help="Case briefing — what was processed + signal map")(_brief_cmd)
app.command(name="hits", help="Parsed hit table for a needle")(_hits_cmd)
app.command(name="hit", help="Full field dump for one hit (file:line)")(_hit_cmd)

_ACTIVE_CASE_FILE = Path(
    os.environ.get("NEXUS_ACTIVE_CASE_FILE", str(Path.home() / ".nexus" / "active_case"))
)


def _resolve_case(case_id: str = "") -> Path | None:
    from nexus.case.outputs import resolve_active_case_dir
    from nexus.config import settings

    if case_id:
        p = Path(case_id)
        case_dir = p if p.is_absolute() else settings.cases_root / case_id
        if not case_dir.exists():
            typer.echo(f"Case not found: {case_id}", err=True)
            return None
        return case_dir
    case_dir = resolve_active_case_dir()
    if case_dir:
        return case_dir
    typer.echo("No active case. Use 'nexus case activate' or 'nexus case init'", err=True)
    return None


def _resolve_analyst(explicit: str = "") -> str:
    from nexus.config import settings

    return (
        (explicit or "").strip()
        or settings.examiner
        or os.environ.get("NEXUS_EXAMINER")
        or os.environ.get("USER")
        or os.environ.get("USERNAME")
        or "unknown"
    )


@app.command()
def approve(
    finding_ids: list[str] = typer.Argument(None, help="Finding IDs to approve"),
    note: str = typer.Option("", "--note", help="Examiner note"),
    reason: str = typer.Option("", "--reason", help="Override reason for findings whose L1 verdict is not PROVEN"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Interactive review mode"),
    examiner: str = typer.Option("", "--examiner", "-e", help="Examiner identity (password file name)"),
    clear_lockout: bool = typer.Option(False, "--clear-lockout", help="Clear 15-minute lockout and exit"),
):
    """Approve DRAFT findings (requires password — blocks AI approval)."""
    analyst = _resolve_analyst(examiner)

    if clear_lockout:
        from nexus.auth import clear_lockout as _clear_lockout

        _clear_lockout(analyst if analyst != "unknown" else None)
        typer.echo(f"Approval lockout cleared ({analyst}).")
        if not finding_ids and not interactive:
            return

    if interactive:
        _interactive_approve(analyst)
        return

    if not finding_ids:
        typer.echo("Usage: nexus approve --examiner e2e_host <finding_id>...")
        raise typer.Exit(1)

    from nexus.cli.approve import _require_approval_auth, approve_finding

    case_dir = _resolve_case()
    if not case_dir:
        raise typer.Exit(1)

    # WO-2: show the L1 verdict before the password prompt; a finding the
    # verifier did not prove needs an explicit override reason.
    from nexus.analysis.claim_verification import verify_drafts

    try:
        verdicts = verify_drafts(case_dir)
    except Exception:  # noqa: BLE001 - verification informs, never blocks outright
        verdicts = {}
    blocked: list[str] = []
    for fid in finding_ids:
        row = verdicts.get(fid) or {}
        verdict = str(row.get("verdict") or "UNVERIFIABLE")
        fails = [k for k, v in (row.get("checks") or {}).items()
                 if (v or {}).get("status") == "fail"]
        typer.echo(f"  L1 {verdict}: {fid}" + (f" — failing: {', '.join(fails)}" if fails else ""))
        if verdict != "PROVEN":
            blocked.append(fid)
    if blocked and not reason.strip():
        typer.echo(
            f"Refused: {len(blocked)} finding(s) are not L1-PROVEN. "
            "Pass --reason '<why the examiner accepts them>' to approve anyway:"
        )
        for fid in blocked:
            typer.echo(f"  - {fid}")
        raise typer.Exit(1)

    password = _require_approval_auth(analyst)
    if not password:
        raise typer.Exit(1)

    for fid in finding_ids:
        row = verdicts.get(fid) or {}
        verdict = str(row.get("verdict") or "UNVERIFIABLE")
        result = approve_finding(
            case_dir, fid, analyst, password, note,
            l1_verdict=verdict,
            override_reason=(reason.strip() if verdict != "PROVEN" else ""),
        )
        if result.get("error"):
            typer.echo(f"  ERROR: {result['error']}")
        else:
            typer.echo(f"  APPROVED: {fid}{' — ' + note if note else ''}")

    from nexus.cli.approve import _hmac_signing_key
    if _hmac_signing_key(password, analyst):
        typer.echo("  HMAC verification entry written to ledger")


def _interactive_approve(analyst: str):
    """Walk through DRAFT findings for interactive review."""

    from nexus.cli.approve import _display_item, _require_approval_auth, approve_finding

    password = _require_approval_auth(analyst)
    if not password:
        raise typer.Exit(1)

    case_dir = _resolve_case()
    if not case_dir:
        raise typer.Exit(1)

    findings_path = case_dir / "findings.json"
    if not findings_path.exists():
        typer.echo("No findings file found")
        return

    findings = json.loads(findings_path.read_text())
    drafts = [f for f in findings if f.get("status") == "DRAFT"]

    if not drafts:
        typer.echo("No DRAFT findings to review")
        return

    from nexus.analysis.claim_verification import verify_drafts

    try:
        verdicts = verify_drafts(case_dir)
    except Exception:  # noqa: BLE001 - verification informs, never blocks outright
        verdicts = {}

    typer.echo(f"\n=== {len(drafts)} DRAFT Findings ===\n")
    for item in drafts:
        fid = item.get("id") or item.get("finding_id", "")
        row = verdicts.get(fid) or {}
        verdict = str(row.get("verdict") or "UNVERIFIABLE")
        fails = [k for k, v in (row.get("checks") or {}).items()
                 if (v or {}).get("status") == "fail"]
        typer.echo(_display_item(item, "finding"))
        typer.echo(f"    L1 verdict: {verdict}" + (f" — failing: {', '.join(fails)}" if fails else ""))
        for key, entry in (row.get("checks") or {}).items():
            if (entry or {}).get("status") == "fail":
                typer.echo(f"      {key}: {str(entry.get('detail') or '')[:120]}")
        choice = typer.prompt("  [a]pprove / [r]eject / [s]kip / [q]uit", default="s")

        if choice.lower() == "a":
            override_reason = ""
            if verdict != "PROVEN":
                override_reason = typer.prompt(
                    f"  Override reason (required — L1 {verdict})", default=""
                ).strip()
                if not override_reason:
                    typer.echo("  Not approved: an override reason is required.")
                    typer.echo()
                    continue
            note_text = typer.prompt("  Note (optional)", default="")
            result = approve_finding(
                case_dir, fid, analyst, password, note_text,
                l1_verdict=verdict, override_reason=override_reason,
            )
            if result.get("status") == "APPROVED":
                typer.echo(f"  ✓ APPROVED: {fid}")
        elif choice.lower() == "r":
            reason = typer.prompt("  Reason for rejection", default="")
            _reject_finding(case_dir, fid, analyst, reason)
            typer.echo(f"  ✗ REJECTED: {fid}")
        elif choice.lower() == "q":
            break
        typer.echo()


import json


@app.command()
def reject(
    finding_ids: list[str] = typer.Argument(..., help="Finding IDs to reject"),
    reason: str = typer.Option("", "--reason", "-r", help="Reason for rejection"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Interactive mode"),
):
    """Reject DRAFT findings with a reason (human only, password required)."""
    from nexus.config import settings
    analyst = settings.examiner or os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"

    from nexus.cli.approve import _require_approval_auth
    password = _require_approval_auth(analyst)
    if not password:
        raise typer.Exit(1)

    case_dir = _resolve_case()
    if not case_dir:
        raise typer.Exit(1)

    if interactive:
        findings_path = case_dir / "findings.json"
        if not findings_path.exists():
            typer.echo("No findings file found")
            return
        findings = json.loads(findings_path.read_text())
        from nexus.cli.approve import _display_item
        drafts = [f for f in findings if f.get("status") == "DRAFT"]
        for item in drafts:
            fid = item.get("id") or item.get("finding_id", "")
            typer.echo(_display_item(item, "finding"))
            choice = typer.prompt("  [r]eject / [s]kip", default="s")
            if choice.lower() == "r":
                r = typer.prompt("  Reason", default="")
                _reject_finding(case_dir, fid, analyst, r)
                typer.echo(f"  ✗ REJECTED: {fid}")
        return

    for fid in finding_ids:
        _reject_finding(case_dir, fid, analyst, reason)
        typer.echo(f"  REJECTED: {fid}{' — ' + reason if reason else ''}")


@lock_case_writes
def _reject_finding(case_dir: Path, finding_id: str, analyst: str, reason: str) -> dict:
    from nexus.case.approval_service import commit_rejection

    return commit_rejection(case_dir, finding_id, analyst, reason)


def build_http_app(server, host: str = "127.0.0.1", port: int = 4508):
    """Compose the Starlette app for `serve --http` (portal + MCP transport).

    Extracted from the serve command so the route layout is testable.

    NOTE: mcp 1.x `streamable_http_app()` already serves its endpoint at
    `/mcp`, so it is mounted at `/` here. Mounting it under `/mcp` again
    would move the real endpoint to `/mcp/mcp` and break every MCP client
    configured against `http://host:port/mcp`.
    """
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.routing import Mount

    from nexus.dashboard.app import create_dashboard
    from nexus.mcp_security import McpBearerAuthMiddleware, bearer_token, is_remote_bind
    from nexus.portal import PortalRateLimitMiddleware, SecurityHeadersMiddleware
    from nexus.portal.http_audit import HttpAuditMiddleware

    dashboard_security_headers = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
    }
    routes: list = []
    dashboard_routes = create_dashboard()
    if dashboard_routes:
        routes.extend(dashboard_routes)
    lifespan = None
    try:
        mcp_app = server.streamable_http_app()
        routes.append(Mount("/", app=mcp_app))
        # Starlette does not run a mounted sub-app's lifespan, so run the
        # MCP session manager from the parent app (otherwise every request
        # fails with "Task group is not initialized").
        lifespan = lambda app: server.session_manager.run()  # noqa: E731
        typer.echo(f"  MCP: http://{host}:{port}/mcp (streamable-http)")
    except AttributeError:
        routes.append(Mount("/mcp", app=server.sse_app()))
        typer.echo(f"  MCP: http://{host}:{port}/mcp (SSE fallback)")
    # D28: the MCP endpoint executes host binaries, so a bind that reaches
    # beyond this machine must carry a bearer token. Loopback stays as it was.
    middleware_list = [
        # 4k.3: transport audit runs FIRST so even rate-limited/401
        # requests are recorded with their real status.
        Middleware(HttpAuditMiddleware),
        Middleware(
            PortalRateLimitMiddleware,
            path_prefix="/portal",
            auth_path_prefix="/portal/api/commit",
        ),
        Middleware(
            SecurityHeadersMiddleware,
            path_prefix="/portal",
            headers=dashboard_security_headers,
        ),
    ]
    if is_remote_bind(host):
        middleware_list.append(
            Middleware(McpBearerAuthMiddleware, token=bearer_token())
        )
    return Starlette(
        routes=routes,
        lifespan=lifespan,
        middleware=middleware_list,
    )


@app.command()
def serve(
    http: bool = typer.Option(False, "--http", help="Run as HTTP server"),
    port: int = typer.Option(4508, "--port", "-p", help="HTTP port"),
    host: str = typer.Option("127.0.0.1", "--host", "-H", help="HTTP bind address"),
    dev: bool = typer.Option(
        False, "--dev", help="Debug mode: auto-clean ALL test cases on startup"
    ),
):
    """Start the DFIR-Nexus MCP server.

    Debug mode (--dev or NEXUS_DEBUG_AUTOCLEAN=1) wipes all case folders
    + the case DB on startup — for live testing sessions so test cases never
    accumulate. NEVER use with real case data.
    """
    from nexus.app import create_server
    # Pass bind host into FastMCP so DNS-rebinding allowlist matches
    # client Host headers (fixes SIFT /mcp HTTP 421 for lab IPs).
    server = create_server(host=host)
    if http:
        import uvicorn

        from nexus.mcp_security import build_allowed_hosts
        from nexus.utils.constants import check_required_env

        # Debug auto-clean: wipe all case data on startup (post-testing routine)
        if dev or os.environ.get("NEXUS_DEBUG_AUTOCLEAN", "").strip().lower() in {"1", "true", "yes"}:
            n = _debug_autoclean_cases()
            typer.echo(f"  DEBUG AUTOCLEAN: removed {n} case folder(s) + case DB + active pointer")

        _reap_stale_runs_if_owner()

        try:
            warnings = check_required_env(host=host, port=port)
            for w in warnings:
                typer.echo(f"  WARNING: {w} not set (loopback — OK for local use)")
        except Exception as exc:
            typer.echo(f"  ERROR: {exc}", err=True)
            raise typer.Exit(1) from None

        starlette_app = build_http_app(server, host=host, port=port)
        # In-process pipeline runs (portal "Run pipeline") talk to THIS server
        # over HTTP MCP. Without this default they fall back to stdio and spawn
        # a fresh `nexus serve` child per tool call — each child re-loads RAG +
        # all tools (~20s per call, duplicate GPU loads). Explicit
        # NEXUS_WINDOWS_MCP_URL / NEXUS_GATEWAY_URL always win.
        if not os.environ.get("NEXUS_WINDOWS_MCP_URL", "").strip() and not os.environ.get(
            "NEXUS_GATEWAY_URL", ""
        ).strip():
            dial_host = host if host not in ("0.0.0.0", "::", "") else "127.0.0.1"
            os.environ["NEXUS_WINDOWS_MCP_URL"] = f"http://{dial_host}:{port}/mcp"
            typer.echo(
                f"  Pipeline MCP: {os.environ['NEXUS_WINDOWS_MCP_URL']} "
                "(in-process runs use this server; no stdio child spawns)"
            )
        typer.echo(f"Starting DFIR-Nexus HTTP server on {host}:{port}")
        typer.echo(f"  Portal: http://{host}:{port}/portal")
        allowed = build_allowed_hosts(host)
        typer.echo(f"  MCP Host allowlist: {', '.join(allowed[:8])}{'…' if len(allowed) > 8 else ''}")
        typer.echo("  (extra hosts: NEXUS_MCP_ALLOWED_HOSTS=ip1,ip2)")
        from nexus.mcp_security import is_remote_bind

        typer.echo(
            "  MCP auth: bearer token REQUIRED (non-loopback bind)"
            if is_remote_bind(host)
            else "  MCP auth: none (loopback bind — not reachable off this machine)"
        )
        log_config = None
        try:
            from nexus.portal.http_audit import http_log_config, http_logging_enabled

            if http_logging_enabled():
                cfg = http_log_config()
                log_config = cfg
                typer.echo(
                    "  HTTP logs: "
                    + str(Path(cfg["handlers"]["httpfile"]["filename"]))
                )
        except Exception as exc:  # noqa: BLE001 — logging setup must not block serve
            typer.echo(f"  WARNING: HTTP file logging disabled: {exc}", err=True)
        uvicorn.run(starlette_app, host=host, port=port, log_config=log_config)
    else:
        _reap_stale_runs_if_owner()
        typer.echo("Starting DFIR-Nexus in stdio mode...", err=True)
        server.run()


def _is_pipeline_child() -> bool:
    """True for a per-call MCP child spawned by a pipeline (``NEXUS_MCP_CHILD``).

    Such a child shares the caller's case store and is short-lived; it must not
    reap run records (it would mark its own caller's live run ``interrupted``).
    """
    return bool(os.environ.get("NEXUS_MCP_CHILD", "").strip())


def _reap_stale_runs_if_owner() -> None:
    """Reap ghost runs only from a process that owns a case store of its own."""
    if _is_pipeline_child():
        return
    _reap_stale_runs()


def _reap_stale_runs() -> None:
    """A restart kills in-process lanes; never leave a ghost 'running' record.

    Lane runs execute as threads in this process, so at startup every record
    still marked ``running`` belongs to a dead process and can never finish.
    Marking them ``interrupted`` keeps the portal honest (defect D48).
    """
    try:
        from nexus.langgraph.pipeline_runs import reap_stale_running_runs

        reaped = reap_stale_running_runs()
        if reaped:
            typer.echo(f"  Reaped {len(reaped)} stale 'running' run record(s) -> interrupted")
    except Exception as exc:  # noqa: BLE001 - startup must never block on this
        typer.echo(f"  WARNING: stale-run reap skipped: {exc}", err=True)


def _debug_autoclean_cases() -> int:
    """Debug mode: delete all case folders + case DB before the server starts.

    Enabled by NEXUS_DEBUG_AUTOCLEAN=1 (or `nexus serve --debug-autoclean`).
    Only touches case data under cases_root — never RAG/model caches/config.
    """
    import contextlib
    import shutil

    from nexus.config import settings

    cases_root = settings.cases_root
    removed = 0
    if cases_root.is_dir():
        for d in sorted(cases_root.glob("CASE-*")):
            if d.is_dir():
                shutil.rmtree(d, ignore_errors=True)
                removed += 1
    db_path = cases_root / "cases.db"
    if db_path.exists():
        with contextlib.suppress(OSError):
            db_path.unlink()
    active = Path(
        os.environ.get("NEXUS_ACTIVE_CASE_FILE", str(Path.home() / ".nexus" / "active_case"))
    )
    with contextlib.suppress(OSError):
        active.parent.mkdir(parents=True, exist_ok=True)
        active.write_text("")
    return removed


@app.command()
def portal():
    """Open the Examiner Portal in the default browser."""
    import webbrowser
    url = "http://127.0.0.1:4508/portal"
    typer.echo(f"Opening Examiner Portal at {url}")
    typer.echo("(Start the server first with: nexus serve --http)")
    webbrowser.open(url)


@app.command()
def cross_mode(
    cases: list[str] = typer.Argument(
        [],
        help="Two or more case ids or case directories (siblings)"),
    case: str = typer.Option(
        "", "--case",
        help=(
            "One case id or directory. WO-1C / D5 = C: the three modes now run "
            "on one case, so a single case's own runs are compared."
        ),
    ),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output"),
):
    """Compare cases across their stored modes.

    Two forms, both real comparisons:

    * ``nexus cross-mode CASE-A CASE-B CASE-C`` — sibling cases (identical
      registered evidence) compared across the modes each was run in.
    * ``nexus cross-mode --case CASE-A`` — one case's own Mode 1/2/3 runs,
      which is what D5 = C (one case, three modes) produces. Without this the
      single-case comparison was impossible: the command demanded two
      positional ids and exited 2.
    """
    import json
    from pathlib import Path

    from nexus.analysis.cross_mode import (
        check_cross_mode,
        check_cross_mode_group,
        render_consistency_markdown,
    )
    from nexus.config import settings

    if case and cases:
        typer.echo("give either --case or positional cases, not both", err=True)
        raise typer.Exit(2)
    if case:
        # One case, its own runs — an intra-case comparison.
        p = Path(case)
        if not p.is_dir():
            p = Path(settings.cases_root) / case
        if not p.is_dir():
            typer.echo(f"case not found: {case}", err=True)
            raise typer.Exit(2)
        result = check_cross_mode(case_dir=p)
    else:
        dirs = []
        for c in cases:
            p = Path(c)
            if not p.is_dir():
                p = Path(settings.cases_root) / c
            if not p.is_dir():
                typer.echo(f"case not found: {c}", err=True)
                raise typer.Exit(2)
            dirs.append(p)
        if len(dirs) < 2:
            typer.echo("give at least two cases, or one case with --case", err=True)
            raise typer.Exit(2)

        result = check_cross_mode_group(dirs)
    if as_json:
        typer.echo(json.dumps(result, indent=2, default=str))
    else:
        typer.echo(render_consistency_markdown(result))
    counts = result.get("counts") or {}
    conflicts = int(counts.get("contradictions") or 0) + int(
        counts.get("row_contradictions") or 0
    )
    raise typer.Exit(1 if conflicts else 0)


@app.command()
def pipeline(
    case: str = typer.Option("", "--case", help="Path to evidence directory or file"),
    also: list[str] = typer.Option([], "--also", help="Additional evidence roots on the same case"),
    from_case: str = typer.Option(
        "",
        "--from-case",
        help="Existing case_id. Default mode is interpret (no re-parse). Tools/coverage/design create a new immutable run inside the same case.",
    ),
    resume: bool = typer.Option(False, "--resume", help="Resume from last checkpoint after human approval"),
    model: str = typer.Option("", "--model", help="LLM model (e.g. openai/gpt-4o, ollama/qwen2.5:32b-instruct)"),
    thread: str = typer.Option("", "--thread", help="Thread ID for checkpoint persistence"),
    mode: str = typer.Option(
        "",
        "--mode",
        help=(
            "Pipeline mode: design | coverage | tools | interpret "
            "(tools = parsers only; interpret = reuse --from-case)"
        ),
    ),
    context_policy: str = typer.Option(
        "",
        "--context",
        help=(
            "WO-1C item 3: independent (evidence only) | informed "
            "(prior reports + DRAFT summaries as labelled examiner context)"
        ),
    ),
):
    """Run the investigation pipeline.

    Modes:
      tools            - deterministic tool lane only; TOOL-RUN.md; no LLM
      coverage         - same lane; LLM interprets N4 hits -> DRAFT
      design           - lane first, then ReAct extras, then interpret
      interpret        - reuse an existing tool-run case (--from-case)
      tools + --from-case - new immutable parser run inside the same case

    Also set via NEXUS_PIPELINE_MODE=design|coverage|tools|interpret
    (aliases: react/hunt -> design; debug/full/lane -> coverage;
     tools_only/no_llm -> tools; from_case -> interpret).

    Requires: pip install dfir-nexus[pipeline]

    Environment variables:
        NEXUS_LLM_MODEL / NEXUS_MODEL — model identifier (not required for tools)
        NEXUS_PIPELINE_MODE — design|coverage|tools|interpret
        NEXUS_GATEWAY_URL — HTTP URL for MCP server (default: stdio)
        NEXUS_BEARER_TOKEN — bearer token for HTTP mode
    """
    import asyncio
    try:
        from nexus.langgraph.llm_pipeline import run_pipeline
    except ImportError:
        typer.echo("Pipeline dependencies not installed.", err=True)
        typer.echo("Run: pip install dfir-nexus[pipeline]", err=True)
        raise typer.Exit(1) from None

    cid = (from_case or "").strip()
    resolved_mode = mode or None
    if cid and not resolved_mode:
        resolved_mode = "interpret"
    if not cid and (case or "").strip():
        # `--case` given a CASE DIRECTORY is a run ON that case, not new evidence.
        # Without this the run took the create path, minted `INC-<ts>` and named
        # it "LangGraph Investigation - <id>" — a second case for evidence that
        # already belongs to one (WO-R1F step 0c: a pipeline run on
        # CASE-D6B93BF1 created INC-20261007063311). Resolve the id and reuse.
        _p = Path(case).expanduser()
        if _p.is_dir() and (_p / "CASE.yaml").is_file():
            cid = _p.name
            if not resolved_mode:
                resolved_mode = "interpret"
            typer.echo(
                f"--case is an existing case directory ({cid}); "
                "running on that case instead of creating a new one."
            )
    # WO-1C item 1: a case is no longer locked to one mode (D5 = C). Any mode
    # can run on any case; each run is its own analysis run with its own id,
    # record and model. `investigation_mode` in CASE.yaml is now only the UI's
    # default picker value.
    if cid:
        if not (case or "").strip():
            typer.echo(f"Interpret from existing case {cid} (no re-parse)")
        else:
            typer.echo(f"Reusing case {cid} in mode {resolved_mode}")
    elif resolved_mode in {"interpret", "from_case", "from-case"} and not cid:
        typer.echo("interpret mode needs --from-case <case_id>", err=True)
        raise typer.Exit(1)

    asyncio.run(run_pipeline(
        evidence_path=case,
        resume=resume,
        thread_id=thread,
        model_name=model,
        mode=resolved_mode,
        evidence_paths=also or None,
        case_id=cid,
        context_policy=(context_policy or "").strip() or None,
    ))


@app.command()
def selftest(
    kind: str = typer.Argument("spoliation", help="Which self-test to run"),
    case_dir: Path = typer.Option(None, "--case", help="Existing case to test (default: a fresh fixture case)"),
):
    """Prove the agent cannot delete, overwrite or exfiltrate case evidence.

    WP 10.20 / WO-A6: drives destructive and exfil payloads through the real
    registered tool surface, scans every tool for destructive verbs outside a
    reviewed list, re-hashes all evidence after the run, and tampers with a
    copy of the audit log to prove the verifier names the record. Any probe
    that is not refused fails the command — it never becomes a skipped check.
    """
    if kind != "spoliation":
        typer.echo(f"Unknown self-test: {kind} (available: spoliation)")
        raise typer.Exit(2)

    from nexus.analysis.spoliation import (
        build_fixture_case,
        render_report,
        run_spoliation_selftest,
    )

    fixture_root: Path | None = None
    if case_dir is None:
        import tempfile

        fixture_root = Path(tempfile.mkdtemp(prefix="nexus-selftest-"))
        case_dir = build_fixture_case(fixture_root)

    try:
        report = run_spoliation_selftest(case_dir)
    finally:
        if fixture_root is not None:
            import shutil

            shutil.rmtree(fixture_root, ignore_errors=True)

    typer.echo(render_report(report))
    if not report["ok"]:
        raise typer.Exit(1)


@app.command()
def update(
    check: bool = typer.Option(False, "--check", help="Only check for updates"),
    no_restart: bool = typer.Option(False, "--no-restart", help="Don't restart after update"),
):
    """Pull latest code from git and rebuild."""
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    if not (repo_root / ".git").exists():
        typer.echo("Not a git repository — cannot auto-update")
        return

    typer.echo(f"Repository: {repo_root}")
    head_before = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=repo_root).stdout.strip()

    if check:
        subprocess.run(["git", "fetch"], cwd=repo_root)
        head_remote = subprocess.run(["git", "rev-parse", "origin/main"], capture_output=True, text=True, cwd=repo_root).stdout.strip()
        if head_before == head_remote:
            typer.echo("Already up to date")
        else:
            typer.echo(f"Update available: {head_before[:8]} -> {head_remote[:8]}")
        return

    result = subprocess.run(["git", "pull", "--ff-only"], capture_output=True, text=True, cwd=repo_root)
    if result.returncode != 0:
        typer.echo(f"Git pull failed: {result.stderr}", err=True)
        return

    typer.echo(result.stdout.strip())

    head_after = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=repo_root).stdout.strip()
    if head_before != head_after:
        typer.echo(f"Updated: {head_before[:8]} -> {head_after[:8]}")
        typer.echo("Reinstalling package...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-e", "."], cwd=repo_root)
        typer.echo("Update complete")
    else:
        typer.echo("Already up to date")


@app.command()
def setup(
    target: str = typer.Argument("test", help="'test' for connectivity, 'client' for LLM config"),
    sift: str = typer.Option(None, "--sift", help="SIFT server URL"),
    windows: str = typer.Option(None, "--windows", help="Windows server URL"),
    remnux: str = typer.Option(None, "--remnux", help="REMnux server URL"),
    client: str = typer.Option("", "--client", help="Client type: claude-code, claude-desktop, other"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Auto-confirm with defaults"),
    uninstall: bool = typer.Option(False, "--uninstall", help="Remove DFIR-Nexus config"),
):
    """Test connectivity or generate LLM client configuration.

    \b
    Examples:
      nexus setup test                      # Test local connectivity
      nexus setup client                    # Interactive LLM config wizard
      nexus setup client --sift 10.0.0.2:4508 --windows 10.0.0.5:4508  # Multi-server
      nexus setup client --uninstall        # Remove config
    """
    if target == "test":
        _run_connectivity_test()
    elif target == "client":
        from nexus.cli.setup_cmd import cmd_setup_client
        cmd_setup_client(args=type("Args", (), {
            "sift": sift, "windows": windows, "remnux": remnux,
            "client": client, "yes": yes, "uninstall": uninstall,
            "no_mslearn": False,
        })())
    else:
        typer.echo(f"Unknown: '{target}'. Use: test, client")


def _run_connectivity_test():
    """Test connectivity to the MCP server and key services."""

    typer.echo("\n=== Connectivity Test ===\n")
    results = []

    from nexus.app import create_server
    try:
        create_server()
        results.append(("Server creation", True, ""))
    except Exception as e:
        results.append(("Server creation", False, str(e)))

    import importlib.util
    if importlib.util.find_spec("chromadb") is not None:
        results.append(("Chromadb (RAG)", True, ""))
    else:
        results.append(("Chromadb (RAG)", False, "pip install dfir-nexus[rag]"))

    if importlib.util.find_spec("pycti") is not None:
        results.append(("pycti (OpenCTI)", True, ""))
    else:
        results.append(("pycti (OpenCTI)", False, "pip install dfir-nexus[opencti]"))

    triage_db = Path.home() / ".nexus" / "data" / "triage"
    if triage_db.exists() and any(triage_db.iterdir()):
        results.append(("Triage databases", True, str(triage_db)))
    else:
        results.append(("Triage databases", False, "Run triage_download()"))

    rag_db = Path.home() / ".nexus" / "data" / "rag"
    if rag_db.exists() and (rag_db / "chroma").exists():
        results.append(("RAG index", True, str(rag_db / "chroma")))
    else:
        results.append(("RAG index", False, "Run forensic_rag_download()"))

    for name, ok, detail in results:
        status_mark = "+" if ok else "-"
        typer.echo(f"  [{status_mark}] {name}: {detail}")


if __name__ == "__main__":
    app()
