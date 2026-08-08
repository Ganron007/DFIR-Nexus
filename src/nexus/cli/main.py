"""DFIR-Nexus CLI — human-only operations.

The full CLI surface (19 top-level commands). For background on which
operations are human-only and why, see Docs/ARCHITECTURE.md.

Usage:
    nexus serve [--http] [--port]          Start MCP server
    nexus approve [ids...] [--note]        Approve DRAFT findings (password required)
    nexus reject <ids...> [--reason]       Reject findings
    nexus report --full                    Generate report
    nexus backup /path                     Backup case
    nexus restore /path                    Restore case
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
    nexus review [--findings]              Review case state
    nexus config [--examiner] [--setup-password]  Configure
    nexus export bundle.json               Export case bundle (positional)
    nexus merge bundle.json                Import case bundle (positional)
    nexus exec --purpose "reason" cmd      Run command with audit
    nexus audit log                        View audit trail
    nexus audit summary                    Audit summary
    nexus todo list                        List TODOs
    nexus todo add "description"           Add TODO
    nexus todo complete TODO-001           Complete TODO
    nexus portal                           Open Examiner Portal
    nexus setup client                     Generate LLM client config
    nexus setup test                       Test connectivity
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

from nexus.cli.audit_cmd import app as audit_app
from nexus.cli.backup import app as backup_app
from nexus.cli.case_cmd import app as case_app
from nexus.cli.config_cmd import app as config_app
from nexus.cli.evidence import app as evidence_app
from nexus.cli.exec_cmd import app as exec_app
from nexus.cli.init_cmd import init as init_cmd
from nexus.cli.report import app as report_app
from nexus.cli.review import app as review_app
from nexus.cli.service import app as service_app
from nexus.cli.sync import app as sync_app
from nexus.cli.todo import app as todo_app

app = typer.Typer(name="nexus", help="DFIR-Nexus — unified DFIR investigation platform")

app.add_typer(report_app, name="report", help="Generate investigation reports")
app.add_typer(backup_app, name="backup", help="Backup and restore cases")
app.add_typer(case_app, name="case", help="Manage investigation cases")
app.add_typer(evidence_app, name="evidence", help="Manage evidence")
app.add_typer(review_app, name="review", help="Review case state")
app.add_typer(config_app, name="config", help="Manage examiner configuration")
app.add_typer(service_app, name="service", help="Manage MCP services")
app.add_typer(sync_app, name="export", help="Export case bundle")
app.add_typer(sync_app, name="merge", help="Merge case bundle")
app.add_typer(exec_app, name="exec", help="Execute forensic command with audit trail")
app.add_typer(audit_app, name="audit", help="View audit trail")
app.add_typer(todo_app, name="todo", help="Manage TODO items")
# Registered as a direct command (not a sub-group) so the documented
# `nexus init "Case" --evidence ...` form works.
app.command(name="init", help="Quickstart — one-command onboarding")(init_cmd)

_ACTIVE_CASE_FILE = Path.home() / ".nexus" / "active_case"


def _resolve_case(case_id: str = "") -> Path | None:
    if case_id:
        case_dir = Path.home() / ".nexus" / "cases" / case_id
        if not case_dir.exists():
            typer.echo(f"Case not found: {case_id}", err=True)
            return None
        return case_dir
    if _ACTIVE_CASE_FILE.exists():
        content = _ACTIVE_CASE_FILE.read_text().strip()
        if content:
            case_dir = Path(content) if Path(content).is_absolute() else Path.home() / ".nexus" / "cases" / content
            if case_dir.exists():
                return case_dir
    typer.echo("No active case. Use 'nexus case activate' or 'nexus case init'", err=True)
    return None


@app.command()
def approve(
    finding_ids: list[str] = typer.Argument(None, help="Finding IDs to approve"),
    note: str = typer.Option("", "--note", help="Examiner note"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Interactive review mode"),
):
    """Approve DRAFT findings (requires password — blocks AI approval)."""
    from nexus.config import settings
    analyst = settings.examiner or os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"

    if interactive:
        _interactive_approve(analyst)
        return

    if not finding_ids:
        typer.echo("Usage: nexus approve <finding_id> [finding_id...] or nexus approve --interactive")
        raise typer.Exit(1)

    from nexus.cli.approve import _require_approval_auth, approve_finding
    password = _require_approval_auth(analyst)
    if not password:
        raise typer.Exit(1)

    case_dir = _resolve_case()
    if not case_dir:
        raise typer.Exit(1)

    for fid in finding_ids:
        result = approve_finding(case_dir, fid, analyst, password, note)
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

    typer.echo(f"\n=== {len(drafts)} DRAFT Findings ===\n")
    for item in drafts:
        fid = item.get("id") or item.get("finding_id", "")
        typer.echo(_display_item(item, "finding"))
        choice = typer.prompt("  [a]pprove / [r]eject / [s]kip / [q]uit", default="s")

        if choice.lower() == "a":
            note_text = typer.prompt("  Note (optional)", default="")
            result = approve_finding(case_dir, fid, analyst, password, note_text)
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
from datetime import UTC


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


def _reject_finding(case_dir: Path, finding_id: str, analyst: str, reason: str) -> dict:
    findings_path = case_dir / "findings.json"
    if not findings_path.exists():
        return {"error": "No findings file found"}
    findings = json.loads(findings_path.read_text())
    for f in findings:
        fid = f.get("id") or f.get("finding_id", "")
        if fid == finding_id and f.get("status") == "DRAFT":
            f["status"] = "REJECTED"
            f["rejected_by"] = analyst
            f["rejected_at"] = datetime.now(UTC).isoformat()
            f["rejection_reason"] = reason
            findings_path.write_text(json.dumps(findings, indent=2, default=str))
            return {"finding_id": finding_id, "status": "REJECTED"}
    return {"error": f"Finding {finding_id} not found or not DRAFT"}


from datetime import datetime


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
    from nexus.portal import PortalRateLimitMiddleware, SecurityHeadersMiddleware

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
    return Starlette(
        routes=routes,
        lifespan=lifespan,
        middleware=[
            Middleware(
                PortalRateLimitMiddleware,
                limit_per_minute=120,
                auth_limit_per_minute=30,
                path_prefix="/portal",
                auth_path_prefix="/portal/api/commit",
            ),
            Middleware(
                SecurityHeadersMiddleware,
                path_prefix="/portal",
                headers=dashboard_security_headers,
            ),
        ],
    )


@app.command()
def serve(
    http: bool = typer.Option(False, "--http", help="Run as HTTP server"),
    port: int = typer.Option(4508, "--port", "-p", help="HTTP port"),
    host: str = typer.Option("127.0.0.1", "--host", "-H", help="HTTP bind address"),
):
    """Start the DFIR-Nexus MCP server."""
    from nexus.app import create_server
    server = create_server()
    if http:
        import uvicorn

        from nexus.utils.constants import check_required_env
        try:
            warnings = check_required_env(host=host, port=port)
            for w in warnings:
                typer.echo(f"  WARNING: {w} not set (loopback — OK for local use)")
        except Exception as exc:
            typer.echo(f"  ERROR: {exc}", err=True)
            raise typer.Exit(1)

        starlette_app = build_http_app(server, host=host, port=port)
        typer.echo(f"Starting DFIR-Nexus HTTP server on {host}:{port}")
        typer.echo(f"  Portal: http://{host}:{port}/portal")
        uvicorn.run(starlette_app, host=host, port=port)
    else:
        typer.echo("Starting DFIR-Nexus in stdio mode...", err=True)
        server.run()


@app.command()
def portal():
    """Open the Examiner Portal in the default browser."""
    import webbrowser
    url = "http://127.0.0.1:4508/portal"
    typer.echo(f"Opening Examiner Portal at {url}")
    typer.echo("(Start the server first with: nexus serve --http)")
    webbrowser.open(url)


@app.command()
def pipeline(
    case: str = typer.Option("", "--case", help="Path to evidence directory or file"),
    resume: bool = typer.Option(False, "--resume", help="Resume from last checkpoint after human approval"),
    model: str = typer.Option("", "--model", help="LLM model (e.g. openai/gpt-4o, ollama/qwen2.5:32b-instruct)"),
    thread: str = typer.Option("", "--thread", help="Thread ID for checkpoint persistence"),
):
    """Run the LLM-driven investigation pipeline.

    Connects to the MCP server, drives a 6-node investigation graph
    using an LLM (Anthropic/OpenAI/Ollama), stages DRAFT findings,
    pauses for human approval, then generates a report.

    Requires: pip install dfir-nexus[pipeline]

    Environment variables:
        NEXUS_MODEL — model identifier (default: claude-sonnet-4-20250514)
        NEXUS_GATEWAY_URL — HTTP URL for MCP server (default: stdio)
        NEXUS_BEARER_TOKEN — bearer token for HTTP mode
    """
    import asyncio
    try:
        from nexus.langgraph.llm_pipeline import run_pipeline
    except ImportError:
        typer.echo("Pipeline dependencies not installed.", err=True)
        typer.echo("Run: pip install dfir-nexus[pipeline]", err=True)
        raise typer.Exit(1)

    asyncio.run(run_pipeline(
        evidence_path=case,
        resume=resume,
        thread_id=thread,
        model_name=model,
    ))


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
        server = create_server()
        results.append(("Server creation", True, ""))
    except Exception as e:
        results.append(("Server creation", False, str(e)))

    try:
        import chromadb
        results.append(("Chromadb (RAG)", True, ""))
    except ImportError:
        results.append(("Chromadb (RAG)", False, "pip install dfir-nexus[rag]"))

    try:
        from pycti import OpenCTIApiClient
        results.append(("pycti (OpenCTI)", True, ""))
    except ImportError:
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
