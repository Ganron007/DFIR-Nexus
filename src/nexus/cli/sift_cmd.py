"""``nexus sift`` — the SIFT lane: selection, reachability, and Option B ingest.

SIFT is an explicitly selected, always-optional lane. Selecting it marks SIFT
analysis as required (``sift_required``) — the only switch that can refuse
analysis when the host is unreachable. Recovery is exactly three paths: bring
the host up and re-run, clear the selection (``nexus sift disable``), or the
examiner's audited skip. Nothing else is ever skipped.
"""
from __future__ import annotations

from pathlib import Path

import typer

app = typer.Typer(help="SIFT lane: status, selection, and SIFT-output ingest.")


def _resolve_case_dir(case: str) -> Path:
    from pathlib import Path as _P

    if case:
        candidate = _P(case)
        if candidate.is_dir():
            return candidate
        for base in (_P.home() / ".nexus" / "cases", _P("cases")):
            hit = base / case
            if hit.is_dir():
                return hit
        typer.echo(f"case not found: {case}")
        raise typer.Exit(1)
    from nexus.case.outputs import resolve_active_case_dir

    try:
        case_dir = resolve_active_case_dir()
    except Exception:  # noqa: BLE001
        case_dir = None
    if case_dir is None:
        typer.echo("No active case. Pass --case <id|dir>.")
        raise typer.Exit(1)
    return case_dir


def _context(case_dir: Path) -> dict[str, str]:
    import yaml

    meta_path = case_dir / "CASE.yaml"
    if not meta_path.is_file():
        return {}
    loaded = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
    intake = loaded.get("intake") if isinstance(loaded, dict) else None
    return {str(k): str(v) for k, v in (intake or {}).items() if v is not None}


def _required(ctx: dict[str, str]) -> bool:
    return (ctx.get("sift_required") or "").strip().lower() in ("1", "true", "yes")


@app.command("status")
def status(case: str = typer.Option("", "--case", help="Case id or directory. Default: the active case.")):
    """Show the SIFT lane selection, evidence paths, and reachability."""
    from nexus.case.sift_sync import sift_reachable

    case_dir = _resolve_case_dir(case)
    ctx = _context(case_dir)
    required = _required(ctx)
    typer.echo(f"case: {case_dir.name}")
    typer.echo(f"SIFT lane selected (sift_required): {'yes' if required else 'no'}")
    for key in ("sift_evidence_root", "sift_memory_file", "sift_disk_image", "sift_os"):
        if ctx.get(key):
            typer.echo(f"  {key}: {ctx[key]}")
    try:
        ok, msg = sift_reachable()
    except Exception as exc:  # noqa: BLE001
        ok, msg = False, str(exc)
    typer.echo(f"SIFT reachable: {'yes' if ok else 'NO'} ({msg[:120]})")
    import os

    mcp = os.environ.get("NEXUS_SIFT_MCP_URL", "").strip()
    typer.echo(f"SIFT MCP URL: {mcp or '(not set - NEXUS_SIFT_MCP_URL)'}")
    if required and not ok:
        typer.echo("")
        typer.echo("SIFT is REQUIRED for this case and unreachable - analysis will refuse. "
                   "Recoveries: bring the host up and re-run; `nexus sift disable`; "
                   "or the examiner's audited skip (`nexus lane skip`).")
        raise typer.Exit(1)


@app.command("enable")
def enable(case: str = typer.Option("", "--case", help="Case id or directory. Default: the active case.")):
    """Mark SIFT analysis as required for this case and run the online check."""
    from nexus.case.sift_sync import sift_reachable
    from nexus.langgraph.case_intake import persist_case_intake

    case_dir = _resolve_case_dir(case)
    persist_case_intake(case_dir, {"sift_required": "true"})
    typer.echo(f"SIFT required: on ({case_dir.name})")
    try:
        ok, msg = sift_reachable()
    except Exception as exc:  # noqa: BLE001
        ok, msg = False, str(exc)
    typer.echo(f"online check: {'reachable' if ok else 'UNREACHABLE'} ({msg[:120]})")
    if not ok:
        typer.echo("Analysis will refuse until the host is up, the selection is "
                   "cleared (`nexus sift disable`), or an audited skip is recorded.")


@app.command("disable")
def disable(case: str = typer.Option("", "--case", help="Case id or directory. Default: the active case.")):
    """Clear the SIFT selection (a first-class recovery path)."""
    from nexus.langgraph.case_intake import clear_case_intake

    case_dir = _resolve_case_dir(case)
    remaining = clear_case_intake(case_dir, ("sift_required",))
    typer.echo(f"SIFT required: cleared ({case_dir.name})")
    if remaining.get("sift_evidence_root"):
        typer.echo("Note: sift_evidence_root is kept; without the selection its jobs "
                   "SKIP with reasons (never a refusal).")


@app.command("setup")
def setup(
    case: str = typer.Option("", "--case", help="Case id or directory to lay out on the SIFT host"),
):
    """Verify the SIFT host and wire it up (Phase 5 bootstrap).

    Checks SSH reachability, the SIFT default toolset, the Nexus checkout +
    venv and free disk; lays out the per-case folders; starts the SIFT-side
    MCP when it is not already listening; prints the examiner .env block and
    hands off to `nexus doctor --gate` + `nexus sift enable`.
    """
    import os
    import subprocess
    from pathlib import Path as _P

    host = os.environ.get("NEXUS_SIFT_SSH_HOST", "192.168.77.135").strip()
    user = os.environ.get("NEXUS_SIFT_SSH_USER", "sansforensics").strip()
    key = os.environ.get(
        "NEXUS_SIFT_SSH_KEY", str(_P.home() / ".ssh" / "cadre-sift-key")
    ).strip()

    if not _P(key).is_file():
        typer.echo(f"SSH key missing: {key}", err=True)
        raise typer.Exit(1)

    def _ssh(remote: str, timeout: int = 60) -> tuple[int, str]:
        cmd = [
            "ssh", "-i", key, "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            f"{user}@{host}", remote,
        ]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 1, str(exc)
        return p.returncode, (p.stdout or "") + (p.stderr or "")

    typer.echo(f"SIFT setup - {user}@{host}")
    rc, out = _ssh("hostname; uname -r")
    if rc != 0:
        typer.echo(f"  SSH: FAILED — {out.strip()[:200]}", err=True)
        raise typer.Exit(1)
    typer.echo(f"  SSH: OK ({out.strip().splitlines()[0]})")

    rc, out = _ssh(
        "for t in vol log2timeline.py psort.py fls mmls icat mactime bulk_extractor; do "
        "command -v $t >/dev/null 2>&1 && echo OK-$t || echo MISS-$t; done"
    )
    tools = [ln for ln in out.splitlines() if ln.startswith(("OK-", "MISS-"))]
    missing = [t.split("-", 1)[1] for t in tools if t.startswith("MISS-")]
    typer.echo(
        f"  tools: {sum(1 for t in tools if t.startswith('OK-'))}/{len(tools)} present"
        + (f" — MISSING: {', '.join(missing)}" if missing else "")
    )

    rc, out = _ssh(
        "if [ -x ~/DFIR-Nexus/.venv/bin/python ]; then "
        "~/DFIR-Nexus/.venv/bin/python -c 'import nexus; print(nexus.__file__)'; "
        "else echo NO-VENV; fi"
    )
    if "NO-VENV" in out or rc != 0:
        typer.echo("  nexus on SIFT: NOT INSTALLED (expected ~/DFIR-Nexus with .venv)", err=True)
    else:
        typer.echo(f"  nexus on SIFT: OK ({out.strip().splitlines()[-1]})")

    rc, out = _ssh("df -h ~ | tail -1 | awk '{print $4}'")
    typer.echo(f"  disk free: {out.strip() or '?'}")

    if case:
        name = _P(case).name
        rc, out = _ssh(
            f"mkdir -p ~/.nexus/cases/{name}/evidence "
            f"~/.nexus/cases/{name}/extractions ~/.nexus/cases/{name}/analysis "
            "&& echo LAYOUT-OK"
        )
        if "LAYOUT-OK" in out:
            typer.echo(f"  layout: ~/.nexus/cases/{name}/{{evidence,extractions,analysis}} ready")

    # SIFT-side MCP: start it when it is not already listening.
    rc, out = _ssh("ss -ltn 2>/dev/null | grep -q ':4508' && echo MCP-UP || echo MCP-DOWN")
    if "MCP-UP" in out:
        typer.echo("  MCP: listening on :4508")
    else:
        typer.echo("  MCP: not running — starting it...")
        start = (
            "cd ~/DFIR-Nexus && "
            "[ -f ~/.nexus/sift-mcp.env ] || { SEC=$(openssl rand -hex 32); "
            "printf 'NEXUS_AUDIT_SECRET=%s\\nNEXUS_PORTAL_PASSWORD=siftmcp-%s\\n"
            f"NEXUS_MCP_ALLOWED_HOSTS={host}\\n' \"$SEC\" \"$SEC\" > ~/.nexus/sift-mcp.env; "
            "chmod 600 ~/.nexus/sift-mcp.env; }; "
            "set -a; . ~/.nexus/sift-mcp.env; set +a; "
            "setsid nohup .venv/bin/python -m nexus serve --http --host 0.0.0.0 "
            "--port 4508 < /dev/null > /tmp/nexus-mcp.log 2>&1 & "
            "sleep 12; ss -ltn 2>/dev/null | grep -q ':4508' && echo MCP-UP || echo MCP-FAILED"
        )
        rc, out = _ssh(start, timeout=120)
        typer.echo(f"  MCP: {'listening on :4508' if 'MCP-UP' in out else 'FAILED — see /tmp/nexus-mcp.log'}")

    typer.echo("")
    typer.echo("Examiner .env block (or export for the serve session):")
    typer.echo(f"  NEXUS_SIFT_SSH_HOST={host}")
    typer.echo(f"  NEXUS_SIFT_SSH_USER={user}")
    typer.echo(f"  NEXUS_SIFT_SSH_KEY={key}")
    typer.echo(f"  NEXUS_SIFT_MCP_URL=http://{host}:4508/mcp")
    typer.echo("Next: `nexus doctor --gate`, then `nexus sift enable --case <case>` "
               "(evidence itself is copied by the examiner into "
               "~/.nexus/cases/<case>/evidence/ on the host).")


@app.command("ingest")
def ingest(
    path: str = typer.Argument(..., help="SIFT outputs: a file, a directory, or a .zip"),
    case: str = typer.Option("", "--case", help="Case id or directory. Default: the active case."),
    family: str = typer.Option(
        "", "--as", help="Destination family name (plaso / vol / fls / bulk_extractor) for mapping"
    ),
):
    """Option B - stage SIFT-produced outputs for indexing (no SIFT host needed)."""
    from nexus.case.sift_ingest import stage_sift_outputs

    case_dir = _resolve_case_dir(case)
    src = Path(path)
    staged = stage_sift_outputs(case_dir, [src], family=family)
    for dest in staged:
        n = sum(1 for _ in dest.rglob("*") if _.is_file())
        typer.echo(f"staged: {dest.relative_to(case_dir)}  ({n} file(s))")
    typer.echo("Next: run the indexer (`nexus index rebuild` or the pipeline) so the rows "
               "land in the case index with the mapped fields.")
