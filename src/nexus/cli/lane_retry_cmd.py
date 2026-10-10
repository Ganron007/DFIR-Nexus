"""WO-TA item 12: retry the failed jobs of a lane run.

A lane run is 400+ jobs and around an hour of tool time. When a job fails, the only
recovery must not be a full re-run that redoes the work that succeeded. The lane's
reuse rule (``apply_prior_ok``) skips every job that already finished OK in the run's
ledger, so a retry runs only the rows that failed.

This reads the lane ledger of the case's tools run, and runs the lane again inside
that same run, with the Windows and SIFT tools loaded the way the pipeline loads them.
The lane's own planner and executor do the work, so a retried job is planned and run
exactly as it was the first time.

It never touches a passing job: an OK row is reused, not re-run. SKIP rows are
examiner decisions and stay as they are.
"""
from __future__ import annotations

import json
from pathlib import Path

import typer


def retry(
    case: str = typer.Option("", "--case", help="Case id or directory. Default: the active case."),
    tool: str = typer.Option(
        "", "--tool",
        help="Not supported yet: a retry re-runs every FAIL job in the run.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be retried and exit."
    ),
) -> None:
    """Re-run only the jobs that FAILED, inside the same run.

    The lane ledger is the source of truth: every row marked FAIL is a job that did not
    process its evidence. Those are run again; OK rows are reused, not re-run. SKIP rows
    are left alone - they are examiner decisions, and a retry must not silently undo one.
    """
    from nexus.langgraph.lane_gate import lane_gate_blocked

    if tool.strip():
        typer.echo(
            "--tool is not supported yet: a retry re-runs every FAIL job in the run. "
            "Run `nexus lane retry --dry-run` to see them.",
            err=True,
        )
        raise typer.Exit(1)

    case_dir = _resolve(case)
    ledger, run_dir = _load_ledger(case_dir)
    if not ledger:
        typer.echo("No lane ledger for this case - run the lane first.", err=True)
        raise typer.Exit(1)
    if run_dir is None:
        typer.echo(
            "The lane ledger is not in a run folder, so the retry cannot run inside its "
            "run. Re-run the lane instead.",
            err=True,
        )
        raise typer.Exit(1)

    failed = [row for row in ledger if str(row.get("status") or "").upper() == "FAIL"]
    if not failed:
        typer.echo("No FAIL rows in the lane ledger - nothing to retry.")
        if lane_gate_blocked(case_dir):
            typer.echo(
                "The gate is blocked by something other than a failed job "
                "(unprocessed evidence, or an examiner skip). `nexus lane status` "
                "names it.",
                err=True,
            )
            raise typer.Exit(1)
        return

    typer.echo(f"{len(failed)} failed job(s) to retry in {run_dir.name}:")
    for row in failed:
        typer.echo(
            f"  {row.get('tool')}  {str(row.get('purpose') or '')[:70]}  "
            f"— {str(row.get('reason') or row.get('error') or '')[:60]}"
        )

    if dry_run:
        typer.echo("Dry run - nothing executed.")
        return

    evidence_paths = _run_evidence_paths(run_dir)
    if not evidence_paths:
        typer.echo(
            "The run's manifest names no evidence paths, so the retry cannot be planned. "
            "Re-run the lane instead.",
            err=True,
        )
        raise typer.Exit(1)

    import asyncio

    typer.echo(f"Re-running the failed jobs in {run_dir.name}...")
    result = asyncio.run(_run_retry(case_dir, run_dir.name, evidence_paths))
    ledger_now = result.get("tool_run_ledger") or []
    still = [row for row in ledger_now if str(row.get("status") or "").upper() == "FAIL"]
    typer.echo(
        f"Retry complete: {len(ledger_now) - len(still)} of {len(ledger_now)} "
        f"job(s) now OK, {len(still)} still failing."
    )
    if still:
        for row in still[:10]:
            typer.echo(f"  STILL FAILING {row.get('tool')}: "
                       f"{str(row.get('reason') or '')[:70]}")
        raise typer.Exit(1)
    # The gate is re-derived from the new ledger, so a cleared failure clears the gate
    # rather than leaving it blocked on stale state.
    from nexus.langgraph.lane_gate import write_lane_gate

    gate = write_lane_gate(case_dir, run_dir.name, ledger_now)
    if gate.get("status") == "blocked":
        typer.echo(
            f"Gate still blocked by {gate.get('blocked_count')} item(s) - "
            "`nexus lane status` names them."
        )


async def _run_retry(case_dir: Path, run_id: str, evidence_paths: list[str]) -> dict:
    """Load the MCP tools the way the pipeline does, then run the lane in the same run.

    One event loop, so the MCP sessions stay open for the whole retry.
    """
    from nexus.langgraph.llm_pipeline import _load_mcp_tools, _parse_tool_result, get_mcp_config
    from nexus.langgraph.tool_lane import run_tool_lane

    tools = await _load_mcp_tools(get_mcp_config())
    if "run_windows_command" not in tools:
        typer.echo(
            "The Windows MCP server did not answer: set NEXUS_WINDOWS_MCP_URL and start "
            "`nexus serve --http`. Nothing was re-run.",
            err=True,
        )
        raise typer.Exit(1)
    return await run_tool_lane(
        tools=tools,
        evidence_path=evidence_paths[0],
        case_id=case_dir.name,
        run_id=run_id,
        case_context={},
        parse_result=_parse_tool_result,
        skip_rag=True,
        pipeline_mode="tools",
        evidence_paths=evidence_paths,
    )


def _read_rows(path: Path) -> list[dict]:
    """The rows of one ledger file, in either shape the lane has written."""
    if not path.is_file():
        return []
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(loaded, dict):
        loaded = loaded.get("ledger") or loaded.get("rows") or []
    if not isinstance(loaded, list):
        return []
    return [row for row in loaded if isinstance(row, dict)]


def _load_ledger(case_dir) -> tuple[list[dict], Path | None]:
    """The lane ledger of the case's tools run, and that run's folder.

    The run is the one the pipeline resolves as the active tools run (committed or
    newest with data), the same run the lane's reuse rule reads. A case made before runs
    existed keeps its flat ledger, which has no run folder to retry into.
    """
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    try:
        run_extractions = resolve_tools_extractions(Path(case_dir))
    except Exception:  # noqa: BLE001 - no run yet: fall through to the legacy ledgers
        run_extractions = None
    if run_extractions is not None:
        rows = _read_rows(run_extractions / "_tool_lane_ledger.json")
        if rows:
            run_dir = run_extractions.parent
            is_run = run_dir.parent.name == "runs"
            return rows, run_dir if is_run else None
    for path in (
        Path(case_dir) / "extractions" / "_tool_lane_ledger.json",
        Path(case_dir) / "ledger" / "_tool_lane_ledger.json",
    ):
        rows = _read_rows(path)
        if rows:
            return rows, None
    return [], None


def _run_evidence_paths(run_dir: Path) -> list[str]:
    """The evidence paths the run was started with, from the run's own manifest."""
    try:
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [str(p) for p in (manifest.get("evidence_paths") or []) if str(p).strip()]


def _resolve(case: str):
    from nexus.case.outputs import resolve_active_case_dir
    from nexus.config import settings

    case_id = (case or "").strip()
    if case_id:
        from nexus.discipline import validate_case_id

        if validate_case_id(case_id):
            typer.echo(f"Invalid case id: {case_id}", err=True)
            raise typer.Exit(1)
        candidate = settings.cases_root / case_id
        if not candidate.is_dir():
            typer.echo(f"Case not found: {candidate}", err=True)
            raise typer.Exit(1)
        return candidate
    resolved = resolve_active_case_dir()
    if resolved is None:
        typer.echo("No active case - pass --case.", err=True)
        raise typer.Exit(1)
    return resolved
