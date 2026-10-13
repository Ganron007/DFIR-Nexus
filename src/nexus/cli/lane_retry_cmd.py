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
from collections import Counter
from pathlib import Path

import typer


def retry_summary_line(ledger: list[dict]) -> str:
    """The retry's outcome, with every status counted as itself: a SKIP or BLOCKED row is not an OK row."""
    counts = Counter(str(row.get("status") or "").upper() for row in ledger)
    return (
        f"Retry complete: {counts.get('OK', 0)} OK, {counts.get('SKIP', 0)} SKIP, "
        f"{counts.get('BLOCKED', 0)} BLOCKED, {counts.get('FAIL', 0)} FAIL of {len(ledger)} job(s)."
    )


def retry(
    case: str = typer.Option("", "--case", help="Case id or directory (required)."),
    tool: str = typer.Option(
        "", "--tool",
        help="Re-run only these tools (comma list, e.g. hayabusa,evtxecmd) in the same run. Their OK jobs "
             "run again; every other row of the run is kept as it is.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be retried and exit."
    ),
) -> None:
    """Complete the run in place: re-run the FAIL jobs and run every planned job that has no OK row yet.

    Every OK row of the run is carried into the new ledger and never re-run. A job waiting on the SIFT host
    runs here once the host is available. An examiner's skip still holds. With --tool, only the named tools
    are planned and run, and every other row is kept as it is.
    """
    tools = {part.strip().lower() for part in tool.replace(";", ",").split(",") if part.strip()}

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

    if tools:
        # A tool re-run: every job of the named tools runs again, its OK rows included. SKIP rows
        # are examiner decisions (or a planner's own skip) and stay as they are; the plain retry
        # picks up a planner skip once its job becomes runnable.
        failed = [
            row for row in ledger
            if str(row.get("tool") or "").lower() in tools
            and str(row.get("status") or "").upper() != "SKIP"
        ]
        if not failed:
            typer.echo(
                f"No rows for {', '.join(sorted(tools))} in the lane ledger - nothing to re-run.",
                err=True,
            )
            raise typer.Exit(1)
    else:
        failed = [row for row in ledger if str(row.get("status") or "").upper() == "FAIL"]
        if not failed:
            # Nothing failed, but the pass still runs: a planned job can be waiting (on the SIFT host, or
            # planned since the last pass). Every OK row is carried, so nothing that passed runs again.
            typer.echo("No FAIL rows: the pass runs what is still pending; every OK row is carried, not re-run.")

    if failed:
        verb = "to re-run" if tools else "to retry"
        typer.echo(f"{len(failed)} job(s) {verb} in {run_dir.name}:")
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

    typer.echo(f"Running the pass in {run_dir.name}...")
    result = asyncio.run(
        _run_retry(case_dir, run_dir.name, evidence_paths,
                   rerun_tools=frozenset(tools), only_tools=frozenset(tools))
    )
    ledger_now = result.get("tool_run_ledger") or []
    still = [
        row for row in ledger_now
        if str(row.get("status") or "").upper() == "FAIL"
        and (not tools or str(row.get("tool") or "").lower() in tools)
    ]
    typer.echo(retry_summary_line(ledger_now))
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
    _index_retried_output(case_dir)


def _index_retried_output(case_dir: Path) -> None:
    """Index what the retry wrote, as the lane does after a batch (incremental).

    The retried jobs write new parsed tables into the run. Without this step they stay out of
    the index until someone indexes the case by hand.
    """
    from nexus.langgraph.case_index import es_available, index_case

    if not es_available():
        typer.echo(
            "Elasticsearch is not reachable: the retried output is not indexed yet. "
            "Run `nexus index` once it is.",
            err=True,
        )
        return
    meta = index_case(case_dir, incremental=True) or {}
    typer.echo(f"Indexed: {int(meta.get('docs') or 0)} docs in {meta.get('index') or 'the case index'}")


async def _run_retry(
    case_dir: Path,
    run_id: str,
    evidence_paths: list[str],
    rerun_tools: frozenset[str] = frozenset(),
    only_tools: frozenset[str] = frozenset(),
) -> dict:
    """Load the MCP tools the way the pipeline does, then run the lane in the same run.

    One session per MCP server stays open for the whole retry (D71): without it every job's
    call opened its own session, and over stdio that started a new server for each job.
    """
    import contextlib

    from nexus.langgraph.llm_pipeline import _load_mcp_tools, _parse_tool_result, get_mcp_config
    from nexus.langgraph.tool_lane import run_tool_lane

    async with contextlib.AsyncExitStack() as sessions:
        tools = await _load_mcp_tools(get_mcp_config(), sessions=sessions)
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
            rerun_tools=rerun_tools or None,
            carry_ok=True,
            only_tools=only_tools or None,
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
    typer.echo("--case is required: name the case this command acts on.", err=True)
    raise typer.Exit(1)
