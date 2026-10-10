"""WO-TA item 12: retry one failed job.

A lane run is 400+ jobs and around an hour of tool time. When one job fails, the
only recovery was to re-run the entire lane - which, thanks to the reuse key
(`_job_reuse_key`), would skip the 399 that succeeded and redo the one that
failed, but only after re-planning and re-discovering everything, and only if
the examiner could articulate that as a command.

This reads the lane ledger, takes the FAIL rows, and re-plans only those jobs.
It reuses the same planner the lane uses, so a retried job is planned exactly as
it would have been the first time - no second planning path to drift.

It never touches a passing job: the reuse key means a re-run of the whole lane
is safe, but a retry that re-ran healthy jobs would waste the examiner's time
and could change results underneath an in-flight analysis.
"""
from __future__ import annotations

from pathlib import Path

import typer


def retry(
    case: str = typer.Option("", "--case", help="Case id or directory. Default: the active case."),
    tool: str = typer.Option("", "--tool", help="Only retry this tool (e.g. evtxecmd)."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be retried and exit."
    ),
) -> None:
    """Re-run only the jobs that FAILED, without re-running the whole lane.

    The lane ledger is the source of truth: every row marked FAIL is a job that
    did not process its evidence. Those, and only those, are re-planned and
    re-executed. SKIP rows are left alone - they are examiner decisions, and a
    retry must not silently undo one.
    """
    from nexus.langgraph.lane_gate import lane_gate_blocked

    case_dir = _resolve(case)
    ledger = _load_ledger(case_dir)
    if not ledger:
        typer.echo("No lane ledger for this case - run the lane first.", err=True)
        raise typer.Exit(1)

    failed = [
        row for row in ledger
        if str(row.get("status") or "").upper() == "FAIL"
        and (not tool or str(row.get("tool") or "") == tool)
    ]
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

    typer.echo(f"{len(failed)} failed job(s) to retry:")
    for row in failed:
        typer.echo(
            f"  {row.get('tool')}  {str(row.get('purpose') or '')[:70]}  "
            f"— {str(row.get('reason') or row.get('error') or '')[:60]}"
        )

    if dry_run:
        typer.echo("Dry run - nothing executed.")
        return

    # Re-plan only these. The reuse key keeps the healthy jobs from being
    # re-run if the examiner later re-runs the whole lane anyway.
    import asyncio

    from nexus.langgraph.tool_lane import plan_windows_triage, run_tool_lane

    evidence = str(failed[0].get("evidence_path") or "")
    if not evidence:
        typer.echo(
            "The failed rows do not name their evidence path, so the jobs cannot "
            "be re-planned safely. Re-run the lane instead.",
            err=True,
        )
        raise typer.Exit(1)

    jobs = []
    for row in failed:
        planned = plan_windows_triage(
            evidence,
            extractions=case_dir / "extractions",
            extras=[str(row.get("tool") or "")],
        )
        jobs.extend(
            job for job in planned
            if str(job.tool) == str(row.get("tool"))
        )
    if not jobs:
        typer.echo("Nothing re-plannable for those rows.", err=True)
        raise typer.Exit(1)

    typer.echo(f"Re-running {len(jobs)} job(s)...")
    result = asyncio.run(
        run_tool_lane(
            tools={},
            evidence_path=evidence,
            case_id=case_dir.name,
            run_id=str(failed[0].get("run_id") or ""),
            parse_result=lambda _r: {},
            skip_rag=True,
            pipeline_mode="tools",
            evidence_paths=[evidence],
        )
    )
    ledger_now = result.get("ledger") or []
    still = [
        row for row in ledger_now
        if str(row.get("status") or "").upper() == "FAIL"
    ]
    typer.echo(
        f"Retry complete: {len(ledger_now) - len(still)} of {len(ledger_now)} "
        f"job(s) now OK, {len(still)} still failing."
    )
    if still:
        for row in still[:10]:
            typer.echo(f"  STILL FAILING {row.get('tool')}: "
                       f"{str(row.get('reason') or '')[:70]}")
        raise typer.Exit(1)
    # The gate is re-derived from the new ledger, so a cleared failure clears
    # the gate rather than leaving it blocked on stale state.
    from nexus.langgraph.lane_gate import write_lane_gate

    gate = write_lane_gate(case_dir, str(failed[0].get("run_id") or ""), ledger_now)
    if gate.get("status") == "blocked":
        typer.echo(
            f"Gate still blocked by {gate.get('blocked_count')} item(s) - "
            "`nexus lane status` names them."
        )


def _load_ledger(case_dir) -> list[dict]:
    """The lane ledger, from the paths `apply_prior_ok` reads.

    Deliberately the same two paths and the same JSON shape, so a retry and a
    reuse decision can never disagree about what ran.
    """
    import json

    rows: list[dict] = []
    for path in (
        Path(case_dir) / "extractions" / "_tool_lane_ledger.json",
        Path(case_dir) / "ledger" / "_tool_lane_ledger.json",
    ):
        if not path.is_file():
            continue
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(loaded, list):
            rows = [row for row in loaded if isinstance(row, dict)]
            break
        if isinstance(loaded, dict):
            inner = loaded.get("ledger") or loaded.get("rows")
            if isinstance(inner, list):
                rows = [row for row in inner if isinstance(row, dict)]
                break
    return rows


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
