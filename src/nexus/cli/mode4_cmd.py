"""Mode 4 CLI — concurrent multi-agent runtime.

Product label: Mode 3 — Multi-agent. Run ids use the M4- prefix.
"""
from __future__ import annotations

import json
from pathlib import Path

import typer

app = typer.Typer(help="Concurrent multi-agent investigation (Mode 4 runtime)")


def _case_dir(case_id: str):
    from nexus.cli.main import _resolve_case

    case_dir = _resolve_case(case_id)
    if not case_dir:
        typer.echo("No active case. Create/activate one or pass --case.", err=True)
        raise typer.Exit(1)
    return case_dir


def _question(case_dir, explicit: str) -> str:
    if explicit.strip():
        return explicit.strip()
    try:
        from nexus.langgraph.query_pack import load_case_intake

        return str(load_case_intake(case_dir).get("question") or "")
    except Exception:  # noqa: BLE001
        return ""


@app.command()
def run(
    question: str = typer.Option("", "--question", "-q"),
    case: str = typer.Option("", "--case"),
    as_json: bool = typer.Option(False, "--json"),
):
    """Start a concurrent multi-agent run and wait for it to finish."""
    from nexus.langgraph.llm_pipeline import get_model
    from nexus.langgraph.mode4_runtime import run_mode4

    case_dir = _case_dir(case)
    try:
        model = get_model()
    except Exception:  # noqa: BLE001
        model = None
    record = run_mode4(case_dir, _question(case_dir, question), model=model)
    if as_json:
        typer.echo(json.dumps(record, default=str))
    else:
        typer.echo(
            f"{record.get('run_id')}  {record.get('status')}  "
            f"stop={record.get('stop_reason')}  "
            f"candidates={len(record.get('candidates') or [])}"
        )
    if record.get("status") == "failed":
        raise typer.Exit(1)


@app.command()
def status(
    run_id: str = typer.Option("", "--run-id"),
    case: str = typer.Option("", "--case"),
    as_json: bool = typer.Option(False, "--json"),
):
    """Show the latest or named multi-agent run."""
    from nexus.langgraph.mode4_runtime import latest_run_id, read_run_record

    case_dir = _case_dir(case)
    run_id = run_id or latest_run_id(case_dir)
    record = read_run_record(case_dir, run_id) if run_id else None
    if record is None:
        typer.echo("No Mode 4 run.", err=True)
        raise typer.Exit(1)
    if as_json:
        typer.echo(json.dumps(record, default=str))
        return
    typer.echo(
        f"{record.get('run_id')}  {record.get('status')}  "
        f"disputes={len(record.get('disputes') or [])}  "
        f"board={len(record.get('board') or [])}"
    )


@app.command()
def board(
    run_id: str = typer.Option("", "--run-id"),
    case: str = typer.Option("", "--case"),
):
    """Print board claims and open disputes."""
    from nexus.langgraph.mode4_runtime import latest_run_id, read_run_record

    case_dir = _case_dir(case)
    run_id = run_id or latest_run_id(case_dir)
    record = read_run_record(case_dir, run_id) if run_id else None
    if record is None:
        typer.echo("No Mode 4 run.", err=True)
        raise typer.Exit(1)
    for entry in record.get("board") or []:
        typer.echo(f"{entry.get('agent_id')}  claims={len(entry.get('claims') or [])}")
    for dispute in record.get("disputes") or []:
        typer.echo(
            f"dispute  {dispute.get('entity_value')}  {dispute.get('claim_kind')}"
        )


@app.command()
def stop(
    run_id: str = typer.Option("", "--run-id"),
    case: str = typer.Option("", "--case"),
):
    """Request a stop at the next superstep boundary."""
    from nexus.langgraph.mode4_runtime import latest_run_id, request_stop_run

    case_dir = _case_dir(case)
    run_id = run_id or latest_run_id(case_dir)
    if not run_id or not request_stop_run(case_dir, run_id):
        typer.echo("Run not found.", err=True)
        raise typer.Exit(1)
    typer.echo(f"stop requested {run_id}")


@app.command()
def steer(
    text: str = typer.Argument(..., help="Examiner directive"),
    run_id: str = typer.Option("", "--run-id"),
    case: str = typer.Option("", "--case"),
):
    """Queue a steer line for the supervisor's next superstep."""
    from nexus.langgraph.mode4_runtime import (
        append_mode4_steering,
        emit_event,
        latest_run_id,
        new_event,
        read_run_record,
    )

    case_dir = _case_dir(case)
    run_id = run_id or latest_run_id(case_dir)
    record = read_run_record(case_dir, run_id) if run_id else None
    if record is None:
        typer.echo("No Mode 4 run.", err=True)
        raise typer.Exit(1)
    entry = append_mode4_steering(case_dir, run_id, text)
    emit_event(case_dir, run_id, new_event(
        run_id, "steering.injected", actor="examiner", detail=text,
        data={"steering": entry}))
    typer.echo(f"steering queued for {run_id}")


@app.command()
def pause(
    run_id: str = typer.Option("", "--run-id"),
    case: str = typer.Option("", "--case"),
):
    """Pause at the next superstep boundary."""
    from nexus.langgraph.mode4_runtime import (
        emit_event,
        latest_run_id,
        mark_paused,
        new_event,
    )

    case_dir = _case_dir(case)
    run_id = run_id or latest_run_id(case_dir)
    if not run_id or not mark_paused(case_dir, run_id, True):
        typer.echo("Run not found.", err=True)
        raise typer.Exit(1)
    emit_event(case_dir, run_id, new_event(
        run_id, "run.pause_requested", actor="examiner",
        detail="pause requested — halts at the next superstep boundary"))
    typer.echo(f"pause requested {run_id}")


@app.command()
def resume(
    run_id: str = typer.Option("", "--run-id"),
    case: str = typer.Option("", "--case"),
    no_run: bool = typer.Option(False, "--no-run",
                                help="Only clear the pause flag"),
):
    """Continue a paused run from its persisted board/superstep snapshot."""
    from nexus.langgraph.mode4_runtime import (
        latest_run_id,
        mark_paused,
        read_run_record,
        resume_mode4,
    )

    case_dir = _case_dir(case)
    run_id = run_id or latest_run_id(case_dir)
    record = read_run_record(case_dir, run_id) if run_id else None
    if record is None:
        typer.echo("No Mode 4 run.", err=True)
        raise typer.Exit(1)
    status = str(record.get("status") or "")
    if status != "paused":
        typer.echo(f"Run is {status}; nothing to resume.", err=True)
        raise typer.Exit(1)
    mark_paused(case_dir, run_id, False)
    typer.echo(f"resuming {run_id}")
    if no_run:
        return
    from nexus.langgraph.llm_pipeline import get_model

    try:
        model = get_model()
    except Exception:  # noqa: BLE001
        model = None
    result = resume_mode4(case_dir, run_id, model=model)
    typer.echo(
        f"{result.get('run_id')}  {result.get('status')}  "
        f"stop={result.get('stop_reason')}  "
        f"candidates={len(result.get('candidates') or [])}"
    )


@app.command("export")
def export(
    run_id: str = typer.Option("", "--run-id"),
    case: str = typer.Option("", "--case"),
    output: Path = typer.Option(..., "--output", help="Output JSON path"),
):
    """Export the run record + full event stream."""
    from nexus.langgraph.mode4_runtime import (
        latest_run_id,
        read_run_events,
        read_run_record,
    )

    case_dir = _case_dir(case)
    run_id = run_id or latest_run_id(case_dir)
    record = read_run_record(case_dir, run_id) if run_id else None
    if record is None:
        typer.echo("No Mode 4 run.", err=True)
        raise typer.Exit(1)
    payload = {
        "record": record,
        "events": read_run_events(case_dir, run_id, limit=100000),
    }
    output.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    typer.echo(f"Wrote {output} ({len(payload['events'])} events)")


@app.command("stage")
def stage(
    run_id: str = typer.Option("", "--run-id"),
    case: str = typer.Option("", "--case"),
    as_json: bool = typer.Option(False, "--json"),
):
    """Stage settled candidates as DRAFT. Does not approve."""
    from nexus.langgraph.mode4_runtime import latest_run_id, stage_mode4

    case_dir = _case_dir(case)
    run_id = run_id or latest_run_id(case_dir)
    if not run_id:
        typer.echo("No Mode 4 run.", err=True)
        raise typer.Exit(1)
    result = stage_mode4(case_dir, run_id)
    typer.echo(json.dumps(result, default=str) if as_json else
               f"staged={result.get('staged_count', len(result.get('staged') or []))} "
               f"skipped={result.get('skipped_count', len(result.get('skipped') or []))}")
