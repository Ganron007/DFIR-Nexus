"""Mode 3 CLI — same agent runtime and event stream as the portal.

Commands wrap the in-process Mode 3 runtime, so the CLI and UI share one
implementation, one event envelope and one audit path. No HTTP server is
required for the CLI; the portal calls the same runtime.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import typer

app = typer.Typer(help="Mode 3 agentic investigation (supervised runtime)")


def _case_dir(case_id: str) -> Path:
    from nexus.cli.main import _resolve_case

    case_dir = _resolve_case(case_id)
    if not case_dir:
        typer.echo("No active case. Create/activate one or pass --case.", err=True)
        raise typer.Exit(1)
    return case_dir


def _resolve_model():
    try:
        from nexus.langgraph.llm_pipeline import get_model

        return get_model()
    except Exception:  # noqa: BLE001 — roles have deterministic fallbacks
        return None


def _question(case_dir: Path, explicit: str) -> str:
    if explicit.strip():
        return explicit.strip()
    try:
        from nexus.langgraph.query_pack import load_case_intake

        return str(load_case_intake(case_dir).get("question") or "")
    except Exception:  # noqa: BLE001
        return ""


def _print_event(event: dict) -> None:
    kind = str(event.get("event_type") or "")
    agent = str(event.get("agent_id") or "")
    tool = str(event.get("tool") or "")
    audit = str(event.get("audit_id") or "")
    detail = str(event.get("detail") or "")
    parts = [str(event.get("ts") or "")[:19], kind]
    if agent:
        parts.append(agent)
    if tool:
        parts.append(tool)
    if audit:
        parts.append(f"audit={audit}")
    if detail:
        parts.append(detail)
    typer.echo("  ".join(parts))


@app.command()
def plan(
    question: str = typer.Option("", "--question", "-q", help="Question/task"),
    case: str = typer.Option("", "--case", help="Case id (default active)"),
    max_orders: int = typer.Option(6, "--max-orders", min=1, max=12),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output"),
):
    """Propose work orders without executing them."""
    from nexus.langgraph.mode3_runtime import (
        EventSink,
        examiner_feedback,
        plan_work_orders,
    )

    case_dir = _case_dir(case)
    run_id = f"M3-plan-{int(time.time())}"
    orders = plan_work_orders(
        case_dir, _question(case_dir, question), run_id=run_id,
        sink=EventSink(case_dir, run_id), max_orders=max_orders,
        known_findings=examiner_feedback(case_dir),
    )
    rows = [o.to_dict() for o in orders]
    if as_json:
        typer.echo(json.dumps({"run_id": run_id, "orders": rows}, indent=2,
                              default=str))
        return
    typer.echo(f"Plan {run_id}: {len(rows)} work order(s)")
    for order in rows:
        typer.echo(
            f"  [{order['role']}] {order['order_id']}: {order['task'][:160]}"
            + (f" (family={order['family']})" if order.get("family") else "")
        )


@app.command()
def run(
    question: str = typer.Option("", "--question", "-q", help="Question/task"),
    case: str = typer.Option("", "--case", help="Case id (default active)"),
    run_id: str = typer.Option("", "--run-id", help="Resume/reuse a run id"),
    max_orders: int = typer.Option(6, "--max-orders", min=1, max=12),
    output: Path = typer.Option(None, "--output", help="Write the run record JSON"),
):
    """Run the supervised Mode 3 investigation, streaming agent events."""
    from nexus.langgraph.mode3_runtime import run_mode3

    case_dir = _case_dir(case)
    run_id = run_id.strip()
    typer.echo(f"Mode 3 run on {case_dir.name}"
               + (f" ({run_id})" if run_id else ""))
    state = run_mode3(
        case_dir, _question(case_dir, question),
        model=_resolve_model(), run_id=run_id, on_event=_print_event,
        max_orders=max_orders, resume=bool(run_id),
    )
    typer.echo(
        f"run_id={state.get('run_id')} status={state.get('status')} "
        f"stop={state.get('stop_reason')} orders="
        f"{state.get('order_index')}/{len(state.get('orders') or [])} "
        f"candidates={len(state.get('candidates') or [])}"
    )
    if output is not None:
        output.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
        typer.echo(f"Wrote {output}")


@app.command()
def status(
    case: str = typer.Option("", "--case", help="Case id (default active)"),
    run_id: str = typer.Option("", "--run-id", help="Run id (default latest)"),
    as_json: bool = typer.Option(False, "--json"),
):
    """Show the current/last Mode 3 run state."""
    from nexus.langgraph.mode3_runtime import (
        latest_run_id,
        read_controls,
        read_run_events,
        read_run_record,
    )

    case_dir = _case_dir(case)
    run_id = run_id.strip() or latest_run_id(case_dir)
    record = read_run_record(case_dir, run_id) if run_id else None
    if record is None:
        typer.echo("No Mode 3 run found", err=True)
        raise typer.Exit(1)
    events = read_run_events(case_dir, run_id, limit=5000)
    controls = read_controls(case_dir, run_id)
    payload = {
        "run_id": run_id,
        "status": record.get("status"),
        "stop_reason": record.get("stop_reason"),
        "pause_requested": controls["pause_requested"],
        "stop_requested": controls["stop_requested"],
        "orders": len(record.get("orders") or []),
        "order_index": record.get("order_index") or 0,
        "results": len(record.get("results") or []),
        "candidates": len(record.get("candidates") or []),
        "gaps": len(record.get("gaps") or []),
        "events": len(events),
    }
    if as_json:
        typer.echo(json.dumps(payload, indent=2, default=str))
        return
    for key, value in payload.items():
        typer.echo(f"  {key}: {value}")


@app.command()
def steer(
    text: str = typer.Argument(..., help="Examiner directive"),
    case: str = typer.Option("", "--case", help="Case id (default active)"),
    run_id: str = typer.Option("", "--run-id", help="Run id (default latest)"),
):
    """Inject a directive the agents pick up on the next work order."""
    from nexus.langgraph.mode3_runtime import (
        EventSink,
        append_steering,
        latest_run_id,
        new_event,
        read_run_record,
    )

    case_dir = _case_dir(case)
    run_id = run_id.strip() or latest_run_id(case_dir)
    if not run_id or read_run_record(case_dir, run_id) is None:
        typer.echo("No Mode 3 run found", err=True)
        raise typer.Exit(1)
    entry = append_steering(case_dir, run_id, text)
    EventSink(case_dir, run_id).emit(new_event(
        run_id, "steering.injected", actor="examiner", detail=text,
        data={"steering": entry}))
    typer.echo(f"Steering recorded for {run_id}: {text[:200]}")


@app.command()
def pause(
    case: str = typer.Option("", "--case", help="Case id (default active)"),
    run_id: str = typer.Option("", "--run-id", help="Run id (default latest)"),
):
    """Pause the run between work orders."""
    from nexus.langgraph.mode3_runtime import latest_run_id, mark_paused

    case_dir = _case_dir(case)
    run_id = run_id.strip() or latest_run_id(case_dir)
    if not run_id or not mark_paused(case_dir, run_id, True):
        typer.echo("No Mode 3 run found", err=True)
        raise typer.Exit(1)
    typer.echo(f"Pause requested for {run_id}")


@app.command()
def stop(
    case: str = typer.Option("", "--case", help="Case id (default active)"),
    run_id: str = typer.Option("", "--run-id", help="Run id (default latest)"),
):
    """Halt a run at the next work order (cooperative stop, not approval)."""
    from nexus.langgraph.mode3_runtime import (
        EventSink,
        latest_run_id,
        new_event,
        read_run_record,
        request_stop,
    )

    case_dir = _case_dir(case)
    run_id = run_id.strip() or latest_run_id(case_dir)
    if not run_id or read_run_record(case_dir, run_id) is None:
        typer.echo("No Mode 3 run found", err=True)
        raise typer.Exit(1)
    request_stop(case_dir, run_id)
    EventSink(case_dir, run_id).emit(new_event(
        run_id, "run.stop_requested", actor="examiner",
        detail="stop requested — halts before the next work order"))
    typer.echo(f"Stop requested for {run_id} (run halts after the current "
               "work order; DRAFTs are not staged or approved).")


@app.command()
def resume(
    case: str = typer.Option("", "--case", help="Case id (default active)"),
    run_id: str = typer.Option("", "--run-id", help="Run id (default latest)"),
    no_run: bool = typer.Option(False, "--no-run", help="Only clear the pause flag"),
):
    """Clear the pause flag and continue the run."""
    from nexus.langgraph.mode3_runtime import (
        latest_run_id,
        mark_paused,
        read_run_record,
        run_mode3,
    )

    case_dir = _case_dir(case)
    run_id = run_id.strip() or latest_run_id(case_dir)
    record = read_run_record(case_dir, run_id) if run_id else None
    if record is None:
        typer.echo("No Mode 3 run found", err=True)
        raise typer.Exit(1)
    status = str(record.get("status") or "")
    if status in ("stopped", "completed", "failed"):
        typer.echo(f"Run is {status}; start a new run.", err=True)
        raise typer.Exit(1)
    mark_paused(case_dir, run_id, False)
    typer.echo(f"Resumed {run_id}")
    if no_run:
        return
    state = run_mode3(
        case_dir, str(record.get("question") or ""),
        model=_resolve_model(), run_id=run_id, on_event=_print_event, resume=True,
    )
    typer.echo(f"status={state.get('status')} stop={state.get('stop_reason')}")


@app.command()
def findings(
    case: str = typer.Option("", "--case", help="Case id (default active)"),
    run_id: str = typer.Option("", "--run-id", help="Run id (default latest)"),
    as_json: bool = typer.Option(False, "--json"),
):
    """List DRAFT candidate findings from a run (never approved here)."""
    from nexus.langgraph.mode3_runtime import latest_run_id, read_run_record

    case_dir = _case_dir(case)
    run_id = run_id.strip() or latest_run_id(case_dir)
    record = read_run_record(case_dir, run_id) if run_id else None
    if record is None:
        typer.echo("No Mode 3 run found", err=True)
        raise typer.Exit(1)
    candidates = record.get("candidates") or []
    if as_json:
        typer.echo(json.dumps(candidates, indent=2, default=str))
        return
    if not candidates:
        typer.echo("No candidate findings (status/stage may not have reached synthesis).")
        return
    for candidate in candidates:
        typer.echo(f"- {candidate.get('title') or '(untitled)'} "
                   f"[{candidate.get('confidence') or '?'}] "
                   f"audit_ids={','.join(candidate.get('audit_ids') or [])}")


@app.command()
def stage(
    case: str = typer.Option("", "--case", help="Case id (default active)"),
    run_id: str = typer.Option("", "--run-id", help="Run id (default latest)"),
    as_json: bool = typer.Option(False, "--json"),
):
    """Stage a run's verified candidates as DRAFT findings (examiner action).

    Skips candidates without real audit_ids (FD-001) and verifier-refuted
    candidates. Staged findings keep run_id/input_call_ids lineage; approval
    stays password-gated with the examiner.
    """
    from nexus.langgraph.mode3_runtime import (
        latest_run_id,
        read_run_record,
        stage_run_candidates,
    )

    case_dir = _case_dir(case)
    run_id = run_id.strip() or latest_run_id(case_dir)
    record = read_run_record(case_dir, run_id) if run_id else None
    if record is None:
        typer.echo("No Mode 3 run found", err=True)
        raise typer.Exit(1)
    result = stage_run_candidates(case_dir, run_id)
    if as_json:
        typer.echo(json.dumps(result, indent=2, default=str))
        return
    typer.echo(f"Staged {result.get('staged_count', 0)} DRAFT finding(s); "
               f"skipped {result.get('skipped_count', 0)}")
    for entry in result.get("staged") or []:
        typer.echo(
            f"  DRAFT {entry.get('finding_id')}: {entry.get('title')} "
            f"({len(entry.get('input_call_ids') or [])} audit id(s))"
        )
    for entry in result.get("skipped") or []:
        typer.echo(f"  skipped: {entry.get('title')} — {entry.get('reason')}")
    typer.echo("DRAFT only — approval stays with the examiner (`nexus approve`).")


@app.command()
def export(
    case: str = typer.Option("", "--case", help="Case id (default active)"),
    run_id: str = typer.Option("", "--run-id", help="Run id (default latest)"),
    output: Path = typer.Option(..., "--output", help="Output JSON path"),
):
    """Export the run record + event stream for review/backup."""
    from nexus.langgraph.mode3_runtime import (
        latest_run_id,
        read_run_events,
        read_run_record,
    )

    case_dir = _case_dir(case)
    run_id = run_id.strip() or latest_run_id(case_dir)
    record = read_run_record(case_dir, run_id) if run_id else None
    if record is None:
        typer.echo("No Mode 3 run found", err=True)
        raise typer.Exit(1)
    payload = {
        "record": record,
        "events": read_run_events(case_dir, run_id, limit=100000),
    }
    output.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    typer.echo(f"Wrote {output} ({len(payload['events'])} events)")
