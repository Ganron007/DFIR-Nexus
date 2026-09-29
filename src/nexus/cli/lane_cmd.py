"""``nexus lane`` — evidence gate control (N2). Never skip evidence processing.

The gate blocks every analysis stage while the tools lane has left an artifact
unprocessed. This CLI mirrors the portal: `status` shows the gate + the N1-N8
stage states, `skip` records the examiner's audited decision (password-verified,
the same credential as `nexus approve`).
"""
from __future__ import annotations

import typer

app = typer.Typer(help="Evidence gate (N2): never skip evidence processing.")


def _resolve_case_dir(case: str):
    from pathlib import Path

    if case:
        candidate = Path(case)
        if candidate.is_dir():
            return candidate
        for base in (Path.home() / ".nexus" / "cases", Path("cases")):
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


@app.command("status")
def status(case: str = typer.Option("", "--case", help="Case id or directory. Default: the active case.")) -> None:
    """Show the evidence gate and the N1-N8 stage states."""
    from nexus.langgraph.lane_gate import (
        lane_gate_blocked,
        lane_stages,
        read_lane_gate,
    )

    case_dir = _resolve_case_dir(case)
    gate = read_lane_gate(case_dir)
    if gate:
        typer.echo(f"evidence gate: {gate.get('status')} (run {gate.get('run_id') or '-'})")
        for item in gate.get("unprocessed") or []:
            typer.echo(f"  UNPROCESSED  {item.get('tool')}: {item.get('purpose')} "
                       f"({str(item.get('reason') or '')[:120]})")
        for skip in gate.get("examiner_skips") or []:
            typer.echo(f"  SKIPPED by {skip.get('examiner')} at {skip.get('ts')}: "
                       f"{skip.get('tool')} {skip.get('purpose')} - {skip.get('reason')}")
    else:
        typer.echo("evidence gate: no tool-lane pass recorded yet")
    typer.echo("")
    for stage in lane_stages(case_dir):
        typer.echo(f"  {stage['stage']}  {stage['status']:<12}{stage['detail']}")
    if lane_gate_blocked(case_dir):
        typer.echo("")
        typer.echo("Gate is BLOCKED - analysis stages will refuse to start until "
                   "the lane re-runs the item or you record `nexus lane skip`.")
        raise typer.Exit(1)


@app.command("skip")
def skip(
    case: str = typer.Option("", "--case", help="Case id or directory. Default: the active case."),
    reason: str = typer.Option(..., "--reason", help="Why this evidence is skipped (recorded, required)."),
    examiner: str = typer.Option("", "--examiner", help="Examiner id. Default: the active case's examiner."),
) -> None:
    """Record an audited examiner skip for unprocessed evidence.

    Password-verified with the same store as `nexus approve`; the decision is
    written into the gate file and the case audit log. A skip is an explicit,
    attributable decision - never a silent omission.
    """
    import getpass

    from nexus.auth import verify_password
    from nexus.langgraph.lane_gate import examiner_skip, lane_gate_blocked

    case_dir = _resolve_case_dir(case)
    gate = lane_gate_blocked(case_dir)
    if not gate:
        typer.echo("The evidence gate is not blocked - nothing to skip.")
        raise typer.Exit(0)

    who = examiner.strip()
    if not who:
        try:
            import yaml

            meta = yaml.safe_load((case_dir / "CASE.yaml").read_text(encoding="utf-8")) or {}
            who = str(meta.get("examiner") or "").strip()
        except Exception:  # noqa: BLE001
            who = ""
    if not who:
        typer.echo("Pass --examiner <id> (no examiner recorded in CASE.yaml).")
        raise typer.Exit(1)

    password = getpass.getpass(f"Password for {who}: ")
    if not verify_password(who, password):
        typer.echo("Incorrect password.")
        raise typer.Exit(1)

    out = examiner_skip(case_dir, examiner=who, reason=reason)
    try:
        from nexus.audit import AuditWriter

        AuditWriter("nexus", audit_dir=case_dir / "audit").log(
            tool="lane_gate_skip",
            params={"examiner": who, "reason": reason[:200], "scope": "all"},
            result_summary={"added": out.get("added"),
                            "status": (out.get("gate") or {}).get("status")},
            source="cli",
        )
    except Exception:  # noqa: BLE001 - the skip itself already succeeded
        pass
    typer.echo(f"Recorded {out.get('added')} skip(s); gate is now "
               f"{(out.get('gate') or {}).get('status')}.")
