"""``nexus verify-claims`` — the Level 1 mechanical claim check.

Answers the gate question: is every claim the case made actually true? Nine
checks per claim, each with its own verdict, and an explicit
``UNVERIFIABLE`` for anything that could not be checked. A missing input is
never reported as a pass, so a case that parsed nothing cannot grade clean just
because the checks had nothing to read.

Exits non-zero on any UNSUPPORTED or CONTRADICTED claim, and on
UNVERIFIABLE, because a gate cannot be signed on unknowns.
"""

from __future__ import annotations

import json

import typer


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


def verify_claims(
    case: str = typer.Option("", "--case", help="Case id or case directory. Default: the active case."),
    as_json: bool = typer.Option(False, "--json", help="Emit the full ledger as JSON."),
    persist: bool = typer.Option(
        False, "--persist", help="Write analysis/claim_ledger.json (default: read-only)."
    ),
) -> None:
    """Verify every claim in a case: citations, entities, techniques, times, counts."""
    from nexus.analysis.claim_verification import (
        VERDICTS,
        render_ledger_markdown,
        verify_case,
        write_ledger,
    )

    case_dir = _resolve_case_dir(case)
    ledger = verify_case(case_dir)
    if persist:
        path = write_ledger(case_dir, ledger)
        typer.echo(f"wrote {path}")

    if as_json:
        typer.echo(json.dumps(ledger, indent=2, sort_keys=True, default=str))
    else:
        typer.echo(f"case: {case_dir.name}  ({case_dir})")
        typer.echo(render_ledger_markdown(ledger).rstrip())

    counts = ledger.get("verdict_counts") or {}
    typer.echo("")
    typer.echo("  ".join(f"{v}={counts.get(v, 0)}" for v in VERDICTS))
    # Anything other than all-PROVEN fails the gate, UNVERIFIABLE included: a
    # check that could not be run is an open question, not a clean bill.
    clean = bool(ledger.get("claims")) and counts.get("PROVEN") == len(ledger["claims"])
    raise typer.Exit(0 if clean else 1)
