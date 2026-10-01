"""`nexus finding ...` (WO-A4 / WP 13.4).

The exhibit is the only sub-command today: it is the reproducibility bundle an
examiner hands a third party. Approved findings only, read-only on case data.
"""
from __future__ import annotations

import json
from pathlib import Path

import typer

app = typer.Typer(no_args_is_help=True, help="Inspect findings")


def _resolve_case(case_id: str) -> Path | None:
    from nexus.analysis.finding_exhibit import resolve_case_dir

    if case_id:
        return resolve_case_dir(case_id)
    from nexus.case.outputs import resolve_active_case_dir

    return resolve_active_case_dir()


@app.command("exhibit")
def exhibit(
    finding_id: str = typer.Argument(..., help="the approved finding to bundle"),
    case: str = typer.Option("", "--case", help="case id (default: the active case)"),
    out: str = typer.Option("", "--out", help="directory for the zip (default: a temp dir)"),
    verify: bool = typer.Option(
        False, "--verify", help="also re-run the recorded argv and diff the cited rows"
    ),
) -> None:
    """Build the reproducibility bundle for an approved finding."""
    from nexus.analysis.finding_exhibit import (
        ExhibitRefused,
        build_exhibit,
        verify_row_reproduced,
    )

    case_dir = _resolve_case(case)
    if case_dir is None:
        typer.echo("No case selected. Pass --case or activate a case.", err=True)
        raise typer.Exit(code=2)

    dest = Path(out) if out else None
    try:
        zip_path = build_exhibit(case_dir, finding_id, dest_dir=dest)
    except ExhibitRefused as exc:
        typer.echo(f"Refused: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(str(zip_path))
    if verify:
        result = verify_row_reproduced(case_dir, finding_id)
        typer.echo(json.dumps({k: v for k, v in result.items() if k != "plan"}, indent=2))
        if not result.get("reproduced"):
            raise typer.Exit(code=1)