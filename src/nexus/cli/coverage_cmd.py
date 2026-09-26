"""``nexus coverage-audit`` — build and read the WP 10.2 coverage audit.

Answers, per case, what the investigation did **not** cover: applicable lane
tools that never ran, indexed families no finding cites, and needles that were
never queried (so their 0-hit rows are not evidence of absence).
"""

from __future__ import annotations

import json

import typer


def coverage_audit(
    case: str = typer.Option(
        "",
        "--case",
        help="Case id or case directory. Default: the active case.",
    ),
    rebuild: bool = typer.Option(
        False,
        "--rebuild",
        help="Recompute and persist analysis/coverage_audit.json (default: read the persisted audit).",
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit the full audit as JSON."),
) -> None:
    """Show the case coverage audit: tools not run, sources not cited, needles not scanned."""
    from pathlib import Path

    from nexus.analysis.coverage_audit import (
        load_coverage_audit,
        summary_lines,
        write_coverage_audit,
    )
    from nexus.case.outputs import resolve_active_case_dir

    case_dir: Path | None = None
    if case:
        candidate = Path(case)
        if candidate.is_dir():
            case_dir = candidate
        else:
            root = Path.home()
            for base in (root / ".nexus" / "cases", Path("cases")):
                hit = base / case
                if hit.is_dir():
                    case_dir = hit
                    break
        if case_dir is None:
            typer.echo(f"case not found: {case}")
            raise typer.Exit(1)
    else:
        try:
            case_dir = resolve_active_case_dir()
        except Exception:  # noqa: BLE001
            case_dir = None
    if case_dir is None:
        typer.echo("No active case. Pass --case <id|dir>.")
        raise typer.Exit(1)

    if rebuild:
        path, audit = write_coverage_audit(case_dir)
        typer.echo(f"wrote {path}")
    else:
        audit = load_coverage_audit(case_dir)
        if not audit:
            audit = {}
            typer.echo(
                "No coverage audit persisted for this case yet. Re-run with --rebuild."
            )

    if as_json:
        typer.echo(json.dumps(audit, indent=2, sort_keys=True))
        raise typer.Exit(0 if audit.get("overall") in {"ok", "gaps", "unknown"} else 1)

    if not audit:
        raise typer.Exit(1)

    typer.echo(f"case: {case_dir.name}  ({case_dir})")
    for line in summary_lines(audit):
        typer.echo(line)
    # Non-zero on gaps so a script or a pre-seal check can gate on it. An
    # "unknown" audit is not a pass either: coverage could not be proven.
    raise typer.Exit(0 if audit.get("overall") == "ok" else 1)
