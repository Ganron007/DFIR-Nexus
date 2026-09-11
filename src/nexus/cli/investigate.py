"""Investigation CLI — WP 4i.10.

Headless fallback for the examiner when the UI isn't available:

  nexus brief                    # case briefing (inventory/alerts/signal map)
  nexus hits <needle> [-f fam]   # parsed hit table with field projection
  nexus hit <file:line>          # full field dump of one hit

The UI remains the primary surface — these verbs keep the N1-N8 spine
viable headless (automation, air-gapped, CI). Registered as top-level
commands in cli/main.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer


def _resolve_case(case_id: str = "") -> Path | None:
    from nexus.case.outputs import resolve_active_case_dir
    from nexus.config import settings

    if case_id:
        p = Path(case_id)
        case_dir = p if p.is_absolute() else settings.cases_root / case_id
        if not case_dir.exists():
            typer.echo(f"Case not found: {case_id}", err=True)
            return None
        return case_dir
    case_dir = resolve_active_case_dir()
    if case_dir:
        return case_dir
    typer.echo("No active case. Use 'nexus case activate' or 'nexus case init'", err=True)
    return None


def brief(
    case_id: str = typer.Argument("", help="Case ID (default: active case)"),
    json_out: bool = typer.Option(False, "--json", help="Emit raw JSON"),
    markdown: bool = typer.Option(False, "--markdown", help="Emit markdown report"),
):
    """Print the deterministic case briefing (WP 4i.1)."""
    from nexus.langgraph.briefing import briefing_to_markdown, case_briefing

    case_dir = _resolve_case(case_id)
    if not case_dir:
        raise typer.Exit(1)
    b = case_briefing(case_dir)
    if json_out:
        typer.echo(json.dumps(b, indent=2, default=str))
        return
    if markdown:
        typer.echo(briefing_to_markdown(b))
        return

    # Compact terminal view
    typer.echo(f"Case briefing — {case_dir.name}")
    typer.echo(f"  files={b.get('total_files')} rows={b.get('total_rows')} "
               f"families={len(b.get('families') or [])} "
               f"backend={b.get('backend') or 'csv'}")
    inv = b.get("inventory") or {}
    if inv:
        typer.echo("  inventory:")
        for fam, e in sorted(inv.items(), key=lambda kv: -kv[1].get("rows", 0)):
            cap = "+" if e.get("capped") else ""
            typer.echo(f"    {fam:16s} {e.get('rows', 0):>8}{cap} rows  {e.get('files', 0)} files")
    led = b.get("ledger") or {}
    typer.echo(f"  parser lane: {led.get('ok', 0)} OK / {led.get('skip', 0)} SKIP / "
               f"{led.get('fail', 0)} FAIL")
    if b.get("hosts"):
        typer.echo("  hosts: " + ", ".join(b["hosts"][:10]))
    tr = b.get("time_range") or {}
    if tr.get("start"):
        typer.echo(f"  window: {tr['start']} -> {tr.get('end', '')}")
    alerts = b.get("alerts") or []
    if alerts:
        typer.echo(f"  alerts ({len(alerts)}):")
        for a in alerts[:15]:
            typer.echo(f"    [{a.get('level','').upper():8s}] {a.get('title','')[:60]:60s} {a.get('host','')}")
    scan = b.get("needle_scan") or []
    if scan:
        typer.echo(f"  signal map ({len(scan)} needles with hits):")
        for s in scan[:25]:
            typer.echo(f"    {s['needle']:40s} {s['hits']:>4} hits  ({s['source']})")
    ent = b.get("entities") or {}
    if ent:
        typer.echo("  top entities:")
        for etype, elist in sorted(ent.items()):
            vals = ", ".join(e["value"] for e in elist[:6])
            typer.echo(f"    {etype:14s} {vals}")
    intake = b.get("intake") or {}
    if intake:
        typer.echo("  intake:")
        for k, v in intake.items():
            typer.echo(f"    {k}: {v[:100]}")


def hits_cmd(
    needle: str = typer.Argument(..., help="Needle or query text"),
    case_id: str = typer.Option("", "--case", help="Case ID (default: active case)"),
    family: str = typer.Option("", "--family", "-f", help="Filter to a family"),
    fields: str = typer.Option("", "--fields", help="Comma-separated field projection"),
    limit: int = typer.Option(50, "--limit", "-n", help="Max hits"),
    json_out: bool = typer.Option(False, "--json", help="Emit raw JSON"),
):
    """Parsed hit table for a needle (WP 4i.10)."""
    from nexus.langgraph.query_pack import attach_hit_fields, n4_query

    case_dir = _resolve_case(case_id)
    if not case_dir:
        raise typer.Exit(1)

    query_text = needle
    if family:
        query_text = f"family:{family} {needle}"
    result = n4_query(case_dir, query_text, limit=limit)
    if result.get("error"):
        typer.echo(f"query error: {result['error']}", err=True)
        raise typer.Exit(1)
    hits = attach_hit_fields(case_dir, list(result.get("hits") or []))

    if json_out:
        typer.echo(json.dumps({"count": result.get("count"), "hits": hits}, indent=2, default=str))
        return

    want = [f.strip() for f in fields.split(",") if f.strip()] if fields else None
    typer.echo(f"{result.get('count', 0)} hits (backend={result.get('backend','csv')})")
    for i, h in enumerate(hits[:limit], 1):
        typer.echo(f"\n[{i}] {h.get('family','?')} {h.get('file','?')}:{h.get('line','?')}"
                   f"  host={h.get('host') or '-'}  terms={h.get('terms','')}")
        f = h.get("fields") or {}
        if want:
            for name in want:
                if f.get(name):
                    typer.echo(f"    {name}: {f[name]}")
        elif f:
            for k, v in list(f.items())[:8]:
                typer.echo(f"    {k}: {v}")
        else:
            typer.echo(f"    {str(h.get('text') or '')[:200]}")


def hit_cmd(
    ref: str = typer.Argument(..., help="Hit ref as file:line"),
    case_id: str = typer.Option("", "--case", help="Case ID (default: active case)"),
    json_out: bool = typer.Option(False, "--json", help="Emit raw JSON"),
):
    """Full field dump for one hit (WP 4i.10)."""
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    case_dir = _resolve_case(case_id)
    if not case_dir:
        raise typer.Exit(1)

    file_rel, _, line_no = ref.rpartition(":")
    if not file_rel or not line_no.isdigit():
        typer.echo("hit ref must be file:line (e.g. evtx/security.csv:42)", err=True)
        raise typer.Exit(1)
    root = resolve_tools_extractions(case_dir)
    path = root / file_rel
    if not path.is_file():
        typer.echo(f"file not found under extractions: {file_rel}", err=True)
        raise typer.Exit(1)

    n = int(line_no)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if n < 1 or n > len(lines):
        typer.echo(f"line {n} out of range (file has {len(lines)} lines)", err=True)
        raise typer.Exit(1)

    header = lines[0] if lines else ""
    row = lines[n - 1]
    import csv

    try:
        cols = next(csv.reader([header]))
        vals = next(csv.reader([row]))
        fields = {c.strip().strip('"'): v.strip() for c, v in zip(cols, vals, strict=False)}
    except Exception:  # noqa: BLE001
        fields = {}

    if json_out:
        typer.echo(json.dumps({"file": file_rel, "line": n, "fields": fields, "raw": row}, indent=2))
        return
    typer.echo(f"{file_rel}:{n}")
    if fields:
        for k, v in fields.items():
            typer.echo(f"  {k}: {v}")
    else:
        typer.echo(f"  {row}")
