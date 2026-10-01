"""One case status (WO-U3 / WP 14.3, UD8).

The portal grew three signals that could disagree: the stepper derived its
stages from artifacts, the gate banner asked the lane gate, and page headers
asked whatever each page happened to have loaded. An examiner comparing two
of them saw two different answers about the same case.

This module is the single source. It answers, for one case:

* the stage list (`lane_stages` - N1..N8, derived, never invented),
* the evidence gate (blocked or clear, with the count and the message),
* whether the index exists and how many documents it holds,
* the pipeline record's terminal state and whether a run is live,
* the latest Mode 2/3 run state,
* findings by status,
* whether a report exists, and
* evidence freshness (WO-A5).

Everything is read; nothing is computed from a guess, and a missing artifact is
reported as ``unknown`` rather than as a failure. Three readers, one answer.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from starlette.responses import JSONResponse
from starlette.routing import Route

__all__ = ["build_case_status", "case_status_routes"]


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _findings(case_dir: Path) -> dict[str, Any]:
    path = case_dir / "findings.json"
    counts: dict[str, int] = {}
    total = 0
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = []
        if isinstance(data, list):
            for row in data:
                if not isinstance(row, dict):
                    continue
                total += 1
                status = str(row.get("status") or "DRAFT").upper()
                counts[status] = counts.get(status, 0) + 1
    return {"total": total, "by_status": counts}


def _latest_run(case_dir: Path, family: str) -> dict[str, Any]:
    """The newest Mode 2/3 run record, or {} when the case has none."""
    directory = case_dir / "analysis" / f"{family}_runs"
    if not directory.is_dir():
        return {}
    newest: dict[str, Any] = {}
    newest_mtime = -1.0
    for path in sorted(directory.glob("*.json")):
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if mtime <= newest_mtime:
            continue
        data = _read_json(path)
        if data:
            newest, newest_mtime = data, mtime
    return newest


def _pipeline(case_dir: Path) -> dict[str, Any]:
    for candidate in (
        case_dir / "analysis" / "pipeline_run.json",
        case_dir / "analysis" / "pipeline.json",
        case_dir / "pipeline_record.json",
    ):
        data = _read_json(candidate)
        if data:
            return data
    return {}


def _index(case_dir: Path) -> dict[str, Any]:
    meta = _read_json(case_dir / "analysis" / "es_index.json")
    if not meta:
        return {"state": "unknown", "docs": None, "capped": None}
    docs = meta.get("docs")
    caps = meta.get("caps") or {}
    return {
        "state": "built",
        "docs": docs if isinstance(docs, int) else None,
        "capped": bool(caps.get("capped") or meta.get("capped") or False),
        "errors": meta.get("errors"),
        "index": meta.get("index"),
        "generated_at": meta.get("generated_at") or meta.get("updated_at"),
    }


def _report(case_dir: Path) -> dict[str, Any]:
    reports = case_dir / "reports"
    if not reports.is_dir():
        return {"state": "absent", "files": []}
    files = sorted(p.name for p in reports.glob("REPORT*") if p.is_file())
    if not files:
        return {"state": "absent", "files": []}
    newest = max(
        (p for p in reports.glob("REPORT*") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
    )
    return {
        "state": "present",
        "files": files,
        "latest": newest.name,
        "modified_at": newest.stat().st_mtime,
    }


def _freshness(case_dir: Path) -> dict[str, Any]:
    try:
        from nexus.analysis.freshness import freshness_brief

        brief = freshness_brief(case_dir)
    except Exception as exc:  # noqa: BLE001 - never fail a status read
        return {"state": "unknown", "error": str(exc)[:120]}
    return brief if isinstance(brief, dict) else {"state": "unknown"}


def build_case_status(case_dir: Path | str) -> dict[str, Any]:
    """Everything a header, a stepper or a banner needs, from one read."""
    from nexus.langgraph.lane_gate import (
        gate_message,
        lane_stages,
        read_lane_gate,
    )

    case_dir = Path(case_dir)
    stages = lane_stages(case_dir)

    # one read of the gate: the banner and the header must not read two copies
    gate_record = read_lane_gate(case_dir)
    is_blocked = str(gate_record.get("status") or "") == "blocked"
    unprocessed = gate_record.get("unprocessed") or []
    gate = {
        "blocked": is_blocked,
        "blocked_count": len(unprocessed) if is_blocked else 0,
        "message": gate_message(gate_record) if is_blocked else "",
        "items": [
            {
                "tool": str(item.get("tool") or ""),
                "purpose": str(item.get("purpose") or ""),
                "reason": str(item.get("reason") or "")[:200],
            }
            for item in (unprocessed[:20] if isinstance(unprocessed, list) else [])
        ],
    }

    pipeline = _pipeline(case_dir)
    pipeline_state = str(pipeline.get("status") or pipeline.get("state") or "")
    mode2 = _latest_run(case_dir, "mode2")
    mode3 = _latest_run(case_dir, "mode3")
    runs = {
        "pipeline": {
            "state": pipeline_state or "unknown",
            "run_id": pipeline.get("run_id") or "",
            "stage": pipeline.get("stage") or "",
            "error": pipeline.get("error") or "",
        },
        "mode2": _run_summary(mode2),
        "mode3": _run_summary(mode3),
    }

    return {
        "case_id": case_dir.name,
        "case_dir": str(case_dir),
        "generated_at": None,  # filled by the endpoint so a fixture is stable
        "stages": stages,
        "gate": gate,
        "index": _index(case_dir),
        "runs": runs,
        "findings": _findings(case_dir),
        "report": _report(case_dir),
        "freshness": _freshness(case_dir),
    }


def _run_summary(record: dict[str, Any]) -> dict[str, Any]:
    if not record:
        return {"state": "none", "run_id": "", "reason": "no run record"}
    return {
        "state": str(record.get("status") or "unknown"),
        "run_id": str(record.get("run_id") or ""),
        "reason": str(record.get("stop_reason") or record.get("reason") or ""),
        "staged": len(record.get("candidates") or record.get("orders") or []) or None,
    }


async def api_case_status(request):
    """GET /portal/api/case/status?case_id= - the single status source."""
    from datetime import UTC, datetime

    params = request.query_params
    case_id = (params.get("case_id") or "").strip()
    if not case_id:
        return JSONResponse({"error": "case_id is required"}, status_code=400)

    try:
        from nexus.analysis.finding_exhibit import resolve_case_dir
        from nexus.case.outputs import resolve_active_case_dir

        case_dir = resolve_case_dir(case_id) if case_id else None
        if case_dir is None:
            case_dir = resolve_active_case_dir()
        if case_dir is None:
            return JSONResponse(
                {"error": f"case not found: {case_id}"}, status_code=404
            )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": f"case resolution failed: {exc}"}, status_code=500)

    try:
        status = build_case_status(case_dir)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": f"status read failed: {exc}"}, status_code=500)
    status["generated_at"] = datetime.now(UTC).isoformat()
    status["requested_case_id"] = case_id
    return JSONResponse(status)


def case_status_routes() -> list[Route]:
    return [Route("/portal/api/case/status", api_case_status, methods=["GET"])]