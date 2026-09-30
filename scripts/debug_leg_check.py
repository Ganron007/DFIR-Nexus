"""WO-7 read-only quality report over the debug matrix cases.

Prints a per-case quality table and writes ``Docs/internal/debug-legs.json`` +
``Docs/internal/debug-legs.md``. It **never writes into a case dir**: every
number comes from persisted artifacts or pure functions (``verify_case`` /
``check_cross_mode``).

Usage::

    python scripts/debug_leg_check.py                    # every CASE-* folder
    python scripts/debug_leg_check.py CASE-4EFD5EB2 ...  # selected cases
"""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO))


def _read_json(path: Path) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _newest(directory: Path, pattern: str = "*.json") -> Path | None:
    if not directory.is_dir():
        return None
    files = [p for p in directory.glob(pattern) if p.is_file()]
    return max(files, key=lambda p: p.stat().st_mtime) if files else None


def _case_meta(case_dir: Path) -> dict[str, Any]:
    import yaml

    try:
        meta = yaml.safe_load((case_dir / "CASE.yaml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        meta = {}
    intake = meta.get("intake") if isinstance(meta.get("intake"), dict) else {}
    name = str(intake.get("name") or meta.get("name") or "")
    group = ""
    mode = str(meta.get("investigation_mode") or "")
    parts = name.split("-")
    if len(parts) >= 2 and parts[0] == "dbg":
        group = parts[1]
    for part in parts:
        if part.startswith("m") and part[1:].isdigit():
            mode = part[1:]
    return {
        "name": name,
        "group": group,
        "mode": mode,
        "description": str(meta.get("description") or ""),
        "status": str(meta.get("status") or ""),
    }


def _lane_tallies(case_dir: Path) -> dict[str, int]:
    runs = case_dir / "analysis" / "pipeline_runs"
    journal = _newest(runs, "*.progress.jsonl")
    counts = {"OK": 0, "SKIP": 0, "FAIL": 0}
    if journal is None:
        return counts
    for line in journal.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if str(row.get("stage") or "tool") != "tool":
            continue
        status = str(row.get("status") or "").upper()
        if status in counts:
            counts[status] += 1
    return counts


def _gate(case_dir: Path) -> dict[str, Any]:
    try:
        from nexus.langgraph.lane_gate import lane_gate_blocked, read_lane_gate

        gate = read_lane_gate(case_dir) or {}
        blocked = bool(lane_gate_blocked(case_dir))
        return {"blocked": blocked, "rows": len(gate.get("entries") or gate.get("rows") or [])}
    except Exception as exc:  # noqa: BLE001 - a report must render without the gate lib
        return {"blocked": None, "error": str(exc)[:140]}


def _index(case_dir: Path) -> dict[str, Any]:
    meta = _read_json(case_dir / "analysis" / "es_index.json")
    return {
        "docs": meta.get("docs"),
        "capped": bool(meta.get("capped")),
        "incremental": bool(meta.get("incremental")),
        "file_counts": len(meta.get("file_counts") or {}),
    }


def _runs(case_dir: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    tools = _newest(case_dir / "analysis" / "pipeline_runs")
    if tools is not None:
        rec = _read_json(tools)
        out["tools_status"] = rec.get("status")
        out["tools_stop_reason"] = rec.get("stop_reason") or ""
    m2 = _newest(case_dir / "analysis" / "mode2_runs")
    if m2 is not None:
        rec = _read_json(m2)
        results = rec.get("results") or []
        out["mode2_status"] = rec.get("status")
        out["mode2_stop_reason"] = rec.get("stop_reason") or ""
        out["mode2_orders"] = len(results)
        out["mode2_partial"] = sum(1 for r in results if isinstance(r, dict) and r.get("partial"))
        proposed = 0
        for r in results:
            if not isinstance(r, dict):
                continue
            parsed = r.get("parsed") or {}
            proposed += len(parsed.get("candidate_findings") or [])
        out["mode2_candidates_proposed"] = proposed
        out["mode2_candidates_settled"] = len(rec.get("candidates") or [])
    m3_dirs = [
        case_dir / "analysis" / "mode3_runs",
        case_dir / "analysis" / "mode3",
        case_dir / "analysis" / "multi_agent",
    ]
    for d in m3_dirs:
        m3 = _newest(d)
        if m3 is None:
            continue
        rec = _read_json(m3)
        board = rec.get("board") or []
        out["mode3_status"] = rec.get("status")
        out["mode3_stop_reason"] = rec.get("stop_reason") or ""
        out["mode3_seats"] = len(board)
        out["mode3_model_errors"] = sum(
            1 for e in board if isinstance(e, dict)
            and str(e.get("finish_reason") or "").startswith("model_error")
        )
        out["mode3_claims_proposed"] = sum(
            len(e.get("claims") or []) for e in board if isinstance(e, dict)
        )
        out["mode3_candidates_settled"] = len(rec.get("candidates") or [])
        break
    return out


def _findings(case_dir: Path) -> dict[str, int]:
    try:
        loaded = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        loaded = []
    rows = loaded if isinstance(loaded, list) else []
    tally: dict[str, int] = {}
    for f in rows:
        if not isinstance(f, dict):
            continue
        status = str(f.get("status") or "DRAFT").upper()
        tally[status] = tally.get(status, 0) + 1
    return {
        "staged": len(rows),
        "approved": tally.get("APPROVED", 0),
        "rejected": tally.get("REJECTED", 0),
        "draft": tally.get("DRAFT", 0),
    }


def _l1(case_dir: Path) -> dict[str, Any]:
    try:
        from nexus.analysis.claim_verification import verify_case

        ledger = verify_case(case_dir)
        return {
            "counts": ledger.get("verdict_counts") or {},
            "overall": ledger.get("overall"),
        }
    except Exception as exc:  # noqa: BLE001
        return {"counts": {}, "overall": f"error: {exc}"[:120]}


def _grade(case_dir: Path) -> dict[str, Any]:
    grade = _read_json(case_dir / "analysis" / "report_grade.json")
    return {
        "class": grade.get("report_class"),
        "label": grade.get("report_class_label"),
        "total": grade.get("total"),
        "max_total": grade.get("max_total"),
    }


def _coverage(case_dir: Path) -> dict[str, Any]:
    audit = _read_json(case_dir / "analysis" / "coverage_audit.json")
    rec = audit.get("reconciliation") or {}
    return {
        "overall": audit.get("overall"),
        "reconciliation": rec.get("summary"),
    }


def _reconciliation(case_dir: Path) -> dict[str, Any]:
    rec = _read_json(case_dir / "analysis" / "reconciliation.json")
    t = rec.get("totals") or {}
    return {
        "available": bool(rec.get("file_counts_present")),
        "files": t.get("files"),
        "match": t.get("match"),
        "mismatch": t.get("mismatch"),
        "fragmented": t.get("fragmented"),
        # WO-15: per-file evidence outlives the case cleanup.
        "mismatch_files": [
            {k: f.get(k) for k in ("file", "source_records", "docs", "deduped",
                                   "delta", "status")}
            for f in (rec.get("files") or ())
            if f.get("status") in ("mismatch", "fragmented", "missing", "unreconcilable")
        ],
    }


def _cross_mode(case_dir: Path) -> dict[str, Any]:
    try:
        from nexus.analysis.cross_mode import check_cross_mode

        result = check_cross_mode(case_dir=case_dir) or {}
        return {
            "contradictions": len(result.get("contradictions") or []),
            "row_contradictions": len(result.get("row_contradictions") or []),
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)[:140]}


def collect(case_dir: Path) -> dict[str, Any]:
    return {
        "case_id": case_dir.name,
        **_case_meta(case_dir),
        "lane": _lane_tallies(case_dir),
        "gate": _gate(case_dir),
        "index": _index(case_dir),
        "runs": _runs(case_dir),
        "findings": _findings(case_dir),
        "l1": _l1(case_dir),
        "grade": _grade(case_dir),
        "coverage": _coverage(case_dir),
        "reconciliation": _reconciliation(case_dir),
        "cross_mode": _cross_mode(case_dir),
    }


def _md_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        "| Case | Group | Mode | Lane OK/SKIP/FAIL | Gate | Index | Staged/Approved | L1 P/U/C/U | Grade | Coverage | Recon (match/mismatch) | Cross-mode contradictions |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lane = r["lane"]
        l1 = (r["l1"].get("counts") or {})
        recon = r["reconciliation"]
        cm = r["cross_mode"]
        gate = r["gate"].get("blocked")
        gate_txt = "clear" if gate is False else ("BLOCKED" if gate else str(r["gate"].get("error") or "?"))
        lines.append(
            f"| {r['case_id']} | {r.get('group') or '?'} | {r.get('mode') or '?'} "
            f"| {lane.get('OK', 0)}/{lane.get('SKIP', 0)}/{lane.get('FAIL', 0)} "
            f"| {gate_txt} | {r['index'].get('docs')} | "
            f"{r['findings'].get('staged', 0)}/{r['findings'].get('approved', 0)} "
            f"| {l1.get('PROVEN', 0)}/{l1.get('UNSUPPORTED', 0)}/{l1.get('CONTRADICTED', 0)}/{l1.get('UNVERIFIABLE', 0)} "
            f"| {r['grade'].get('class') or '-'} "
            f"| {r['coverage'].get('overall') or '-'} "
            f"| {recon.get('match') if recon.get('available') else '-'}/{recon.get('mismatch') if recon.get('available') else '-'} "
            f"| {cm.get('contradictions', cm.get('error', '?'))} |"
        )
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    cases_root = REPO / "cases"
    wanted = [a for a in argv if a.startswith("CASE-")]
    directories = (
        [cases_root / c for c in wanted]
        if wanted
        else sorted(p for p in cases_root.iterdir() if p.is_dir() and p.name.startswith("CASE-"))
    )
    rows = [collect(d) for d in directories if d.is_dir()]

    out_dir = REPO / "Docs" / "internal"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "debug-legs.json").write_text(
        json.dumps({"generated_at": datetime.now(UTC).isoformat(), "cases": rows}, indent=2, default=str),
        encoding="utf-8",
    )
    table = _md_table(rows)
    (out_dir / "debug-legs.md").write_text(
        f"# Debug matrix — per-leg quality (read-only)\n\nGenerated {datetime.now(UTC).isoformat()}\n\n{table}\n",
        encoding="utf-8",
    )
    print(table)
    print(f"\n{len(rows)} case(s) -> Docs/internal/debug-legs.json + debug-legs.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
