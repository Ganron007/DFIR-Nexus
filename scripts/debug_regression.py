#!/usr/bin/env python
"""Regression checker + watchdog (WO-A8 / WP 10.3 D17 = B).

**Checks, never drives** (DEBUG-MODE-PLAN Rule 0): this script reads cases that
already exist and compares the invariants they already report. It never runs a
tool, never builds a case, and never touches evidence. A checker that drives is
a second pipeline that can rot silently.

It reuses `debug_leg_check.collect` - the same read-only collector the 18-run
matrix used - so the numbers compared here are the numbers the matrix reported,
not a parallel implementation that can disagree with them.

    python scripts/debug_regression.py                 # compare vs the baseline
    python scripts/debug_regression.py --write        # (re)write the baseline
    python scripts/debug_regression.py --case CASE-X   # one case
    python scripts/debug_regression.py --watch CASE-X --stale-minutes 20

Exit codes: 0 no regression · 1 regression (the diff is printed) · 2 usage or
baseline error.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

BASELINE = REPO / "Docs" / "internal" / "debug-baseline.json"

# What counts as a regression, per invariant. A *drop* in quality is a
# regression; a rise is not, and neither is a schema bump.
RULES: list[tuple[str, str, str]] = [
    # (path, rule, meaning)
    ("lane.ok", "down", "fewer tool-lane rows succeeded"),
    ("lane.fail", "up", "more tool-lane rows failed"),
    ("gate.blocked", "up", "the evidence gate started blocking"),
    ("index.docs", "down", "fewer documents reached the index"),
    ("runs.model_errors", "up", "a model error appeared"),
    ("findings.staged", "down", "fewer findings staged"),
    ("findings.approved", "down", "fewer findings approved"),
    ("l1.counts.PROVEN", "down", "fewer PROVEN claims"),
    ("grade.report_class", "worse", "the report class dropped"),
    ("reconciliation.match", "down", "fewer files reconcile"),
    ("reconciliation.mismatch", "up", "more files mismatch"),
    ("reconciliation.malformed_quoting", "up", "a CSV fell back to line rows"),
    ("cross_mode.contradictions", "up", "cross-mode contradictions appeared"),
    ("coverage.overall", "worse", "coverage got worse"),
]

CLASS_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}
COVERAGE_ORDER = {"complete": 0, "ok": 0, "partial": 1, "gaps": 2, "unknown": 3}


def _get(row: dict[str, Any], dotted: str) -> Any:
    current: Any = row
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _regressions(current: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    """Human-readable diffs, one per broken invariant."""
    out: list[str] = []
    for path, rule, meaning in RULES:
        old = _get(baseline, path)
        new = _get(current, path)
        if old is None and new is None:
            continue
        if rule == "down":
            try:
                if float(new) < float(old):  # type: ignore[arg-type]
                    out.append(f"{path}: {old} -> {new} ({meaning})")
            except (TypeError, ValueError):
                continue
        elif rule == "up":
            try:
                if float(new) > float(old):  # type: ignore[arg-type]
                    out.append(f"{path}: {old} -> {new} ({meaning})")
            except (TypeError, ValueError):
                continue
        elif rule == "worse":
            order = (
                CLASS_ORDER if path == "grade.report_class" else COVERAGE_ORDER
            )
            if path in ("grade.report_class", "coverage.overall") and (
                order.get(str(new), 9) > order.get(str(old), -1)
            ):
                out.append(f"{path}: {old} -> {new} ({meaning})")
    return out


# --------------------------------------------------------------------------
# the watchdog: the silent-death class
# --------------------------------------------------------------------------

PROGRESS_GLOBS = (
    "extractions/_tool_lane_progress.json",
    "analysis/mode3_runs/*/state.json",
    "analysis/mode2_runs/*/state.json",
    "analysis/mode3_runs/*/run.json",
    "analysis/mode2_runs/*/run.json",
)


def _progress_files(case_dir: Path) -> list[Path]:
    out: list[Path] = []
    for pattern in PROGRESS_GLOBS:
        out.extend(p for p in case_dir.glob(pattern) if p.is_file())
    return sorted(out)


def run_status(case_dir: Path) -> str:
    """``running`` / ``settled`` / ``stopped`` / ``paused`` / ``unknown``."""
    from debug_leg_check import _runs  # the matrix's own reader

    try:
        runs = _runs(case_dir)
    except Exception:  # noqa: BLE001 - a watcher must not die on one case
        return "unknown"
    return str(runs.get("status") or runs.get("latest_status") or "unknown")


def watchdog(case_id: str, cases_root: Path, stale_minutes: float = 20.0) -> dict[str, Any]:
    """Is a `running` case still moving?

    A Mode 2/3 run that stops writing progress but never reaches a terminal
    state is the failure mode an examiner notices hours later, as a spinner.
    Progress files that have not changed inside the window are the evidence.
    """
    case_dir = cases_root / case_id
    if not case_dir.is_dir():
        return {"case_id": case_id, "stale": False, "reason": "case not found"}
    status = run_status(case_dir)
    files = _progress_files(case_dir)
    newest = max((f.stat().st_mtime for f in files), default=0.0)
    age_minutes = (time.time() - newest) / 60.0 if newest else None
    return {
        "case_id": case_id,
        "status": status,
        "progress_files": [str(f) for f in files],
        "newest_progress_age_minutes": (
            round(age_minutes, 1) if age_minutes is not None else None
        ),
        # stale only matters while the run claims to be running: a settled run
        # has stopped writing by design.
        "stale": bool(status == "running" and (age_minutes is None or age_minutes > stale_minutes)),
        "stale_minutes": stale_minutes,
    }


# --------------------------------------------------------------------------
# baseline
# --------------------------------------------------------------------------

def _git_head() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO, capture_output=True, text=True, timeout=10, check=False,
        ).stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def cases_root() -> Path:
    try:
        from nexus.config import settings

        return Path(settings.cases_root)
    except Exception:  # noqa: BLE001
        return REPO / "cases"


def collect_all(root: Path, only: list[str] | None = None) -> dict[str, Any]:
    from debug_leg_check import collect

    rows: dict[str, Any] = {}
    if not root.is_dir():
        return {"head": _git_head(), "cases": rows}
    for case_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        if only and case_dir.name not in only:
            continue
        if not case_dir.name.startswith(("CASE-", "INC-")):
            continue
        try:
            rows[case_dir.name] = collect(case_dir)
        except Exception as exc:  # noqa: BLE001 - one broken case is not a crash
            rows[case_dir.name] = {"case_id": case_dir.name, "error": str(exc)[:200]}
    return {"head": _git_head(), "cases": rows}


def compare(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    """Every broken invariant, per case, plus cases that vanished."""
    report: dict[str, Any] = {"regressions": {}, "missing_cases": [], "new_cases": []}
    base_cases = baseline.get("cases") or {}
    now_cases = current.get("cases") or {}
    for case_id, base_row in base_cases.items():
        now_row = now_cases.get(case_id)
        if now_row is None:
            report["missing_cases"].append(case_id)
            continue
        breaks = _regressions(now_row, base_row)
        if breaks:
            report["regressions"][case_id] = breaks
    report["new_cases"] = sorted(set(now_cases) - set(base_cases))
    report["regressed"] = bool(report["regressions"] or report["missing_cases"])
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default=str(BASELINE))
    parser.add_argument("--cases-root", default=None)
    parser.add_argument("--case", action="append", dest="cases", help="limit to a case id")
    parser.add_argument("--write", action="store_true", help="write the baseline from the current state")
    parser.add_argument("--watch", default="", help="watchdog mode for one case id")
    parser.add_argument("--stale-minutes", type=float, default=20.0)
    args = parser.parse_args(argv)

    root = Path(args.cases_root) if args.cases_root else cases_root()

    if args.watch:
        result = watchdog(args.watch, root, args.stale_minutes)
        print(json.dumps(result, indent=2))
        if result.get("stale"):
            print(
                f"STALE: case {args.watch} is still 'running' but its progress "
                f"files have not changed in "
                f"{result.get('newest_progress_age_minutes')} min "
                f"(limit {args.stale_minutes})",
                file=sys.stderr,
            )
            return 1
        return 0

    current = collect_all(root, args.cases)
    baseline_path = Path(args.baseline)

    if args.write or not baseline_path.is_file():
        if not args.write:
            print(
                f"no baseline at {baseline_path}; writing one now "
                "(run the matrix once before trusting it)",
                file=sys.stderr,
            )
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(json.dumps(current, indent=2, sort_keys=True), encoding="utf-8")
        print(f"baseline written: {baseline_path.relative_to(REPO)} ({len(current['cases'])} case(s))")
        return 0

    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"baseline unreadable: {exc}", file=sys.stderr)
        return 2

    report = compare(current, baseline)
    print(f"cases compared: {len(current['cases'])} (baseline {len(baseline.get('cases') or {})})")
    if report["new_cases"]:
        print(f"new cases (not in the baseline): {', '.join(report['new_cases'])}")
    if report["missing_cases"]:
        print(f"MISSING cases: {', '.join(report['missing_cases'])}")
    for case_id, breaks in report["regressions"].items():
        print(f"\nREGRESSION {case_id}")
        for line in breaks:
            print(f"  - {line}")
    if report["regressed"]:
        print(f"\nREGRESSION: {len(report['regressions'])} case(s) worse than the baseline")
        return 1
    print("no regression")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())