"""Read a finished mode's log, actual record and case audit (Part 11 rule 18).

    python devtools/runbook/review_run.py T19-R1z3b:CASE-6C6A9449:2

Reports every retained error, including pre-audit rejections. Does not execute
tools, alter case records, or approve findings. Nonzero exit means review issues.
"""
from __future__ import annotations

import collections
import json
import re
import sys
from datetime import datetime
from pathlib import Path

from dotenv import dotenv_values

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from nexus.langgraph.es_native import is_unknown_field_hint as _unknown_field_hint  # noqa: E402

ROOT = Path(__file__).resolve().parents[2] / "cases"
MODEL_ENV = Path(__file__).resolve().parents[2] / ".env"
STAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z$")
RUN_ID = re.compile(r"(RUN-\S+-interpret-\w+|M2-\d{8}T\d{6}-\w{6}|M3-\d{8}T\d{6}-\w{6})")
TOOL_RESULT = re.compile(r"^\S+\s+tool\.result\s+\S+\s+(\S+)(?:\s+(.*))?$")
APPROVAL_PAUSE = re.compile(r"awaiting approval at await_approval \((\d+) DRAFT finding\(s\) staged\)")


def _record(folder: Path, run_id: str, mode: str, issues: list[str]) -> dict:
    if not run_id:
        issues.append("run id missing from log")
        return {}
    candidates = [folder / "runs" / run_id / "manifest.json",
                  folder / "analysis" / f"mode{mode}_runs" / f"{run_id}.json"]
    candidates.extend(sorted((folder / "analysis" / f"mode{mode}_runs" / run_id).glob("*.json")))
    for path in candidates:
        if not path.is_file():
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            issues.append(f"cannot read run record {path.name}: {exc}")
            continue
        if isinstance(record, dict) and record.get("run_id") == run_id:
            return record
    issues.append(f"run record missing for {run_id}")
    return {}


def review(tag: str, case: str, mode: str) -> dict:
    folder = ROOT / case
    log = folder / ".trace" / f"run-{tag}-mode{mode}.log"
    issues: list[str] = []
    try:
        lines = log.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError as exc:
        lines = []
        issues.append(f"cannot read run log: {exc}")
    stamps = [m.group(1) for line in lines if (m := STAMP.fullmatch(line.strip()))]
    start, end = (stamps[0], stamps[-1]) if len(stamps) >= 2 else ("", "")
    minutes = None
    if start and end:
        try:
            minutes = (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds() / 60
            if minutes < 0:
                issues.append("terminal timestamp precedes start")
        except ValueError:
            issues.append("invalid run timestamps")
    else:
        issues.append("start or terminal UTC stamp missing")
    exit_line = next((line for line in reversed(lines) if line.startswith(f"MODE{mode}_EXIT=")), "")
    if exit_line != f"MODE{mode}_EXIT=0":
        issues.append(exit_line or "exit code missing")
    cli_status = next((line.strip() for line in reversed(lines)
                       if RUN_ID.match(line.strip().removeprefix("run_id="))), "")
    found = RUN_ID.search(cli_status)
    run_id = found.group(1) if found else ""
    record = _record(folder, run_id, mode, issues)
    status = str(record.get("status") or "unknown")
    stop = str(record.get("stop_reason") or record.get("error") or "")
    model_record = record.get("model") or {}
    model = str(model_record.get("model") or "") if isinstance(model_record, dict) else str(model_record)
    expected_model = ""
    try:
        if not MODEL_ENV.is_file():
            raise ValueError("operator .env is missing")
        expected_model = str(dotenv_values(MODEL_ENV, interpolate=False).get("NEXUS_LLM_MODEL") or "").strip()
        if not expected_model:
            raise ValueError("NEXUS_LLM_MODEL is missing or empty in operator .env")
    except (OSError, UnicodeError, ValueError) as exc:
        issues.append(f"cannot read expected NEXUS_LLM_MODEL: {exc}")
    if expected_model and model != expected_model:
        issues.append(f"wrong or missing model: {model or '?'}; expected {expected_model}")
    pause = APPROVAL_PAUSE.fullmatch(stop) if mode == "1" and status == "interrupted" else None
    if pause:
        if not (folder / "analysis/interpretation.md").is_file():
            issues.append("approval pause has no interpretation artifact")
    elif status != "completed":
        issues.append(f"record status={status}: {stop}")
    candidates = len(record.get("candidates") or [])
    if pause:
        candidates = int(pause.group(1))
    tracebacks = [i for i, line in enumerate(lines) if "Traceback (most recent call last)" in line]
    fatal_log = [line for line in lines if re.match(
        r"(?:\S+\s+(?:run|work_order|agent)\.failed\b|"
        r"(?:\[[^\]]+\]\s+|\d{4}-\d\d-\d\d[T ]\S+\s+)?ERROR\b|Exception ignored)",
        line.lstrip())]
    errors: collections.Counter[str] = collections.Counter()
    hints = calls = unaudited = 0
    error_ids: set[str] = set()
    for path in sorted((folder / "audit").glob("*.jsonl")):
        with path.open(encoding="utf-8-sig") as stream:
            for line_no, line in enumerate(stream, 1):
                try:
                    entry = json.loads(line)
                except ValueError:
                    issues.append(f"invalid audit JSON: {path.name}:{line_no}")
                    continue
                ts = str(entry.get("ts", ""))[:19]
                if not start or not (start <= ts <= end):
                    continue
                calls += 1
                error = str((entry.get("result_summary") or {}).get("error") or "")
                if not error:
                    continue
                audit_id = str(entry.get("audit_id") or "")
                if audit_id:
                    error_ids.add(audit_id)
                if _unknown_field_hint(error):
                    hints += 1
                else:
                    errors[f"{entry.get('tool')} [{audit_id}]: {error}"] += 1
    # Older builds omitted pre-validation audit entries. Match ids to avoid counting
    # the same audited failure again when it also appears in the run's log.
    for line_no, line in enumerate(lines, 1):
        match = TOOL_RESULT.match(line)
        if not match:
            continue
        tool, detail = match.group(1), match.group(2) or ""
        aid = re.match(r"audit=(\S+)(?:\s+(.*))?$", detail)
        if aid:
            if aid.group(1) in error_ids:
                continue
            detail = aid.group(2) or ""
        if not detail:
            continue
        if _unknown_field_hint(detail):
            hints += 1
        else:
            errors[f"{tool} [log:{line_no}]: {detail}"] += 1
            unaudited += 1
    if errors:
        issues.append(f"{sum(errors.values())} tool error(s)")
    if tracebacks:
        issues.append(f"{len(tracebacks)} traceback(s)")
    if fatal_log:
        issues.append(f"{len(fatal_log)} fatal/error log line(s)")
    # TA-5.2: a run records the knowledge it chose (skills, playbooks, executed analytics) in one section.
    knowledge = record.get("knowledge") if isinstance(record.get("knowledge"), dict) else None
    if record and knowledge is None:
        issues.append("record has no knowledge section (TA-5.2)")
    duration = f"{minutes:.1f}" if minutes is not None else "?"
    print(f"\n== {tag} mode {mode} [{start} .. {end}] {exit_line or 'no exit line'}")
    print(f"   run_id={run_id or '?'} status={status} stop={stop or '(none)'} candidates/DRAFTs={candidates}")
    print(f"   model={model or '?'} minutes={duration} audited calls={calls} unknown-field hints={hints} "
          f"other tool errors={sum(errors.values())} log-only errors={unaudited} tracebacks={len(tracebacks)} "
          f"expected_model={expected_model or '?'}")
    if knowledge is not None:
        ran = [a for a in knowledge.get("analytics") or [] if a.get("outcome") == "ran"]
        print(f"   knowledge: {len(knowledge.get('skills') or [])} skill(s), "
              f"{len(knowledge.get('playbooks') or [])} playbook(s), {len(ran)} analytic(s) ran "
              f"({sum(1 for a in ran if a.get('hits'))} with hits)")
        print("     skills: " + ", ".join(f"{s.get('skill')}[{s.get('best_score')}]"
                                          for s in knowledge.get("skills") or []))
        print("     playbooks: " + ", ".join(str(p.get("playbook")) for p in knowledge.get("playbooks") or []))
    for key, count in errors.items():
        print(f"     {count:3d} x {key}")
    for i in tracebacks:
        print("   traceback:", " | ".join(line.strip() for line in lines[max(0, i - 1):i + 7]))
    for line in fatal_log:
        print("   log error:", line)
    for issue in issues:
        print("   ISSUE:", issue)
    return {"run_id": run_id, "status": status, "stop_reason": stop, "model": model,
            "expected_model": expected_model,
            "minutes": minutes, "candidates": candidates, "audited_calls": calls,
            "tool_errors": sum(errors.values()), "unaudited_tool_errors": unaudited,
            "unknown_field_hints": hints, "tracebacks": len(tracebacks), "issues": issues}


def main(specs: list[str]) -> int:
    if not specs:
        raise SystemExit(__doc__)
    reports = [review(*spec.split(":")) for spec in specs]
    return int(any(report["issues"] for report in reports))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
