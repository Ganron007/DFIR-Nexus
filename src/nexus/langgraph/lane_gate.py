"""Evidence gate - N2 must finish before any analysis. HARD RULE (operator, 2026-09-29).

The rule, encoded here and enforced at every analysis entry point:

1. Never skip evidence processing.
2. The tool lane (any mode) finishes every registered artifact before anything
   downstream proceeds; it never stops early on a failure and never claims
   completion while an artifact is unprocessed.
3. When a tool cannot finish (timeout / failure), the lane finishes all
   remaining evidence, then HALTS and alerts: the gate is written as
   ``blocked`` and every analysis stage refuses to start.
4. No analysis stage (Mode 1 full-run, Mode 2, Mode 3, interpret / coverage /
   design) runs until the examiner either re-runs the lane so the item
   processes, or explicitly skips it through an **audited** decision (HMAC
   challenge, same path as finding approvals).
5. The gate and the N1-N8 stage states are visible on the portal and in the
   CLI.

Why this exists: `$I30` was routed to the Recycle Bin parser and `$LogFile`
carried a SKIP although a validated parser sat in the tree. Both were claims
about our own routing that no test contradicted; this gate makes an
unprocessed artifact a visible, blocking, examiner-owned decision instead.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GATE_FILENAME = "lane_gate.json"

#: N1-N8 spine (Docs/NEXUS-MODE.md). Used for the stage panel.
N_STAGES: tuple[tuple[str, str], ...] = (
    ("N1", "Intake - question, window, playbooks"),
    ("N2", "Process - every registered artifact parsed (evidence gate)"),
    ("N3", "Index - this case's N2 output only"),
    ("N4", "Query - code search, hits only, no LLM"),
    ("N5", "Interpret - modes narrate N4 hits"),
    ("N6", "Approve - human HMAC, DRAFT -> APPROVED"),
    ("N7", "Timeline - hits + ingest chronology"),
    ("N8", "Export - template from APPROVED, no new facts"),
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def gate_path(case_dir: Path | str) -> Path:
    return Path(case_dir) / "analysis" / GATE_FILENAME


def read_lane_gate(case_dir: Path | str) -> dict[str, Any]:
    path = gate_path(case_dir)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _key(item: dict[str, Any]) -> tuple[str, str]:
    return (str(item.get("tool") or ""), str(item.get("purpose") or ""))


def _recompute(gate: dict[str, Any]) -> dict[str, Any]:
    skipped = {_key(s) for s in (gate.get("examiner_skips") or [])}
    pending = [u for u in (gate.get("unprocessed") or []) if _key(u) not in skipped]
    gate["status"] = "blocked" if pending else "clear"
    gate["blocked_count"] = len(pending)
    return gate


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _job_state(status: str) -> str:
    mapped = {
        "OK": "processed",
        "PASS": "processed",
        "FAIL": "failed",
        "ERROR": "failed",
        "RUNNING": "running",
        "SKIP": "skipped",
        "SKIPPED": "skipped",
    }
    return mapped.get(str(status or "").upper(), "unknown")


def _jobs_from_ledger(ledger: list[dict[str, Any]]) -> list[dict[str, str]]:
    jobs: list[dict[str, str]] = []
    for row in ledger:
        jobs.append({
            "tool": str(row.get("tool") or ""),
            "purpose": str(row.get("purpose") or ""),
            "family": str(row.get("family") or ""),
            "state": _job_state(str(row.get("status") or "")),
        })
    return jobs


def coverage_snapshot(case_dir: Path | str) -> dict[str, Any]:
    """Counts from the last gate, for a run record or a model prompt."""
    gate = read_lane_gate(case_dir)
    jobs = list(gate.get("jobs") or [])
    counts = {"processed": 0, "failed": 0, "running": 0, "skipped": 0, "unknown": 0}
    pending: list[str] = []
    for job in jobs:
        state = str(job.get("state") or "unknown")
        counts[state] = counts.get(state, 0) + 1
        if state in ("failed", "running", "unknown"):
            name = str(job.get("family") or job.get("purpose") or job.get("tool") or "")
            if name:
                pending.append(name)
    for item in gate.get("unprocessed") or []:
        name = str(item.get("purpose") or item.get("tool") or "")
        if name:
            pending.append(name)
    return {
        "status": gate.get("status") or "absent",
        "counts": counts,
        "pending": list(dict.fromkeys(pending)),
    }


def pending_family_notice(case_dir: Path | str) -> str:
    """One line for a model prompt. Empty when nothing is still outstanding."""
    pending = coverage_snapshot(case_dir)["pending"]
    if not pending:
        return ""
    shown = ", ".join(pending[:12])
    return (
        "PENDING EVIDENCE (not yet in the index): "
        f"{shown}. Do not claim these families are absent.\n"
    )


def _announce_processed(case_dir: Path | str, jobs: list[dict[str, str]]) -> None:
    """Tell a running Mode 2 or Mode 3 run that a family finished."""
    landed = [
        str(job.get("family") or job.get("purpose") or job.get("tool") or "")
        for job in jobs
        if job.get("state") == "processed"
    ]
    names = [name for name in dict.fromkeys(landed) if name]
    if not names:
        return
    text = "Evidence landed: " + ", ".join(names)
    root = Path(case_dir)
    targets = (
        ("analysis/mode2_runs", "nexus.modes.multi_role", "append_steering"),
        ("analysis/mode3_runs", "nexus.modes.multi_agent", "append_mode3_steering"),
    )
    for folder, module_name, fn_name in targets:
        directory = root / folder
        if not directory.is_dir():
            continue
        for path in directory.glob("*.json"):
            try:
                state = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(state, dict) or str(state.get("status") or "") != "running":
                continue
            run_id = str(state.get("run_id") or path.stem)
            try:
                import importlib

                module = importlib.import_module(module_name)
                getattr(module, fn_name)(root, run_id, text)
            except Exception:  # noqa: BLE001 — a notice must not fail the gate
                continue


def write_lane_gate(
    case_dir: Path | str,
    run_id: str,
    ledger: list[dict[str, Any]],
    *,
    ts: str | None = None,
) -> dict[str, Any]:
    """Persist the gate after a tool-lane pass. Unprocessed = FAIL rows.

    Examiner skips from the previous gate survive here only for items that are
    *still* unprocessed; an item that now parses simply disappears from the
    unprocessed list and any stale skip for it is dropped.
    """
    prior = read_lane_gate(case_dir)
    unprocessed = [
        {
            "tool": str(row.get("tool") or ""),
            "purpose": str(row.get("purpose") or ""),
            "reason": str(row.get("reason") or "")[:300],
        }
        for row in ledger
        if str(row.get("status")) == "FAIL"
    ]
    still_bad = {_key(u) for u in unprocessed}
    skips = [s for s in (prior.get("examiner_skips") or []) if _key(s) in still_bad]
    jobs = _jobs_from_ledger(ledger)
    gate: dict[str, Any] = {
        "schema": 1,
        "run_id": str(run_id or ""),
        "ts": ts or _now(),
        "rule": "never skip evidence processing (operator, 2026-09-29)",
        "unprocessed": unprocessed,
        "examiner_skips": skips,
        "jobs": jobs,
    }
    _recompute(gate)
    _atomic_write(gate_path(case_dir), gate)
    _announce_processed(case_dir, jobs)
    return gate


def examiner_skip(
    case_dir: Path | str,
    *,
    examiner: str,
    reason: str,
    items: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Record an audited examiner skip for unprocessed items.

    The caller is responsible for identity (HMAC challenge-response, the same
    path as finding approvals). Every skip keeps who / when / why.
    """
    gate = dict(read_lane_gate(case_dir))
    if not gate:
        gate = {"schema": 1, "unprocessed": []}
    skips = list(gate.get("examiner_skips") or [])
    wanted = {_key(i) for i in items} if items else None
    added = 0
    for unproc in gate.get("unprocessed") or []:
        key = _key(unproc)
        if wanted is not None and key not in wanted:
            continue
        if any(_key(s) == key for s in skips):
            continue
        skips.append({
            **unproc,
            "examiner": examiner,
            "reason": str(reason or "")[:300],
            "ts": _now(),
        })
        added += 1
    gate["examiner_skips"] = skips
    _recompute(gate)
    _atomic_write(gate_path(case_dir), gate)
    return {"gate": gate, "added": added}


def confirm_preprocessed_pair(
    case_dir: Path | str,
    *,
    raw_name: str,
    output_name: str,
    output_sha256: str,
    examiner: str,
) -> dict[str, Any]:
    """Record that a pre-processed output stands in for its raw artifact.

    The raw job is an audited skip only when it is still on the unprocessed
    list. The pairing itself is always stored.
    """
    gate = dict(read_lane_gate(case_dir))
    if not gate:
        gate = {"schema": 1, "unprocessed": [], "examiner_skips": []}
    reason = f"pre-processed output supplied: {output_name} {output_sha256}"
    pairs = list(gate.get("pairs") or [])
    pairs.append({
        "raw": raw_name,
        "output": output_name,
        "output_sha256": output_sha256,
        "examiner": examiner,
        "reason": reason[:300],
        "ts": _now(),
    })
    gate["pairs"] = pairs
    _atomic_write(gate_path(case_dir), gate)
    skipped = examiner_skip(
        case_dir,
        examiner=examiner,
        reason=reason,
        items=[{"tool": raw_name, "purpose": raw_name}],
    )
    gate = skipped["gate"]
    gate["pairs"] = pairs
    _atomic_write(gate_path(case_dir), gate)
    return gate


def lane_gate_blocked(case_dir: Path | str) -> dict[str, Any]:
    """The gate when it is blocking, {} otherwise."""
    gate = read_lane_gate(case_dir)
    return gate if gate.get("status") == "blocked" else {}


def gate_message(gate: dict[str, Any]) -> str:
    items = gate.get("unprocessed") or []
    lines = [
        "EVIDENCE GATE BLOCKED - never skip evidence processing (operator rule).",
        f"{len(items)} artifact job(s) were left unprocessed by the tool lane:",
    ]
    for item in items[:10]:
        lines.append(
            f"  - {item.get('tool')}: {item.get('purpose')} "
            f"({str(item.get('reason') or '')[:80]})"
        )
    lines.append(
        "Analysis stages (N4+) will not start. Re-run the tools lane so the "
        "item processes, or record an audited examiner skip: "
        "POST /portal/api/lane/skip (HMAC challenge, same as approvals) / "
        "`nexus lane skip`."
    )
    return "\n".join(lines)


def lane_stages(case_dir: Path | str) -> list[dict[str, Any]]:
    """N1-N8 stage states derived from case artifacts (no invented states)."""
    case_dir = Path(case_dir)
    out: list[dict[str, Any]] = []

    def add(code: str, status: str, detail: str) -> None:
        out.append({"stage": code, "status": status, "detail": detail})

    # N1 intake
    intake_q = ""
    case_yaml = case_dir / "CASE.yaml"
    if case_yaml.is_file():
        try:
            import yaml

            meta = yaml.safe_load(case_yaml.read_text(encoding="utf-8")) or {}
            intake = meta.get("intake") or {}
            intake_q = str(intake.get("question") or "")
        except Exception:  # noqa: BLE001
            intake_q = ""
    ev = case_dir / "evidence.json"
    ev_count = 0
    if ev.is_file():
        try:
            data = json.loads(ev.read_text(encoding="utf-8"))
            ev_count = len(data if isinstance(data, list) else (data.get("evidence") or []))
        except (OSError, ValueError):
            ev_count = 0
    add("N1", "done" if intake_q else "pending",
        f"{ev_count} evidence item(s); question {'set' if intake_q else 'missing'}")

    # N2 process (the gate)
    gate = read_lane_gate(case_dir)
    ledger = sorted(case_dir.rglob("runs/*/extractions/_tool_lane_ledger.json"))
    if gate:
        blocked = gate.get("status") == "blocked"
        add("N2", "blocked" if blocked else "done",
            f"run {gate.get('run_id')}: {len(gate.get('unprocessed') or [])} unprocessed, "
            f"{len(gate.get('examiner_skips') or [])} examiner skip(s)")
    elif ledger:
        add("N2", "done", f"ledger present ({ledger[-1].parent.parent.parent.name})")
    else:
        add("N2", "pending", "no tool lane ledger yet")

    # N3 index
    index_state = case_dir / "analysis" / "index_state.json"
    docs = 0
    if index_state.is_file():
        try:
            docs = int(json.loads(index_state.read_text(encoding="utf-8")).get("docs") or 0)
        except (OSError, ValueError):
            docs = 0
    add("N3", "done" if docs else "pending", f"{docs} indexed doc(s)")

    # N4 query
    add("N4", "done" if (case_dir / "analysis" / "mode1_full_run.json").is_file() else "pending",
        "needle scan ran" if (case_dir / "analysis" / "mode1_full_run.json").is_file()
        else "no scan output yet")

    # N5 interpret
    mode_runs = list((case_dir / "analysis" / "mode2_runs").glob("*.json")) + list(
        (case_dir / "analysis" / "mode3_runs").glob("*.json")
    )
    add("N5", "done" if mode_runs else "pending",
        f"{len(mode_runs)} mode run record(s)")

    # N6 approve
    findings = case_dir / "findings.json"
    approved = drafts = 0
    if findings.is_file():
        try:
            rows = json.loads(findings.read_text(encoding="utf-8")) or []
            approved = sum(1 for f in rows if str(f.get("status")) == "APPROVED")
            drafts = sum(1 for f in rows if str(f.get("status")) == "DRAFT")
        except (OSError, ValueError):
            pass
    add("N6", "done" if approved else ("in_progress" if drafts else "pending"),
        f"{approved} approved / {drafts} draft")

    # N7 timeline
    timeline = case_dir / "timeline.json"
    events = 0
    if timeline.is_file():
        try:
            data = json.loads(timeline.read_text(encoding="utf-8"))
            events = len(data if isinstance(data, list) else (data.get("events") or []))
        except (OSError, ValueError):
            events = 0
    add("N7", "done" if events else "pending", f"{events} timeline event(s)")

    # N8 export
    report = case_dir / "reports" / "REPORT.md"
    add("N8", "done" if report.is_file() else "pending",
        "REPORT.md generated" if report.is_file() else "no report yet")
    return out
