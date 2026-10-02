"""Negative-space events (WP 10.44 / WO-A7).

The examiner's "no" and the verifier's "no" are decisions worth auditing, but
they are not findings — staging them as findings would let the agent grow the
finding list by refuting. A negative-space event is an audited, non-finding
record of: dismissed false positives, missing evidence, recommended human
review, suspected hallucinations, and refuted verifier claims.

Events go through the case AuditWriter (per-case hash-chained audit log) with
``tool="negative_space"``, so tampering with them is detectable by the same
mechanism as any other audit entry. The report renders them in a tail
section; the grade must not read them (D12 = A).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

TOOL_NAME = "negative_space"

KINDS = frozenset({
    "false_positive_dismissed",
    "missing_evidence",
    "human_review_recommended",
    "hallucination_suspected",
    "refuted",
    # WO-V6: a family that produced nothing because its prerequisite was empty.
    # "psscan saw 134 processes and malfind returned no rows" is not evidence
    # of a clean image; it is a gap in coverage.
    "coverage_gap",
})


def _case_dir(case_dir: Path | str) -> Path | None:
    """The case directory, or None when this is not a case at all.

    A negative-space event is an audit record of a case. Written against a
    directory that is not a case it lands with ``case_id: ""`` in whatever
    folder the caller happened to pass - an entry that belongs to no case and
    cannot be verified against one. Every real case directory carries its
    identity (``materialize_case_dir`` writes CASE.yaml + findings.json), so
    this refuses only stray paths, never a real case.
    """
    path = Path(case_dir)
    try:
        if not path.is_dir():
            return None
        if not (path / "CASE.yaml").is_file() and not (path / "findings.json").is_file():
            return None
    except OSError:
        return None
    return path


def record(
    case_dir: Path | str,
    kind: str,
    subject: str,
    detail: str,
    refs: list[str] | None = None,
) -> str | None:
    """Record one negative-space event. Returns the audit_id (best-effort).

    Never raises: an audit emission must not break the reject path, the
    verifier, the coverage audit or the report that triggers it.
    """
    if kind not in KINDS:
        log.warning("negative_space: unknown kind %r — not recorded", kind)
        return None
    target = _case_dir(case_dir)
    if target is None:
        log.warning(
            "negative_space: %s is not a case directory — %r not recorded",
            case_dir, kind,
        )
        return None
    try:
        from nexus.audit import AuditWriter

        writer = AuditWriter(TOOL_NAME, audit_dir=target / "audit")
        return writer.log(
            tool=TOOL_NAME,
            params={"kind": kind, "subject": str(subject)[:200]},
            result_summary={"detail": str(detail)[:400]},
            extra={
                "kind": kind,
                "subject": str(subject)[:200],
                "detail": str(detail)[:400],
                "refs": [str(r)[:120] for r in (refs or [])][:20],
            },
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("negative_space record failed (%s): %s", kind, exc)
        return None


def read_events(case_dir: Path | str) -> list[dict[str, Any]]:
    """Every recorded negative-space event, in audit order."""
    path = Path(case_dir) / "audit" / f"{TOOL_NAME}.jsonl"
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    # A torn audit line must never resurrect the previous event
                    # (or crash the report that renders these) - skip and say so.
                    log.warning("negative_space: skipping a malformed audit line")
                    continue
                if isinstance(entry, dict) and entry.get("kind") in KINDS:
                    out.append(entry)
    except OSError as exc:
        log.warning("negative_space read failed: %s", exc)
    return out


def render_markdown(case_dir: Path | str) -> str:
    """The report tail section. Empty string when there is nothing to show."""
    events = read_events(case_dir)
    if not events:
        return ""
    lines = [
        "## Negative space",
        "",
        "Decisions and findings of absence recorded during the investigation. "
        "These are audit events, not findings, and are not part of the grade.",
        "",
        "| Kind | Subject | Detail |",
        "|---|---|---|",
    ]
    for e in events:
        detail = str(e.get("detail") or "").replace("|", "\\|")
        subject = str(e.get("subject") or "").replace("|", "\\|")
        lines.append(f"| {e.get('kind')} | {subject} | {detail} |")
    lines.append("")
    return "\n".join(lines)


def record_refuted_verdicts(
    case_dir: Path | str,
    run_id: str,
    refuted_titles: list[str],
) -> int:
    """Emit point for the Mode 2/3 verifier: one ``refuted`` event per title."""
    n = 0
    for title in refuted_titles:
        title = str(title).strip()
        if not title:
            continue
        if record(
            case_dir,
            "refuted",
            title,
            "The verifier refuted this claim; it was excluded from staging.",
            refs=[str(run_id)],
        ):
            n += 1
    return n


def record_ledger_flags(case_dir: Path | str, ledger: dict[str, Any]) -> int:
    """Emit point after the L1 ledger is written (report generation).

    UNVERIFIABLE claims recommend human review; a failed L1.3 (invented
    entity) is a suspected hallucination. Reads the ledger only — claim
    verification semantics are untouched.
    """
    n = 0
    for claim in (ledger or {}).get("claims") or []:
        fid = str(claim.get("id") or "")
        verdict = str(claim.get("verdict") or "")
        checks = claim.get("checks") or {}
        if verdict == "UNVERIFIABLE" and record(
            case_dir, "human_review_recommended", fid,
            f"claim could not be verified: {str(claim.get('title') or '')[:120]}",
            refs=[fid],
        ):
            n += 1
        if str((checks.get("L1.3") or {}).get("status") or "") == "fail" and record(
            case_dir, "hallucination_suspected", fid,
            str((checks.get("L1.3") or {}).get("detail") or "")[:300],
            refs=[fid],
        ):
            n += 1
    return n


def record_missing_evidence(case_dir: Path | str, coverage: dict[str, Any]) -> int:
    """Emit point after the coverage audit: gaps become missing-evidence events."""
    if str((coverage or {}).get("overall") or "").lower() != "gaps":
        return 0
    sections = (coverage or {}).get("sections") or {}
    gaps = sorted(
        name for name, v in sections.items()
        if isinstance(v, dict) and v.get("status") == "gaps"
    )
    if not gaps:
        gaps = sorted(
            name for name in ("tools", "sources", "needles")
            if isinstance((coverage or {}).get(name), dict)
            and (coverage or {})[name].get("status") == "gaps"
        )
    return 1 if record(
        case_dir, "missing_evidence", "coverage",
        f"coverage audit reports gaps in: {', '.join(gaps) or 'unknown'}",
        refs=gaps,
    ) else 0
