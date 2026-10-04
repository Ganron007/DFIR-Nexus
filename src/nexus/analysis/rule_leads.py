"""WO-K4 part 1 — rule-engine detections as first-class leads.

Hayabusa and Chainsaw already run in the lane, and their output is where the
Sigma ruleset actually fires. Until now those detections were only rows in a CSV:
they never reached `leads.jsonl`, so a rule that fired at `critical` and a rule
that fired at `low` were equally invisible to the briefing and to the director.

This turns each detection into a lead carrying **the rule id, the level and the
rows** the work order asks for, so a rule hit can be ranked and cited like any
other lead.

Both engines are read because they do not agree on what a detection is:

* **Hayabusa** (`extractions/hayabusa/*.csv`) gives `RuleID`, `RuleTitle`,
  `Level`, `Computer`, `EventID` and `Details` - a real severity per detection.
* **Chainsaw** (`extractions/chainsaw/*.csv`) gives the rule title in
  `detections` and no level, so those leads carry a neutral score and a note that
  the engine supplied no severity, rather than a fabricated one.
"""
from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any

from nexus.analysis.leads import Lead

log = logging.getLogger(__name__)

#: Hayabusa levels, most severe first. Anything unknown scores as low.
#: `med` is Hayabusa's own spelling (measured on a real run: levels high/low/med/
#: info); omitting it scored every medium detection as low.
_LEVEL_SCORE = {
    "critical": 1.0,
    "high": 0.9,
    "medium": 0.6,
    "med": 0.6,
    "low": 0.3,
    "informational": 0.1,
    "info": 0.1,
}

#: A run's extraction directory names, newest run wins.
def _newest_runs(case_dir: Path) -> list[Path]:
    runs = Path(case_dir) / "runs"
    if not runs.is_dir():
        return []
    found = [p for p in runs.iterdir() if p.is_dir() and (p / "extractions").is_dir()]
    return sorted(found, key=lambda p: p.name, reverse=True)


def _csv_rows(path: Path):
    """Rows from a lane CSV, tolerant of the multi-line quoted fields both tools emit."""
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            yield from csv.DictReader(fh)
    except (OSError, csv.Error) as exc:
        log.debug("rule-engine CSV unreadable (%s): %s", path, exc)


def _trim(value: Any, limit: int = 300) -> str:
    return " ".join(str(value or "").split())[:limit]


def hayabusa_leads(case_dir: Path | str, *, limit: int = 400) -> list[Lead]:
    """One lead per Hayabusa detection (rule id, level, rows)."""
    out: list[Lead] = []
    for run in _newest_runs(Path(case_dir)):
        base = run / "extractions" / "hayabusa"
        if not base.is_dir():
            continue
        for path in sorted(base.glob("*.csv")):
            for row in _csv_rows(path):
                rule_id = _trim(row.get("RuleID"), 60)
                title = _trim(row.get("RuleTitle"), 160)
                # A detection must have a TITLE. A truncated or malformed CSV
                # yields a partial row whose only populated field is a fragment of
                # the cut field (measured: a row subject became "unterminated"),
                # and that is not a detection.
                if not title:
                    continue
                level = _trim(row.get("Level"), 20).lower()
                out.append(Lead(
                    kind="rule_engine",
                    subject=title or rule_id,
                    family="hayabusa",
                    detail=(
                        f"Hayabusa {level or 'unrated'} detection"
                        + (f" [{rule_id}]" if rule_id else "")
                        + f": {title or rule_id}"
                    ),
                    rows=({
                        "rule_id": rule_id,
                        "rule_title": title,
                        "level": level,
                        "computer": _trim(row.get("Computer"), 80),
                        "event_id": _trim(row.get("EventID"), 12),
                        "timestamp": _trim(row.get("Timestamp"), 40),
                        "details": _trim(row.get("Details"), 300),
                    },),
                    audit_ids=(),
                    score=_LEVEL_SCORE.get(level, 0.3),
                    extra={"engine": "hayabusa", "level": level, "rule_id": rule_id},
                ))
                if len(out) >= limit:
                    return out
        if out:
            break  # the newest run that has output is the one that ran
    return out


def chainsaw_leads(case_dir: Path | str, *, limit: int = 400) -> list[Lead]:
    """One lead per Chainsaw detection.

    Chainsaw's CSV carries no severity, so these score at the neutral end and say
    so - inventing a level would rank a chainsaw hit against a hayabusa one on a
    number neither engine produced.
    """
    out: list[Lead] = []
    for run in _newest_runs(Path(case_dir)):
        base = run / "extractions" / "chainsaw"
        if not base.is_dir():
            continue
        for path in sorted(base.glob("*.csv")):
            for row in _csv_rows(path):
                title = _trim(row.get("detections"), 160)
                if not title:
                    continue
                out.append(Lead(
                    kind="rule_engine",
                    subject=title,
                    family="chainsaw",
                    detail=f"Chainsaw detection (no level reported): {title}",
                    rows=({
                        "rule_title": title,
                        "event_id": _trim(row.get("Event ID"), 12),
                        "computer": _trim(row.get("Computer"), 80),
                        "timestamp": _trim(row.get("timestamp"), 40),
                        "count": _trim(row.get("count"), 12),
                    },),
                    audit_ids=(),
                    score=0.5,
                    extra={"engine": "chainsaw", "level": ""},
                ))
                if len(out) >= limit:
                    return out
        if out:
            break
    return out


def rule_engine_leads(
    case_dir: Path | str,
    *,
    limit: int = 400,
) -> list[Lead]:
    """Both engines' detections, strongest first.

    Never raises: a case whose lane produced no rule output yields [] (the
    ordinary state before the lane has run), not an error.
    """
    leads: list[Lead] = []
    for engine in (hayabusa_leads, chainsaw_leads):
        try:
            leads.extend(engine(case_dir, limit=limit))
        except Exception as exc:  # noqa: BLE001 - one engine must not lose the other
            log.warning("rule-engine leads failed (%s): %s", engine.__name__, exc)
    leads.sort(key=lambda lead: (-lead.score, lead.family, lead.subject))
    return leads


def ruleset_note(case_dir: Path | str) -> dict[str, Any]:
    """What the lane actually ran, for the run's coverage record.

    The work order asks the lane to run both engines with the **current** ruleset
    at every level. Hayabusa is scheduled without a minimum-level flag, so every
    level is included; this reports what was found so the claim is checkable
    rather than assumed.
    """
    leads = rule_engine_leads(case_dir)
    by_engine: dict[str, int] = {}
    by_level: dict[str, int] = {}
    for lead in leads:
        engine = str((lead.extra or {}).get("engine") or lead.family)
        by_engine[engine] = by_engine.get(engine, 0) + 1
        level = str((lead.extra or {}).get("level") or "unrated")
        by_level[level] = by_level.get(level, 0) + 1
    return {
        "detections": len(leads),
        "by_engine": by_engine,
        "by_level": by_level,
        "levels_included": "all (Hayabusa is scheduled with no minimum-level flag)",
    }
