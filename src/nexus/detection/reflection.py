"""Self-improvement reflection module for DFIR-Nexus.

Captures lessons learned from investigations at three granularity levels:
- **micro**: per-detection feedback (did this rule fire? was it a true positive?)
- **meso**: per-technique-category aggregation (which ATT&CK tactics have gaps?)
- **macro**: weekly trend analysis (improvement over time, recurring gaps)

All data is stored in a local SQLite database. All functions are pure
(db_path parameter for storage, no global state).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class ReflectionLevel(StrEnum):
    """Granularity of a reflection entry."""

    MICRO = "micro"
    MESO = "meso"
    MACRO = "macro"


class Outcome(StrEnum):
    """Outcome of a detection or investigation step."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    TRUE_NEGATIVE = "true_negative"
    UNKNOWN = "unknown"


@dataclass
class ReflectionEntry:
    """A single reflection / lesson-learned record."""

    id: str
    level: ReflectionLevel
    case_id: str
    technique_id: str
    tactic_id: str
    detection_rule_id: str
    outcome: Outcome
    # What happened
    summary: str
    # What we learned
    lesson: str
    # Actionable recommendation
    recommendation: str
    # Tools or methods that were effective
    effective_tools: list[str] = field(default_factory=list)
    # Detection gaps identified
    gaps: list[str] = field(default_factory=list)
    # Timestamp
    timestamp: str = ""
    # Additional metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["level"] = self.level.value
        d["outcome"] = self.outcome.value
        return d


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS reflections (
    id TEXT PRIMARY KEY,
    level TEXT NOT NULL,
    case_id TEXT NOT NULL,
    technique_id TEXT NOT NULL DEFAULT '',
    tactic_id TEXT NOT NULL DEFAULT '',
    detection_rule_id TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    lesson TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    effective_tools_json TEXT NOT NULL DEFAULT '[]',
    gaps_json TEXT NOT NULL DEFAULT '[]',
    timestamp TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_reflections_level ON reflections(level);
CREATE INDEX IF NOT EXISTS idx_reflections_case ON reflections(case_id);
CREATE INDEX IF NOT EXISTS idx_reflections_technique ON reflections(technique_id);
CREATE INDEX IF NOT EXISTS idx_reflections_tactic ON reflections(tactic_id);
CREATE INDEX IF NOT EXISTS idx_reflections_ts ON reflections(timestamp);
"""


def init_reflection_db(db_path: str | Path) -> None:
    """Initialize the reflection SQLite database with the required schema.

    Safe to call multiple times (CREATE IF NOT EXISTS).

    Args:
        db_path: Path to the SQLite database file.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(_CREATE_SQL)
        conn.commit()
    finally:
        conn.close()


def record_micro_reflection(
    db_path: str | Path,
    *,
    case_id: str,
    technique_id: str,
    detection_rule_id: str,
    outcome: Outcome,
    summary: str,
    lesson: str,
    recommendation: str,
    effective_tools: list[str] | None = None,
    gaps: list[str] | None = None,
    tactic_id: str = "",
    metadata: dict[str, Any] | None = None,
) -> ReflectionEntry:
    """Record a micro-level (per-detection) reflection.

    Args:
        db_path: Path to the reflection SQLite database.
        case_id: The case this reflection belongs to.
        technique_id: MITRE technique ID (e.g., "T1059.001").
        detection_rule_id: ID of the detection rule evaluated.
        outcome: Whether the detection was a TP/FP/FN/TN.
        summary: Brief description of what happened.
        lesson: What we learned from this.
        recommendation: Actionable next step.
        effective_tools: Tools that helped in this investigation.
        gaps: Detection or process gaps identified.
        tactic_id: MITRE tactic ID (e.g., "TA0002").
        metadata: Arbitrary extra data.

    Returns:
        The created ReflectionEntry.
    """
    entry = _build_entry(
        level=ReflectionLevel.MICRO,
        case_id=case_id,
        technique_id=technique_id,
        tactic_id=tactic_id,
        detection_rule_id=detection_rule_id,
        outcome=outcome,
        summary=summary,
        lesson=lesson,
        recommendation=recommendation,
        effective_tools=effective_tools,
        gaps=gaps,
        metadata=metadata,
    )
    _insert_entry(db_path, entry)
    return entry


def record_meso_reflection(
    db_path: str | Path,
    *,
    case_id: str,
    technique_id: str,
    tactic_id: str,
    outcome: Outcome,
    summary: str,
    lesson: str,
    recommendation: str,
    effective_tools: list[str] | None = None,
    gaps: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> ReflectionEntry:
    """Record a meso-level (per-technique-category) reflection.

    Args:
        db_path: Path to the reflection SQLite database.
        case_id: The case this reflection belongs to.
        technique_id: Primary technique assessed.
        tactic_id: Tactic category (e.g., "TA0006" for Credential Access).
        outcome: Aggregate outcome for this technique category.
        summary: What happened across detections for this technique.
        lesson: Pattern-level insight.
        recommendation: How to improve detection coverage.
        effective_tools: Tools effective against this technique class.
        gaps: Systemic gaps for this technique category.
        metadata: Arbitrary extra data.

    Returns:
        The created ReflectionEntry.
    """
    entry = _build_entry(
        level=ReflectionLevel.MESO,
        case_id=case_id,
        technique_id=technique_id,
        tactic_id=tactic_id,
        detection_rule_id="",
        outcome=outcome,
        summary=summary,
        lesson=lesson,
        recommendation=recommendation,
        effective_tools=effective_tools,
        gaps=gaps,
        metadata=metadata,
    )
    _insert_entry(db_path, entry)
    return entry


def record_macro_reflection(
    db_path: str | Path,
    *,
    case_id: str,
    summary: str,
    lesson: str,
    recommendation: str,
    effective_tools: list[str] | None = None,
    gaps: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> ReflectionEntry:
    """Record a macro-level (weekly) reflection.

    Args:
        db_path: Path to the reflection SQLite database.
        case_id: Case or review period identifier.
        summary: High-level trend summary.
        lesson: Strategic insight.
        recommendation: Process or capability improvement.
        effective_tools: Tools that showed consistent value.
        gaps: Organization-wide detection or process gaps.
        metadata: Arbitrary extra data.

    Returns:
        The created ReflectionEntry.
    """
    entry = _build_entry(
        level=ReflectionLevel.MACRO,
        case_id=case_id,
        technique_id="",
        tactic_id="",
        detection_rule_id="",
        outcome=Outcome.UNKNOWN,
        summary=summary,
        lesson=lesson,
        recommendation=recommendation,
        effective_tools=effective_tools,
        gaps=gaps,
        metadata=metadata,
    )
    _insert_entry(db_path, entry)
    return entry


def get_reflections(
    db_path: str | Path,
    *,
    level: ReflectionLevel | None = None,
    case_id: str | None = None,
    technique_id: str | None = None,
    tactic_id: str | None = None,
    limit: int = 100,
) -> list[ReflectionEntry]:
    """Query reflections with optional filters.

    Args:
        db_path: Path to the reflection SQLite database.
        level: Filter by reflection level.
        case_id: Filter by case ID.
        technique_id: Filter by technique ID.
        tactic_id: Filter by tactic ID.
        limit: Maximum number of entries to return.

    Returns:
        List of ReflectionEntry objects, newest first.
    """
    path = Path(db_path)
    if not path.exists():
        return []

    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    try:
        clauses: list[str] = []
        params: list[Any] = []
        if level:
            clauses.append("level = ?")
            params.append(level.value)
        if case_id:
            clauses.append("case_id = ?")
            params.append(case_id)
        if technique_id:
            clauses.append("technique_id = ?")
            params.append(technique_id)
        if tactic_id:
            clauses.append("tactic_id = ?")
            params.append(tactic_id)

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT * FROM reflections{where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [_row_to_entry(r) for r in rows]
    finally:
        conn.close()


def get_detection_gap_summary(
    db_path: str | Path,
    *,
    days: int = 30,
) -> dict[str, Any]:
    """Aggregate detection gaps by tactic for the given time window.

    Args:
        db_path: Path to the reflection SQLite database.
        days: Number of days to look back.

    Returns:
        Dict with ``gaps_by_tactic``, ``total_reflections``,
        ``false_negative_rate``, and ``top_gaps``.
    """
    path = Path(db_path)
    if not path.exists():
        return {
            "gaps_by_tactic": {},
            "total_reflections": 0,
            "false_negative_rate": 0.0,
            "top_gaps": [],
        }

    cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()

    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM reflections WHERE timestamp >= ? ORDER BY timestamp DESC",
            (cutoff,),
        ).fetchall()
    finally:
        conn.close()

    entries = [_row_to_entry(r) for r in rows]
    total = len(entries)

    gaps_by_tactic: dict[str, int] = {}
    fn_count = 0
    all_gaps: list[str] = []

    for entry in entries:
        if entry.outcome == Outcome.FALSE_NEGATIVE:
            fn_count += 1
        if entry.tactic_id:
            gap_count = len(entry.gaps)
            gaps_by_tactic[entry.tactic_id] = (
                gaps_by_tactic.get(entry.tactic_id, 0) + gap_count
            )
        all_gaps.extend(entry.gaps)

    # Count most common gap descriptions
    gap_freq: dict[str, int] = {}
    for g in all_gaps:
        gap_freq[g] = gap_freq.get(g, 0) + 1
    top_gaps = sorted(gap_freq.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "gaps_by_tactic": gaps_by_tactic,
        "total_reflections": total,
        "false_negative_rate": fn_count / total if total > 0 else 0.0,
        "top_gaps": [{"gap": g, "count": c} for g, c in top_gaps],
    }


def get_tool_effectiveness(
    db_path: str | Path,
    *,
    days: int = 30,
) -> dict[str, int]:
    """Count how often each tool was cited as effective.

    Args:
        db_path: Path to the reflection SQLite database.
        days: Number of days to look back.

    Returns:
        Dict mapping tool name → citation count, sorted descending.
    """
    path = Path(db_path)
    if not path.exists():
        return {}

    cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()

    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT effective_tools_json FROM reflections WHERE timestamp >= ?",
            (cutoff,),
        ).fetchall()
    finally:
        conn.close()

    counts: dict[str, int] = {}
    for row in rows:
        tools = json.loads(row["effective_tools_json"])
        for tool in tools:
            counts[tool] = counts.get(tool, 0) + 1

    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_entry(
    *,
    level: ReflectionLevel,
    case_id: str,
    technique_id: str,
    tactic_id: str,
    detection_rule_id: str,
    outcome: Outcome,
    summary: str,
    lesson: str,
    recommendation: str,
    effective_tools: list[str] | None,
    gaps: list[str] | None,
    metadata: dict[str, Any] | None,
) -> ReflectionEntry:
    """Construct a ReflectionEntry with defaults."""
    return ReflectionEntry(
        id=f"REFL-{uuid.uuid4().hex[:12].upper()}",
        level=level,
        case_id=case_id,
        technique_id=technique_id,
        tactic_id=tactic_id,
        detection_rule_id=detection_rule_id,
        outcome=outcome,
        summary=summary,
        lesson=lesson,
        recommendation=recommendation,
        effective_tools=effective_tools or [],
        gaps=gaps or [],
        timestamp=datetime.now(UTC).isoformat(),
        metadata=metadata or {},
    )


def _insert_entry(db_path: str | Path, entry: ReflectionEntry) -> None:
    """Insert a reflection entry into SQLite."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(_CREATE_SQL)
        conn.execute(
            """
            INSERT INTO reflections (
                id, level, case_id, technique_id, tactic_id,
                detection_rule_id, outcome, summary, lesson,
                recommendation, effective_tools_json, gaps_json,
                timestamp, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.id,
                entry.level.value,
                entry.case_id,
                entry.technique_id,
                entry.tactic_id,
                entry.detection_rule_id,
                entry.outcome.value,
                entry.summary,
                entry.lesson,
                entry.recommendation,
                json.dumps(entry.effective_tools),
                json.dumps(entry.gaps),
                entry.timestamp,
                json.dumps(entry.metadata),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _row_to_entry(row: sqlite3.Row) -> ReflectionEntry:
    """Convert a SQLite Row to a ReflectionEntry."""
    return ReflectionEntry(
        id=row["id"],
        level=ReflectionLevel(row["level"]),
        case_id=row["case_id"],
        technique_id=row["technique_id"],
        tactic_id=row["tactic_id"],
        detection_rule_id=row["detection_rule_id"],
        outcome=Outcome(row["outcome"]),
        summary=row["summary"],
        lesson=row["lesson"],
        recommendation=row["recommendation"],
        effective_tools=json.loads(row["effective_tools_json"]),
        gaps=json.loads(row["gaps_json"]),
        timestamp=row["timestamp"],
        metadata=json.loads(row["metadata_json"]),
    )
