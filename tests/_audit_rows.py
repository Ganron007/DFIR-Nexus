"""Test helper: log a call whose rows the case's audit trail keeps, through the product's audit writer.

A claim that cites the returned audit id is grounded in those rows, so its subject comes from them, the same
way it does for a claim that a real search call grounds.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from nexus.audit import AuditWriter


def cite_rows(
    case_dir: Path,
    rows: list[dict[str, Any]],
    *,
    tool: str = "es_search",
    audit_id: str | None = None,
) -> str:
    """Log one call that stored ``rows`` as its evidence, and return the audit id it was written under.

    ``audit_id`` names the entry, for a test whose claims cite ids it chose; the writer mints one otherwise.
    """
    written = AuditWriter("nexus", audit_dir=Path(case_dir) / "audit").log(
        tool=tool,
        params={"query": tool},
        result_summary={"evidence_rows": rows},
        audit_id=audit_id,
    )
    assert written, "the audit writer did not log the call"
    return written
