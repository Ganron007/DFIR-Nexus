"""Classify a Mode 1 draft without treating an examiner's own draft as suspect.

Model-staged drafts are checked again. A draft the examiner built is left
alone. A cited query that now returns no rows is REFUTED. Audit-backed drafts
whose query is not re-run stay INFERRED.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any


def _origin(draft: dict[str, Any]) -> str:
    provenance = draft.get("provenance") or {}
    origin = str(provenance.get("origin") or "").strip().lower()
    if origin:
        return origin
    return "examiner" if draft.get("examiner_selected") else "llm"


def classify_draft(
    draft: dict[str, Any],
    *,
    search: Callable[[dict[str, Any]], list[Any]] | None = None,
) -> dict[str, Any]:
    """Return a verifier record. Does not delete the draft."""
    origin = _origin(draft)
    audits = [str(a) for a in (draft.get("audit_ids") or []) if a]
    if origin == "examiner":
        return {
            "verdict": "skipped",
            "reason": "examiner-built drafts are not auto-verified",
            "audit_ids": audits,
        }
    if not audits:
        return {
            "verdict": "REFUTED",
            "reason": "FD-001: model draft has no audit_id",
            "audit_ids": [],
        }
    if search is None:
        return {
            "verdict": "INFERRED",
            "reason": "audit ids present; cited query was not re-run",
            "audit_ids": audits,
        }
    hits = list(search(draft) or [])
    if hits:
        return {
            "verdict": "CONFIRMED",
            "reason": f"{len(hits)} row(s) still match the cited query",
            "audit_ids": audits,
        }
    return {
        "verdict": "REFUTED",
        "reason": "cited query returned no rows",
        "audit_ids": audits,
    }
