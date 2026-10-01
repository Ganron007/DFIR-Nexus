"""Classify a Mode 1 draft without treating an examiner's own draft as suspect.

Model-staged drafts are checked again. A draft the examiner built is left
alone. A cited query that now returns no rows is REFUTED and recorded as a
negative-space event. Audit-backed drafts whose query is not re-run stay
INFERRED. A search that cannot run does not become a refutation.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
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


def cited_terms(draft: dict[str, Any]) -> list[str]:
    """Needles the draft claims were searched. Empty when none were stored."""
    raw = draft.get("needles")
    if raw is None:
        raw = (draft.get("provenance") or {}).get("needles") or []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return [str(term).strip() for term in raw if str(term).strip()]


def _index_hits(case_dir: Path, terms: list[str]) -> list[Any] | None:
    """Re-run the cited needles. None when the search itself fails."""
    try:
        from nexus.langgraph.query_pack import n4_hits

        hits, _backend = n4_hits(Path(case_dir), terms, (None, None))
    except Exception:  # noqa: BLE001 — a broken search is not a refutation
        return None
    return list(hits or [])


def apply_verifier(
    case_dir: Path | str | None,
    draft: dict[str, Any],
    *,
    hits: list[Any] | None = None,
) -> dict[str, Any]:
    """Classify *draft*.

    ``hits`` is the row set the caller just retrieved. When it is omitted and
    the draft stored needles, those needles are re-run against the index.
    REFUTED stays on the draft, is audited as negative space, and is not deleted.
    """
    terms = cited_terms(draft)
    search: Callable[[dict[str, Any]], list[Any]] | None = None
    if hits is not None:
        rows = list(hits)

        def search(_draft: dict[str, Any], rows: list[Any] = rows) -> list[Any]:
            return rows
    elif terms and case_dir is not None:
        found = _index_hits(Path(case_dir), terms)
        if found is not None:
            rows = found

            def search(_draft: dict[str, Any], rows: list[Any] = rows) -> list[Any]:
                return rows

    verdict = classify_draft(draft, search=search)
    if verdict.get("verdict") == "REFUTED" and case_dir is not None:
        try:
            from nexus.analysis.negative_space import record

            record(
                case_dir,
                "refuted",
                str(draft.get("title") or ", ".join(terms) or "draft"),
                str(verdict.get("reason") or ""),
                list(verdict.get("audit_ids") or []),
            )
        except Exception:  # noqa: BLE001 — the verdict still stands
            pass
    return verdict
