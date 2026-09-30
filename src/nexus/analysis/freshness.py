"""Evidence freshness (WP 10.41 / WO-A5).

A registered artifact's SHA-256 is the chain of custody; nothing re-checks it
automatically, so post-registration modification is invisible until someone
runs ``verify_evidence`` by hand. This module captures freshness at the two
moments that matter — lane start and lane end — persists the result to
``analysis/evidence_freshness.json``, and classifies the result so surfaces
can show one honest word: ``ok`` / ``modified`` / ``missing`` / ``unknown``.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

FRESHNESS_FILE = "evidence_freshness.json"


def _classify(results: list[dict[str, Any]]) -> str:
    """One honest word for the whole case: missing beats modified in naming."""
    if not results:
        return "unknown"  # nothing registered — nothing verified
    names = [r.get("name", "") for r in results if not r.get("valid")]
    if not names:
        return "ok"
    missing = [
        r.get("name", "")
        for r in results
        if not r.get("valid") and "not found" in str(r.get("error") or "").lower()
    ]
    if len(missing) == len(names):
        return "missing"
    if missing:
        return "missing"
    return "modified"


def capture_freshness(case_dir: Path, phase: str) -> dict[str, Any]:
    """Re-hash every registered item, persist the result, return it.

    Never raises: a broken verification is recorded as ``unknown`` — evidence
    integrity reporting must not be the thing that kills a lane.
    """
    case_dir = Path(case_dir)
    payload: dict[str, Any] = {
        "schema": 1,
        "verified_at": datetime.now(UTC).isoformat(),
        "phase": phase,
        "result": "unknown",
        "items": [],
        "error": "",
    }
    try:
        from nexus.case.evidence_service import verify_evidence

        verified = verify_evidence(case_dir)
        items = verified.get("results") or []
        payload["items"] = items
        payload["result"] = _classify(items)
    except Exception as exc:  # noqa: BLE001 - reporting must not break the lane
        payload["error"] = f"{type(exc).__name__}: {exc}"
        log.warning("evidence freshness capture failed (%s): %s", phase, exc)

    out = case_dir / "analysis"
    out.mkdir(parents=True, exist_ok=True)
    try:
        (out / FRESHNESS_FILE).write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
    except OSError as exc:
        log.warning("could not write freshness state: %s", exc)
    return payload


def freshness_brief(case_dir: Path) -> dict[str, Any]:
    """The surface projection: ``{verified_at, result}`` (or unknown)."""
    fp = Path(case_dir) / "analysis" / FRESHNESS_FILE
    if not fp.is_file():
        return {"verified_at": "", "result": "unknown", "items": []}
    try:
        data = json.loads(fp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"verified_at": "", "result": "unknown", "items": []}
    return {
        "verified_at": str(data.get("verified_at") or ""),
        "result": str(data.get("result") or "unknown"),
        "items": data.get("items") or [],
    }


def freshness_regressions(
    start: dict[str, Any], end: dict[str, Any]
) -> list[dict[str, str]]:
    """Items that were intact at lane start and are not at lane end.

    Pre-existing problems are recorded in the freshness JSON; only a change
    *during* the lane becomes a gate-visible FAIL row (WO-A5).
    """
    def _state(items: list[dict[str, Any]]) -> dict[str, bool]:
        return {
            str(r.get("name") or ""): bool(r.get("valid"))
            for r in items
            if r.get("name")
        }

    before = _state(start.get("items") or [])
    after = _state(end.get("items") or [])
    out: list[dict[str, str]] = []
    for name, was_ok in before.items():
        if was_ok and after.get(name) is False:
            out.append({"name": name, "was": "ok", "now": "not ok"})
    return out
