"""SIFT preflight: a SIFT-required case refuses while the host is unreachable.

Operator policy (2026-09-29): SIFT is an explicitly selected, always-optional
lane. Only a case that selects it (``sift_required`` in case context) can be
refused, and the refusal is scoped to SIFT — Windows evidence processing and
every case without the selection are never affected. Recovery is exactly three
paths: bring the host up and re-run, clear the selection
(``nexus sift disable``), or the examiner's audited skip (``nexus lane skip``).
"""
from __future__ import annotations

from pathlib import Path


def sift_required(case_dir: Path) -> bool:
    """True when the case explicitly selects the SIFT lane."""
    try:
        import yaml

        meta = yaml.safe_load((Path(case_dir) / "CASE.yaml").read_text(encoding="utf-8")) or {}
        intake = meta.get("intake") if isinstance(meta, dict) else None
        value = str((intake or {}).get("sift_required") or "")
    except Exception:  # noqa: BLE001 - unreadable context is not a selection
        return False
    return value.strip().lower() in ("1", "true", "yes")


def sift_preflight_message(case_dir: Path | None) -> str:
    """``""`` when fine; a refusal message when SIFT is required + unreachable."""
    if case_dir is None or not sift_required(case_dir):
        return ""
    from nexus.case.sift_sync import sift_reachable

    try:
        ok, msg = sift_reachable()
    except Exception as exc:  # noqa: BLE001 - any probe failure is "unreachable"
        ok, msg = False, str(exc)
    if ok:
        return ""
    return (
        "SIFT analysis is required for this case but the SIFT host is "
        f"unreachable ({str(msg)[:140]}). Recoveries: bring the host up and "
        "re-run; clear the selection (`nexus sift disable`); or record the "
        "examiner's audited skip (`nexus lane skip`)."
    )
