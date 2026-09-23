"""Needle vocabulary gate: scannable terms only (F6).

Mode 1 scans keyword *content*; two term classes never belong in that scan:

- bare numbers (event IDs, ports, status codes) — those belong to typed field
  checks (``event_ids:``), and the match-site layer already treats numeric
  matches as facts, not signal;
- evidence-container file names (``security.evtx``, ...) — the artifact name
  is provenance, not behaviour.

The gate is applied at the vocabulary accessors (playbooks / ATT&CK / Sigma /
ITM / external packs). The raw terms stay in the YAML so provenance is
preserved and a future data migration can move them into ``event_ids:`` /
``artifacts:`` keys without losing anything.
"""

from __future__ import annotations

import re

NUMERIC_TERM = re.compile(r"^\d+$")
_CONTAINER_FILE = re.compile(r"\.(evtx|csv|log|txt)$", re.IGNORECASE)


def is_scannable_term(term: object) -> bool:
    """True when a term may enter the keyword scan surface."""
    text = str(term or "").strip()
    if len(text) < 2:
        return False
    if NUMERIC_TERM.fullmatch(text):
        return False
    if _CONTAINER_FILE.search(text):
        return False
    return True


def split_terms(terms: list | tuple | None) -> tuple[list[str], dict[str, list[str]]]:
    """Split terms into ``(scannable, context)``.

    ``context`` carries ``event_ids`` (bare numbers) and ``artifacts``
    (container file names) — preserved for typed checks, never scanned.
    """
    scan: list[str] = []
    context: dict[str, list[str]] = {"event_ids": [], "artifacts": []}
    for term in terms or []:
        text = str(term or "").strip()
        if not text:
            continue
        if NUMERIC_TERM.fullmatch(text):
            if text not in context["event_ids"]:
                context["event_ids"].append(text)
        elif _CONTAINER_FILE.search(text):
            if text not in context["artifacts"]:
                context["artifacts"].append(text)
        elif is_scannable_term(text):
            scan.append(text)
    return scan, context


def filter_scannable(terms: list | tuple | None) -> list[str]:
    """Scannable terms only (order preserved)."""
    return split_terms(terms)[0]
