"""Readable finding titles, grounded in the rows.

A finding title is the first thing an examiner reads and the only thing many will
read. Three producers were emitting machine identifiers into it:

* Mode 1 staged ``Signal: sdelete - 1 hit(s) across evtxecmd`` - the *needle*
  that matched, not what the row says. All eleven titles on the first real case
  read that way, which made the report an inventory of search terms.
* Mode 3 staged ``evtxecmd: presence`` - an entity value and a claim kind, which
  is a dispute key rendered as English.
* Mode 2 already reads well ("Host identity: WIN-7LFOBBPCFKB is inferred to be
  SRL-FORGE"), which is the standard to meet.

The fix is not to guess a better label - it is to put the **row's own
descriptor** in the title, because that is grounded by construction. Where a
needle matched a row that does not describe it, the title says so, which turns
the "mention, not an instance" defect (L1.10) visible before approval rather than
after.
"""
from __future__ import annotations

import re
from typing import Any

__all__ = ["row_descriptor", "needle_title", "claim_title"]

# Fields that state what a row is about, most specific first.
_DESCRIPTOR_FIELDS = (
    "MapDescription", "RuleTitle", "Task", "Opcode", "Description",
    "Message", "EventName", "SourceName", "Provider_Name",
)
# A descriptor worth quoting is short and sentence-like. Long values are XML or
# JSON blobs, which help nobody in a title.
_MAX_DESCRIPTOR = 110
_NOISE_DESCRIPTOR = re.compile(
    r"^\s*(?:[\d\W_]*|true|false|null|n/?a|-)\s*$", re.I
)


def _clean(value: Any) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    text = text.strip("\"'`| ")
    if not text or _NOISE_DESCRIPTOR.match(text):
        return ""
    if len(text) > _MAX_DESCRIPTOR:
        text = text[: _MAX_DESCRIPTOR - 1].rsplit(" ", 1)[0] + "…"
    return text


def _clean_id(value: Any) -> str:
    """Like ``_clean`` but keeps an all-digits value.

    Event ids are exactly that - "8194", "4104" - and the noise filter that
    rejects bare numbers for descriptors was silently dropping the single most
    useful token a responder can search on.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip().strip("\"'`| ")
    if not text or len(text) > 24 or _NOISE_DESCRIPTOR.match(text) and not text.isdigit():
        return ""
    return text


def row_descriptor(row: dict[str, Any] | None) -> str:
    """What this row says it is about, or "" when it says nothing usable.

    Reads the named descriptor fields, then falls back to the row's rendered
    ``detail`` / ``text``. The event id is folded in when present, because
    "Restore point created successfully" is far more useful to a responder with
    "EventID 8194" attached than without.
    """
    if not isinstance(row, dict):
        return ""
    fields = row.get("fields") if isinstance(row.get("fields"), dict) else {}

    label = ""
    for key in _DESCRIPTOR_FIELDS:
        label = _clean(row.get(key)) or _clean(fields.get(key))
        if label:
            break

    eid = _clean_id(row.get("EventId") or row.get("event_id")
                    or fields.get("EventId") or fields.get("EventID")
                    or fields.get("event_id"))
    if eid and eid.lower() not in label.lower():
        label = f"EventID {eid}" + (f" {label}" if label else "")

    if not label:
        # A one-character fragment of a row is not a description. The named
        # descriptor fields can legitimately be short (an EventId), but free-text
        # fallbacks cannot - they are fragments of a row, not statements about it.
        for key in ("detail", "text", "title", "MapDescription"):
            candidate = _clean(row.get(key))
            if len(candidate) >= 4 and not candidate.lower().startswith(
                ("source:", "rule:", "match", "loc:")
            ):
                label = candidate
                break
    return label


def needle_title(needle: str, hits: list[dict[str, Any]], families: list[str]) -> str:
    """Mode 1: a statement about the rows, led by what the rows say.

    Keeps the needle, because it is what makes the finding traceable back to the
    search that found it and what the report groups on. But the reader gets the
    conclusion first-class instead of as a hit count.
    """
    needle = str(needle or "").strip() or "signal"
    rows = [h for h in (hits or []) if isinstance(h, dict)]
    n = len(rows)
    fam = ", ".join(families) if families else "indexed rows"

    labels: list[str] = []
    for h in rows:
        label = row_descriptor(h)
        if label and label not in labels:
            labels.append(label)
        if len(labels) == 2:
            break

    if not labels:
        return f"{needle} matched {n} {fam} row(s)"

    said = "; ".join(labels)
    # The needle matched this row somewhere. If the row never names it in its own
    # descriptor, the match is incidental - a System Restore event that lists the
    # needle among registered applications. Saying so is the honest title.
    if needle.lower() not in said.lower():
        return (f"{needle} appears in {n} {fam} row(s), which describe: {said}")
    return f"{needle} in {n} {fam} row(s) - {said}"


def claim_title(
    entity: str,
    kind: str,
    value: str = "",
    justification: str = "",
) -> str:
    """Mode 3: a claim in English rather than a dispute key.

    ``evtxecmd: presence`` is a machine pair. The claim carries a value and a
    justification; either is a sentence an examiner can read, so one of them
    leads the title.
    """
    entity = str(entity or "").strip() or "artifact"
    kind = str(kind or "").strip().lower()

    detail = _clean(value)
    if not detail or detail.lower() in {"true", "present", "yes", "1"}:
        detail = ""
    if not detail:
        detail = _clean(justification)

    verb = {
        "presence": "present",
        "existence": "present",
        "execution": "executed",
        "observation": "observed",
        "interpretation": "interpreted",
        "persistence": "persisting",
        "temporal": "timed",
        "network": "connected",
        "attribution": "attributed",
    }.get(kind, kind or "observed")

    if detail:
        return f"{entity} - {verb}: {detail}"
    return f"{entity} {verb}"
