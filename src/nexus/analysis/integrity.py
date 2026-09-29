"""Citation + timestamp integrity at submission — WIRING-PLAN 10.4 (hardens FD-001).

Three checks, applied where a DRAFT is written so they cannot be bypassed:

**1. Citation existence (hard reject).** Every ``audit_id`` a finding cites must
exist in *this case's* audit log. FD-001 only demands at least one real
reference, so today a finding can cite three genuine calls plus two invented
ones and still stage as PARTIAL. This module closes that: unknown references are
rejected at submission, not downgraded. *Existent but unrelated* references stay
a downgrade (that is the EH-9 linkage rule, deliberately not a rejection).

**2. Timestamp validity (nullify + flag, never reject).** ``event_timestamp`` and
evidence-row timestamps are checked for ISO-8601 validity and for values that
parse but cannot be real — epoch zero, pre-1990, far future, placeholder text.
Suspicious values are **nullified and flagged** rather than rejected, because a
bad timestamp is a data-quality problem, not an attempt to fabricate provenance.
Rejecting there would teach callers to drop the whole finding instead of the
field.

**3. Seal verification (flag).** A staged finding carries a content digest
(:func:`seal_digest`). :func:`verify_seal` recomputes it; a mismatch means the
entry changed after staging. That is surfaced, never silently repaired — a
tamper signal must reach a human.

Kept separate from :mod:`nexus.discipline` on purpose: the FD rules describe what
a finding must *contain*; this module verifies the references and values it
contains are real.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

SEAL_ALGO = "sha256"

#: Keys excluded from the seal — they legitimately change after staging
#: (approval fields, bookkeeping, the seal itself).
SEAL_EXCLUDE_KEYS = frozenset(
    {
        "content_hash",
        "seal",
        "status",
        "approved_by",
        "approved_at",
        "rejected_by",
        "rejected_at",
        "rejection_reason",
        "hmac_signature",
        "hmac_salt",
        "modified_at",
        "notes",
        # WO-2: approval-time annotations - written with the approval, after
        # staging, so they must not invalidate the submission seal.
        "l1_verdict_at_approval",
        "override_reason",
    }
)

_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}"
    r"([T ]\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?"
    r"(Z|[+-]\d{2}:?\d{2})?)?$"
)
_PLACEHOLDERS = {
    "",
    "-",
    "n/a",
    "na",
    "none",
    "null",
    "unknown",
    "tbd",
    "0",
    "epoch",
    "not available",
}
#: Windows FILETIME epoch (1601-01-01) as a Unix timestamp — a common parser bug.
_FILETIME_EPOCH = -11644473600
_MIN_YEAR = 1990
_MAX_FUTURE_DAYS = 366


def seal_digest(entry: dict[str, Any]) -> str:
    """Content digest of a staged finding (stable across key ordering)."""
    hashable = {k: v for k, v in entry.items() if k not in SEAL_EXCLUDE_KEYS}
    canonical = json.dumps(hashable, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def verify_seal(entry: dict[str, Any]) -> tuple[bool, str]:
    """Recompute the seal. Returns ``(ok, reason)``; never raises."""
    stored = str((entry.get("seal") or {}).get("digest") or entry.get("content_hash") or "")
    if not stored:
        return False, "no seal recorded"
    try:
        actual = seal_digest(entry)
    except Exception as exc:  # noqa: BLE001
        return False, f"seal recompute failed: {exc}"
    if actual != stored:
        return False, "content changed after staging (seal mismatch)"
    return True, "seal intact"


def _parse_iso(raw: str) -> datetime | None:
    text = raw.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def validate_timestamp(raw: Any, *, now: datetime | None = None) -> tuple[str, str]:
    """Return ``(value, flag)``. ``value`` is "" when the input must not be used.

    ``flag`` is "" when the value is fine, otherwise a short machine reason.
    """
    if raw is None:
        return "", ""
    text = str(raw).strip()
    if text.lower() in _PLACEHOLDERS:
        return "", "placeholder"
    if not _ISO_RE.match(text):
        return "", "not_iso8601"
    parsed = _parse_iso(text)
    if parsed is None:
        return "", "unparseable"
    epoch = parsed.timestamp()
    if abs(epoch - _FILETIME_EPOCH) < 1:
        return "", "filetime_epoch"
    if epoch <= 0:
        return "", "nonpositive_epoch"
    if parsed.year < _MIN_YEAR:
        return "", "pre_1990"
    reference = now or datetime.now(UTC)
    if (parsed - reference).days > _MAX_FUTURE_DAYS:
        return "", "future_dated"
    return text, ""


_TIMESTAMP_FIELD_NAMES = ("event_timestamp", "timestamp", "ts", "first_seen", "last_seen")

# Fields whose *name* marks them as a time. The fixed list above cannot keep up
# with the corpus: parsers also write start_time / end_time / entry_ts /
# date_added / last_used_at / mactime / mtime, and an implausible value in any
# of those used to escape validation entirely - which is the exact hole L1.5
# exists to close. Matching on the name means a new field is covered the day it
# is written rather than the day somebody remembers to add it here.
_TIMESTAMP_NAME_RE = re.compile(
    r"(?:^|_)(?:time|timestamp|ts|date|seen|datetime|mactime|mtime|added|at)$"
    r"|(?:^|_)(?:start|end|entry|last|first|modified|created|registered|saved)"
    r"_(?:time|timestamp|ts|date|seen|at)$",
    re.I,
)
# Not times, despite the shape.
_TIMESTAMP_NAME_EXEMPT = frozenset({
    "date_histogram", "sse_read_timeout", "due_date", "deadline",
    "candidate_findings", "draft_timeline_ids", "disk_timeline",
    "newest_extraction_mtime", "file_mtimes", "ad_credential_attacks",
    "date_detection",
})
# Cap on the nested list walk, so a finding carrying thousands of artifact rows
# cannot turn timestamp validation into a full extra pass over the case.
_MAX_NESTED_ROWS = 200


def _is_timestamp_field(key: str) -> bool:
    if key in _TIMESTAMP_FIELD_NAMES:
        return True
    if key in _TIMESTAMP_NAME_EXEMPT:
        return False
    return bool(_TIMESTAMP_NAME_RE.search(key))


def _iter_timestamp_fields(finding: dict[str, Any], _depth: int = 0) -> list[tuple[str, Any]]:
    """Every timestamp-bearing field on a finding: ``(field_path, raw)``.

    Top-level fields matched by name, then dict values and short lists of dicts
    walked one level (artifacts and evidence rows carry their own times). The
    list walk is capped at ``_MAX_NESTED_ROWS`` so a large finding cannot make
    this unbounded.
    """
    out: list[tuple[str, Any]] = []
    for key, value in finding.items():
        if not isinstance(key, str):
            continue
        if _is_timestamp_field(key):
            if value is None or isinstance(value, (str, int, float, datetime)):
                out.append((key, value))
        elif _depth == 0 and isinstance(value, dict):
            for sub, subval in _iter_timestamp_fields(value, _depth + 1):
                out.append((f"{key}.{sub}", subval))
        elif _depth == 0 and isinstance(value, list):
            for i, row in enumerate(value[:_MAX_NESTED_ROWS]):
                if isinstance(row, dict):
                    for sub, subval in _iter_timestamp_fields(row, _depth + 1):
                        out.append((f"{key}[{i}].{sub}", subval))
    return out


def sanitize_timestamps(finding: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Nullify + flag every implausible timestamp on a finding (in place).

    Returns ``{"nullified": [{field, original, reason}], "kept": n}``. The caller
    records ``nullified`` as an auditable note on the staged entry.
    """
    nullified: list[dict[str, str]] = []
    kept = 0
    for field, raw in _iter_timestamp_fields(finding):
        value, flag = validate_timestamp(raw, now=now)
        if flag:
            container = finding
            if field.startswith("evidence["):
                idx = int(field.split("[", 1)[1].split("]", 1)[0])
                key = field.split(".", 1)[1]
                try:
                    container = finding["evidence"][idx]
                except (KeyError, IndexError, TypeError):
                    continue
                container[key] = ""
            else:
                container[field] = ""
            nullified.append({"field": field, "original": str(raw)[:64], "reason": flag})
        else:
            kept += 1
    return {"nullified": nullified, "kept": kept}


def verify_citations(finding: dict[str, Any], known_ids: set[str]) -> dict[str, Any]:
    """Split cited audit ids into verified / unknown / malformed.

    ``known_ids`` must come from this case's audit log. An id that is not in the
    store is *unknown* — the finding is claiming a tool call that never happened.
    """
    cited: list[str] = []
    for aid in finding.get("audit_ids") or []:
        if aid:
            cited.append(str(aid).strip())
    for art in finding.get("artifacts") or []:
        if isinstance(art, dict) and art.get("audit_id"):
            cited.append(str(art["audit_id"]).strip())
    seen: set[str] = set()
    unique = [a for a in cited if not (a in seen or seen.add(a))]

    unknown = sorted(a for a in unique if a not in known_ids)
    return {
        "cited": unique,
        "verified": sorted(a for a in unique if a in known_ids),
        "unknown": unknown,
        "count": len(unique),
    }


def load_known_audit_ids(case_dir) -> set[str]:
    """Every ``audit_id`` present in the case's audit logs (JSONL)."""
    from pathlib import Path

    case = Path(case_dir)
    audit_dir = case / "audit"
    ids: set[str] = set()
    if not audit_dir.is_dir():
        return ids
    for jsonl in audit_dir.glob("*.jsonl"):
        try:
            with jsonl.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    aid = entry.get("audit_id")
                    if aid:
                        ids.add(str(aid))
        except OSError:
            continue
    return ids


_NARRATIVE_FIELDS = ("title", "description", "interpretation", "rationale",
                     "claim", "impact", "observation")


def _evidence_blob(finding: dict[str, Any]) -> str:
    """Everything the finding's own rows actually say, as one searchable blob."""
    parts: list[str] = []
    for row in finding.get("evidence") or ():
        if not isinstance(row, dict):
            continue
        for key in ("detail", "source", "artifact", "loc"):
            parts.append(str(row.get(key) or ""))
        fields = row.get("fields")
        if isinstance(fields, dict):
            parts.extend(str(v) for v in fields.values())
    for key in ("sources", "families", "family"):
        v = finding.get(key)
        if isinstance(v, list):
            parts.extend(str(x) for x in v)
        elif v:
            parts.append(str(v))
    return " ".join(parts).lower()


def sanitize_entity_mentions(
    finding: dict[str, Any],
    *,
    case_dir=None,
    resolver=None,
) -> dict[str, Any]:
    """Nullify and flag every entity a finding names that its own rows do not.

    The asymmetry with Modes 2 and 3 is structural, not a prompt problem. Both
    agent runtimes put every candidate through ``accept_claim`` (FD-001..007)
    and a verifier node before anything is staged. Mode 1 goes needle -> scribe
    -> DRAFT with nothing in between, so an LLM-written interpretation can name a
    process the rows never mention. On the first real case one finding's
    interpretation named ``msmpeng.exe`` while all eleven of its evidence rows
    were ``PwSh Engine Started`` - PowerShell only.

    The remedy follows the rule 10.4 already sets for timestamps: **nullify and
    flag, never reject.** A mention that does not resolve might be a negative
    one ("this is not msmpeng.exe"), and rejecting a correct finding over a
    phrase would be worse than flagging it. So the unsupported mention is
    removed from the narrative, recorded, and the examiner sees both.

    ``resolver`` is the optional live-index hook. Without it this returns
    ``unknown`` rather than guessing - a check with no input is not a pass.
    """
    rows_blob = _evidence_blob(finding)
    if not rows_blob.strip():
        return {"checked": False, "reason": "finding carries no evidence rows",
                "unsupported": [], "nullified": []}

    from nexus.analysis.cross_mode import _entities

    found: list[dict[str, Any]] = []
    for field in _NARRATIVE_FIELDS:
        value = finding.get(field)
        if not isinstance(value, str) or not value.strip():
            continue
        for etype, entity in _entities(value):
            if entity in rows_blob:
                continue
            if resolver is not None and resolver(entity):
                continue
            found.append({"field": field, "entity_type": etype,
                          "entity": entity, "value": value})

    if not found:
        return {"checked": True, "reason": "", "unsupported": [], "nullified": []}

    nullified: list[dict[str, Any]] = []
    by_field: dict[str, list[str]] = {}
    for item in found:
        by_field.setdefault(item["field"], []).append(item["entity"])
    for field, entities in by_field.items():
        text = str(finding.get(field) or "")
        kept = text
        for entity in sorted(set(entities), key=len, reverse=True):
            for form in {entity, entity.title(), entity.upper()}:
                if form and form in kept:
                    kept = kept.replace(form, f"[{entity}: unsupported by the cited rows]")
        if kept != text:
            finding[field] = kept
            nullified.append({"field": field, "entities": sorted(set(entities))})

    return {
        "checked": True,
        "reason": "",
        "unsupported": found,
        "nullified": nullified,
    }


def enforce_submission_integrity(
    finding: dict[str, Any],
    case_dir,
    *,
    known_ids: set[str] | None = None,
    now: datetime | None = None,
    resolver=None,
) -> dict[str, Any]:
    """Apply all three checks to a finding about to be staged.

    Returns ``{"ok": bool, "errors": [...], "warnings": [...],
    "citations": {...}, "timestamps": {...}}``. ``ok`` is False only for unknown
    citations — a bad timestamp is a warning with the value already nullified.
    """
    ids = load_known_audit_ids(case_dir) if known_ids is None else known_ids
    citations = verify_citations(finding, ids)
    timestamps = sanitize_timestamps(finding, now=now)
    entities = sanitize_entity_mentions(finding, case_dir=case_dir, resolver=resolver)

    errors: list[str] = []
    warnings: list[str] = []

    if not citations["cited"]:
        errors.append("FD-001: no audit_id reference — a finding must cite a real tool call")
    elif citations["unknown"]:
        listed = ", ".join(citations["unknown"][:10])
        more = f" (+{len(citations['unknown']) - 10} more)" if len(citations["unknown"]) > 10 else ""
        errors.append(
            f"citation integrity: {len(citations['unknown'])} cited audit_id(s) do not exist in this "
            f"case's audit log: {listed}{more}. A finding may not reference a tool call that "
            f"never happened (WP 10.4)."
        )

    for item in timestamps["nullified"]:
        warnings.append(
            f"timestamp nullified: {item['field']}={item['original']!r} "
            f"({item['reason']}) - implausible value cleared, not used as evidence"
        )

    for item in entities.get("nullified") or ():
        listed = ", ".join(item["entities"][:6])
        warnings.append(
            f"entity mention nullified: {item['field']} named {listed}, which the cited "
            f"rows do not contain. The mention was marked rather than the finding being "
            f"rejected - a negative mention ('this is not X') is legitimate, and the "
            f"examiner decides."
        )

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "citations": citations,
        "timestamps": timestamps,
        "entities": entities,
    }
