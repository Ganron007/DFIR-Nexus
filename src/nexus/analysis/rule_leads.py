"""WO-K4 part 1 / WO-R1F item 1 — rule-engine detections as first-class leads.

Hayabusa and Chainsaw already run in the lane, and their output is where the
Sigma ruleset actually fires. Until now those detections were only rows in a CSV:
they never reached `leads.jsonl`, so a rule that fired at `critical` and a rule
that fired at `low` were equally invisible to every mode.

**Why Modes 2 and 3 missed the compromise (WO-R1F, measured on SC1).** The index
held 82 rows naming Cobalt Strike, and 0 of 807 leads mentioned it, because:

* the cap was applied to the **first 400 rows in file order** and the sort came
  after — the first `crit` record sits at row 58,368 of 89,872;
* Hayabusa spells its top level **`crit`**, which was absent from the score map,
  so all 27 critical detections scored 0.3 like an unknown level;
* one lead was emitted **per row**, not per rule — 27 rows of one `crit` rule
  would have flooded the list had they survived the cap.

This module now reads **every** detection, aggregates per ``(engine, rule,
level)``, sorts by severity then count, and only then caps — counting **rules,
not rows**. An unknown level is logged once, by name, instead of being scored
silently.

Both engines are read because they do not agree on what a detection is:

* **Hayabusa** (`extractions/hayabusa/*.csv`) gives `RuleID`, `RuleTitle`,
  `Level`, `Computer`, `EventID` and `Details` — a real severity per detection.
* **Chainsaw** (`extractions/chainsaw/*.csv`) gives the rule title in
  `detections` and no level, so those leads carry a neutral score and a note that
  the engine supplied no severity, rather than a fabricated one. Chainsaw is
  aggregated per rule for the same reason as Hayabusa.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any

from nexus.analysis.leads import Lead

log = logging.getLogger(__name__)

#: Hayabusa levels, most severe first. `crit` is Hayabusa's own spelling for its
#: top level (measured on SC1: 27 rows) — omitting it scored all 27 critical
#: detections as an unknown level. `med` is its spelling for medium.
_LEVEL_SCORE = {
    "critical": 1.0,
    "crit": 1.0,
    "high": 0.9,
    "medium": 0.6,
    "med": 0.6,
    "low": 0.3,
    "informational": 0.1,
    "info": 0.1,
}

#: The levels a lead probe/wave treats as "must be dispositioned".
CRIT_HIGH_LEVELS = frozenset({"crit", "critical", "high"})

#: An unknown level is reported once per process, by name, so a new spelling is
#: visible instead of silently scored at the bottom.
_UNKNOWN_LEVELS_SEEN: set[str] = set()

#: How many rules a cap counts. A cap counts RULES, not rows: one rule firing
#: 27,000 times is one lead, and 400 rules is 400 leads.
DEFAULT_RULE_LIMIT = 400

#: Sample rows kept per aggregated rule.
_SAMPLES_PER_RULE = 5


def _warn_unknown_level(level: str) -> None:
    if not level or level in _LEVEL_SCORE or level in _UNKNOWN_LEVELS_SEEN:
        return
    _UNKNOWN_LEVELS_SEEN.add(level)
    log.warning(
        "rule-engine level %r is not in the score map — scoring it as low. "
        "Add the engine's spelling to _LEVEL_SCORE.",
        level,
    )


#: A run's extraction directory names, newest run wins.
def _newest_runs(case_dir: Path) -> list[Path]:
    runs = Path(case_dir) / "runs"
    if not runs.is_dir():
        return []
    found = [p for p in runs.iterdir() if p.is_dir() and (p / "extractions").is_dir()]
    return sorted(found, key=lambda p: p.name, reverse=True)


def _csv_rows(path: Path):
    """Rows from a lane CSV, tolerant of the multi-line quoted fields both tools emit.

    Each yielded row carries ``_line`` (the record's first physical line, 1-based)
    and ``_raw`` (the record's original text with quoting preserved). Those are
    what make the row addressable in the index: `case_index` ids a document by
    ``sha1(family \0 file \0 line \0 text)``, where ``text`` is the sanitized raw
    line. A lead that cannot be turned into that id cannot be fetched back by any
    mode, which is how a failed lookup used to become a refutation (WO-R2F item 3).
    """
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            for row, start, raw in _csv_records(fh):
                row["_line"] = start
                row["_raw"] = raw
                yield row
    except (OSError, csv.Error) as exc:
        log.debug("rule-engine CSV unreadable (%s): %s", path, exc)


def _csv_records(fh):
    """``(row, first_physical_line, raw_record_text)`` per CSV record.

    Uses the indexer's own reader so a quoted newline is ONE record and the
    line number is that record's first physical line - exactly the ``line`` the
    indexed document carries. Reimplementing the reader here would drift from
    `iter_record_rows` the first time one of them changed.
    """
    from nexus.langgraph.case_index import iter_record_rows

    header: list[str] | None = None
    for start, raw, cells in iter_record_rows(fh):
        if header is None:
            if cells is None:
                return  # not a CSV we can key; no header to map through
            header = [str(c or "").strip().lstrip("﻿").strip('"') for c in cells]
            continue
        if cells is None:
            # WO-22 fallback row: no reliable columns, so the detection fields
            # are unavailable. Still yield it - the raw text is what the index
            # stored, so the id remains computable.
            yield {}, start, raw
            continue
        row = {name: ("" if value is None else str(value))
               for name, value in zip(header, cells, strict=False)}
        yield row, start, raw


def _doc_id(path: Path, root: Path, family: str, line: int, raw: str) -> str:
    """The ES ``_id`` of the indexed document for one extraction row.

    Must equal `case_index._bulk_ndjson`'s hash exactly or the lookup misses:
    ``sha1(family \0 file-relative-to-root \0 line \0 sanitized-text)``, where
    ``text`` is the sanitized raw record line truncated to the index line cap.
    """
    import hashlib

    from nexus.langgraph.case_index import _MAX_LINE, _index_rel
    from nexus.langgraph.path_sanitize import sanitize_row_text

    case_dir = root.parent.parent
    text = sanitize_row_text(
        str(raw or "").strip()[:_MAX_LINE], None, case_dir, family=family,
    )
    return hashlib.sha1(
        f"{family}\x00{_index_rel(path, root)}\x00{line}\x00{text}".encode(
            "utf-8", "replace")
    ).hexdigest()


def _rule_extraction_root(run: Path) -> Path:
    """The root `case_index` used for this family's files.

    `iter_extraction_files` returns ``(path, root, family)`` where root is the
    extractions dir (or ``sift/extractions`` / the case ingest dir). The rule
    engines live under ``<run>/extractions``, so that is the root whose
    relative path the doc id is keyed on.
    """
    return run / "extractions"


def _trim(value: Any, limit: int = 300) -> str:
    return " ".join(str(value or "").split())[:limit]


def _sort_key(rule: dict[str, Any]) -> tuple[float, int, str, str]:
    """Severity first, then how often the rule fired."""
    return (-float(rule.get("score") or 0.0), -int(rule.get("count") or 0),
            str(rule.get("family") or ""), str(rule.get("subject") or ""))


def _lead_from_rule(rule: dict[str, Any]) -> Lead:
    engine = str(rule.get("engine") or "")
    level = str(rule.get("level") or "")
    count = int(rule.get("count") or 0)
    subject = str(rule.get("subject") or "")
    family = str(rule.get("family") or "")
    extra: dict[str, Any] = {
        "engine": engine,
        "level": level,
        "rule_id": str(rule.get("rule_id") or ""),
        "count": count,
        "first": rule.get("first") or "",
        "last": rule.get("last") or "",
        "hosts": list(rule.get("hosts") or []),
        "crit_high": level in CRIT_HIGH_LEVELS,
    }
    tag = rule.get("attack_ids") or []
    if not tag:
        # Neither engine emits MITRE columns, so attribute from the rule's own
        # text against the case's technique needles (item 8).
        tag = _techniques_for_rule_text(
            f"{rule.get('subject') or ''} {rule.get('detail') or ''} "
            + " ".join(str(s.get("details") or "") for s in (rule.get("samples") or ())),
            str(rule.get("family") or ""),
        )
    if tag:
        extra["attack_ids"] = list(tag)
        # The NAME, not just the id (item 8). A reader should not have to look a
        # bare `T1059.001` up.
        extra["attack_names"] = attack_technique_names(tag)
    first, last, hosts = extra["first"], extra["last"], extra["hosts"]
    span = ""
    if first or last:
        span = f"; first {first or '?'} → last {last or '?'}"
    return Lead(
        kind="rule_engine",
        subject=subject,
        family=family,
        detail=(
            f"{engine.capitalize()} {level or 'unrated'} detection"
            + (f" [{extra['rule_id']}]" if extra["rule_id"] else "")
            + f": {subject}"
            + (" (no level reported)" if engine == "chainsaw" and not level else "")
            + f" — {count} occurrence(s)"
            + (f" on {', '.join(hosts[:3])}" if hosts else "")
            + span
            + (f"; ATT&CK {', '.join(extra.get('attack_names') or tag)}" if tag else "")
        ),
        rows=tuple(rule.get("samples") or ()),
        audit_ids=(),
        score=float(rule.get("score") or 0.0),
        extra=extra,
    )


def _attack_ids_from_tags(raw: Any) -> list[str]:
    """ATT&CK technique ids from a rule's tags (WO-R1F item 8).

    Hayabusa's `MitreTactics`/`MitreTags` columns and Chainsaw's `tags` both
    carry them in whatever shape the rule used; a plain substring scan for
    `T####` is tolerant of all of them and never invents an id.
    """
    import re

    text = str(raw or "")
    found = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text.upper())
    seen: list[str] = []
    for tid in found:
        if tid not in seen:
            seen.append(tid)
    return seen


def _techniques_for_rule_text(text: str, family: str = "") -> list[str]:
    """ATT&CK ids whose needles appear in a rule's title/detail (item 8).

    Hayabusa and Chainsaw emit NO MITRE columns (measured: their CSVs carry none),
    so the id cannot be read off the row. The case's own `attack_needles.yaml`
    maps each technique to the strings that evidence it and the families it
    applies to — so a rule whose text contains a technique's needle, for a family
    that technique covers, is attributed that technique.

    Conservative by construction: attribution needs a needle hit AND a family
    match, and the ids come from the shipped registry rather than a guess.
    """
    blob = str(text or "").lower()
    fam = str(family or "").lower()
    if not blob:
        return []
    out: list[str] = []
    try:
        from nexus.knowledge.loader import get_attack_needles

        entries = get_attack_needles()
    except Exception:  # noqa: BLE001 — attribution is best-effort
        return []
    for entry in entries:
        tid = str(entry.get("technique") or "").upper()
        if not tid or tid in out:
            continue
        families = {str(f).lower() for f in (entry.get("families") or [])}
        if fam and families and fam not in families:
            continue
        needles = [str(n).lower() for n in (entry.get("needles") or [])]
        # The long, distinctive needles carry the signal; a 3-char token like
        # "-enc" would attribute PowerShell to half the case.
        strong = [n for n in needles if len(n) >= 6]
        if any(n in blob for n in strong):
            out.append(tid)
    return out[:4]


def attack_technique_names(ids: list[str] | tuple[str, ...] | None) -> list[str]:
    """`T1059.001` -> `T1059.001 PowerShell` (WO-R1F item 8).

    The WO asks for the ATT&CK technique NAME on a rule-engine lead, not just the
    id. Names come from the shipped registry; an unresolvable id is returned as
    the bare id rather than a guess.
    """
    out: list[str] = []
    names: dict[str, str] = {}
    try:
        from nexus.knowledge.loader import get_attack_techniques

        for entry in get_attack_techniques():
            tid = str(
                entry.get("technique") or entry.get("id")
                or entry.get("technique_id") or ""
            ).upper()
            label = str(entry.get("name") or entry.get("title") or "")
            if tid and label and tid not in names:
                names[tid] = label
    except Exception:  # noqa: BLE001 — the registry is optional at this layer
        names = {}
    for raw in ids or []:
        tid = str(raw or "").strip().upper()
        if not tid:
            continue
        label = names.get(tid) or names.get(tid.split(".")[0]) or ""
        out.append(f"{tid} {label}".strip())
    return out


def hayabusa_leads(case_dir: Path | str, *, limit: int = DEFAULT_RULE_LIMIT) -> list[Lead]:
    """One lead per Hayabusa RULE (aggregated), strongest first.

    Reads every detection before ranking. ``limit`` counts rules.
    """
    by_rule: dict[tuple[str, str], dict[str, Any]] = {}
    for run in _newest_runs(Path(case_dir)):
        base = run / "extractions" / "hayabusa"
        if not base.is_dir():
            continue
        root = _rule_extraction_root(run)
        for path in sorted(base.glob("*.csv")):
            for row in _csv_rows(path):
                title = _trim(row.get("RuleTitle"), 160)
                # A detection must have a TITLE. A truncated or malformed CSV
                # yields a partial row whose only populated field is a fragment of
                # the cut field (measured: a row subject became "unterminated"),
                # and that is not a detection.
                if not title:
                    continue
                rule_id = _trim(row.get("RuleID"), 60)
                level = _trim(row.get("Level"), 20).lower()
                _warn_unknown_level(level)
                # ONE LEAD PER RULE (title), not per (rule, level): the probe and
                # the doc both require it, and a rule that fires at two levels is
                # still one rule to investigate. The strongest level it reached
                # wins, and the counts are summed.
                key = (title, "")
                rule = by_rule.get(key)
                if rule is None:
                    rule = {
                        "engine": "hayabusa", "family": "hayabusa",
                        "rule_id": rule_id, "subject": title, "level": level,
                        "score": _LEVEL_SCORE.get(level, 0.3),
                        "count": 0, "first": "", "last": "",
                        "hosts": [], "samples": [],
                        "attack_ids": _attack_ids_from_tags(
                            row.get("MitreTactics") or row.get("Tags")
                        ),
                    }
                    by_rule[key] = rule
                else:
                    new_score = _LEVEL_SCORE.get(level, 0.3)
                    if new_score > float(rule.get("score") or 0.0):
                        rule["score"] = new_score
                        rule["level"] = level
                        if rule_id:
                            rule["rule_id"] = rule_id
                rule["count"] += 1
                ts = _trim(row.get("Timestamp"), 40)
                if ts:
                    if not rule["first"] or ts < rule["first"]:
                        rule["first"] = ts
                    if not rule["last"] or ts > rule["last"]:
                        rule["last"] = ts
                host = _trim(row.get("Computer"), 80)
                if host and host not in rule["hosts"]:
                    rule["hosts"].append(host)
                if len(rule["samples"]) < _SAMPLES_PER_RULE:
                    rule["samples"].append({
                        "rule_id": rule_id,
                        "rule_title": title,
                        "level": level,
                        "computer": host,
                        "event_id": _trim(row.get("EventID"), 12),
                        "timestamp": ts,
                        "details": _trim(row.get("Details"), 300),
                        "file": str(path),
                        "line": row.get("_line") or "",
                        "doc_id": _doc_id(
                            path, root, "hayabusa",
                            int(row.get("_line") or 0),
                            row.get("_raw") or "",
                        ),
                    })
        if by_rule:
            break  # the newest run that has output is the one that ran
    return [_lead_from_rule(r) for r in sorted(by_rule.values(), key=_sort_key)[:limit]]


def chainsaw_leads(case_dir: Path | str, *, limit: int = DEFAULT_RULE_LIMIT) -> list[Lead]:
    """One lead per Chainsaw RULE (aggregated).

    Chainsaw's CSV carries no severity, so these score at the neutral end and say
    so — inventing a level would rank a chainsaw hit against a hayabusa one on a
    number neither engine produced.
    """
    by_rule: dict[tuple[str, str], dict[str, Any]] = {}
    for run in _newest_runs(Path(case_dir)):
        base = run / "extractions" / "chainsaw"
        if not base.is_dir():
            continue
        root = _rule_extraction_root(run)
        for path in sorted(base.glob("*.csv")):
            for row in _csv_rows(path):
                title = _trim(row.get("detections"), 160)
                if not title:
                    continue
                key = (title, "")
                rule = by_rule.get(key)
                if rule is None:
                    rule = {
                        "engine": "chainsaw", "family": "chainsaw",
                        "rule_id": "", "subject": title, "level": "",
                        "score": 0.5, "count": 0, "first": "", "last": "",
                        "hosts": [], "samples": [],
                        "attack_ids": _attack_ids_from_tags(row.get("tags")),
                    }
                    by_rule[key] = rule
                # Chainsaw's `count` column is the rule's own hit count; fall
                # back to one per row when it is absent.
                try:
                    rule["count"] += int(_trim(row.get("count"), 12) or 1)
                except ValueError:
                    rule["count"] += 1
                ts = _trim(row.get("timestamp"), 40)
                if ts:
                    if not rule["first"] or ts < rule["first"]:
                        rule["first"] = ts
                    if not rule["last"] or ts > rule["last"]:
                        rule["last"] = ts
                host = _trim(row.get("Computer"), 80)
                if host and host not in rule["hosts"]:
                    rule["hosts"].append(host)
                if len(rule["samples"]) < _SAMPLES_PER_RULE:
                    rule["samples"].append({
                        "rule_title": title,
                        "event_id": _trim(row.get("Event ID"), 12),
                        "computer": host,
                        "timestamp": ts,
                        "count": _trim(row.get("count"), 12),
                        "file": str(path),
                        "line": row.get("_line") or "",
                        "doc_id": _doc_id(
                            path, root, "chainsaw",
                            int(row.get("_line") or 0),
                            row.get("_raw") or "",
                        ),
                    })
        if by_rule:
            break
    return [_lead_from_rule(r) for r in sorted(by_rule.values(), key=_sort_key)[:limit]]


def _merge_across_engines(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One rule = one lead, whichever engines saw it.

    The same Sigma rule fires in BOTH engines on this data (measured: 30 titles,
    identical counts), and two engines confirming one rule is corroboration, not
    two leads. Merge by title:

    * score/level — the strongest level any engine reached;
    * count — the MAX, not the sum: both engines saw the same events, so summing
      would double-count them;
    * ``engines`` — every engine that saw it, so the corroboration is visible.
    """
    merged: dict[str, dict[str, Any]] = {}
    for rule in rules:
        title = str(rule.get("subject") or "")
        existing = merged.get(title)
        if existing is None:
            copy = dict(rule)
            copy["engines"] = [str(rule.get("engine") or "")]
            merged[title] = copy
            continue
        engine = str(rule.get("engine") or "")
        if engine and engine not in existing["engines"]:
            existing["engines"].append(engine)
        if float(rule.get("score") or 0.0) > float(existing.get("score") or 0.0):
            existing["score"] = rule["score"]
            existing["level"] = rule.get("level") or ""
            if rule.get("rule_id"):
                existing["rule_id"] = rule["rule_id"]
        existing["count"] = max(int(existing.get("count") or 0),
                                int(rule.get("count") or 0))
        for field, pick in (("first", min), ("last", max)):
            a, b = str(existing.get(field) or ""), str(rule.get(field) or "")
            vals = [v for v in (a, b) if v]
            existing[field] = pick(vals) if vals else ""
        hosts = list(existing.get("hosts") or [])
        for host in rule.get("hosts") or []:
            if host not in hosts:
                hosts.append(host)
        existing["hosts"] = hosts
        samples = list(existing.get("samples") or [])
        for sample in rule.get("samples") or []:
            if len(samples) >= _SAMPLES_PER_RULE:
                break
            samples.append(sample)
        existing["samples"] = samples
        ids = list(existing.get("attack_ids") or [])
        for tid in rule.get("attack_ids") or []:
            if tid not in ids:
                ids.append(tid)
        existing["attack_ids"] = ids
    return list(merged.values())


def rule_engine_leads(
    case_dir: Path | str,
    *,
    limit: int = DEFAULT_RULE_LIMIT,
) -> list[Lead]:
    """Both engines' rules, merged to one lead per rule, strongest first.

    Never raises: a case whose lane produced no rule output yields [] (the
    ordinary state before the lane has run), not an error.
    """
    rules: list[dict[str, Any]] = []
    for engine in (hayabusa_leads, chainsaw_leads):
        try:
            for lead in engine(case_dir, limit=limit):
                rules.append({
                    **dict(lead.extra or {}),
                    "engine": str((lead.extra or {}).get("engine") or lead.family),
                    "family": lead.family,
                    "subject": lead.subject,
                    "level": str((lead.extra or {}).get("level") or ""),
                    "score": lead.score,
                    "count": (lead.extra or {}).get("count") or 0,
                    "first": (lead.extra or {}).get("first") or "",
                    "last": (lead.extra or {}).get("last") or "",
                    "hosts": list((lead.extra or {}).get("hosts") or []),
                    "samples": [dict(r) for r in lead.rows],
                })
        except Exception as exc:  # noqa: BLE001 - one engine must not lose the other
            log.warning("rule-engine leads failed (%s): %s", engine.__name__, exc)
    merged = _merge_across_engines(rules)
    merged.sort(key=_sort_key)
    # The merged dict carries `engines`; fold it into the extra the lead exposes.
    out: list[Lead] = []
    for rule in merged[:limit]:
        lead = _lead_from_rule(rule)
        engines = list(rule.get("engines") or [])
        if engines:
            out.append(Lead(
                kind=lead.kind, subject=lead.subject, family=lead.family,
                detail=lead.detail + (
                    f" (seen by {', '.join(engines)})" if len(engines) > 1 else ""
                ),
                rows=lead.rows, audit_ids=lead.audit_ids, score=lead.score,
                extra={**dict(lead.extra or {}), "engines": engines},
            ))
        else:
            out.append(lead)
    return out


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
    crit_high = 0
    for lead in leads:
        engine = str((lead.extra or {}).get("engine") or lead.family)
        by_engine[engine] = by_engine.get(engine, 0) + 1
        level = str((lead.extra or {}).get("level") or "unrated")
        by_level[level] = by_level.get(level, 0) + 1
        if (lead.extra or {}).get("crit_high"):
            crit_high += 1
    return {
        "detections": len(leads),
        "rules": len(leads),
        "crit_high_rules": crit_high,
        "by_engine": by_engine,
        "by_level": by_level,
        "levels_included": "all (Hayabusa is scheduled with no minimum-level flag)",
    }
