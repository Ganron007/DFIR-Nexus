"""WO-KR2 — behavioural analytics: loader and validator.

`needles/behavioral_analytics.yaml` carries stored ES query JSON (`es:`) for the
families the rule engines do not cover. This module loads them, resolves which
apply to a case's families, and **validates** them.

The validation is the point. A stale field name in an analytic does not raise -
it matches nothing - and "matched nothing" is indistinguishable from "the
behaviour was absent". That failure mode would be read as a clean result, so
every analytic is checked:

* it must pass `nexus.knowledge.query_validation.validate_stored_query`:
  - (a) passes `langgraph.es_native.validate_query` (allowlisted clauses only);
  - (b) references only fields that exist in `field_registry.yaml` for declared families;
  - (c) cites a source (e.g. CAR analytic id or ATT&CK technique).

An item that fails validation is **not loaded**, and the failure is logged.
A failing item is never silently skipped.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from nexus.knowledge.query_validation import validate_stored_query

log = logging.getLogger(__name__)

PACK_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "knowledge" / "needles"
    / "behavioral_analytics.yaml"
)
CAR_PACK_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "knowledge" / "needles"
    / "car_analytics.yaml"
)

#: WO-KL2b: the rules translated from the pinned SigmaHQ snapshot by
#: `devtools/knowledge/sigma_import.py`. A separate file from the hand-curated pack
#: so the generated set can be regenerated without touching the authored one.
SIGMA_PACK_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "knowledge" / "needles"
    / "sigma_analytics.yaml"
)

#: Every pack the product loads when no explicit path is given.
PACK_PATHS = (PACK_PATH, SIGMA_PACK_PATH)
#: no term in this pack may be derived from a K1 or GATE-H sample (WO-K4).
PROVENANCE = "external: MITRE CAR + ATT&CK; no sample-derived terms"


def load_pack(path: Path | str | None = None) -> dict[str, Any]:
    """The parsed pack (empty packs when the file is missing or unreadable)."""
    target = Path(path) if path else PACK_PATH
    if not target.is_file():
        return {"version": 1, "packs": []}
    try:
        import yaml

        data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001 - a missing pack must not break a run
        log.warning("behavioural analytics pack unreadable: %s", exc)
        return {"version": 1, "packs": []}
    packs = data.get("packs")
    if not isinstance(packs, list):
        data["packs"] = []
    return data


def analytics(path: Path | str | None = None) -> list[dict[str, Any]]:
    """Every valid analytic, in file order.

    With no `path`, **every** pack in `PACK_PATHS` is loaded (the hand-curated
    behavioural pack and the SigmaHQ-derived one). An explicit `path` loads just
    that file, which the tests use. Failing items are not loaded and the rejection
    is logged.
    """
    paths: tuple[Path | str | None, ...] = (path,) if path else PACK_PATHS
    raw_items: list[dict[str, Any]] = []
    for one in paths:
        raw_items.extend(a for a in (load_pack(one).get("packs") or []) if isinstance(a, dict))

    valid: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw_items:
        ident = str(item.get("id") or "").strip()
        if ident and ident in seen:
            continue  # the same id twice in the loaded set would double-count
        es = item.get("es")
        fams = item.get("families") or []
        cite = item.get("citation")
        if not isinstance(es, dict) or not es:
            log.warning("Analytic %s rejected: missing or non-dict 'es' query", ident)
            continue
        problems = validate_stored_query(es, declared_families=fams, citation=cite)
        if problems:
            log.warning("Analytic %s rejected: %s", ident, "; ".join(problems))
            continue
        if ident:
            seen.add(ident)
        valid.append(item)
    return valid


def catalog_fields(path: Path | str | None = None) -> set[str]:
    """Registry column names plus the core envelope, lowercased."""
    from nexus.analysis.leads import registry_fields

    names = {str(c).strip().lower() for c in registry_fields(Path(".")) if str(c).strip()}
    names |= {
        "family", "file", "host", "user", "event", "eventid", "event_id", "line",
        "computer", "machine",
    }
    return names


def validate_pack(
    pack: dict[str, Any] | None = None,
    fields: set[str] | None = None,
) -> list[str]:
    """Every problem with the pack, as human-readable strings. Empty == valid.

    Never raises: a caller deciding whether to offer a pack needs the list, not
    an exception.
    """
    items = (pack or load_pack()).get("packs") or []
    car_ids = car_citation_ids()

    problems: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(items, 1):
        if not isinstance(item, dict):
            problems.append(f"entry {index}: not a mapping")
            continue
        ident = str(item.get("id") or "").strip()
        where = ident or f"entry {index}"
        if not ident:
            problems.append(f"entry {index}: missing id")
        elif ident in seen:
            problems.append(f"{where}: duplicate id")
        seen.add(ident)

        if not str(item.get("name") or "").strip():
            problems.append(f"{where}: missing name")

        families = item.get("families") or []
        if not isinstance(families, list) or not families:
            problems.append(f"{where}: no families - the analytic would never be offered")

        es = item.get("es")
        if es is None:
            problems.append(f"{where}: missing es")
        else:
            es_problems = validate_stored_query(
                es, declared_families=families, citation=item.get("citation")
            )
            for prob in es_problems:
                problems.append(f"{where}: {prob}")

        citation = item.get("citation") or {}
        if not isinstance(citation, dict):
            problems.append(f"{where}: citation must be a mapping")
        else:
            cid = str(citation.get("id") or "").strip()
            ctype = str(citation.get("type") or "").strip()
            if not cid:
                problems.append(f"{where}: citation has no id")
            elif ctype == "car" and car_ids and cid not in car_ids:
                problems.append(
                    f"{where}: cites {cid} but no such analytic is held in car_analytics.yaml"
                )
        if not (item.get("techniques") or []):
            problems.append(f"{where}: no techniques - the analytic maps to no ATT&CK behaviour")
        if not str(item.get("rationale") or "").strip():
            problems.append(f"{where}: missing rationale")
    return problems


def car_citation_ids(path: Path | str | None = None) -> set[str]:
    """CAR analytic ids we already hold, so a citation can be checked."""
    target = Path(path) if path else CAR_PACK_PATH
    if not target.is_file():
        return set()
    try:
        import yaml

        data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return set()
    out: set[str] = set()
    for item in data.get("packs") or []:
        if isinstance(item, dict):
            value = str(item.get("analytic") or "").strip()
            if value:
                out.add(value)
    return out


def _es_clause_matches(clause: dict[str, Any], record: dict[str, Any]) -> bool:
    """Evaluate whether an in-memory record matches an ES query clause."""
    import fnmatch

    if not isinstance(clause, dict) or not clause:
        return True

    def _norm(name: str) -> str:
        return str(name or "").replace("_", "").replace("-", "").replace(" ", "").lower()

    lowered = {_norm(k): v for k, v in record.items()}
    all_text = " ".join(str(v) for v in record.values()).lower()

    for op, spec in clause.items():
        if op == "match_all":
            return True
        if op == "match_none":
            return False
        if op in ("term", "match", "match_phrase", "wildcard", "prefix"):
            if not isinstance(spec, dict):
                return False
            for fpath, val_spec in spec.items():
                if fpath in ("text", "text.wc"):
                    target_val = all_text
                else:
                    raw_name = fpath.removeprefix("fields.")
                    if raw_name.endswith(".kw"):
                        raw_name = raw_name[:-3]
                    target_val = str(lowered.get(_norm(raw_name)) or "")

                val = val_spec.get("value") if isinstance(val_spec, dict) else val_spec
                val_str = str(val or "").strip().lower()

                if op == "wildcard":
                    if not fnmatch.fnmatch(target_val.lower(), val_str):
                        return False
                elif op in ("match", "match_phrase"):
                    if val_str not in target_val.lower():
                        return False
                elif op == "prefix":
                    if not target_val.lower().startswith(val_str):
                        return False
                else:  # term
                    if target_val.lower() != val_str and val_str not in target_val.lower():
                        return False
            return True
        if op == "terms":
            if not isinstance(spec, dict):
                return False
            for fpath, vals in spec.items():
                if fpath in ("text", "text.wc"):
                    target_val = all_text
                else:
                    raw_name = fpath.removeprefix("fields.")
                    if raw_name.endswith(".kw"):
                        raw_name = raw_name[:-3]
                    target_val = str(lowered.get(_norm(raw_name)) or "").lower()
                val_set = {str(v).strip().lower() for v in vals}
                if target_val not in val_set:
                    return False
            return True
        if op == "exists":
            fpath = str(spec.get("field") or "") if isinstance(spec, dict) else ""
            raw_name = fpath.removeprefix("fields.")
            if raw_name.endswith(".kw"):
                raw_name = raw_name[:-3]
            v = lowered.get(_norm(raw_name))
            return v is not None and str(v).strip() != ""
        if op == "bool":
            if not isinstance(spec, dict):
                return False
            for must_c in spec.get("must") or []:
                if not _es_clause_matches(must_c, record):
                    return False
            for filt_c in spec.get("filter") or []:
                if not _es_clause_matches(filt_c, record):
                    return False
            for not_c in spec.get("must_not") or []:
                if _es_clause_matches(not_c, record):
                    return False
            shoulds = spec.get("should") or []
            if shoulds:
                matched_should = sum(1 for sc in shoulds if _es_clause_matches(sc, record))
                min_match = int(
                    spec.get("minimum_should_match")
                    or (0 if (spec.get("must") or spec.get("filter")) else 1)
                )
                if min_match > 0 and matched_should < min_match:
                    return False
            return True
    return True


def matches_record(analytic: dict[str, Any], record: dict[str, Any]) -> bool:
    """Whether *record* satisfies *analytic*'s stored ES query.

    ES query JSON only (WO-KR2b). The Mode 1 query parser is not imported here: a
    stored query is ES query JSON, and an analytic without an `es:` matches nothing
    rather than falling back to a syntax this layer does not speak.
    """
    es = (analytic or {}).get("es")
    if isinstance(es, dict) and es:
        return _es_clause_matches(es, record)
    return False


def analytics_for(
    families: list[str] | set[str] | None,
    path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Analytics that apply to *families*.

    ``None`` or an empty set means "every analytic" - a caller with no family
    list should not silently get none.
    """
    wanted = {str(f).strip().lower() for f in (families or []) if str(f).strip()}
    items = analytics(path)
    if not wanted:
        return items
    return [
        item for item in items
        if wanted & {str(f).strip().lower() for f in (item.get("families") or [])}
    ]
