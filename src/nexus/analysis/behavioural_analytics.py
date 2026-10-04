"""WO-K4 — behavioural analytics: loader and validator.

`needles/behavioral_analytics.yaml` carries typed `dsl:` analytics for the
families the rule engines do not cover. This module loads them, resolves which
apply to a case's families, and **validates** them.

The validation is the point. A stale field name in an analytic does not raise -
it matches nothing - and "matched nothing" is indistinguishable from "the
behaviour was absent". That failure mode would be read as a clean result, so
every analytic is checked two ways before it is offered:

* it must **parse** under the N4 DSL (`parse_query`);
* every field it names must be a real registry column;
* it must **cite a source** - a CAR analytic id we actually hold, or an ATT&CK
  technique - because an uncited analytic is a guess.

Nothing here is derived from a sample: the citations are external, and
`PROVENANCE` records that. `tests/test_behavioural_analytics.py` pins it.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

PACK_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "knowledge" / "needles"
    / "behavioral_analytics.yaml"
)
CAR_PACK_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "knowledge" / "needles"
    / "car_analytics.yaml"
)

#: Where every analytic's citation must come from. External by construction:
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
    """Every analytic, in file order."""
    return [a for a in (load_pack(path).get("packs") or []) if isinstance(a, dict)]


def catalog_fields(path: Path | str | None = None) -> set[str]:
    """Registry column names plus the core envelope, lowercased.

    Lowercased because that is how `parse_query` matches a catalog key.
    """
    from nexus.analysis.leads import registry_fields

    names = {str(c).strip().lower() for c in registry_fields(Path(".")) if str(c).strip()}
    # Core envelope columns are typed-filterable on every case.
    names |= {"family", "file", "host", "user", "event", "eventid", "event_id", "line",
              "computer", "machine"}
    return names


def _catalog(names: set[str]) -> dict[str, Any]:
    return {name: {} for name in names}


def validate_pack(
    pack: dict[str, Any] | None = None,
    fields: set[str] | None = None,
) -> list[str]:
    """Every problem with the pack, as human-readable strings. Empty == valid.

    Never raises: a caller deciding whether to offer a pack needs the list, not
    an exception.
    """
    from nexus.langgraph.query_dsl import QuerySyntaxError, parse_query

    items = (pack or load_pack()).get("packs") or []
    known = fields if fields is not None else catalog_fields()
    catalog = _catalog(known)
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

        dsl = str(item.get("dsl") or "").strip()
        if not dsl:
            problems.append(f"{where}: missing dsl")
        else:
            # The DSL does not negate a typed filter: `not path:\Windows` is
            # parsed as a POSITIVE filter on `path`, so it asserts the opposite
            # of what it reads as. Measured 2026-10-03 - three analytics written
            # that way would have inverted. Refuse it rather than trust it.
            from nexus.analysis.behavioural_analytics import negation_is_honoured

            if not negation_is_honoured(dsl):
                problems.append(
                    f"{where}: uses `not field:value`, which the DSL parses as a "
                    "POSITIVE filter - the analytic would assert the opposite; "
                    "express the exclusion as a follow-on filter instead"
                )
            try:
                parsed = parse_query(dsl, catalog)
                for filt in parsed.filters:
                    if str(filt.get("op") or "") == "exists":
                        # `exists:<field>` names the field in the VALUE, not the
                        # filter name - checking the name would flag every
                        # existence test as an unknown column.
                        named = str(filt.get("value") or "").lower()
                    else:
                        named = str(filt.get("name") or "").lower()
                    if named and named not in known:
                        problems.append(
                            f"{where}: field {named!r} is not a registry column"
                        )
            except QuerySyntaxError as exc:
                problems.append(f"{where}: dsl does not parse: {exc}")

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


def matches_record(analytic: dict[str, Any], record: dict[str, Any]) -> bool:
    """Whether *record* satisfies *analytic*'s filter set.

    A minimal evaluator for the ops this pack uses (`contains`, `in`, `exists`)
    so an analytic can be proven **behaviour-keyed** rather than asserted to be:
    a record carrying the behaviour but never the tool's name must match. Field
    lookup is case-insensitive because the registry is.
    """
    from nexus.langgraph.query_dsl import parse_query

    dsl = str((analytic or {}).get("dsl") or "").strip()
    if not dsl or not record:
        return False
    parsed = parse_query(dsl)

    # Registry columns are snake_case (`command_line`) while a real row is
    # usually PascalCase (`CommandLine`), so compare on a case- and
    # separator-insensitive key. Without this an analytic would match nothing on
    # the very rows it was written for.
    def _norm(name: str) -> str:
        return str(name or "").replace("_", "").replace(" ", "").lower()

    lowered = {_norm(k): v for k, v in record.items()}

    def _has(name: str) -> bool:
        value = lowered.get(_norm(name))
        return value is not None and str(value).strip() != ""

    def _text(name: str) -> str:
        return str(lowered.get(_norm(name)) or "")

    for filt in parsed.filters:
        op = str(filt.get("op") or "contains")
        if op == "exists":
            if not _has(str(filt.get("value") or "")):
                return False
            continue
        name = str(filt.get("name") or "")
        if op == "in":
            values = [str(v).lower() for v in (filt.get("values") or [])]
            if _text(name).lower() not in values:
                return False
        elif op == "eq":
            if _text(name).lower() != str(filt.get("value") or "").lower():
                return False
        else:  # contains
            needle = str(filt.get("value") or "").lower()
            if needle and needle not in _text(name).lower():
                return False
    for term in parsed.not_terms:
        needle = str(term).lower()
        if any(needle in str(v).lower() for v in lowered.values()):
            return False
    return True


def negation_is_honoured(dsl: str) -> bool:
    """Whether *dsl* contains a `not field:` term the parser will ignore.

    The DSL folds `and not field:value` into a **positive** filter, so such a
    term asserts the opposite of how it reads. Exposed so a caller can refuse
    one instead of running an analytic that inverts itself.
    """

    return _re_negated(dsl) is None


def _re_negated(dsl: str):
    import re

    return re.search(r"\bnot\s+[A-Za-z_][\w.\-]*\s*:", str(dsl or ""))


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
