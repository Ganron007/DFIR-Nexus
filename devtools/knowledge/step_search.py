"""IC-6 (Part 9): a skill step's search, authored by meaning and compiled to ES query JSON.

Why: the stored step queries were produced by `convert_to_es.py` (removed) from each step's free-text `query`.
On CASE-C5B04D31 that gave 79 literal phrases (several terms glued into one wildcard string, e.g.
`*procdump nanodump mimikatz sekurlsa*`), 32 floods, 36 zero-hit queries and typed columns guessed
from the step's pivot (`GrantedAccess` as a process-name value). Validity was checked; meaning was not.

A step now states its search as data (`search:`), and this module compiles it:

    search:
      basis: [attack:DET0363]        # pinned sources the event facts come from
      events:                        # the log the step reads (OR across entries)
      - {channel: Microsoft-Windows-Sysmon/Operational, codes: ['10']}
      families: [pecmd]              # or: the artefact families whose rows hold it
      all:                           # every clause must hold
      - {field: ecs.winlog.event_data.TargetImage, endswith: ['\\lsass.exe']}
      any:                           # at least one clause must hold
      - ...
      none:                          # no clause may hold
      - ...

A clause names one field and one operator: `is`, `endswith`, `startswith`, `contains` (each a list of
values, OR within the clause), `phrase` (a phrase search over the field's text), or `exists: true`.

Checks (`check_step`), each against a pinned source:

* every (channel, code) is named by a cited ATT&CK v20 detection strategy's analytics
  (`attack:DETxxxx`, the pinned registry), or exists in a pinned EvtxECmd map (`evtx-map`) or a pinned
  provider manifest (`manifest`) for that channel;
* every `ecs.winlog.event_data.<Name>` field is an EventData name that a pinned EvtxECmd map or
  provider manifest gives for one of the step's events;
* every other field is a known `ecs.*` field or a `fields.<column>` the field registry records for one
  of the step's families;
* no value is a glued phrase: a value holding whitespace is allowed only in a `phrase` clause;
* each value is recorded with where it comes from: verbatim in a cited basis (an ATT&CK analytic's
  text or tunables), else `authored` (house method, labelled as such).

The compiled query is stored as the step's `es:`; `--check` in `compile_skills.py` fails on drift.
Nothing in `src/nexus` compiles a stored query (WO-KR2).
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
ATTACK_REGISTRY = REPO / "src" / "nexus" / "data" / "knowledge" / "attack" / "attack_registry.yaml"
EVTX_MAPS = REPO / "src" / "nexus" / "data" / "schema" / "evtxecmd_maps.yaml"
MANIFESTS = Path(__file__).resolve().parent / "pinned" / "manifests"
FIELD_REGISTRY = REPO / "src" / "nexus" / "data" / "schema" / "field_registry.yaml"
ECS_MAP = REPO / "src" / "nexus" / "data" / "schema" / "ecs_map.yaml"

#: ATT&CK's Windows log source names -> the channel the event is written to. A naming convention,
#: authored; `check_step` verifies each channel against the pinned maps and manifests.
ATTACK_CHANNELS: dict[str, tuple[str, ...]] = {
    "WinEventLog:Security": ("Security",),
    "WinEventLog:Sysmon": ("Microsoft-Windows-Sysmon/Operational",),
    "WinEventLog:System": ("System",),
    "WinEventLog:Application": ("Application",),
    "WinEventLog:PowerShell": ("Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"),
    "WinEventLog:WMI": ("Microsoft-Windows-WMI-Activity/Operational",),
    "WinEventLog:TaskScheduler": ("Microsoft-Windows-TaskScheduler/Operational",),
    "WinEventLog:Windows Defender": ("Microsoft-Windows-Windows Defender/Operational",),
    "WinEventLog:Microsoft-Windows-Windows Defender/Operational":
        ("Microsoft-Windows-Windows Defender/Operational",),
    "WinEventLog:Microsoft-Windows-CodeIntegrity/Operational":
        ("Microsoft-Windows-CodeIntegrity/Operational",),
    "WinEventLog:Microsoft-Windows-Windows Firewall With Advanced":
        ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",),
}

_EVENT_CODES = re.compile(r"(?:EventCode\s*=\s*|Event\s*ID\s*)(\d{1,5}(?:\s*[,/]\s*\d{1,5})*)", re.I)
_DATA_NAME = re.compile(r'Data\[@Name="([^"]+)"\]')
_OPS = ("is", "endswith", "startswith", "contains", "phrase", "exists")
#: Fields every row may carry (the index envelope).
ENVELOPE = frozenset({"family", "event_id", "host", "user", "file", "text", "ts"})


# ── pinned sources ──────────────────────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _registry() -> dict[str, Any]:
    return yaml.safe_load(ATTACK_REGISTRY.read_text(encoding="utf-8")) or {}


@lru_cache(maxsize=1)
def _strategies() -> dict[str, list[dict[str, Any]]]:
    """DETxxxx -> its analytics (as the pinned v20 registry records them)."""
    out: dict[str, list[dict[str, Any]]] = {}
    for tech in _registry().get("techniques") or []:
        for det in tech.get("detection") or []:
            ident = str(det.get("id") or "")
            if ident and ident not in out:
                out[ident] = list(det.get("analytics") or [])
    return out


def attack_pairs(det_id: str) -> set[tuple[str, str]]:
    """The (channel, event code) pairs a detection strategy's analytics name."""
    pairs: set[tuple[str, str]] = set()
    for analytic in _strategies().get(det_id) or []:
        for ref in analytic.get("log_source_refs") or []:
            channels = ATTACK_CHANNELS.get(str(ref.get("name") or ""))
            if not channels:
                continue
            for group in _EVENT_CODES.findall(str(ref.get("channel") or "")):
                for code in re.split(r"[,/\s]+", group):
                    if code:
                        for channel in channels:
                            pairs.add((channel, code))
    return pairs


def attack_text(det_id: str) -> str:
    """Every word a detection strategy's analytics state (descriptions, sources, tunables)."""
    parts: list[str] = []
    for analytic in _strategies().get(det_id) or []:
        parts.append(str(analytic.get("description") or ""))
        for ref in analytic.get("log_source_refs") or []:
            parts.append(str(ref.get("channel") or ""))
        for tun in analytic.get("tunables") or []:
            parts.append(str(tun.get("field") or ""))
            parts.append(str(tun.get("description") or ""))
    return "\n".join(parts)


@lru_cache(maxsize=1)
def _map_names() -> dict[tuple[str, str], set[str]]:
    """(channel, event id) -> EventData names the pinned EvtxECmd maps read."""
    doc = yaml.safe_load(EVTX_MAPS.read_text(encoding="utf-8")) or {}
    out: dict[tuple[str, str], set[str]] = {}
    for pack in doc.get("packs") or []:
        key = (str(pack.get("channel") or ""), str(pack.get("event_id") or ""))
        names = out.setdefault(key, set())
        for col in (pack.get("columns") or {}).values():
            for variant in [col, *(col.get("variants") or [])]:
                for src in variant.get("sources") or []:
                    names.update(_DATA_NAME.findall(str(src.get("xpath") or "")))
    return out


@lru_cache(maxsize=1)
def _manifest_events() -> dict[tuple[str, str], str]:
    """(channel, event id) -> the event's message, from the pinned provider manifests.

    The manifests are `wevtutil gp /ge /gm` output: each event names its channel by id and carries its
    message, but not its EventData template, so they prove an event exists and what it means; the
    EventData names come from the EvtxECmd maps.
    """
    import xml.etree.ElementTree as ET

    out: dict[tuple[str, str], str] = {}
    for path in sorted(MANIFESTS.glob("*.xml")):
        root = ET.parse(path).getroot()

        def local(tag: str) -> str:
            return tag.rsplit("}", 1)[-1]

        channels = {el.get("id") or "": el.get("name") or "" for el in root.iter() if local(el.tag) == "channel"}
        for el in root.iter():
            if local(el.tag) != "event":
                continue
            chan = channels.get(el.get("channel") or "", "")
            if chan:
                out[(chan, el.get("value") or "")] = el.get("message") or ""
    return out


def known_event(channel: str, code: str) -> bool:
    key = (channel, str(code))
    return key in _map_names() or key in _manifest_events()


@lru_cache(maxsize=1)
def _ecs_map_names() -> dict[tuple[str, str], set[str]]:
    """(channel, event id) -> EventData names the ECS map reads (checked on verbatim public-sample rows by
    tests/test_cs1b_map_sources.py)."""
    doc = yaml.safe_load(ECS_MAP.read_text(encoding="utf-8")) or {}
    out: dict[tuple[str, str], set[str]] = {}
    for channel, events in (doc.get("winlog_event_data") or {}).items():
        for code, names in (events or {}).items():
            out[(str(channel), str(code))] = {str(n) for n in (names or {})}
    return out


def event_data_names(channel: str, code: str) -> set[str]:
    key = (channel, str(code))
    return set(_map_names().get(key, set())) | set(_ecs_map_names().get(key, set()))


@lru_cache(maxsize=1)
def _field_registry() -> dict[str, Any]:
    doc = yaml.safe_load(FIELD_REGISTRY.read_text(encoding="utf-8")) or {}
    cols = doc.get("columns") if isinstance(doc.get("columns"), dict) else doc
    return cols if isinstance(cols, dict) else {}


# ── compile ─────────────────────────────────────────────────────────────────────────────────────

def _typed_column(field: str) -> str:
    """The registry's type for a `fields.<column>` that the index maps as a non-text type, else ''."""
    if not field.startswith("fields."):
        return ""
    info = _field_registry().get(field[len("fields."):])
    kind = str((info or {}).get("type") or "") if isinstance(info, dict) else ""
    return kind if kind in ("boolean", "long", "double", "integer", "date", "ip") else ""


def _escape_wildcard(value: str) -> str:
    return value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def _keyword_field(field: str) -> str:
    """The exact-match form of a field: `fields.<col>` filters on its `.kw` copy."""
    return f"{field}.kw" if field.startswith("fields.") else field


def _pattern_field(field: str) -> str:
    """The wildcard form: `ecs.*` carries a `.wc` subfield, `fields.*` a `.kw` keyword, `text` its `.wc`."""
    if field.startswith("fields."):
        return f"{field}.kw"
    if field == "text":
        return "text.wc"
    if field in ENVELOPE:
        return field  # the envelope's keyword fields (`file`, `family`, `host`) take a pattern themselves
    return f"{field}.wc"


def _phrase_field(field: str) -> str:
    if field == "text":
        return "text"
    if field.startswith("fields."):
        return field
    if field.startswith("ecs.winlog.event_data."):
        return f"{field}.wc"  # event-data names carry no text subfield; a phrase is a contains
    return f"{field}.text"


def _clause(clause: dict[str, Any]) -> dict[str, Any]:
    field = str(clause.get("field") or "")
    ops = [op for op in _OPS if op in clause]
    if len(ops) != 1:
        raise ValueError(f"clause on {field!r} must name exactly one operator of {_OPS}")
    op = ops[0]
    if op == "exists":
        return {"exists": {"field": field}}
    values = clause[op]
    values = [str(v) for v in (values if isinstance(values, list) else [values])]
    typed = _typed_column(field)
    branches: list[dict[str, Any]] = []
    for value in values:
        if op == "is" and typed:
            # A typed column (boolean, number, date) has no keyword copy and no case to fold: ES reads the
            # value as that type (`task_hidden` is boolean, so `True` must be `true`).
            branches.append({"term": {field: value.lower() if typed == "boolean" else value}})
            continue
        if op == "is":
            if field in ENVELOPE:
                branches.append({"term": {field: value}})
            else:
                branches.append({"term": {_keyword_field(field): {"value": value, "case_insensitive": True}}})
        elif op == "phrase":
            target = _phrase_field(field)
            if target.endswith(".wc"):
                branches.append({"wildcard": {target: {"value": f"*{_escape_wildcard(value)}*",
                                                       "case_insensitive": True}}})
            else:
                branches.append({"match_phrase": {target: value}})
        else:
            esc = _escape_wildcard(value)
            pattern = {"endswith": f"*{esc}", "startswith": f"{esc}*", "contains": f"*{esc}*"}[op]
            branches.append({"wildcard": {_pattern_field(field): {"value": pattern, "case_insensitive": True}}})
    if len(branches) == 1:
        return branches[0]
    return {"bool": {"should": branches, "minimum_should_match": 1}}


def _events(events: list[dict[str, Any]]) -> dict[str, Any]:
    branches: list[dict[str, Any]] = []
    for ev in events:
        codes = [str(c) for c in (ev.get("codes") or [])]
        filt: list[dict[str, Any]] = [
            {"term": {"ecs.winlog.channel": {"value": str(ev["channel"]), "case_insensitive": True}}}]
        if codes:
            filt.append({"terms": {"event_id": codes}})
        branches.append({"bool": {"filter": filt}})
    return branches[0] if len(branches) == 1 else {"bool": {"should": branches, "minimum_should_match": 1}}


def compile_search(search: dict[str, Any]) -> dict[str, Any]:
    """The step's ES query: its source (events or families) AND `all` AND one of `any`, NOT `none`."""
    filt: list[dict[str, Any]] = []
    events = search.get("events") or []
    families = [str(f) for f in (search.get("families") or [])]
    if events and families:
        filt.append({"bool": {"should": [_events(events), {"terms": {"family": families}}],
                              "minimum_should_match": 1}})
    elif events:
        filt.append(_events(events))
    elif families:
        filt.append({"terms": {"family": families}})
    for clause in search.get("all") or []:
        filt.append(_clause(clause))
    anys = [_clause(c) for c in (search.get("any") or [])]
    if anys:
        filt.append(anys[0] if len(anys) == 1 else {"bool": {"should": anys, "minimum_should_match": 1}})
    body: dict[str, Any] = {"filter": filt}
    nones = [_clause(c) for c in (search.get("none") or [])]
    if nones:
        body["must_not"] = nones
    if not filt:
        raise ValueError("a search must name its source (events or families) or a clause")
    return {"bool": body}


def compile_source(search: dict[str, Any]) -> dict[str, Any] | None:
    """The step's source alone (its events or families), for asking whether a case holds that log at all."""
    source = {k: search[k] for k in ("events", "families") if search.get(k)}
    return compile_search(source) if source else None


#: Short names for the channels a step names, for the label a seat reads.
_CHANNEL_LABEL = {
    "Microsoft-Windows-Sysmon/Operational": "Sysmon",
    "Microsoft-Windows-PowerShell/Operational": "PowerShell/Operational",
    "Microsoft-Windows-TaskScheduler/Operational": "TaskScheduler/Operational",
    "Microsoft-Windows-Windows Defender/Operational": "Defender/Operational",
    "Microsoft-Windows-WMI-Activity/Operational": "WMI-Activity/Operational",
    "Microsoft-Windows-WinRM/Operational": "WinRM/Operational",
}


def source_label(search: dict[str, Any]) -> str:
    """What the step reads, in words: `Sysmon 10; Security 4656, 4663; families pecmd`."""
    parts = []
    for ev in search.get("events") or []:
        channel = str(ev.get("channel") or "")
        name = _CHANNEL_LABEL.get(channel, channel)
        codes = ", ".join(str(c) for c in ev.get("codes") or [])
        parts.append(f"{name} {codes}" if codes else f"{name} (any event)")
    if search.get("families"):
        parts.append("families " + ", ".join(str(f) for f in search["families"]))
    return "; ".join(parts)


def compile_aggs(aggregate: dict[str, Any]) -> dict[str, Any]:
    field = str(aggregate.get("field") or "")
    if not field:
        raise ValueError("an aggregate step names the field it counts")
    target = field if field in ENVELOPE or not field.startswith("fields.") else f"{field}.kw"
    return {"by": {"terms": {"field": target, "size": int(aggregate.get("size") or 20)}}}


# ── check ───────────────────────────────────────────────────────────────────────────────────────

def _index_family(name: str) -> str:
    """The family the indexer records: a tool's output folder by its tool (`mftecmd-usn` rows are `mftecmd`,
    D44), an imported row by its importer's source (`ingest-cloudtrail` rows are `cloudtrail`)."""
    import sys

    sys.path.insert(0, str(REPO / "src"))
    from nexus.langgraph.query_pack import _tool_folder_family

    if name.startswith("ingest-"):
        return name[len("ingest-"):]
    return _tool_folder_family(f"{name}/x") or name


def _clauses(search: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for key in ("all", "any", "none") for c in (search.get(key) or []) if isinstance(c, dict)]


def check_step(step: dict[str, Any]) -> tuple[list[str], list[dict[str, str]]]:
    """(problems, value provenance) for one step's `search:`."""
    problems: list[str] = []
    provenance: list[dict[str, str]] = []
    search = step.get("search") or {}
    basis = [str(b) for b in (search.get("basis") or [])]
    dets = [b.split(":", 1)[1] for b in basis if b.startswith("attack:")]
    for det in dets:
        if det not in _strategies():
            problems.append(f"basis {det} is not a detection strategy in the pinned ATT&CK registry")
    cited_pairs: set[tuple[str, str]] = set()
    for det in dets:
        cited_pairs |= attack_pairs(det)
    events = search.get("events") or []
    pairs: list[tuple[str, str]] = []
    for ev in events:
        channel = str(ev.get("channel") or "")
        for code in [str(c) for c in (ev.get("codes") or [])]:
            pairs.append((channel, code))
            if (channel, code) in cited_pairs:
                continue
            if known_event(channel, code) and any(b in ("evtx-map", "manifest") for b in basis):
                continue
            problems.append(f"event {channel} {code}: not named by a cited ATT&CK analytic, and not cited "
                            f"from a pinned EvtxECmd map or manifest")
    families = {str(f) for f in (search.get("families") or [])}
    registry = _field_registry()
    for clause in _clauses(search):
        field = str(clause.get("field") or "")
        if field.startswith("ecs.winlog.event_data."):
            name = field.rsplit(".", 1)[1]
            if pairs and not any(name in event_data_names(c, e) for c, e in pairs):
                problems.append(f"{field}: no pinned map or manifest gives {name!r} for {sorted(set(pairs))}")
        elif field.startswith("fields."):
            col = field[len("fields."):]
            info = registry.get(col)
            if not isinstance(info, dict):
                # The registry was built from the ES-Mapping catalog and misses real columns (SQLECmd's
                # `KeywordSearchTerm`, Hindsight's `url`); such a column stands only on its positive control.
                provenance.append({"field": field, "value": "", "source": "column not in the field registry; "
                                                                           "stands on its positive control"})
            elif families:
                have = {_index_family(str(f)) for f in (info.get("families") or info.get("populated_in") or [])}
                if have and not (have & families):
                    problems.append(f"{field}: the registry records it for {sorted(have)}, not {sorted(families)}")
        elif field == "text":
            if not any(op in clause for op in ("phrase", "contains")):
                problems.append("text: the row text is analysed; search it with `phrase` or `contains` only")
        elif field.startswith("ecs.") or field in ENVELOPE:
            pass
        else:
            problems.append(f"{field}: not an ecs.* field, a fields.<column>, or the envelope")
        for op in ("is", "endswith", "startswith", "contains", "phrase"):
            if op not in clause:
                continue
            values = clause[op] if isinstance(clause[op], list) else [clause[op]]
            for value in values:
                text = str(value)
                # A path holds spaces as one value (`\Start Menu\Programs`); free terms with a space between
                # them are the glued phrase KR2b produced.
                # An exact `is` value may be a multi-word name (`ANONYMOUS LOGON`): equality cannot glue terms.
                if op not in ("phrase", "is") and re.search(r"\s", text.strip()) and not re.search(r"[\\/]", text):
                    problems.append(f"{field} {op} {text!r}: a value holding whitespace is a glued phrase; "
                                    f"write it as a `phrase` clause or split it")
                source = next((f"attack:{d}" for d in dets if text.strip("\\*").lower()
                               in attack_text(d).lower()), "authored")
                provenance.append({"field": field, "value": text, "source": source})
    if not events and not families and not _clauses(search):
        problems.append("the search names no source and no clause")
    return problems, provenance
