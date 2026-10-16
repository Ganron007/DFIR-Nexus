"""The events a claim's own words name, and whether the calls it cites returned them (D238).

A claim is grounded on the rows it cites: its subject comes from them (``subject.attach_subjects``) and a
time_order claim's second entity must be in them (D87). What a claim says the rows *are* was not checked.
On CASE-C5B04D31 (Mode 3 run 4, 2026-10-16) a seat ran ``*lsass*`` over the Hayabusa timeline, got 30
Security 4688 rows (lsass.exe starting at boot), and wrote "30 Sysmon 10 events showing processes opening
handles to lsass.exe": the description of the skill it had read, not of its rows. The case has no Sysmon
log. The rows named the subject, so every check passed and two critical DRAFTs were staged; the verifier
"confirmed" the claim on the same rows.

An event is named by its source and number ("Sysmon 10", "Sysmon EventID-10", "Security 4688 rows",
"Defender 1116 events") or by number alone after an event word ("EID 129", "EventID 4624/4625"). A source
word is one the pinned tables name: a provider or channel of ``event_categories.yaml`` or a Hayabusa channel
and its abbreviation (``hayabusa_fields.yaml``). Nothing is typed here. An event named inside a negation ("no
Sysmon 10 events") is not asserted, so it is not checked.

A cited call returned the event when one of its rows has the event id and, for a named source, the source's
provider or channel (a row that names neither cannot contradict the source). A call stores at most
``EVIDENCE_ROW_CAP`` rows: when it returned more, its query is run again with the event added, and its exact
total answers. A call that cannot be run again leaves the event unknown, never unrecorded.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from functools import lru_cache
from typing import Any

#: Words in the pinned names that name no source by themselves.
_GENERIC = frozenset({"microsoft", "windows", "operational", "analytic", "debug", "admin"})
#: Words that introduce an event number.
_EVENT_WORD = r"(?:event[\s_-]*(?:ids?|codes?)|eventids?|eventcodes?|eids?|evids?|events?)"
#: Several ids of one event word ("4624/4625", "4698 or 4699"). Not a comma: in "EID 1116, 10 events" the
#: second number is a count.
_IDS = r"\d{1,5}(?:\s*(?:/|\bor\b|\band\b)\s*\d{1,5})*"
#: After a number: not a date, a time, a version or a longer token ("event 2023-01-25" names no event).
_END = r"(?![\w.:/-])"
#: What a source and number are counted as ("Security 4688 rows").
_ROW_WORD = r"(?:events?|rows?|records?|entries)\b"
#: Words that make the rest of their sentence a statement of absence ("No 7045 (service install) or Sysmon
#: EID 7 event in the window") or of what is not known to be there ("would have appeared in EID-140").
_NEGATION = re.compile(r"\b(?:no|not|without|absent|absence|zero|never|none|nothing|neither|nor|lack(?:s|ing)?|"
                       r"missing|cannot|can't|unable|would|could|might|if|whether|expected)\b|\b0\s+$", re.I)
#: The same sentence, after the event, saying it was not found ("Searches for EID 7036 ... returned zero hits").
_NOT_FOUND = re.compile(
    r"\b(?:returned|returns|return|found|yielded|yields|gave)\s+(?:0|zero|no|nothing|none)\b"
    r"|\b(?:0|zero|no|none)\s+(?:hits?|rows?|results?|matches|records?)\b"
    r"|\bnot\s+(?:found|present|indexed|recorded|logged|available)\b|\b(?:is|are|was|were)\s+absent\b"
    r"|\bdo(?:es)?\s+not\s+exist\b", re.I)
#: A sentence ends at a full stop before a space (not the one in "lsass.exe"), a semicolon or a line end.
_CLAUSE_END = re.compile(r"\.(?=\s|$)|[;!?\n]")

#: (source word or "", event id): an event a text names.
Event = tuple[str, str]
#: Runs a cited query with one event added; the exact number of rows, or None when it cannot run.
Replay = Callable[[dict[str, Any], Event], "int | None"]


def _norm(text: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(text or "").lower())


def _base(name: str) -> str:
    """A provider or channel name without its vendor prefix and log suffix: `Security-Auditing`."""
    return re.sub(r"^microsoft-windows-", "", name.split("/")[0].strip(), flags=re.I)


@lru_cache(maxsize=1)
def _source_names() -> dict[str, frozenset[str]]:
    """{source word (lower case): the provider and channel names, as written, that it stands for}."""
    from nexus.langgraph import event_categories, hayabusa_fields

    doc = event_categories._doc()
    names: set[str] = {str(e["provider"]) for e in doc.get("entries") or []}
    for row in doc.get("channels") or []:
        names |= {str(row["channel"]), str(row["provider"])}
    abbreviations = {str(k): str(v) for k, v in (hayabusa_fields._table().get("channels") or {}).items()}
    names |= set(abbreviations.values())
    out: dict[str, set[str]] = {}

    def add(word: str, *written: str) -> None:
        if word and word not in _GENERIC:
            out.setdefault(word, set()).update(written)

    for name in names:
        base = _base(name)
        add(base.lower(), name)
        # "Security-Auditing" is also written "Security"; "User Profile Service" is not written "user".
        first = base.split("-")[0].lower()
        if len(first) >= 3:
            add(first, name)
    for abbreviation, channel in abbreviations.items():
        add(abbreviation.lower(), abbreviation, channel)
    # A source word also stands for every name of the same log: "Sec" is the Security channel, and the
    # Security channel's provider is Microsoft-Windows-Security-Auditing.
    same_log: dict[str, set[str]] = {}
    for written in out.values():
        for name in written:
            same_log.setdefault(_norm(_base(name)), set()).add(name)
    for written in out.values():
        for name in list(written):
            written |= same_log.get(_norm(_base(name)), set())
    return {word: frozenset(found) for word, found in out.items()}


@lru_cache(maxsize=1)
def _patterns() -> tuple[re.Pattern[str], re.Pattern[str]]:
    words = sorted(_source_names(), key=len, reverse=True)
    source = r"(?<![\w-])(" + "|".join(re.escape(w).replace(r"\ ", r"\s+") for w in words) + r")"
    qualified = re.compile(
        source + r"(?:"
        + r"\s*[-:]?\s*" + _EVENT_WORD + r"\s*[-#:=]?\s*(" + _IDS + r")"    # Sysmon EventID 10, EventCode=4698
        + r"|\s*-\s*(" + _IDS + r")" + _END                                  # Sysmon-10
        + r"|\s+(" + _IDS + r")\s+(?:[\w-]+\s+){0,2}" + _ROW_WORD           # Sysmon 10 (process-access) events
        + r")",
        re.I,
    )
    bare = re.compile(r"(?<![\w-])" + _EVENT_WORD + r"\s*[-#:=]?\s*(" + _IDS + r")" + _END, re.I)
    return qualified, bare


def _negated(text: str, start: int, end: int) -> bool:
    """The event is named in a sentence that says it is absent, or not known to be there."""
    before = _CLAUSE_END.split(text[:start])[-1]
    after = _CLAUSE_END.split(text[end:], maxsplit=1)[0]
    return bool(_NEGATION.search(before) or _NOT_FOUND.search(after))


def _ids(raw: str) -> list[str]:
    return [str(int(n)) for n in re.findall(r"\d{1,5}", raw)]


def named_events(text: Any) -> list[Event]:
    """``[(source word or "", event id)]`` the text asserts, in order, each once."""
    text = str(text or "")
    if not text.strip():
        return []
    qualified, bare = _patterns()
    found: list[Event] = []
    taken: list[tuple[int, int]] = []
    for m in qualified.finditer(text):
        taken.append(m.span())
        if _negated(text, m.start(), m.end()):
            continue
        raw = next(g for g in m.groups()[1:] if g)
        found += [(m.group(1).lower(), event_id) for event_id in _ids(raw)]
    for m in bare.finditer(text):
        if any(a <= m.start() < b for a, b in taken) or _negated(text, m.start(), m.end()):
            continue
        found += [("", event_id) for event_id in _ids(m.group(1))]
    return list(dict.fromkeys(found))


def label(event: Event) -> str:
    source, event_id = event
    return f"{source} {event_id}".strip() if source else f"event {event_id}"


def _row_event(row: dict[str, Any]) -> tuple[str, set[str]]:
    """(event id, normalized provider and channel names) one row records."""
    fields = row.get("fields") if isinstance(row.get("fields"), dict) else {}
    event_id = str(row.get("event_id") or fields.get("EventID") or fields.get("EventId") or "").strip()
    names = {_norm(row.get(key)) for key in ("provider", "channel")}
    names |= {_norm(fields.get(key)) for key in ("Provider", "Channel")}
    return (str(int(event_id)) if event_id.isdigit() else event_id), {n for n in names if n}


def _records(row: dict[str, Any], event: Event) -> bool:
    source, event_id = event
    row_id, names = _row_event(row)
    if row_id != event_id:
        return False
    if not source or not names:
        return True
    wanted = {_norm(n) for n in _source_names().get(source, frozenset({source}))}
    return bool(wanted & names)


def event_filter(event: Event, *, strict: bool = False) -> dict[str, Any]:
    """The ES clause for rows that record ``event``.

    For a claim's cited rows a row naming no provider or channel is kept (it cannot contradict the source).
    ``strict`` asks whether the case holds the event at all, where such a row proves nothing (IC-14).
    """
    source, event_id = event
    clause: list[dict[str, Any]] = [{"term": {"event_id": event_id}}]
    if source:
        names = sorted(_source_names().get(source, frozenset({source})))
        should: list[dict[str, Any]] = [
            {"terms": {"ecs.event.provider": names}},
            {"terms": {"ecs.winlog.channel": names}},
        ]
        if not strict:
            should.append({"bool": {"must_not": [{"exists": {"field": "ecs.event.provider"}},
                                                 {"exists": {"field": "ecs.winlog.channel"}}]}})
        clause.append({"bool": {"should": should, "minimum_should_match": 1}})
    return {"bool": {"filter": clause}}


def es_replay(case_id: str) -> Replay:
    """Replay a cited ``es_search`` query on the case index with one event added (its exact total)."""
    def replay(query: dict[str, Any], event: Event) -> int | None:
        try:
            from nexus.langgraph.es_native import es_search

            result = es_search(case_id, {"bool": {"filter": [query, event_filter(event)]}}, size=1)
        except Exception:  # noqa: BLE001 - a replay that cannot run leaves the event unknown
            return None
        if result.get("error") or result.get("degraded"):
            return None
        try:
            return int(result.get("total"))
        except (TypeError, ValueError):
            return None
    return replay


def event_grounding(text: Any, calls: dict[str, dict[str, Any]], *, rows: list[dict[str, Any]] | None = None,
                    replay: Replay | None = None) -> dict[str, list[str]]:
    """Which events ``text`` names that the cited calls did not return.

    ``calls`` is ``evidence_rows.cited_calls``; ``rows`` are rows already attached to the claim. Returns
    ``{"named", "recorded", "unrecorded", "unknown"}`` as labels. An event is ``unknown`` when no stored row
    has it and a call that returned more rows than it stored could not be run again.
    """
    named = named_events(text)
    out: dict[str, list[str]] = {"named": [label(e) for e in named], "recorded": [], "unrecorded": [],
                                 "unknown": []}
    if not named:
        return out
    # A call that stored no rows (a triage check, a run record) returned no event, so it says nothing either way.
    row_calls = [call for call in calls.values() if isinstance(call.get("rows"), list)]
    stored = [r for call in row_calls for r in call["rows"] if isinstance(r, dict)]
    stored += [r for r in rows or [] if isinstance(r, dict)]
    # A call that reported no total (an aggregation, a sample, a lead) or more rows than it stored may hold
    # the event among the rows it did not keep.
    incomplete = [call for call in row_calls
                  if call.get("total") is None or int(call["total"]) > len(call["rows"])]
    for event in named:
        if any(_records(row, event) for row in stored):
            out["recorded"].append(label(event))
            continue
        if not row_calls:
            out["unknown"].append(label(event))
            continue
        answers = []
        for call in incomplete:
            query = (call.get("params") or {}).get("query")
            if call.get("tool") != "es_search" or not isinstance(query, dict) or replay is None:
                answers.append(None)
                continue
            answers.append(replay(query, event))
        if any(a for a in answers):
            out["recorded"].append(label(event))
        elif any(a is None for a in answers):
            out["unknown"].append(label(event))
        else:
            out["unrecorded"].append(label(event))
    return out


@lru_cache(maxsize=512)
def _index_event_count(case_id: str, event: Event) -> int | None:
    try:
        from nexus.langgraph.es_native import es_search

        result = es_search(case_id, event_filter(event, strict=True), size=1)
    except Exception:  # noqa: BLE001 - no index: it cannot say
        return None
    if result.get("error") or result.get("degraded"):
        return None
    try:
        return int(result.get("total"))
    except (TypeError, ValueError):
        return None


def events_in_case(case_dir: Any, text: Any) -> bool | None:
    """Whether the case's index holds any event ``text`` names (IC-14).

    True or False when the text names events and the index answers; None when it names none or the index
    cannot say. A playbook line "LSASS access detected in Sysmon Event ID 10" was shown as why every alert of
    CASE-C5B04D31 mattered, a case with no Sysmon log.
    """
    from pathlib import Path

    events = named_events(text)
    if not events or case_dir is None:
        return None
    answers = [_index_event_count(Path(case_dir).name, event) for event in events]
    if any(a for a in answers):
        return True
    return None if any(a is None for a in answers) else False


def downgrade_ungrounded_confirmations(verdicts: list[Any], case_dir: Any) -> list[dict[str, Any]]:
    """A verifier's "confirmed" whose basis names an event its cited calls did not return confirms nothing.

    Run 4's verifier confirmed lsass.exe on "30 Sysmon EventID-10 process-access events" while the rows it
    cited were Security 4688 (D238). As a refutation needs a positive control (D42), a confirmation needs
    its basis to be what its calls returned. The verdict becomes ``unverifiable`` with the reason in its
    basis, and is returned so the caller records the change.
    """
    from pathlib import Path

    from nexus.langgraph.evidence_rows import cited_calls

    confirmed = [v for v in verdicts or []
                 if isinstance(v, dict) and str(v.get("class") or "").strip().lower() == "confirmed"]
    if not confirmed or case_dir is None:
        return []
    case_dir = Path(case_dir)

    def ids_of(verdict: dict[str, Any]) -> list[str]:
        raw = verdict.get("audit_ids") or verdict.get("audit_id") or []
        return [str(a).strip() for a in ([raw] if isinstance(raw, str) else raw) if str(a).strip()]

    calls = cited_calls(case_dir, sorted({a for v in confirmed for a in ids_of(v)}))
    replay = es_replay(case_dir.name)
    changed = []
    for verdict in confirmed:
        own = {a: calls[a] for a in ids_of(verdict) if a in calls}
        unrecorded = event_grounding(verdict.get("basis"), own, replay=replay)["unrecorded"] if own else []
        if not unrecorded:
            continue
        verdict["class"] = "unverifiable"
        verdict["downgraded_from"] = "confirmed"
        verdict["basis"] = (str(verdict.get("basis") or "").strip()
                            + f" [downgraded: the basis names {', '.join(unrecorded)}, which no cited call "
                            "returned]").strip()
        changed.append(verdict)
    return changed


def recorded_events(rows: list[dict[str, Any]]) -> list[str]:
    """What rows do record, for a message that says what a claim got wrong."""
    seen: dict[str, None] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        event_id, _names = _row_event(row)
        if event_id:
            source = str(row.get("channel") or row.get("provider") or "").strip()
            seen[f"{source} {event_id}".strip()] = None
    return list(seen)
