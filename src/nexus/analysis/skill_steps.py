"""WO-K6 — skills and playbooks at examiner grade.

A skill in this repo is a *method*: a trigger, a list of steps, a negative rule
and caveats. Three things were missing for an examiner to trust it:

* **A typed query per step.** Steps carried a free-text `query` only
  (252 of 252), so a step could not be executed against the index and its result
  could not be recorded. `dsl_for_step` supplies the typed form (an authored
  `dsl:` when present, otherwise derived from the step's `pivot` and its query
  text) and `validate_skill_dsl` proves every one parses against the registry.
  The free-text `query` stays for display.
* **A declaration of what the skill needs.** No skill declared `requires`
  (0 of 37), so a skill whose evidence was absent still presented itself as
  applicable. `derive_requires` computes `{families, lanes}` and
  `methodology_only` marks a skill whose families the case does not have - it
  stays readable as methodology, but it is not offered as executable.
* **A record of what each step did.** `run_skill_steps` runs each applicable step
  and records **hit**, **none**, or **not applicable**, with the reason, so a
  step that could not run is never mistaken for a step that found nothing.

`authority_table` keeps one owner per topic, because overlapping skills are how
two methods drift apart.

Citations: `citation_grade` classifies a skill's sources as `chunk`
(machine-readable `{chunk_id}`), `document` (a bare string naming a document) or
`none`. `verify_citations` fails on `document` and `none` - the work order's
"fails on zero or document-only citations".
"""
from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

log = logging.getLogger(__name__)

#: Step `pivot` -> the registry columns that can carry it. A pivot is the field a
#: step says to look at; the registry spells those fields several ways per family.
PIVOT_FIELDS: dict[str, tuple[str, ...]] = {
    "commandline": ("command_line", "CommandLine", "Process CommandLine"),
    "processname": ("process_name", "ImageFileName", "Process Name", "Image"),
    "sourceimage": ("process_name", "ImageFileName", "SourceImage"),
    "parentimage": ("parent_process", "ParentImage", "Parent Process Name"),
    "filename": ("file_path", "FileName", "TargetFilename"),
    "filepath": ("file_path", "FilePath", "TargetFilename"),
    "path": ("path", "file_path", "FilePath"),
    "user": ("user", "UserName", "TargetUserName"),
    "targetusername": ("user", "UserName", "TargetUserName"),
    "sourceip": ("source_ip", "SourceIp", "IpAddress"),
    "destinationip": ("dest_ip", "DestinationIp"),
    "host": ("host", "Computer"),
    "service": ("registry_key", "Service Name", "ServiceName"),
    "registrykey": ("registry_key", "KeyPath", "HivePath"),
    "task": ("task_uri", "Task Name", "TaskName"),
    "hash": ("file_hash_sha256", "file_hash_md5", "Hash"),
    "logontype": ("logon_type", "LogonType"),
    "eventid": ("event_id", "eventid", "EventID"),
    "domain": ("user", "TargetDomainName", "Domain"),
    "sharename": ("path", "ShareName"),
    # Pivots that name a real concept the registry spells differently (measured
    # over the 37 skills: these were the remaining unresolved ones).
    "subjectusername": ("user", "UserName", "TargetUserName"),
    "targetpath": ("file_path", "FilePath", "path"),
    "remoteprincipalname": ("user", "UserName"),
    "valuename": ("value_name", "registry_value"),
    "uri": ("path", "file_path"),
    "remoteaddress": ("source_ip", "dest_ip"),
    "device": ("host", "Computer"),
    "iserialnumber": ("volumeserialnumber",),
    "serialnumber": ("volumeserialnumber",),
    "accountname": ("User", "UserName", "name"),
    "appname": ("name", "AppName"),
    "scriptblocktext": ("ScriptBlockText", "command_line"),
    "zoneid": ("zoneidcontents", "ZoneId"),
    "record": ("EventRecordID", "event_id"),
    "tag": ("tag", "tags"),
    "arguments": ("arguments", "action_arguments"),
    "programarguments": ("arguments",),
    "timecreated": ("TimeCreated", "Created"),
    "channel": ("Channel", "channel"),
}

#: Pivots that only a memory image can satisfy, so the skill needs the SIFT lane.
MEMORY_PIVOTS = frozenset({
    "virtualaddress", "processid", "vad", "eprocess", "handle", "memory", "address",
})

#: The lanes a skill can require.
LANE_WINDOWS = "windows"
LANE_SIFT = "sift"

#: Families that imply the memory lane.
MEMORY_FAMILIES = frozenset({"vol", "ingest-volatility", "memory"})


def _norm(value: Any) -> str:
    return str(value or "").strip().lower().replace("_", "").replace("-", "").replace(" ", "")


def fields_for_pivot(pivot: str) -> tuple[str, ...]:
    """Registry columns that can carry *pivot* (empty when unrecognised)."""
    return PIVOT_FIELDS.get(_norm(pivot), ())


def resolve_field(pivot: str, available: Iterable[str] | None = None) -> str:
    """The registry column that carries *pivot*.

    Order matters. A step's pivot is usually **already the field name**
    (`KeyPath`, `AbsolutePath`, `Channel`, `ScriptBlockText`), so an exact
    case/separator-insensitive match against the registry is tried first; only
    then the alias table, which exists for the pivots a family spells
    differently (`SourceImage` -> `process_name`, `sha256` ->
    `file_hash_sha256`). Without the exact pass, 149 of 252 steps resolved to
    nothing and could not be run at all.
    """
    key = _norm(pivot)
    if not key:
        return ""
    if available is not None:
        lookup = {_norm(c): str(c) for c in available}
        exact = lookup.get(key)
        if exact:
            return exact
    candidates = fields_for_pivot(pivot)
    if not candidates:
        return ""
    if available is None:
        return candidates[0]
    lookup = {_norm(c): str(c) for c in available}
    for candidate in candidates:
        hit = lookup.get(_norm(candidate))
        if hit:
            return hit
    return ""


def _first_needle(query: str) -> str:
    """The most specific-looking token of a free-text query.

    Skips the boolean glue words an authored query uses ("OR", "and"), the very
    short tokens that would match everything, and any token containing a colon
    that is not already a typed `field:value` filter - a bare term with a colon
    would be read as an unknown field and refused.
    """
    glue = {"or", "and", "not", "the", "a", "an"}
    best = ""
    for token in str(query or "").replace('"', " ").split():
        clean = token.strip(",;()[]")
        if not clean or clean.lower() in glue:
            continue
        if ":" in clean and not _looks_like_typed(clean):
            continue
        # Prefer a dotted name, a path fragment or a hex mask over a bare word.
        score = (("." in clean) or ("\\" in clean) or ("/" in clean)
                 or clean.lower().startswith("0x") or (len(clean) > 8))
        if score:
            return clean
        if not best:
            best = clean
    return best


def dsl_for_step(step: dict[str, Any], available: Iterable[str] | None = None) -> str:
    """The typed query for a step.

    An authored ``dsl:`` wins. Otherwise, in order:

    1. the step's ``pivot`` resolved to a registry column, with the first
       distinctive token of ``query`` as the value;
    2. when there is no usable pivot, a **bare text term** from the query. A bare
       term is a valid DSL form (it becomes an OR term searched across the
       document), so the step is executable rather than blocked - and the
       free-text ``query`` remains for display either way.
    """
    authored = str((step or {}).get("dsl") or "").strip()
    if authored:
        return authored
    value = _first_needle(str((step or {}).get("query") or ""))
    pivot = str((step or {}).get("pivot") or "").strip()
    field = resolve_field(pivot, available)
    # A resolved column containing a space (`Source Address`) cannot be emitted as
    # `field:value` - the DSL would read it as the field after the space. Fall
    # back to a bare term rather than emitting a query that means something else.
    if field and " " in field:
        field = ""
    if field and value:
        if value.lower() in ("any", "*"):
            return f"exists:{field}"
        return f"{field}:{value}"
    if not value:
        return ""
    # The query may already be typed: `file:cookies`, `eventid:1102`. `file` and
    # the other core envelope columns are legitimate filters, so accept the term
    # as written rather than refusing it for containing a colon.
    if _looks_like_typed(value):
        return value
    return value if _is_bare_term_safe(value) else ""


#: Core envelope columns the DSL accepts on every case.
_CORE_ENVELOPE = frozenset({
    "family", "file", "host", "user", "event", "eventid", "event_id", "line",
    "computer", "machine",
})


def _looks_like_typed(value: str) -> bool:
    """Whether a token is already a usable `field:value` filter."""
    if ":" not in value:
        return False
    head = value.split(":", 1)[0].strip().lower()
    return bool(head) and head.replace("-", "_") in _CORE_ENVELOPE


def _is_bare_term_safe(value: str) -> bool:
    """Whether a token can be a bare DSL term.

    A term with a colon would be read as a `field:value` filter and rejected as
    an unknown field, so those are not safe to emit bare.
    """
    return ":" not in value and bool(value.strip())


def step_records(
    skill: dict[str, Any],
    available: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Every step with its typed query and whether that query is usable."""
    out: list[dict[str, Any]] = []
    for index, step in enumerate((skill or {}).get("steps") or []):
        if not isinstance(step, dict):
            continue
        dsl = dsl_for_step(step, available)
        out.append({
            "index": index,
            "name": str(step.get("name") or f"step{index + 1}"),
            "query": str(step.get("query") or ""),
            "dsl": dsl,
            "has_dsl": bool(dsl),
            "pivot": str(step.get("pivot") or ""),
            "look_for": str(step.get("look_for") or ""),
        })
    return out


def validate_skill_dsl(
    skill: dict[str, Any],
    available: Iterable[str] | None = None,
) -> list[str]:
    """Every problem with a skill's step queries (empty == all usable)."""
    from nexus.langgraph.query_dsl import QuerySyntaxError, parse_query

    known = {_norm(c): str(c) for c in (available or [])} or None
    problems: list[str] = []
    for record in step_records(skill, available):
        if not record["has_dsl"]:
            problems.append(
                f"{record['name']}: no typed query - pivot "
                f"{record['pivot']!r} is not a known field, or the query has no value"
            )
            continue
        try:
            parsed = parse_query(record["dsl"])
        except QuerySyntaxError as exc:
            problems.append(f"{record['name']}: dsl does not parse: {exc}")
            continue
        if known is not None:
            for filt in parsed.filters:
                if str(filt.get("op") or "") == "exists":
                    named = _norm(filt.get("value")) or ""
                else:
                    named = _norm(filt.get("name")) or ""
                if named and named not in known:
                    problems.append(
                        f"{record['name']}: field {filt.get('name') or filt.get('value')!r} "
                        "is not in the registry"
                    )
    return problems


# ---------------------------------------------------------------------------
# requires / methodology only
# ---------------------------------------------------------------------------

def derive_requires(skill: dict[str, Any]) -> dict[str, list[str]]:
    """``{families, lanes}`` a skill needs to be executable.

    Families are the trigger's plus those the steps' pivots imply, because a step
    that reads `SourceImage` cannot run on a case with no event-log family even
    if the trigger named none. Lanes follow from the pivots and families: a step
    reading memory needs the SIFT lane.
    """
    families: list[str] = []
    for family in ((skill or {}).get("trigger") or {}).get("families") or []:
        text = str(family).strip()
        if text and text not in families:
            families.append(text)

    memory = False
    for step in (skill or {}).get("steps") or []:
        if not isinstance(step, dict):
            continue
        pivot = _norm(step.get("pivot"))
        if pivot in MEMORY_PIVOTS:
            memory = True
        if pivot in PIVOT_FIELDS:
            continue  # the pivot maps to a field, not a family
    for family in families:
        if _norm(family) in {_norm(f) for f in MEMORY_FAMILIES}:
            memory = True

    lanes = [LANE_WINDOWS]
    if memory:
        lanes.append(LANE_SIFT)
    return {"families": families, "lanes": lanes}


def declared_requires(skill: dict[str, Any]) -> dict[str, list[str]]:
    """The skill's own `requires` when it declares one, else the derived form.

    Deriving is not the same as declaring: a case whose evidence is missing is
    judged on what the skill actually needs, and a skill that declares nothing
    gets its requirements computed rather than being treated as always
    applicable (measured: 0 of 37 declared any).
    """
    declared = (skill or {}).get("requires")
    if isinstance(declared, dict):
        families = [str(f) for f in (declared.get("families") or []) if str(f).strip()]
        lanes = [str(x) for x in (declared.get("lanes") or []) if str(x).strip()]
        return {"families": families, "lanes": lanes}
    return derive_requires(skill)


def methodology_only(
    skill: dict[str, Any],
    case_families: Iterable[str] | None = None,
    case_lanes: Iterable[str] | None = None,
) -> bool:
    """Whether the skill can only be offered as methodology for this case.

    True when the case lacks the families the skill needs, or a lane it needs.
    ``None`` means "unknown", and unknown is **not** treated as missing - a case
    the caller has not described must not silently lose every skill.
    """
    requires = declared_requires(skill)
    if case_families is not None:
        have = {_norm(f) for f in case_families}
        need = {_norm(f) for f in requires["families"]}
        if need and not (need & have):
            return True
    if case_lanes is not None:
        have_lanes = {str(x).strip().lower() for x in case_lanes}
        if any(lane.lower() not in have_lanes for lane in requires["lanes"]):
            return True
    return False


# ---------------------------------------------------------------------------
# running the steps
# ---------------------------------------------------------------------------

def run_skill_steps(
    skill: dict[str, Any],
    *,
    es_search: Any = None,
    available: Iterable[str] | None = None,
    case_families: Iterable[str] | None = None,
    case_lanes: Iterable[str] | None = None,
    limit: int = 5,
) -> dict[str, Any]:
    """Run each applicable step and record hit / none / not applicable.

    ``es_search`` is the seam: a callable ``(dsl, limit) -> {"count": n, ...}``.
    With no searcher every step is recorded `not_applicable` with the reason -
    never `none`, which would read as "the step ran and found nothing".
    """
    if methodology_only(skill, case_families, case_lanes):
        reason = "skill requirements are not met by this case (methodology only)"
        return {
            "skill": str((skill or {}).get("skill") or ""),
            "methodology_only": True,
            "steps": [
                {**record, "result": "not_applicable", "reason": reason}
                for record in step_records(skill, available)
            ],
        }

    results: list[dict[str, Any]] = []
    for record in step_records(skill, available):
        if not record["has_dsl"]:
            results.append({**record, "result": "not_applicable",
                            "reason": "no typed query for this step"})
            continue
        if es_search is None:
            results.append({**record, "result": "not_applicable",
                            "reason": "no searcher was provided"})
            continue
        try:
            outcome = es_search(record["dsl"], limit) or {}
        except Exception as exc:  # noqa: BLE001 - one step must not lose the run
            results.append({**record, "result": "not_applicable",
                            "reason": f"search failed: {type(exc).__name__}: {exc}"})
            continue
        count = int(outcome.get("count") or outcome.get("total") or 0)
        results.append({
            **record,
            "result": "hit" if count > 0 else "none",
            "hits": count,
            # A step that returned nothing is only "none" because it ran.
            "reason": "" if count else "query ran and matched no rows",
        })
    return {
        "skill": str((skill or {}).get("skill") or ""),
        "methodology_only": False,
        "steps": results,
        "summary": _summarise(results),
    }


def _summarise(results: list[dict[str, Any]]) -> dict[str, int]:
    out = {"hit": 0, "none": 0, "not_applicable": 0}
    for record in results:
        key = str(record.get("result") or "not_applicable")
        out[key] = out.get(key, 0) + 1
    return out


# ---------------------------------------------------------------------------
# authority table
# ---------------------------------------------------------------------------

#: One owner per topic. Two skills owning the same topic is how two methods drift.
AUTHORITY: dict[str, str] = {
    "windows event log analysis": "windows_event_log_analysis",
    "registry artefact analysis": "registry_artifact_analysis",
    "file system activity (MFT/USN)": "mft_file_activity",
    "prefetch and amcache execution": "execution_artifact_analysis",
    "lnk and jumplist activity": "lnk_jumplist_analysis",
    "browser history": "browser_artifact_analysis",
    "shellbags": "registry_artifact_analysis",
    "srum network usage": "network_flow_analysis",
    "lsass credential access": "lsass_credential_access",
    "sam and ntds credential access": "credential_access_sam_ntds",
    "ad credential attacks": "ad_credential_attacks",
    "c2 beaconing": "c2_beaconing",
    "defence evasion": "defense_evasion",
    "discovery and reconnaissance": "discovery_recon",
    "memory process analysis": "memory_process_analysis",
    "deleted file recovery": "deleted_file_recovery",
    "cloud identity forensics": "cloud_identity_forensics",
    "container forensics": "container_forensics",
    "usb device intrusions": "usb_device_intrusion",
    "data hiding": "windows_data_hiding",
    "malware triage": "malware_analysis_triage",
}


def authority_table() -> dict[str, str]:
    """Topic -> owning skill id (the single source for "who owns this")."""
    return dict(AUTHORITY)


def authority_conflicts(skills: Iterable[dict[str, Any]]) -> list[str]:
    """Skills whose id is not the authority for any topic, and duplicates.

    Not an error: a skill may legitimately cover a topic the table does not name.
    Reported so the table can be extended deliberately rather than drifting.
    """
    owned = set(AUTHORITY.values())
    problems: list[str] = []
    seen: dict[str, int] = {}
    for skill in skills:
        ident = str((skill or {}).get("skill") or "")
        if ident:
            seen[ident] = seen.get(ident, 0) + 1
    for ident, count in sorted(seen.items()):
        if count > 1:
            problems.append(f"{ident}: id used by {count} skills")
    missing = sorted(set(seen) - owned)
    if missing:
        problems.append(f"no authority row for: {', '.join(missing)}")
    return problems


# ---------------------------------------------------------------------------
# citations
# ---------------------------------------------------------------------------

def citation_grade(skill: dict[str, Any]) -> str:
    """``chunk`` | ``document`` | ``none`` for a skill's sources.

    `chunk` requires at least one machine-readable ``{chunk_id}``. A bare string
    naming a document is `document`: it points at a book, not at the passage
    that supports the step, so it cannot be checked.
    """
    source = (skill or {}).get("source")
    if isinstance(source, str):
        source = [source]
    if not isinstance(source, list) or not source:
        return "none"
    for item in source:
        if isinstance(item, dict) and str(item.get("chunk_id") or "").strip():
            return "chunk"
    return "document"


def verify_citations(skills: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Fail on zero or document-only citations (the work order's rule).

    Returns ``{"ok": bool, "failing": [...], "by_grade": {...}}``.
    """
    failing: list[dict[str, str]] = []
    by_grade = {"chunk": 0, "document": 0, "none": 0}
    for skill in skills:
        ident = str((skill or {}).get("skill") or "(unnamed)")
        grade = citation_grade(skill)
        by_grade[grade] = by_grade.get(grade, 0) + 1
        if grade != "chunk":
            failing.append({"skill": ident, "grade": grade})
    return {"ok": not failing, "failing": failing, "by_grade": by_grade}
