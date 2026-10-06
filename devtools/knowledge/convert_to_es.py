"""WO-KR2b (design time): convert the free step queries into ES query JSON, properly.

This replaces the KR2 conversion, which was **valid but wrong** (reviewer, R0):

* it took only the **first** acceptable token of a step's free `query`, so **204 of
  252 steps lost their OR-alternatives** - `vssadmin create shadow OR vssadmin delete
  shadows OR diskshadow` became only `*diskshadow*`, so a step would under-detect;
* it embedded Mode 1 `field:value` syntax as literal text in **43** steps
  (`"*file:prefetch*"`), which can never match, so those steps would read "ran,
  found nothing";
* it guessed a typed column from the step's `pivot` even when the value could not
  live there - `asrep_roast` (pivot `TargetUserName`) put the AS-REP failure code
  `0x40850210` in `fields.TargetUserName.kw`.

The rules here, from WO-KR2b:

1. **Every alternative survives.** ``A OR B OR C`` becomes
   ``{"bool": {"should": [A', B', C'], "minimum_should_match": 1}}``. Nothing is
   dropped without an entry in ``es_dropped`` recording the term and the reason.
2. **Typed fields where the value demands them.** Event ids go to the top-level
   keyword ``event_id``; a Mode 1 ``field:value`` token becomes a clause on that
   field; an extension-bearing name goes to the pivot's column. A value that no
   typed column can carry falls back to ``text`` / ``text.wc`` with an
   ``es_text_only_reason``.
3. **No Mode 1 syntax inside a value.** ``file:prefetch`` becomes a clause on
   ``file``; ``family:evtx`` becomes a ``terms`` clause over the family expansion.
   The literal string ``"file:prefetch"`` must never appear in a stored query.

Run it with ``--check`` in CI: it fails when a knowledge file disagrees with what
this converter produces, so the stored queries cannot silently drift again.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from nexus.analysis.skill_steps import PIVOT_FIELDS  # noqa: E402
from nexus.knowledge.query_validation import (  # noqa: E402
    CORE_ENVELOPE_FIELDS,
    expand_families,
    load_field_registry,
    validate_stored_query,
)

# Design-time use of the Mode 1 compiler, which WO-KR2 allows for the conversion:
# `src/nexus` never compiles a stored knowledge query.
from nexus.langgraph.case_index import ast_to_es  # noqa: E402
from nexus.langgraph.query_dsl import parse_query  # noqa: E402

ANALYTICS_PATH = REPO_ROOT / "src" / "nexus" / "data" / "knowledge" / "needles" / "behavioral_analytics.yaml"
SKILLS_DIR = REPO_ROOT / "src" / "nexus" / "data" / "knowledge" / "skills"
#: The analytics' AUTHORED queries, pinned by `pin_analytics_source.py`. Design
#: time only: nothing in `src/nexus` reads it.
ANALYTICS_SOURCE = Path(__file__).resolve().parent / "analytics_source.yaml"

#: Pivot column names that identify a person, not an artefact. A free term in such
#: a step is the behaviour or the artefact ("delegation", "0x40850210"), never an
#: account name, so putting it in the identity column is a clause that cannot match
#: - the silent zero KR2b exists to stop. A real account search is written as a
#: typed `user:name` token, which rule 2 handles.
_IDENTITY_COLUMNS = frozenset({
    "user", "username", "targetusername", "subjectusername", "accountname",
    "userid", "targetuser", "subjectuser",
})

#: A token that is a file name rather than a bare word.
_EXTENSION = re.compile(
    r"\.(exe|dll|sys|drv|ps1|bat|cmd|vbs|js|jar|lnk|pf|db|dat|evtx|evt|log|txt|"
    r"json|xml|yml|yaml|csv|zip|7z|rar|gz|hve|hiv|reg|msi|scr|com|bin|img|raw)$",
    re.IGNORECASE,
)
_HEX = re.compile(r"^0x[0-9a-f]+$", re.IGNORECASE)
_EVENT_ID = re.compile(r"^\d{4,5}$")
_FIELD_VALUE = re.compile(r"^([a-z_][a-z0-9_]*):([^\s].*)$", re.IGNORECASE)
#: A field name with no value (`ip:`) - an incomplete filter, not a search term.
_EMPTY_FIELD = re.compile(r"^[a-z_][a-z0-9_]*:$", re.IGNORECASE)
#: `C:\x` and `C:/x` are Windows paths, not `field:value`.
_DRIVE_PATH = re.compile(r"^[a-z]:[\\/]", re.IGNORECASE)
_OR = re.compile(r"\s+OR\s+", re.IGNORECASE)

#: WO-KR2c change 2: the steps whose `look_for` is an INVESTIGATION ORDER, not
#: evidence to search. Each was a keyword search that fired on any row mentioning the
#: word and counted as coverage - the R0' defect verbatim. They are reclassified as
#: procedures: shown to agents, never executed, never counted.
PROCEDURE_STEPS = frozenset({
    "hash_on_acquire", "triage_first", "encryption_check", "backward_analysis",
    "chain_of_custody",
})

#: Columns that hold a FILE PATH. R0F item 3 deletes the value-shape route that sent
#: an extension-bearing token or a pivot to one of these by shape; until WO-CS1 moves
#: the routing to `ecs.file.path`, such a clause goes to `text.wc` with a reason.
FILE_PATH_COLUMNS = frozenset({
    "filepath", "filename", "targetfilename", "targetpath", "absolutepath",
})

PROCEDURE_REASON = (
    "R0' defect: this step's look_for is an investigation ORDER (do X, then Y), not "
    "evidence to search. It is shown to agents as a procedure and never executed, "
    "so it cannot fire on noise and cannot count as coverage."
)

#: Every keyword the step's search carried, and why a keyword search was wrong.
PROCEDURE_DROPPED = [
    {"term": "sha256", "reason": "procedure verb, not evidence: hashing is what the "
                                 "examiner does, not what is searched for"},
    {"term": "md5", "reason": "procedure verb, not evidence"},
    {"term": "hash", "reason": "procedure verb, not evidence"},
    {"term": "kape", "reason": "names a tool the examiner runs, not a field value "
                               "to search for"},
    {"term": "triage", "reason": "procedure verb, not evidence"},
    {"term": "bitlocker", "reason": "a pre-acquisition decision, not a search over "
                                    "indexed evidence"},
    {"term": "encryption", "reason": "procedure verb, not evidence"},
    {"term": "encrypted", "reason": "procedure verb, not evidence"},
    {"term": "rdp", "reason": "an entry vector named in the procedure, not a column "
                              "value"},
    {"term": "phish", "reason": "an entry vector named in the procedure"},
    {"term": "msiexec", "reason": "an entry vector named in the procedure, not a "
                                  "column value"},
    {"term": "event_id 4624", "reason": "a real clue, but this step is the order of "
                                        "investigation, not a search for it"},
]


def _wild(field: str, value: str) -> dict[str, Any]:
    return {"wildcard": {field: {"value": f"*{value}*", "case_insensitive": True}}}


def _column_kind(col: str, cols: dict[str, Any]) -> str:
    info = cols.get(col) or {}
    return str(info.get("type") or "")


def _value_fits_column(col: str, value: str) -> bool:
    """KL2d/KR2c rule 1: the value's kind must match the column's.

    Delegates to `value_shape_guard`, which holds the WO's own table as data: an IP
    column takes only IP-shaped values, a host only a hostname, a process column only
    an image name. Protocols, product names, column names and tool/plugin names go to
    `text.wc` instead - never an IP, port, host or process field.

    A missing devtool must not break the converter, so failure means "yes, compatible"
    and the step keeps its previous (shape-blind) answer, which the population check
    catches later.
    """
    try:
        _here = str(Path(__file__).resolve().parent)
        if _here not in sys.path:
            sys.path.insert(0, _here)
        from value_shape_guard import compatible  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return True
    return compatible(col, value)


def _norm_key(value: str) -> str:
    """Case-, space- and underscore-insensitive key for matching column names."""
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _resolve_column(name: str, fams: list[str], cols: dict[str, Any]) -> str | None:
    """The registry column `name` names, when the step's families produce it.

    Pivot values are written as column names (`CommandLine`, `TargetUserName`) while
    the registry uses its own spelling (`command_line`), so matching is on a
    normalised key and consults `PIVOT_FIELDS` for the known aliases.

    WO-KR2c 0b/0c: a candidate is chosen only when it is **populated** for the
    step's families, not merely declared. `families` is what the catalog declares,
    and `expand_families` widens `evtxecmd` into `ingest-hayabusa`/`ingest-kape`,
    whose shared 32-column schema makes the importer slots look valid for EVTX -
    while nothing fills them there. So the candidate order is:

      1. the column the caller literally named, populated for these families;
      2. the aliases, populated for these families;
      3. the column the caller literally named;
      4. the aliases.

    That keeps `FileName` resolving to `FileName` when it is a real column for the
    family, which 0c asks for ("choose the column from the declared family's own
    mapped columns first"), and it prefers a populated candidate over a declared one
    when the population profile can tell them apart.

    A **registry placeholder** never resolves. `rules.<rule>.meta.attack` and
    `matches[][].value` describe a nested shape, not a column the index emits, so a
    clause naming one can never match - the R0' `capa_capabilities` defect verbatim:
    "`exists` on `fields.rules.<rule>.meta.attack`, with the literal placeholder
    `<rule>`".
    """
    if not name:
        return None
    # a template placeholder or a multi-level path is not a resolvable column
    if "<" in name or ">" in name or "[]" in name:
        return None
    expanded = expand_families(fams)
    by_norm = {_norm_key(col): col for col in cols}

    # WO-R0F item 4: the KL2d family-map resolution (which lived in the deleted
    # `sigma_family_fields.py`) is gone. Until WO-CS1 item 7 routes stored queries to
    # the common `ecs.*` fields, resolution is by the name the caller used plus the
    # known aliases, preferring a column the population profile says is populated.

    # Prefer the column the caller literally named, then the known aliases:
    # `FileName` should resolve to `FileName` when that column exists for the
    # families, not to its `file_path` alias.
    aliases = PIVOT_FIELDS.get(_norm_key(name), ())
    named = by_norm.get(_norm_key(name))
    lit: list[str] = [named] if named else []
    pop_lit: list[str] = [named] if _populated_for(named, cols, expanded) else []
    pop_al: list[str] = []
    plain_al: list[str] = []

    for cand in aliases:
        col = by_norm.get(_norm_key(cand))
        if not col:
            continue
        if _populated_for(col, cols, expanded):
            pop_al.append(col)
        else:
            plain_al.append(col)

    for pool in (pop_lit, pop_al, lit, plain_al):
        for col in pool:
            col_fams = {str(f).lower() for f in ((cols.get(col) or {}).get("families") or [])}
            if not col_fams or (col_fams & expanded):
                return col
    return None


def _populated_for(column: str | None, cols: dict[str, Any], fams: set[str]) -> bool:
    """Whether the registry says `column` is filled for any of `fams`.

    An empty `populated_in` is NOT a negative answer - it means the population
    corpus never sampled the column, and unsampled is not invalid. This is checked
    first so the ordering never rejects an unprofiled column.
    """
    if not column:
        return False
    info = cols.get(column) or {}
    populated = {str(f).lower() for f in (info.get("populated_in") or [])}
    if not populated:
        return False
    return bool(populated & fams)


#: WO-CS1 item 7: the ~15-row concept table. A typed clause moves to the common
#: `ecs.*` field, so a stored query no longer names a per-tool column. A typed
#: clause is kept only when its `ecs` field is populated for one of the step's
#: families (checked against the re-profiled population incl. ecs.*); everything
#: else goes to `text.wc` with a reason.
CONCEPT_TO_ECS: dict[str, tuple[str, str]] = {
    # concept            (ecs field,                 clause kind: term|wildcard)
    "process": ("ecs.process.name", "wildcard"),
    "processname": ("ecs.process.name", "wildcard"),
    "commandline": ("ecs.process.command_line", "wildcard"),
    "parent": ("ecs.process.parent.executable", "wildcard"),
    "parentimage": ("ecs.process.parent.executable", "wildcard"),
    "parentprocess": ("ecs.process.parent.executable", "wildcard"),
    "file": ("ecs.file.path", "wildcard"),
    "filename": ("ecs.file.path", "wildcard"),
    "filepath": ("ecs.file.path", "wildcard"),
    "path": ("ecs.file.path", "wildcard"),
    "targetpath": ("ecs.file.path", "wildcard"),
    "registry": ("ecs.registry.path", "wildcard"),
    "registrykey": ("ecs.registry.path", "wildcard"),
    "user": ("ecs.user.name", "term"),
    "username": ("ecs.user.name", "term"),
    "targetuser": ("ecs.user.target.name", "term"),
    "targetusername": ("ecs.user.target.name", "term"),
    "sourceip": ("ecs.source.ip", "term"),
    "destinationip": ("ecs.destination.ip", "term"),
    "eventid": ("ecs.event.code", "term"),
    "logontype": ("ecs.winlog.logon.type", "term"),
    "service": ("ecs.service.name", "wildcard"),
    "hash": ("ecs.file.hash.sha256", "term"),
}


#: WO-CS1b item 5: a per-tool COLUMN's concept, so a compiled analytic's
#: `fields.<col>` can be rewritten to the common `ecs.*` field when the population
#: profile vouches for it for one of the analytic's families. Tool columns stay only
#: where no `ecs` equivalent exists.
COLUMN_TO_ECS: dict[str, str] = {
    "process_name": "ecs.process.name",
    "imagename": "ecs.process.name",
    "commandline": "ecs.process.command_line",
    "command_line": "ecs.process.command_line",
    "parentimage": "ecs.process.parent.executable",
    "parentprocess": "ecs.process.parent.name",
    "parent_process": "ecs.process.parent.name",
    "file_path": "ecs.file.path",
    "filepath": "ecs.file.path",
    "filename": "ecs.file.name",
    "targetfilename": "ecs.file.path",
    "registry_key": "ecs.registry.path",
    "registrykey": "ecs.registry.path",
    "keypath": "ecs.registry.path",
    "registry_value": "ecs.registry.value",
    "user": "ecs.user.name",
    "username": "ecs.user.name",
    "targetusername": "ecs.user.target.name",
    "subjectusername": "ecs.user.name",
    "source_ip": "ecs.source.ip",
    "ipaddress": "ecs.source.ip",
    "dest_ip": "ecs.destination.ip",
    "destinationip": "ecs.destination.ip",
    "event_id": "ecs.event.code",
    "eventid": "ecs.event.code",
    "logon_type": "ecs.winlog.logon.type",
    "logontype": "ecs.winlog.logon.type",
    "service_name": "ecs.service.name",
    "servicename": "ecs.service.name",
    "file_hash_sha256": "ecs.file.hash.sha256",
    "sha256": "ecs.file.hash.sha256",
}


def ecs_rewrite(es: dict[str, Any] | None, fams: list[str]) -> dict[str, Any]:
    """Rewrite `fields.<col>` to its common `ecs.*` field where the profile vouches.

    Recurses the whole ES query. A tool column stays when it has no `ecs` concept or
    the profile does not populate that ecs field for the given families.
    """
    if not isinstance(es, dict):
        return es
    out: dict[str, Any] = {}
    for key, value in es.items():
        if key.startswith("fields."):
            base = key[len("fields."):]
            strip = base.split(".")[0] if "." in base else base
            concept = COLUMN_TO_ECS.get(strip.lower())
            if concept and _ecs_populated_for(fams, concept):
                # an ECS string field is keyword-based (no `.kw` subfield)
                new_key = concept
                out[new_key] = value
                continue
            out[key] = value
        elif isinstance(value, dict):
            out[key] = ecs_rewrite(value, fams)
        elif isinstance(value, list):
            out[key] = [ecs_rewrite(v, fams) if isinstance(v, dict) else v for v in value]
        else:
            out[key] = value
    return out


def concept_ecs_field(pivot: str) -> tuple[str, str] | None:
    """The (ecs field, clause kind) for a pivot's concept, or None."""
    return CONCEPT_TO_ECS.get(_norm(pivot))


def _ecs_populated_for(fams: list[str], ecs_field: str) -> bool:
    """Whether a population profile vouches for `ecs_field` on any of `fams`.

    WO-CS1 item 7: a typed clause is kept only if its `ecs` field is populated for
    one of the step's families in the real-run profile. No profile data -> False
    (an unsampled field is not vouched for; the clause goes to text with a reason).
    """
    try:
        from nexus.knowledge.query_validation import load_field_registry

        reg = load_field_registry()
    except Exception:  # noqa: BLE001
        return False
    info = reg.get(ecs_field) or reg.get(ecs_field.lower()) or {}
    populated = {str(f).lower() for f in (info.get("populated_in") or [])}
    if not populated:
        return False
    wanted = {str(f).lower() for f in (fams or [])}
    return bool(populated & wanted) or not wanted


def _norm(value: Any) -> str:
    return str(value or "").strip().lower().replace("_", "").replace("-", "").replace(" ", "")


def _column_field(col: str, cols: dict[str, Any]) -> str:
    """`fields.<col>` for a keyword column, `fields.<col>.kw` for a text one."""
    return f"fields.{col}" if _column_kind(col, cols) != "text" else f"fields.{col}.kw"


def _is_typed(token: str) -> bool:
    """Whether a token names a field, an id or a file, rather than a bare word."""
    return bool(
        (_FIELD_VALUE.match(token) and not _DRIVE_PATH.match(token))
        or _EVENT_ID.match(token)
        or _HEX.match(token)
        or _EXTENSION.search(token)
    )


def _typed_clause(
    token: str, fams: list[str], pivot_col: str | None, cols: dict[str, Any],
    dropped: list[dict[str, str]], text_only: list[str],
) -> dict[str, Any] | None:
    """One ES clause for one token that carries its own field, else None."""
    tok = token.strip(",;()[]\"'")

    # A `field:value` token: typed on that field, never a literal string.
    m = _FIELD_VALUE.match(tok)
    if m and not _DRIVE_PATH.match(tok):
        field, value = m.group(1).lower(), m.group(2)
        if field == "family":
            members = sorted(expand_families([value]) or {value})
            return {"terms": {"family": members}}
        if field == "event":
            return {"term": {"event_id": value}}
        if field in CORE_ENVELOPE_FIELDS:
            return _wild(field, value)
        col = _resolve_column(field, fams, cols)
        if col:
            return _wild(_column_field(col, cols), value)
        dropped.append({"term": tok, "reason": f"unknown field {field!r}"})
        return None

    # An event id is a first-class typed value.
    if _EVENT_ID.match(tok):
        return {"term": {"event_id": tok}}

    # A hex mask (an encryption type, a status code). Typed only when the step's
    # families actually produce a column that could hold it.
    if _HEX.match(tok):
        for cand in ("TicketEncryptionType", "EncryptionType", "Status", "SubStatus"):
            col = _resolve_column(cand, fams, cols)
            if col:
                return _wild(_column_field(col, cols), tok)
        text_only.append(f"{tok}: no typed column for a hex mask in these families")
        return _wild("text.wc", tok)

    # R0F item 3 deleted the value-shape file-path route. WO-CS1 item 7 restores a
    # file-name token's typed clause, but on the COMMON field: `ecs.file.path`. It is
    # kept only when a population check can vouch for it; the caller verifies.
    ecs_file = concept_ecs_field("filepath")
    if ecs_file and _ecs_populated_for(fams, ecs_file[0]):
        return _wild(ecs_file[0], tok)
    text_only.append(
        f"{tok}: a file name token; no populated ecs.file.path for these families, "
        f"searched in text"
    )
    return _wild("text.wc", tok)


def _phrase_clause(
    phrase: str, pivot_col: str | None, cols: dict[str, Any], text_only: list[str],
    fams: list[str] | None = None,
) -> dict[str, Any]:
    """One clause for the words of an alternative, kept as a phrase.

    A phrase is kept whole: ``trusted for delegation`` searches for that phrase,
    not for three separate words that must all appear anywhere in the row. Splitting
    it would both over- and under-match, and the authored query wrote a phrase.

    The pivot's column is used only when it is not an identity column: a behaviour
    word ("delegation", "Replicating") is not an account name, and pinning it there
    is a clause that cannot match - the silent zero KR2b exists to stop. A real
    account search is written as a typed ``user:name`` token, handled by
    ``_typed_clause``.
    """
    # Content fixes that apply wherever the clause lands. The R0' defect is the
    # CONTENT, not the column: `reg save sam` is never a real command line, and
    # `ExecStart` is never part of a path. Both are fixed here, BEFORE the column
    # decision, so a step whose families resolve to no typed column still gets the
    # right search text instead of the authored (unmatchable) one.
    if _is_command_with_hive(phrase):
        return _wild("text.wc", _with_hive(phrase, text_only))
    # WO-CS1 item 7: route the pivot's concept to the COMMON `ecs.*` field when the
    # population profile vouches for it for this step's families. This replaces the
    # per-tool column routing (the rest of KR2c's field routing).
    if pivot_col:
        concept = concept_ecs_field(_norm_key(pivot_col)) or concept_ecs_field(pivot_col)
        if concept and _ecs_populated_for(fams or [], concept[0]):
            return _wild(concept[0], phrase)
    # R0F item 3: the pivot's route to a per-tool file-path column is DELETED - a
    # free phrase is never a path just because the pivot names one.
    if pivot_col and _norm_key(pivot_col) in FILE_PATH_COLUMNS:
        text_only.append(
            f"{phrase}: file-path pivot; no populated ecs.file.path, searched in text"
        )
        return _wild("text.wc", phrase)
    if pivot_col and _norm_key(pivot_col) not in {_norm_key(c) for c in _IDENTITY_COLUMNS}:
        # KL2d / KR2c rule 1: the value's KIND must match the column's. "Modbus" is
        # not an IP, "PLC log" is not a hostname, "pslist" is not a process - those
        # belong in `text.wc`, with the reason recorded, exactly as the WO's table
        # prescribes ("never an IP, port, host or process field; they go to text.wc").
        if not _value_fits_column(pivot_col, phrase):
            text_only.append(
                f"{phrase}: value of the wrong kind for {pivot_col}; searched in text"
            )
            return _wild("text.wc", phrase)
        # KR2c / R0' defect 8: a unit-file keyword is not part of a PATH.
        # `ExecStart`/`OnCalendar` live in a systemd unit's contents, so they belong
        # in the row text; the file column holds the unit file's path.
        if _is_unit_file_keyword(phrase):
            text_only.append(
                f"{phrase}: unit-file keyword, not a path; searched in text"
            )
            return _wild("text.wc", phrase)
        return _wild(_column_field(pivot_col, cols), phrase)
    text_only.append(
        f"{phrase}: free phrase; the step's pivot "
        f"{'is an identity column' if pivot_col else 'names no registry column'}"
    )
    return _wild("text.wc", phrase)


#: `reg save` is the command whose value is meaningless without a hive. The R0' sample
#: found the step searched `*reg save sam*`, which the real command never emits.
_HIVE_COMMAND = re.compile(r"^reg\s+save\s+(?P<hive>sam|system|security)\b", re.I)
#: A systemd unit-file keyword is not part of a path, so it is not a `file_path` value.
_UNIT_FILE_KEYWORD = re.compile(r"\b(ExecStart|OnCalendar|ExecStop|WantedBy)\b")


def _is_command_with_hive(phrase: str) -> bool:
    return bool(_HIVE_COMMAND.match(str(phrase or "").strip()))


def _expand_hive_command(phrase: str) -> str:
    """`reg save sam` -> `reg save *\\sam` so the clause names the hive."""
    m = _HIVE_COMMAND.match(str(phrase or "").strip())
    if not m:
        return phrase
    hive = m.group("hive").lower()
    rest = str(phrase).strip()[m.end():]
    return f"reg save *\\{hive}{' ' + rest.strip() if rest.strip() else ''}"


def _is_unit_file_keyword(phrase: str) -> bool:
    return bool(_UNIT_FILE_KEYWORD.search(str(phrase or "")))


def _with_hive(phrase: str, text_only: list[str]) -> str:
    """Expand a hive-reading command so the term names the hive.

    `reg save` always names a hive (`reg save HKLM\\sam ...`), so the bare `reg save sam`
    the authored query writes is never what the real command produces. Whether the
    clause lands on `command_line` or `text.wc` depends on the families, so the
    expansion applies on both paths - it is the CONTENT that was wrong, not the column.
    """
    m = _HIVE_COMMAND.match(str(phrase or "").strip())
    if not m:
        return phrase
    text_only.append(f"{phrase}: expanded to name the hive the command reads")
    hive = m.group("hive").lower()
    rest = str(phrase).strip()[m.end():]
    return f"reg save *\\{hive}{' ' + rest.strip() if rest.strip() else ''}"


def build_es(
    query: str, fams: list[str], pivot: str, cols: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, str]], list[str]]:
    """The ES query for a step's free `query`, with its drops and text reasons.

    Alternatives are split on the authored `` OR `` and each becomes one ``should``
    branch, so **none is lost** (the KR2 defect). Within an alternative, tokens that
    carry their own field (an event id, a ``field:value``, a hex mask, a file name)
    become their own clause, and the remaining words stay one phrase.
    """
    text = str(query or "").strip()
    if not text:
        return {"match_all": {}}, [], []

    pivot_col = _resolve_column(pivot, fams, cols) if pivot else None
    dropped: list[dict[str, str]] = []
    reasons: list[str] = []
    branches: list[dict[str, Any]] = []

    for alt in _OR.split(text):
        alt = alt.strip()
        if not alt:
            continue
        parts: list[dict[str, Any]] = []
        words: list[str] = []
        for tok in alt.replace('"', " ").split():
            clean = tok.strip(",;()[]\"'")
            if not clean:
                continue
            if _EMPTY_FIELD.match(clean):
                # `ip:` is a filter with no value. It cannot become a clause, and
                # it must not become the literal text `*ip:*` (KR2b rule 3).
                dropped.append({"term": clean, "reason": "field filter with no value"})
                continue
            if _is_typed(clean):
                clause = _typed_clause(clean, fams, pivot_col, cols, dropped, reasons)
                if clause is not None:
                    parts.append(clause)
            else:
                words.append(clean)
        if words:
            phrase_part = _phrase_clause(" ".join(words), pivot_col, cols, reasons, fams)
            if phrase_part is not None:
                parts.append(phrase_part)
        if not parts:
            continue
        branches.append(parts[0] if len(parts) == 1 else {"bool": {"must": parts}})

    if not branches:
        return {"match_all": {}}, dropped, reasons
    if len(branches) == 1:
        return branches[0], dropped, reasons
    return {"bool": {"should": branches, "minimum_should_match": 1}}, dropped, reasons


def _read_yaml(path: Path) -> tuple[dict[str, Any], list[str]]:
    raw = path.read_text(encoding="utf-8")
    header = []
    for line in raw.splitlines():
        if line.startswith("#"):
            header.append(line)
        elif line.strip():
            break
    return yaml.safe_load(raw) or {}, header


def _write_yaml(path: Path, data: dict[str, Any], header: list[str]) -> None:
    dumped = yaml.dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)
    path.write_text("\n".join(header) + "\n" + dumped if header else dumped, encoding="utf-8")


def convert_skills(check: bool = False) -> dict[str, Any]:
    """Rewrite every skill step's `es:` from its free `query`. Idempotent."""
    cols = load_field_registry()
    stats = {"steps": 0, "alternatives": 0, "dropped": 0, "text_only": 0, "changed": 0,
             "authored": 0, "procedures": 0}
    for sf in sorted(SKILLS_DIR.glob("*.yaml")):
        data, header = _read_yaml(sf)
        req = data.get("requires") or {}
        fams = [str(f) for f in (req.get("families") or [])]
        steps = data.get("steps") or []
        dirty = False
        for step in steps:
            if not isinstance(step, dict):
                continue
            stats["steps"] += 1
            step_fams = [str(f) for f in ((step.get("requires") or {}).get("families") or fams)]
            query = str(step.get("query") or "")

            # A hand-authored query the converter cannot express is kept, exactly as
            # the analytics keep theirs: `es_authored_reason` records why, and the
            # step is validated rather than rebuilt. Without this, a step whose real
            # query needs clauses over several DIFFERENT columns (the capa step asks
            # about the capability name, its ATT&CK mapping and its MBC mapping in one
            # `should`) would be silently replaced by a weaker single-column query.
            if str(step.get("es_authored_reason") or "").strip():
                stats["authored"] += 1
                es = step.get("es")
                if not isinstance(es, dict) or not es:
                    raise SystemExit(
                        f"{sf.name} / {step.get('name')}: marked authored but has no `es:`")
                if not str(step.get("es_text_only_reason") or "").strip():
                    stats["text_only"] += 1
                continue

            es, dropped, reasons = build_es(query, step_fams, str(step.get("pivot") or ""), cols)
            stats["alternatives"] += len(_OR.split(query)) if query.strip() else 0
            stats["dropped"] += len(dropped)
            if reasons:
                stats["text_only"] += 1
            # WO-KR2c change 2: a procedure step has no `es:` by contract. Comparing
            # it against a rebuilt keyword search would make `--check` demand the very
            # thing the rule removes.
            is_proc = step.get("name") in PROCEDURE_STEPS
            if check:
                if is_proc:
                    expected_alt = [
                        {"term": alt.strip(), "reason": "procedure step: shown to "
                                                        "agents, never executed"}
                        for alt in _OR.split(str(step.get("query") or ""))
                        if alt.strip()
                    ]
                    expected_proc = expected_alt + [
                        d for d in PROCEDURE_DROPPED
                        if d["term"] not in {a["term"] for a in expected_alt}
                    ]
                    if step.get("es") is not None or step.get("kind") != "procedure" \
                            or not step.get("procedure_reason") \
                            or step.get("es_dropped") != expected_proc:
                        raise SystemExit(
                            f"{sf.name} / {step.get('name')}: procedure step is not "
                            f"stored as a procedure - re-run without --check")
                    stats["procedures"] += 1
                    continue
                if step.get("es") != es or bool(dropped) != bool(step.get("es_dropped")):
                    raise SystemExit(
                        f"{sf.name} / {step.get('name')}: stored es: disagrees with the "
                        f"converter - re-run without --check"
                    )
                continue
            if step.get("es") != es:
                step["es"] = es
                dirty = True
            for key, value in (("es_dropped", dropped), ("es_text_only_reason", reasons)):
                if value:
                    if step.get(key) != value:
                        step[key] = value
                        dirty = True
                elif key in step and step.pop(key) is not None:
                    dirty = True
            # WO-KR2c change 2: PROCEDURE steps are not queries. A step whose
            # `kind: procedure` is declared (in PROCEDURE_STEPS, with the reason a
            # procedure is the honest description) has its `es:` REMOVED and gets
            # `procedure_reason` + `es_dropped`, so it is shown to agents as a
            # procedure, never executed, and never counted as coverage. Without this
            # the converter would rebuild a keyword search for it, which is the R0'
            # defect: those searches fire on noise and count as coverage.
            if step.get("name") in PROCEDURE_STEPS:
                step["kind"] = "procedure"
                step["procedure_reason"] = PROCEDURE_REASON
                if step.pop("es", None) is not None:
                    dirty = True
                if step.pop("es_text_only_reason", None) is not None:
                    dirty = True
                # es_dropped must account for THIS step's own free-query
                # alternatives (KR2b (a): no alternative disappears unrecorded),
                # then the standard procedure verbs. Using one fixed list for every
                # step lost a step's real alternatives (chain_of_custody: custody/
                # seized/collected).
                alt_dropped = [
                    {"term": alt.strip(), "reason": "procedure step: shown to agents, "
                                                    "never executed"}
                    for alt in _OR.split(str(step.get("query") or ""))
                    if alt.strip()
                ]
                proc_dropped = alt_dropped + [
                    d for d in PROCEDURE_DROPPED
                    if d["term"] not in {a["term"] for a in alt_dropped}
                ]
                if step.get("es_dropped") != proc_dropped:
                    step["es_dropped"] = proc_dropped
                    dirty = True
                stats["procedures"] += 1
            step.pop("dsl", None)
        if dirty and not check:
            stats["changed"] += 1
            _write_yaml(sf, data, header)
    return stats


def convert_analytics(check: bool = False) -> dict[str, Any]:
    """Regenerate every analytic's `es:` from its **authored** query.

    KR2's converter was not idempotent: it consumed `dsl`, wrote `es`, and deleted
    `dsl`, so a second run compiled an empty query to `match_all` and overwrote the
    real one. **26 of 36 analytics were left matching every row** - a stored query
    that asserts nothing.

    The authored queries are pinned in `devtools/knowledge/analytics_source.yaml`
    (recovered from the revision before KR2 deleted them). This compiles each one
    with the sanctioned Mode 1 compiler - design-time use, which WO-KR2 allows -
    writes only `es:`, and refuses to leave an analytic as `match_all`.
    """
    data, header = _read_yaml(ANALYTICS_PATH)
    source = _read_yaml(ANALYTICS_SOURCE)[0]
    authored: dict[str, str] = {
        str(k): str(v) for k, v in (source.get("queries") or {}).items()
    }

    literal = re.compile(r'^\*?[a-z_]+:[^\\/]')
    stats: dict[str, Any] = {
        "analytics": 0, "compiled": 0, "authored_es": 0, "match_all": [],
        "literals": [], "text_only": 0, "changed": 0, "compiler_refused": [],
    }
    dirty = False

    def fields_of(node: Any, out: list[str]) -> list[str]:
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("term", "terms", "wildcard", "match", "match_phrase",
                         "prefix", "exists") and isinstance(v, dict):
                    out.extend(str(f) for f in v)
                fields_of(v, out)
        elif isinstance(node, list):
            for v in node:
                fields_of(v, out)
        return out

    for analytic in data.get("packs") or []:
        if not isinstance(analytic, dict):
            continue
        stats["analytics"] += 1
        ident = str(analytic.get("id") or "")
        fams = [str(f) for f in (analytic.get("families") or [])]
        cite = analytic.get("citation")

        if ident in authored:
            es = ast_to_es(parse_query(authored[ident]))
            # WO-CS1b item 5: route the compiled analytic's concept columns to the
            # common `ecs.*` fields where the profile populates them for this family.
            es = ecs_rewrite(es, fams)
            problems = validate_stored_query(es, declared_families=fams, citation=cite)
            if problems:
                # The compiler cannot express this one with the registry's columns
                # (`ba-cred-logon-type3` asks for `logon_type`, which the event-log
                # families do not produce). Keep the hand-authored query when it is
                # a real query, and record why the program refused - never pretend
                # the compiled one is fine.
                existing = analytic.get("es") or {}
                existing_problems = validate_stored_query(
                    existing, declared_families=fams, citation=cite)
                if not existing or existing == {"match_all": {}} or existing_problems:
                    raise SystemExit(
                        f"analytic {ident}: the compiler refused ({problems[0]}) and no "
                        f"valid authored `es:` stands in its place"
                    )
                stats["compiler_refused"].append({"id": ident, "why": problems[0]})
                analytic["es_authored_reason"] = (
                    "the Mode 1 compiler cannot express this against the registry "
                    f"({problems[0]}); reviewed and kept by hand"
                )
                dirty = True
            else:
                stats["compiled"] += 1
                if analytic.get("es") != es:
                    analytic["es"] = es
                    dirty = True
                if analytic.pop("es_authored_reason", None) is not None:
                    dirty = True
        else:
            # Authored directly as `es:` (the KL2 additions); keep it, but it must
            # still be a real query.
            stats["authored_es"] += 1

        es = analytic.get("es") or {}
        if es == {"match_all": {}}:
            stats["match_all"].append(ident)
        for value in re.findall(r'"value":\s*"([^"]*)"', json.dumps(es)):
            if literal.match(value):
                stats["literals"].append({"id": ident, "value": value})
        flds = fields_of(es, [])
        if flds and all(f in ("text", "text.wc") for f in flds):
            stats["text_only"] += 1
            reason = "envelope text search: no registry column carries this mixed evidence"
            if analytic.get("es_text_only_reason") != reason:
                analytic["es_text_only_reason"] = reason
                dirty = True
        # `dsl:` is not a storage format; drop any that survives.
        if analytic.pop("dsl", None) is not None:
            dirty = True

    if check:
        return stats
    if dirty:
        stats["changed"] = 1
        _write_yaml(ANALYTICS_PATH, data, header)
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail when a stored query disagrees with the converter")
    args = parser.parse_args(argv)

    skill_stats = convert_skills(check=args.check)
    an_stats = convert_analytics(check=args.check)

    print(f"skill steps : {skill_stats['steps']} "
          f"({skill_stats['alternatives']} alternatives, "
          f"{skill_stats['dropped']} dropped with a reason, "
          f"{skill_stats['authored']} hand-authored, "
          f"{skill_stats['text_only']} text-only)"
          + ("" if args.check else f", {skill_stats['changed']} file(s) rewritten"))
    print(f"analytics   : {an_stats['analytics']} "
          f"({an_stats['compiled']} compiled from the pinned authored query, "
          f"{an_stats['authored_es']} authored as es:, "
          f"{an_stats['text_only']} text-only)"
          + ("" if args.check else f", {an_stats['changed']} file(s) rewritten"))
    if an_stats["match_all"]:
        print(f"REFUSING: analytic(s) left as match_all: {an_stats['match_all']}",
              file=sys.stderr)
        return 1
    if an_stats["literals"]:
        print(f"LITERAL field:value in an analytic value: {an_stats['literals']}", file=sys.stderr)
        return 1
    if args.check:
        print("stored queries match the converter")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
