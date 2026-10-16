"""The subject a finding is about, derived from the rows it cites (operator decision 2026-10-12).

A finding's subject is what its cited rows are about: the process for an execution, the
destination for a connection, the file or registry key for a file or registry event, and the
account for anything else that names one. The host is the last resort.

The event decides the category: the pinned table (``event_categories.yaml``) gives the
category of each row's provider and event id. A row the pinned table does not name takes its
family's category (``family_categories.yaml``, D112), and ``other`` when neither names one. The
category chooses which field is the subject. The value is normalized the same way in every mode, so a
claim made by Mode 1, Mode 2 or Mode 3 about the same rows names the same subject.

The event id is never the subject. The case, the analysis context (independent or informed)
and the mode are not inputs: they cannot change which subject a row set has.
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

from nexus.discipline import entity_key
from nexus.langgraph.event_categories import OTHER, present, row_category

#: The ECS leaves a search hit carries into its evidence row, as dotted paths.
ECS_SUBJECT_PATHS = (
    "event.code",
    "event.provider",
    "winlog.channel",
    "host.name",
    "user.name",
    "user.target.name",
    "process.executable",
    "source.ip",
    "destination.ip",
    "destination.domain",
    "file.path",
    "registry.path",
)

#: The subject field, its row key, and the kind of entity it names.
FIELD_ROW_KEY = {
    "account": "account",
    "source_address": "source_ip",
    "destination_address": "destination_ip",
    "process": "process",
    "file": "file_path",
    "registry": "registry_path",
    "host": "host",
}
FIELD_KIND = {
    "account": "account",
    "source_address": "address",
    "destination_address": "address",
    "process": "process",
    "file": "file",
    "registry": "registry",
    "host": "host",
}

#: Subject precedence per category group: the first field a row carries is the subject.
ORDER_BY_GROUP = {
    "process": ("process", "account", "host"),
    "network": ("destination_address", "process", "host"),
    "file": ("file", "process", "host"),
    "registry": ("registry", "process", "host"),
    "account": ("account", "source_address", "process", "file", "registry", "host"),
}

#: The columns a family's own rows name the subject with, for families whose rows carry no ECS subject
#: leaves (checked against the case index, 2026-10-12). Each entry is (subject field, column). A column is
#: read from the parsed fields first, then from the hit's envelope. Not here, and why: SRUM AppId and
#: UserId are numeric table ids; Amcache KeyName is a GUID; WER, JSON and CSV name no subject; prefetch
#: free text (the memory timeline's Text) is not parsed.
FAMILY_SUBJECT_COLUMNS = {
    "pecmd": (("process", "ExecutableName"),),
    "prefetch": (("process", "Process"),),
    # MemProcFS's output is one family (D210). Its `Process` column names the process a row is about in
    # every file that has one: the memory image's prefetch, the modules a process loaded (and unloaded),
    # and the connections it owns (CASE-C5B04D31, 2026-10-15: 9,283 rows in four files).
    "memprocfs": (("process", "Process"),),
    "srumecmd": (("process", "ExeInfo"), ("account", "user")),
    # D112 (2026-10-13): AppCompatCache's Path is the executable each row names. A RECmd batch row carries its
    # key as BatchKeyPath when it has no KeyPath (the ECS map reads KeyPath).
    "appcompat": (("process", "Path"),),
    "recmd": (("registry", "BatchKeyPath"),),
}

#: The subject order of a family's rows when they carry no pinned category: the program the row is about
#: comes before the account that ran it (a SRUM row is an app's use by a user).
FAMILY_ORDER = {family: ORDER_BY_GROUP["process"] for family in FAMILY_SUBJECT_COLUMNS}

#: The group of every category in the pinned table. tests/test_subject.py checks that the
#: table and this map name the same categories, so a new pinned category needs a decision here.
GROUP_OF_CATEGORY = {
    "process_creation": "process",
    "process_access": "process",
    "process_termination": "process",
    "process_tampering": "process",
    "create_remote_thread": "process",
    "raw_access_thread": "process",
    "image_load": "process",
    "driver_load": "process",
    "ps_module": "process",
    "ps_script": "process",
    "ps_classic_start": "process",
    "ps_classic_provider_start": "process",
    "ps_classic_script": "process",
    "pipe_created": "process",
    "wmi_event": "process",
    "clipboard_capture": "process",
    "sysmon_status": "process",
    "sysmon_error": "process",
    "network_connection": "network",
    "dns_query": "network",
    "file_change": "file",
    "file_event": "file",
    "file_delete": "file",
    "file_delete_detected": "file",
    "file_block_executable": "file",
    "file_block_shredding": "file",
    "file_executable_detected": "file",
    "create_stream_hash": "file",
    "registry_event": "registry",
    # Operator decision 2026-10-12 (D94): the logon categories of the Elastic Windows Security pipeline.
    # A logon's subject is the account it logs on (user.target.name, see subject_fields), so account.
    "authentication": "account",
    "iam": "account",
    # D95 (operator 2026-10-15), from Windows' own provider manifests: a WinRM shell created on this
    # host is about who opened it (the account, then its client address); a task run is about the
    # process it launched; a task registration, update or deletion is about the account that made it.
    "remote_session": "account",
    "scheduled_task_run": "process",
    "scheduled_task_change": "account",
    # D232 (operator 2026-10-16), from Defender's manifest: a detection is about what it detected (the
    # file, else the process a behavior ran in); a protection setting change is about the setting.
    "malware": "file",
    "configuration": "registry",
}


def subject_fields(ecs: Any) -> dict[str, str]:
    """The row fields a hit's flat ECS leaves give, placeholders dropped.

    ``account`` is the logged-on or acted-on account: the ECS target account when the event has
    one (a logon's target is ``user.target.name``, its ``user.name`` is the requesting account),
    else the acting account.
    """
    if not isinstance(ecs, dict):
        return {}
    account = present(ecs.get("user.target.name")) or present(ecs.get("user.name"))
    values = {
        "provider": present(ecs.get("event.provider")),
        "channel": present(ecs.get("winlog.channel")),
        "account": account,
        "source_ip": present(ecs.get("source.ip")),
        # A remote end named by host, not address (a WinRM session's connection string, D95).
        "destination_ip": present(ecs.get("destination.ip")) or present(ecs.get("destination.domain")),
        "process": present(ecs.get("process.executable")),
        "file_path": present(ecs.get("file.path")),
        "registry_path": present(ecs.get("registry.path")),
        "host": present(ecs.get("host.name")),
    }
    return {key: value for key, value in values.items() if value}


def ecs_leaves(ecs: Any) -> dict[str, str]:
    """The flat ``{dotted path: value}`` of the subject ECS leaves a document carries."""
    if not isinstance(ecs, dict):
        return {}
    out: dict[str, str] = {}
    for path in ECS_SUBJECT_PATHS:
        node: Any = ecs
        for part in path.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        if node not in (None, ""):
            out[path] = str(node)[:200]
    return out


#: The kinds a second entity of a time_order claim may name: the subject kinds.
OTHER_ENTITY_KINDS = frozenset(FIELD_KIND.values())


def normalize_entity(kind: str, value: str) -> str:
    """A subject value as every mode writes it: lower case, one account name, one address, single spaces."""
    text = str(value or "").strip().lower()
    if kind == "account":
        text = text.rsplit("\\", 1)[-1]
    if kind == "address":
        text = text.strip("[]")
    return " ".join(text.split())


def _normalize(field: str, value: str) -> str:
    return normalize_entity(FIELD_KIND[field], value)


def _row_text(node: Any) -> list[str]:
    """Every string a row holds, at any depth."""
    if isinstance(node, dict):
        return [s for v in node.values() for s in _row_text(v)]
    if isinstance(node, (list, tuple)):
        return [s for v in node for s in _row_text(v)]
    return [str(node)] if node is not None else []


def ground_other_entity(kind: Any, value: Any, rows: list[dict[str, Any]]) -> dict[str, str]:
    """The second entity of a time_order claim, when a cited row carries it; ``{}`` otherwise (D87).

    The model names the second entity, and it is kept only when a cited row holds that value as a whole token,
    so a claim cannot order two entities the evidence does not name. The kind must be a subject kind.
    """
    kind = str(kind or "").strip().lower()
    if kind not in OTHER_ENTITY_KINDS or not present(value):
        return {}
    normalized = normalize_entity(kind, str(value))
    if not normalized:
        return {}
    blob = "\n".join(s for row in rows if isinstance(row, dict) for s in _row_text(row)).lower()
    if not re.search(rf"(?<![a-z0-9]){re.escape(normalized)}(?![a-z0-9])", blob):
        return {}
    return {"type": kind, "value": normalized}


def _loc_order(row: dict[str, Any]) -> tuple[str, int, str]:
    loc = str(row.get("loc") or "")
    path, _, line = loc.rpartition(":")
    return (path, int(line) if line.isdigit() else 0, loc)


def derive_subject(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """The subject and category of the rows a finding cites.

    Returns ``{"entity": {"type", "value"} or {}, "category": str}``. The category is the most
    common pinned category among the rows (ties go to the earliest row by file and line). The
    subject is the first field of that category's precedence that any row carries, read in row
    order, so the same rows always give the same subject.
    """
    ordered = sorted((r for r in rows or [] if isinstance(r, dict)), key=_loc_order)
    if not ordered:
        return {"entity": {}, "category": OTHER}
    categories = [row_category(r) for r in ordered]
    counts = Counter(categories)
    top = max(counts.values())
    chosen = next(c for c in categories if counts[c] == top)

    group = GROUP_OF_CATEGORY.get(chosen, "account")
    order = ORDER_BY_GROUP[group]
    if chosen == OTHER:
        order = FAMILY_ORDER.get(_family_of_rows(ordered), order)
    for field in order:
        for row in ordered:
            value = present(row.get(FIELD_ROW_KEY[field]))
            if value:
                entity = {"type": FIELD_KIND[field], "value": _normalize(field, value)}
                return {"entity": entity, "category": chosen}
    return {"entity": {}, "category": chosen}


def _family_of_rows(rows: list[dict[str, Any]]) -> str:
    """The family the rows came from: the most common one, ties to the earliest row (the row's source)."""
    families = [str(row.get("source") or "").split("/", 1)[0] for row in rows]
    counts = Counter(families)
    top = max(counts.values())
    return next(family for family in families if counts[family] == top)


def family_subject_fields(hit: dict[str, Any]) -> dict[str, str]:
    """The row fields a hit's family columns give (see FAMILY_SUBJECT_COLUMNS), placeholders dropped."""
    columns = FAMILY_SUBJECT_COLUMNS.get(str(hit.get("family") or ""), ())
    fields = hit.get("fields") if isinstance(hit.get("fields"), dict) else {}
    out: dict[str, str] = {}
    for field, column in columns:
        value = present(fields[column] if column in fields else hit.get(column))
        if value:
            out[FIELD_ROW_KEY[field]] = value
    return out


def subject_key(entity: Any, category: Any) -> str:
    """The identity the duplicate check and the cross-mode comparison both use.

    The entity is normalized as ``discipline.entity_key`` normalizes it (type and value matched
    case- and separator-blind), with the category. Empty when the entity names nothing.
    """
    key = entity_key(entity)
    return f"{key}|{category or OTHER}" if key else ""


def _claim_audit_ids(claim: dict[str, Any]) -> list[str]:
    raw = claim.get("audit_ids") or claim.get("audit_id") or []
    if isinstance(raw, str):
        raw = [raw]
    return [str(item).strip() for item in raw if str(item).strip()]


def attach_subjects(claims: list[dict[str, Any]], case_dir: Path | None) -> None:
    """Attach to each claim the subject its cited rows give (operator decision 2026-10-12).

    The claim gets ``subject = {type, value, category}`` derived from the rows its audit calls stored,
    by the rule staging uses. A claim whose rows give no subject gets ``{}``: it cannot be compared with
    another claim on the board. A time_order claim also gets ``other_subject``: its second entity, kept
    only when a cited row carries it (``ground_other_entity``, D87). An affirmed claim that names an event
    its cited calls did not return gets ``unrecorded_events`` (D238), and a claim that credits a baseline check
    it does not cite, or with an answer its cited call did not give, ``ungrounded_verdicts`` (D258). The
    audit trail is read once.
    """
    from nexus.langgraph.evidence_rows import cited_calls, rows_of_calls, unique_rows
    from nexus.langgraph.named_events import es_replay, event_grounding
    from nexus.langgraph.named_verdicts import verdict_grounding

    ids = sorted({aid for c in claims if isinstance(c, dict) for aid in _claim_audit_ids(c)})
    calls = cited_calls(case_dir, ids) if case_dir is not None and ids else {}
    stored = rows_of_calls(calls)
    replay = es_replay(case_dir.name) if case_dir is not None else None
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        claim.pop("unrecorded_events", None)
        claim.pop("ungrounded_verdicts", None)
        own = {aid: calls[aid] for aid in _claim_audit_ids(claim) if aid in calls}
        if str(claim.get("polarity") or "affirm").strip().lower() != "deny":
            # The value is what the claim asserts. Its entity label names what it is about, which for an
            # absence is the event looked for ("EID-140 (Task Scheduler task executed)").
            unrecorded = event_grounding(claim.get("value"), own, replay=replay)["unrecorded"] if own else []
            if unrecorded:
                claim["unrecorded_events"] = unrecorded
        # D258: a baseline check the claim credits, in what it asserts or in why it is confident, is one it
        # cites and answered as the claim says.
        stated = f"{claim.get('value') or ''}\n{claim.get('confidence_justification') or ''}"
        ungrounded = verdict_grounding(stated, own)["ungrounded"]
        if ungrounded:
            claim["ungrounded_verdicts"] = ungrounded
        rows = unique_rows(stored, _claim_audit_ids(claim))
        subject = derive_subject(rows)
        entity = subject["entity"]
        claim["subject"] = (
            {"type": entity["type"], "value": entity["value"], "category": subject["category"]}
            if entity else {}
        )
        if str(claim.get("claim_kind") or "") == "time_order":
            claim["other_subject"] = ground_other_entity(
                claim.get("other_entity_type"), claim.get("other_entity_value"), rows,
            )
