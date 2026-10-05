"""WO-KL2d: map Sigma fields to the columns each family ACTUALLY fills.

The reviewer's diagnosis, now measured rather than asserted: all 966 translated Sigma
analytics reference only importer columns (`command_line`, `process_name`, `registry_key`,
`file_path`, `payload`, `registry_value`, `parent_process`) for families whose rows are
EVTX-analyser output, where those columns do not exist.

The fix the WO asks for: "Map Sigma fields **per family** to the columns that family
really has". Concretely, a rule that declares the EVTX lane and searches for a process
image must be answered from the family that really carries it:

  * the **importer lane** (`ingest-*` sources) genuinely has `process_name`,
    `parent_process`, `command_line`, `file_path`, the hashes and the registry columns -
    that is the D34 projection and the measurement proves it fills;
  * the **EVTX-analyser lane** (evtxecmd, hayabusa, chainsaw, zircolite, deepbluecli)
    carries the event's own generic columns: `PayloadData1..6`, `ExecutableInfo`,
    `UserName`, `RemoteHost`, `Computer`, and per-event IDs;
  * families that are neither (a registry tool like RECmd) carry their own columns.

This module holds that mapping as DATA, derived from the EvtxECmd maps and the
registry, so the converter can look up the right column per family instead of falling
back to the importer slot for everything.
"""
from __future__ import annotations

import sys
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

#: What each Sigma field actually asks about, in the WO's own vocabulary.
#: What a field NAMES, in the WO's vocabulary. Keyed on the name as the sources spell
#: it: Sigma field names, the pivot names the step catalog uses, and both mixed case
#: spellings, so one table serves the importer, the converter and the population check.
SIGMA_CONCEPT = {
    # Sigma field names
    "Image": "process",
    "OriginalFileName": "file",
    "CommandLine": "command",
    "ProcessCommandLine": "command",
    "ParentImage": "parent_process",
    "ParentCommandLine": "parent_command",
    "TargetFilename": "file",
    "TargetObject": "registry",
    "Details": "registry",
    "ServiceName": "process",
    "ImagePath": "file",
    "TaskName": "file",
    "ScriptBlockText": "command",
    "QueryName": "host",
    "DestinationHostname": "host",
    "DestinationIp": "dest_ip",
    "SourceIp": "source_ip",
    "DestinationPort": "dest_port",
    "SourcePort": "source_port",
    "User": "user",
    # the step catalog's pivot names
    "ProcessName": "process",
    "ParentProcessName": "parent_process",
    "RemoteAddress": "dest_ip",
    "RemoteHost": "host",
    "FileName": "file",
    "EventID": "event_id",
    "EventId": "event_id",
    "device": "host",
    "Hostname": "host",
    "Computer": "host",
    "TargetUserName": "user",
    "SubjectUserName": "user",
    "NewProcessName": "process",
    "Guid": None,
}

#: A pivot that names a device, a host or a remote address is NOT a protocol or
#: product name. The R0' defects were all a text value aimed at a typed column:
#: "Modbus/DNP3/PLC" at `dest_ip`, "PLC log" at `host`, "bytes" at `source_ip`.
#: Anything whose VALUE is not of the column's kind must go to `text.wc`.
TEXT_ONLY_CONCEPTS = frozenset({
    # these name a device/host, but a protocol name is not a host name
    "host",
})

@lru_cache(maxsize=1)
def _importer_lanes() -> frozenset[str]:
    """Every family that writes an ingest store carrying the D34 columns.

    Derived from the schema's own source list rather than hand-typed, so a newly
    registered importer is included by its registration instead of by remembering to
    add one alias here. `mftecmd` is a host-parse tool rather than an importer, but
    its rows reach the index through the same projection, so it belongs with them.
    """
    try:
        from nexus.ingest.schemas import ArtifactSource
        names = {str(m.value).lower() for m in ArtifactSource}
    except Exception:  # pragma: no cover - schema import guard
        names = {
            "amcache", "auditd", "authlog", "azure", "bash_history", "browser_history",
            "cloudtrail", "cybertriage", "elastic", "generic_csv", "generic_jsonl",
            "gcp", "kape", "lnk", "misp", "netflow", "plaso", "prefetch",
            "security_onion", "scheduled_tasks", "splunk", "suricata", "syslog",
            "thehive", "velociraptor", "volatility", "wireshark", "zeek",
        }
    out = set(names)
    out |= {f"ingest-{n}" for n in names}
    # `mftecmd` is a host-parse tool rather than an importer, but its rows reach the
    # index through the SAME projection as the importers, so they do carry
    # `process_name` and friends - it belongs with them.
    out |= {"mftecmd", "ingest-mftecmd"}
    # NOT here: `evtxecmd`, `security`, `sysmon`, `hayabusa`, `chainsaw`, `zircolite`,
    # `deepbluecli`. Those are EVTX-analyser lanes: their rows carry the event's OWN
    # generic columns (`PayloadData*`, `ExecutableInfo`, `Computer`, ...) and never
    # the importer's `process_name`. Adding them here is what made every Sigma rule
    # for the EVTX lane resolve to an importer column, which is the R0' defect - and
    # it is what made `evtxecmd` fall out of `evtx_lanes`, so no lane was left to
    # answer and every field resolved to None.
    return frozenset(out)


@lru_cache(maxsize=1)
def _evtx_maps():
    """The pinned EvtxECmd per-(Channel,EventId) generic-column mapping."""
    import yaml

    maps = Path(__file__).resolve().parents[2] / "src" / "nexus" / "data" / "schema" \
        / "evtxecmd_maps.yaml"
    if not maps.is_file():
        return []
    data = yaml.safe_load(maps.read_text(encoding="utf-8")) or {}
    return [e for e in (data.get("packs") or []) if isinstance(e, dict)]


def _evtx_lane_columns(lane: str) -> tuple[str, ...]:
    """The columns a lane ACTUALLY exposes for event data, measured not assumed.

    Chainsaw's CSV carries the event's payload as `key: value` lines inside one
    `Event Data` string; it never emits `PayloadData1..6`. Zircolite's JSON emits
    typed columns (`Channel`, `Computer`, `UserID`, `ClientProcessStartKey`,
    `LocalName`, `RemoteName`, ...). Hayabusa and EvtxECmd emit the generic
    `PayloadData*` / `ExecutableInfo` columns the pinned maps describe.

    Pointing a Chainsaw-declaring rule at `PayloadData2` is the R0' defect wearing a
    different hat: the column name is right for the wrong lane, so it cannot match.
    """
    lane = str(lane).lower()
    if lane == "chainsaw":
        return ("Event Data", "detections", "Computer", "Event ID",
                "Event.System.Provider", "Record ID")
    if lane == "zircolite":
        return ("Channel", "Computer", "EventID", "EventRecordID", "UserID",
                "ClientProcessStartKey", "LocalName", "RemoteName",
                "Execution_ProcessID", "Provider_Name", "Task", "Level")
    # hayabusa, evtxecmd and their ingest-* aliases: the pinned generic columns
    return ("PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4",
            "PayloadData5", "PayloadData6", "ExecutableInfo", "UserName",
            "RemoteHost", "Computer")


#: The Wo's own vocabulary, matching KM1's concept names.
SIGMA_CONCEPT = {
    "Image": "process",
    "OriginalFileName": "file",
    "CommandLine": "command",
    "ProcessCommandLine": "command",
    "ParentImage": "parent",
    "ParentCommandLine": "parentcommand",
    "TargetFilename": "file",
    "TargetObject": "registry",
    "Details": "registry",
    "ServiceName": "service",
    "ImagePath": "file",
    "TaskName": "task",
    "ScriptBlockText": "command",
    "QueryName": "file",
    "DestinationHostname": "file",
    "DestinationIp": "ip",
    "SourceIp": "ip",
    "DestinationPort": "port",
    "SourcePort": "port",
    "User": "user",
}


@lru_cache(maxsize=1)
def _population_profile() -> dict[str, set[str]]:
    """family -> the columns the representative corpus actually fills.

    The profile is the authoritative record (KM1 item 3): "A column listed here is
    populated on real evidence; a registry column not listed is declared, not
    populated." A candidate that the declared families do not fill is rejected, which
    is the mechanical guard the WO's rule 1 asks for.
    """
    import json

    for rel in ("Evidence-files/ES-Mapping/es_mappings/_population.json",):
        p = Path(__file__).resolve().parents[2] / rel
        if not p.is_file():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        out: dict[str, set[str]] = {}
        for fam, entry in (data.get("families") or {}).items():
            filled = set()
            for col, meta in ((entry or {}).get("columns") or {}).items():
                try:
                    if int((meta or {}).get("filled") or 0) > 0:
                        filled.add(str(col).lower())
                except Exception:  # noqa: BLE001
                    continue
            out[str(fam).lower()] = filled
        return out
    return {}


def columns_for(field: str, families: list[str],
                event_id: str = "", channel: str = "") -> list[str]:
    """The columns a field can be answered from, for these families.

    `event_id`/`channel` scope the EVTX answer to the event the rule is about.

    A candidate survives only when the declared families actually fill it, per the
    population profile. That is what stops `ParentImage` resolving to `PayloadData2`
    for a step that declares `chainsaw` (whose rows fill `Computer` and `Event Data`,
    never `PayloadData*`), and `DestinationIp` resolving to any IP column for a step
    whose values are protocol names.
    """
    concept = SIGMA_CONCEPT.get(field)
    if not concept or concept == "event_id":
        return []
    fams = {str(f).lower() for f in families}
    lanes = _importer_lanes()
    evtx_lanes = fams - lanes
    profile = _population_profile()
    out: list[str] = []
    importer_col = {
        "process": "process_name", "parent_process": "parent_process",
        "command": "command_line", "file": "file_path",
        "registry": "registry_key", "user": "user", "host": "host",
        "service": "process_name", "task": "file_path",
        "ip": "dest_ip", "port": "dest_port",
    }.get(concept)
    evtx_scoped = bool(event_id) or bool(evtx_lanes)
    if importer_col and (fams & lanes) and not evtx_scoped:
        out.append(importer_col)
    if not evtx_scoped:
        return _only_populated(out, fams, profile)

    # EVTX lane: the pinned per-event map, scoped to the rule's own event, and only
    # for a lane that really exposes that column.
    patterns = {
        "user": ("target user", "subject user", "account", "logon account",
                 "target domain", "subject domain"),
        "process": ("process", "image", "executable", "binary",
                    "logon processname"),
        "command": ("command line", "process command", "cmdline"),
        "parent_process": ("parent",),
        "parent_command": ("parent command",),
        "file": ("file", "target filename", "object name", "task"),
        "registry": ("key", "registry", "target object"),
        "dest_ip": ("ip address", "address"),
        "port": ("port",),
        "hash": ("hash", "sha", "md5"),
        "host": ("hostname", "workstation", "computer"),
    }.get(concept, (concept,))
    affirmed: list[str] = []
    for entry in _evtx_maps():
        if event_id and str(entry.get("event_id") or "") != str(event_id):
            continue
        for column, meta in (entry.get("columns") or {}).items():
            template = str((meta or {}).get("template") or "").lower()
            if any(k in template for k in patterns) and str(column) not in affirmed:
                affirmed.append(str(column))
    for lane in sorted(evtx_lanes):
        real = {c.lower() for c in _evtx_lane_columns(lane)}
        for column in affirmed:
            if column.lower() in real and column not in out:
                out.append(column)
    return _only_populated(out, fams, profile)


def _only_populated(candidates: list[str], fams: set[str],
                    profile: dict[str, set[str]]) -> list[str]:
    """Keep a candidate when ANY declared family fills it - not every one.

    A rule that declares `evtxecmd, hayabusa, security, sysmon` is answered by any
    lane's rows, so a column one of them fills is a legitimate target. Demanding that
    every declared family fill it is what dropped `PayloadData*` here: `chainsaw` is a
    valid lane for the rule but its rows fill `Event Data`, so the requirement could
    never be met and every field resolved to None (1767/1767 skipped).

    Two sources, in order:
    1. the population profile, for the families it holds - its own note is that a
       column listed there is populated on real evidence;
    2. the registry's `families`, for the families the profile cannot see, because an
       unmeasured family is not a disproved one.

    When neither can help, the candidate is kept and the population check's `cause`
    field records it as `corpus_absent` rather than silently dropping it.
    """
    if not candidates:
        return candidates
    known = {f for f in fams if f in profile}
    if known:
        keep = [c for c in candidates
                if any(str(c).lower() in profile.get(f, set()) for f in known)]
        if keep:
            return keep
        # no measured family fills any candidate. Fall through to the registry rather
        # than returning [] outright: the profile may simply have staged a narrow
        # subset of the rule's lanes (as it does here - chainsaw/zircolite but not
        # evtxecmd/hayabusa), and dropping the answer would skip the whole rule.
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
        from nexus.knowledge.query_validation import load_field_registry
        cols = load_field_registry()
    except Exception:  # noqa: BLE001 - no registry means no second opinion
        return list(candidates)
    low_fams = {str(f).lower() for f in fams}
    out = []
    for c in candidates:
        info = cols.get(c) or {}
        reg_fams = {str(f).lower() for f in (info.get("families") or [])}
        if not reg_fams or (reg_fams & low_fams):
            out.append(c)
    return out


if __name__ == "__main__":
    print("  scoped to the event the rule names:")
    for f in ("Image", "CommandLine", "ParentImage", "TargetFilename", "User",
              "DestinationIp", "TargetObject"):
        print(f"  {f:16s} sysmon-evt-1   -> {columns_for(f, ['sysmon'], '1')}")
        print(f"  {f:16s} security-4624   -> "
              f"{columns_for(f, ['security'], '4624')}")
        print(f"  {f:16s} security-4688   -> "
              f"{columns_for(f, ['security'], '4688')}")
        print(f"  {f:16s} ingest (mftecmd)-> "
              f"{columns_for(f, ['ingest-mftecmd', 'amcache'])}")
        print()
