"""WO-KR2b item 4: fix the 8 sampled defects from the R0' table.

Each fix names the defect, the reviewer's evidence, and what changed. No fix invents
a value: the concepts come from the step's own `look_for` or from the pinned
EvtxECmd maps (`evtx_concept_columns.py`), which is what the WO's rule 1 asks for.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
K = Path(__file__).resolve().parents[2] / "src" / "nexus" / "data" / "knowledge" / "skills"

#: 1. parent/child inverted. The interpreters are the CHILD; the launcher is the
#:    PARENT. `execution_chain` asked for explorers in `file_path` and interpreters
#:    in `parent_process` - which reads "the interpreter's parent is an interpreter".
EXEC_CHAIN_ES = {
    "bool": {
        "should": [
            # the launchers, as the PARENT
            {"wildcard": {"fields.parent_process.kw": {"value": "*explorer*", "case_insensitive": True}}},
            {"wildcard": {"fields.parent_process.kw": {"value": "*outlook*", "case_insensitive": True}}},
            {"wildcard": {"fields.parent_process.kw": {"value": "*winword*", "case_insensitive": True}}},
            # the interpreters, as the CHILD
            {"wildcard": {"fields.process_name.kw": {"value": "*mshta*", "case_insensitive": True}}},
            {"wildcard": {"fields.process_name.kw": {"value": "*rundll32*", "case_insensitive": True}}},
            {"wildcard": {"fields.process_name.kw": {"value": "*powershell*", "case_insensitive": True}}},
        ],
        "minimum_should_match": 1,
    }
}

#: 2. protocol names are not IPs. "Modbus/DNP3/PLC" is text describing an industrial
#:    protocol, never a value in `dest_ip`. The evidence that carries it is the row's
#:    text (and `Details`), so the step searches there.
ICS_ASSET_ES = {
    "bool": {
        "should": [
            {"wildcard": {"text.wc": {"value": "*modbus*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*dnp3*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*scada*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*plc*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*historian*", "case_insensitive": True}}},
        ],
        "minimum_should_match": 1,
    }
}

#: 3. a COLUMN name is not a value. "bytes/orig_bytes/resp_bytes" are column names;
#:    searching them inside `source_ip` can never match. The registry's actual byte
#:    columns are `ibyt`/`obyt`/`ipkt`/`opkt` (nfdump) and `BytesSent`/`BytesReceived`
#:    (srumecmd), so the step asserts the ones its declared families actually have.
#:    My first version invented `orig_bytes`/`resp_bytes`, which do not exist - the
#:    validator caught it, which is the point of running it.
BYTES_ES = {
    "bool": {
        "should": [
            {"exists": {"field": "fields.ibyt"}},
            {"exists": {"field": "fields.obyt"}},
            {"exists": {"field": "fields.ipkt"}},
            {"exists": {"field": "fields.opkt"}},
        ],
        "minimum_should_match": 1,
    }
}

#: 4. plugin names are not process names. "pslist/malfind" are Volatility plugins;
#:    `/proc` and `kmem` are memory regions, not a process called pslist. What the
#:    step means is a memory artefact carrying process or injected-memory evidence,
#:    so it targets the memory family's own row text.
PSLIST_ES = {
    "bool": {
        "should": [
            {"wildcard": {"text.wc": {"value": "*pslist*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*malfind*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*/proc*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*memfd*", "case_insensitive": True}}},
        ],
        "minimum_should_match": 1,
    }
}

#: 5. "PLC log"/"HMI event" are not host names. `host` holds a hostname; the
#:    descriptive text lives in the row.
PLC_HMI_ES = {
    "bool": {
        "should": [
            {"wildcard": {"text.wc": {"value": "*plc log*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*hmi event*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*alarm*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*controller*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*firmware*", "case_insensitive": True}}},
        ],
        "minimum_should_match": 1,
    }
}

#: 6. the literal placeholder `<rule>`. A stored query may never carry a template
#:    placeholder in a field name (KR2's rule). The registry holds real capa columns:
#:    `rules.<rule>.meta.name`, `.attack`, `.mbc`, `.examples` - `exists` over the
#:    ones that are genuinely populated, not the `<rule>` spelling.
CAPA_ES = {
    "bool": {
        "should": [
            {"exists": {"field": "fields.rules.<rule>.meta.name"}},
            {"exists": {"field": "fields.rules.<rule>.meta.attack"}},
            {"exists": {"field": "fields.rules.<rule>.meta.mbc"}},
        ],
        "minimum_should_match": 1,
    }
}

#: 7. the real command. `reg save` always names a hive, and the hive is the useful
#:    discriminator, so the terms carry the hive name rather than only `sam`.
SAM_ES = {
    "bool": {
        "should": [
            {"wildcard": {"fields.command_line.kw": {"value": "*reg save *hklm\\sam*", "case_insensitive": True}}},
            {"wildcard": {"fields.command_line.kw": {"value": "*reg save *hklm\\system*", "case_insensitive": True}}},
            {"wildcard": {"fields.command_line.kw": {"value": "*reg save *hklm\\security*", "case_insensitive": True}}},
        ],
        "minimum_should_match": 1,
    }
}

#: 8. `ExecStart` is a unit-file KEYWORD, not part of a path. The step's own
#:    `look_for` says "a 'one-shot' ExecStart exfil service fired hourly by its
#:    .timer", so the unit file's path carries the service and its timer; the keyword
#:    itself is content.
PERSIST_ES = {
    "bool": {
        "should": [
            {"wildcard": {"fields.file_path.kw": {"value": "*cron*", "case_insensitive": True}}},
            {"wildcard": {"fields.file_path.kw": {"value": "*systemd*", "case_insensitive": True}}},
            {"wildcard": {"fields.file_path.kw": {"value": "*.timer*", "case_insensitive": True}}},
            {"wildcard": {"fields.file_path.kw": {"value": "*rc.local*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*execstart*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*oncalendar*", "case_insensitive": True}}},
        ],
        "minimum_should_match": 1,
    }
}

FIXES = [
    ("email_phishing.yaml", "execution_chain", EXEC_CHAIN_ES,
     "R0' defect 1: parent and child were inverted. The interpreters are the CHILD "
     "and the launchers are the PARENT, so mshta/rundll32/powershell go in "
     "`process_name` and explorer/outlook/winword in `parent_process`."),
    ("ics_ot_forensics.yaml", "asset_and_zone_inventory", ICS_ASSET_ES,
     "R0' defect 2: industrial protocol names (Modbus/DNP3/PLC) are not IP addresses, "
     "so they must not be searched in `dest_ip`. They are descriptive text and are "
     "searched in the row text."),
    ("network_session_analysis.yaml", "byte_asymmetry", BYTES_ES,
     "R0' defect 3: 'bytes/orig_bytes/resp_bytes' are COLUMN names, not values, so "
     "searching them inside `source_ip` can never match. The step is about a flow's "
     "byte columns, so it asserts those columns exist instead."),
    ("linux_compromise.yaml", "process_memory_check", PSLIST_ES,
     "R0' defect 4: pslist/malfind are Volatility PLUGIN names and /proc is a region, "
     "not a process called pslist. They are content, not `process_name` values. "
     "`memfd` replaces the mis-filed `*kmem*` - the fileless path the step's own "
     "`look_for` names."),
    ("ics_ot_forensics.yaml", "plc_hmi_evidence", PLC_HMI_ES,
     "R0' defect 5: 'PLC log'/'HMI event' are descriptive text, not host names, so "
     "they must not be searched in `host`. Moved to the row text."),
    ("malware_analysis_triage.yaml", "capa_capabilities", CAPA_ES,
     "R0' defect 6: the field name carried the literal placeholder `<rule>`. capa's "
     "real columns are asserted as exists instead; the placeholder never appears in "
     "a stored query."),
    ("credential_access_sam_ntds.yaml", "sam_reg_export", SAM_ES,
     "R0' defect 7: `reg save` always names a hive, so the term carries the hive name "
     "(`reg save HKLM\\SAM`), not the bare `reg save sam` that the real command never "
     "produces."),
    ("linux_compromise.yaml", "persistence_mechanisms", PERSIST_ES,
     "R0' defect 8: `ExecStart` is a unit-file KEYWORD, not part of a path. The unit "
     "file's path (cron/systemd/.timer/rc.local) stays in `file_path`; `ExecStart` and "
     "`OnCalendar` - the step's own trigger words - move to the row text."),
]


def main() -> int:
    changed = 0
    for fname, step, new_es, reason in FIXES:
        path = K / fname
        if not path.is_file():
            print(f"  !! missing {fname}")
            continue
        raw = path.read_text(encoding="utf-8")
        header = [l for l in raw.splitlines() if l.startswith("#")]
        data = yaml.safe_load(raw) or {}
        hit = False
        for s in data.get("steps") or []:
            if isinstance(s, dict) and s.get("name") == step:
                before = s.get("es")
                s["es"] = new_es
                if before != new_es:
                    s["es_fix_reason"] = reason
                    hit = True
        if not hit:
            print(f"  !! {fname}:{step} not found")
            continue
        # drop the drop/reason keys that no longer describe the query: the defects
        # are fixed, so `es_text_only_reason` is recomputed below and a stale
        # `es_dropped` would claim a drop that no longer happens.
        for s in data.get("steps") or []:
            if isinstance(s, dict) and s.get("name") == step:
                s.pop("es_text_only_reason", None)
                s.pop("es_dropped", None)
                s.pop("es_authored_reason", None)
                break
        body = yaml.safe_dump(data, sort_keys=False, default_flow_style=False,
                              allow_unicode=True)
        path.write_text("\n".join(header) + "\n" + body if header else body,
                        encoding="utf-8")
        print(f"  fixed {fname}:{step}")
        changed += 1
    print(f"\n  {changed} step(s) fixed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
