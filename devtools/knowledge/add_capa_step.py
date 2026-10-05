"""WO-KL2c: add the `capa` investigation step, cited to real KB chunks.

`capa` was the one genuine knowledge gap: `malware_analysis_triage` had
`static_indicators` (entropy/packing) and `yara_and_memory_scan` (rules), but no step
that reads what capa produces - the capabilities a binary declares, mapped to ATT&CK
and MBC. That is the strongest behavioural-intent signal in the malware leg.

The step is authored here, not typed from memory: its two citations are real chunks
in the local KB (`G:\\doc_extract`), found with `kb find "capa"`:
  d_0d452e595fff:c0091  Defensive Security ... Live Forensics 2024  (using `capa -r` to
                        see `what binary is doing`)
  d_8beaf108808f:c0075  Evasive Malware (Kyle)  (anti-VM instructions identified by CAPA)
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))

SKILL = REPO / "src" / "nexus" / "data" / "knowledge" / "skills" / "malware_analysis_triage.yaml"

SOURCES = [
    {
        "chunk_id": "d_0d452e595fff:c0091",
        "rel_path": "EBOOKS/eBooks/Defensive_Security_Linux_Attack,_Detection_and_Live_Forensics_2024.md",
        "lines": "3543-3596",
        "citation": "d_0d452e595fff:c0091",
    },
    {
        "chunk_id": "d_8beaf108808f:c0075",
        "rel_path": "EBOOKS/NoStarchPress/Evasive_malware_-_Kyle/Evasive_malware_-_Kyle.md",
        "lines": "2667-2700",
        "citation": "d_8beaf108808f:c0075",
    },
]

STEP = {
    "name": "capa_capabilities",
    "look_for": (
        "capa's capability set, read from its JSON/flavor output: the rule names it fired "
        "(rules.<rule>.meta.name) and their ATT&CK/MBC mappings. The high-signal families "
        "are behavioural-intent claims - process injection, credential access, anti-VM and "
        "anti-analysis (the Evasive Malware case names an anti-VM CPUID instruction CAPA "
        "identified), encoded/obfuscated content, and persistence. A capability is what the "
        "binary CAN do: it is the strongest static intent evidence, but it is not proof the "
        "code path ran."
    ),
    "corroborate": (
        "Pair each capability with observed execution before calling it behaviour: prefetch "
        "and ShimCache for that it ran, EVTX/4688 or Sysmon 1 for the command line, and "
        "memory for injected code. A capability with no observation is a capability, not an "
        "attack - and a binary whose capabilities are all benign (signed installer, updater) "
        "is the benign alternative to state."
    ),
    "query": "capa capability OR attack OR mbc",
    "pivot": "rules.<rule>.meta.attack",
    "requires": {"families": ["capa"]},
    "es": {
        "bool": {
            "should": [
                {"exists": {"field": "fields.rules.<rule>.meta.attack.kw"}},
                {"exists": {"field": "fields.rules.<rule>.meta.mbc.kw"}},
                {"exists": {"field": "fields.rules.<rule>.meta.name.kw"}},
            ],
            "minimum_should_match": 1,
        }
    },
}


def main() -> int:
    raw = SKILL.read_text(encoding="utf-8")
    header = []
    for line in raw.splitlines():
        if line.startswith("#"):
            header.append(line)
        elif line.strip():
            break
    data = yaml.safe_load(raw) or {}

    steps = data.get("steps") or []
    names = {str(s.get("name")) for s in steps if isinstance(s, dict)}
    if STEP["name"] in names:
        print("  step already present; nothing to do")
        return 0

    # Insert after `static_indicators` - capa belongs with the static pass.
    at = next((i for i, s in enumerate(steps)
               if isinstance(s, dict) and s.get("name") == "static_indicators"), len(steps) - 1)
    steps.insert(at + 1, STEP)
    data["steps"] = steps

    sources = data.get("source") or []
    have = {str(s.get("chunk_id")) for s in sources if isinstance(s, dict)}
    for src in SOURCES:
        if src["chunk_id"] not in have:
            sources.append(src)
    data["source"] = sources

    # The trigger must name the family, or `derive_requires` never offers it.
    trig = data.setdefault("trigger", {})
    fams = trig.get("families") or []
    if "capa" not in fams:
        fams.append("capa")
    trig["families"] = fams

    body = yaml.dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)
    SKILL.write_text("\n".join(header) + "\n" + body if header else body, encoding="utf-8")
    print(f"  added step '{STEP['name']}' and {len(SOURCES)} citation(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
