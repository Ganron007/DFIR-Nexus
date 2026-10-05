"""WO-KL2e 2: declare `primary_families` for the skills whose SUBJECT is a family.

The reviewer's probes: CloudTrail-only -> the cloud skill; Zeek-only -> network;
`vol`-only -> memory; Amcache-only -> execution. One hit on a primary family must
surface the skill. The two-family rule stays for everything else, which is what keeps
an EVTX-only case from surfacing every USB/mobile/email skill.

The primary families are taken from the WO's own examples plus each skill's own
`trigger.families` - the evidence types the skill is ABOUT - never invented.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

K = Path(__file__).resolve().parents[2] / "src" / "nexus" / "data" / "knowledge" / "skills"

#: skill -> the families that ARE its subject. Source: the WO's own examples
#: (`cloud_identity_forensics`, `memory_process_analysis`, `network_session_analysis`)
#: and the Amcache/execution acceptance case.
PRIMARY: dict[str, list[str]] = {
    "cloud_identity_forensics": ["cloudtrail", "azure", "m365", "elastic", "splunk"],
    "network_session_analysis": ["zeek", "netstat", "wireshark", "tshark-flows",
                                 "nfdump"],
    "memory_process_analysis": ["vol", "volatility", "memory"],
    # Amcache is the execution-phase artifact: what ran, when, and from where. The
    # skill whose subject it is `execution_anomaly` ("suspicious parentage, unsigned
    # binaries, LOLBins"), whose trigger already lists it.
    "execution_anomaly": ["amcache"],
}


def main() -> int:
    changed = 0
    for skill, primaries in PRIMARY.items():
        path = K / f"{skill}.yaml"
        if not path.is_file():
            print(f"  !! {skill}.yaml missing")
            continue
        header = [l for l in path.read_text(encoding="utf-8").splitlines()
                  if l.startswith("#")]
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        # Only declare primaries the skill already tolerates, so the subject is
        # never invented: a family the trigger does not list stays out.
        declared = {str(f).lower() for f in ((data.get("trigger") or {}).get("families") or [])}
        from nexus.knowledge.skills import family_names
        wide: set[str] = set()
        for f in declared:
            wide |= family_names(f)
        keep = [p for p in primaries if p in declared or family_names(p) & wide]
        if not keep:
            print(f"  !! {skill}: none of {primaries} is in its trigger families")
            continue
        if data.get("primary_families") == keep:
            print(f"  =  {skill}: already {keep}")
            continue
        data["primary_families"] = keep
        body = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
        path.write_text(("\n".join(header) + "\n" + body) if header else body,
                        encoding="utf-8")
        print(f"  +  {skill}: primary_families={keep}")
        changed += 1
    print(f"\n  {changed} skill(s) declared primary_families")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
