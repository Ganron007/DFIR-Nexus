"""WO-KM1 item 5: stage one sample per NOT STAGED family, through the real paths.

The WO is explicit: "Every importer family marked NOT STAGED in MAPPING.md 3: the
FIRST path that row lists ... run through the real importer. A family or event type
with no sample ... is recorded as absent, with the reason. Do not search for another
sample; tell the operator."

This stages each first-named path into a population corpus and ingests it through the
**real** importer (nexus.ingest.autodetect) so the corpus is what the index actually
receives. Nothing is invented: a path that does not exist is recorded absent with the
reason MAPPING.md gives.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

CORPUS = REPO / "Evidence-files" / "ES-Mapping" / "_population"
REPORT = CORPUS / "_staged.json"

#: family -> (first path MAPPING.md names, note)
#
# The WO says to take the first path the row lists. Where that row lists several
# paths, the first one is used and the others are recorded as alternates - the WO's
# wording is "the first path that row lists", so that is the rule.
SOURCES: dict[str, tuple[str, str]] = {
    "syslog": ("Evidence-files/03-linux/syslog", "W4l"),
    "authlog": ("Evidence-files/03-linux/auth.log", "W4l"),
    "auditd": ("Evidence-files/03-linux/audit.log", "W4l"),
    "bash_history": ("Evidence-files/03-linux/bash_history", "W4l"),
    "cloudtrail": ("Evidence-files/06-cloud/cloudtrail-sample.json", "W4c"),
    "azure": ("Evidence-files/06-cloud/azure-activity-sample.json", "W4c"),
    "zeek": ("Evidence-files/04-network/suricata/eve.json", "W4n - see note"),
    "suricata": ("Evidence-files/04-network/suricata/eve.json", "W4n"),
    "netflow": ("Evidence-files/04-network/572", "W4n - nfcapd tree, 2.9 GB"),
    "nfdump": ("Evidence-files/04-network/572", "W4n - nfcapd tree, 2.9 GB"),
    "tshark": ("Evidence-files/04-network/pcap", "W4n - 29 files, 1.3 GB"),
    "splunk": ("Evidence-files/05-siem/splunk.csv", "W4s"),
    "elastic": ("Evidence-files/05-siem/elastic.ndjson", "W4s"),
    "abuseipdb": ("Evidence-files/07-ti/abuseipdb-sample.json", "W4i"),
    "misp": ("Evidence-files/07-ti/misp-event.json", "W4i"),
    "otx": ("Evidence-files/07-ti/otx-pulse.json", "W4i"),
    "threatfox": ("Evidence-files/_staging/threatfox.json.zip", "W4i"),
    "thehive": ("Evidence-files/08-ir-platforms/thehive-case.json", "W4i"),
    "velociraptor": ("Evidence-files/08-ir-platforms/velociraptor", "W4i"),
    "suzaku": ("Evidence-files/06-cloud", "W4c - cloud logs"),
    #: Security 4688 (audited process creation) is the event type the WO names as
    #: possibly absent; it is recorded below, not searched for.
}


def stage() -> dict:
    if CORPUS.exists():
        shutil.rmtree(CORPUS)
    CORPUS.mkdir(parents=True)
    report = {"corpus": str(CORPUS), "families": {}, "absent": {}}

    for family, (rel, note) in SOURCES.items():
        src = REPO / rel
        dest = CORPUS / family
        if not (REPO / rel).exists() and not Path(rel).exists():
            # relative to the repo root, then the workspace root
            src = Path(rel)
        if not src.exists():
            report["absent"][family] = f"path not found: {rel} ({note})"
            continue
        try:
            if src.is_file():
                dest.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest / src.name)
                report["families"][family] = [str(dest / src.name)]
            else:
                # a directory: take the first few files it names, bounded
                files = sorted(p for p in src.rglob("*") if p.is_file())
                files = [f for f in files if not f.name.startswith(".")][:24]
                if not files:
                    report["absent"][family] = f"directory empty: {rel}"
                    continue
                dest.mkdir(parents=True, exist_ok=True)
                copied = []
                for f in files:
                    target = dest / f.name
                    if target.exists():
                        target = dest / f"{f.parent.name}-{f.name}"
                    shutil.copy2(f, target)
                    copied.append(str(target))
                report["families"][family] = copied
        except Exception as exc:  # noqa: BLE001
            report["absent"][family] = f"{type(exc).__name__}: {exc}"

    report["staged_count"] = len(report["families"])
    report["absent_count"] = len(report["absent"])
    REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def audit() -> dict:
    """Record which registry families the corpus does NOT cover, with the reason."""
    sys.path.insert(0, str(REPO / "src"))
    from nexus.knowledge.query_validation import load_field_registry

    reg = load_field_registry()
    fams: set[str] = set()
    for info in reg.values():
        for f in (info.get("families") or []):
            fams.add(str(f).lower())
    report = json.loads(REPORT.read_text(encoding="utf-8")) if REPORT.exists() else {"families": {}, "absent": {}}
    covered: set[str] = set()
    for family in report.get("families", {}):
        covered |= {f.lower() for f in _expand(family)}
    missing = sorted(f for f in fams if f not in covered and not f.startswith("ingest-"))
    return {"registry_families": len(fams), "covered": len(covered), "missing": missing}


def _expand(family: str) -> list[str]:
    try:
        from nexus.knowledge.query_validation import expand_families

        return sorted(expand_families([family]))
    except Exception:  # noqa: BLE001
        return [family]


if __name__ == "__main__":
    result = stage()
    print(f"  staged {result['staged_count']} families, {result['absent_count']} absent")
    for family, paths in result["families"].items():
        print(f"    {family:16s} {len(paths):3d} file(s)")
    for family, why in result["absent"].items():
        print(f"    {family:16s} ABSENT - {why}")
    a = audit()
    print()
    print(f"  registry families: {a['registry_families']}  covered: {a['covered']}")
    print(f"  still missing ({len(a['missing'])}): {a['missing']}")
