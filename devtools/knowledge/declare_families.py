"""WO-KL2c (design time): declare the artifact families the skills already cover.

Diagnosis first: `derive_requires` reads `trigger.families`, and the skills name
*alias* families (`evtx`, `mft`, `registry`) while the case index reports *tool*
families (`evtxecmd`, `mftecmd-usn`, `sbecmd`). So a skill whose procedure already
reads shellbags was not offered for the `sbecmd` family, and the coverage table read
16 of 61 families when far more are genuinely covered.

This declares the registry family name on the skill that already analyses that
artifact. It adds **no new claim** - the skill's steps and citations are unchanged;
it is the family name of the data those steps read. A family with no skill that
genuinely analyses it is left uncovered and reported (WO-KL2c: "Any family left
uncovered gets an explicit 'no investigation knowledge yet' line").

Usage::

    python devtools/knowledge/declare_families.py            # show the plan
    python devtools/knowledge/declare_families.py --write    # apply it
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SKILLS = REPO / "src" / "nexus" / "data" / "knowledge" / "skills"

#: skill -> the registry families its procedure already reads. Each entry is
#: justified by the artifact the skill's own steps pivot on.
PLAN: dict[str, list[str]] = {
    # EVTX rule engines run over the same event-log rows these skills analyse.
    "windows_event_log_analysis": ["deepbluecli", "zircolite"],
    # Shellbags (BagMRU/BagMRU) are a registry artifact.
    "registry_artifact_analysis": ["sbecmd"],
    # Chrome history (Hindsight) and SQLite browser databases are browser artifacts.
    "browser_artifact_analysis": ["hindsight", "sqlecmd", "thumbcache"],
    # $I30 index records and the USN journal are the same NTFS file-activity data.
    "mft_file_activity": ["mftecmd-i30", "mftecmd-usn"],
    # `mactime` renders the bodyfile the timeline skill already builds.
    "timeline_construction": ["mactime"],
    # NetFlow (`nfdump`) and tshark flow exports are the same session data.
    "network_session_analysis": ["nfdump", "tshark-flows"],
    # Scanning/marking a sample: capabilities, entropy, rules.
    "malware_analysis_triage": ["capa", "densityscout", "yara"],
    # USB device history.
    "usb_device_intrusion": ["usbdeview"],
}

#: Deliberately NOT declared. `logfileparser` is a generic log parser with no
#: artefact-specific skill to attach it to, so it stays uncovered and visible.
UNCOVERED = {"logfileparser": "generic log parser; no skill analyses the family itself"}


def _insert(path: Path, families: list[str]) -> tuple[bool, list[str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    try:
        trig = next(i for i, line in enumerate(lines) if re.match(r"^trigger:\s*$", line))
    except StopIteration:
        return False, ["no `trigger:` block"]
    fam = None
    for i in range(trig + 1, min(trig + 6, len(lines))):
        if re.match(r"^\s+families:\s*$", lines[i]):
            fam = i
            break
    if fam is None:
        return False, ["no `families:` under trigger"]
    end = fam + 1
    while end < len(lines) and re.match(r"^\s+-\s*\S", lines[end]):
        end += 1
    existing = {re.sub(r"^\s+-\s*", "", line).strip() for line in lines[fam + 1:end]}
    added = [f for f in families if f not in existing]
    if not added:
        return False, []
    # Match the indent of the items already in the list. Getting this wrong turns
    # the whole list into one folded scalar (`'sysmon - deepbluecli - zircolite'`)
    # rather than a YAML error, so it must come from the file, not from a constant.
    indent = "  "
    if end > fam + 1:
        m = re.match(r"^(\s+)-", lines[fam + 1])
        if m:
            indent = m.group(1)
    lines[end:end] = [f"{indent}- {f}" for f in added]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True, added


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)

    total = 0
    for skill, families in PLAN.items():
        path = SKILLS / f"{skill}.yaml"
        if not path.is_file():
            print(f"  MISSING {skill}.yaml")
            continue
        if args.write:
            changed, added = _insert(path, families)
            print(f"  {skill:32s} {'+ ' + ', '.join(added) if changed else '(already declared)'}")
            total += len(added)
        else:
            print(f"  {skill:32s} -> {', '.join(families)}")
    if args.write:
        print(f"\n  added {total} family declaration(s)")
    print()
    for fam, why in UNCOVERED.items():
        print(f"  left uncovered: {fam} - {why}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
