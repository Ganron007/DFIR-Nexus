"""TA-5.1 (design time): every family name a skill declares resolves through the one family registry.

`devtools/runbook/family_vocab.py` and the registry measured 20 declared names (2026-10-29) that are neither a
registry producer nor an evidence kind, all in `trigger.families` and `primary_families`: no matcher can ever match
them, so they declared evidence the skill could never be chosen by. Each one is renamed to the registry name of the
producer or kind that carries that evidence, or dropped, because the same skill already names that evidence or because
no producer in the product reads it. The reasons below are the plan; a drop that claims "the skill names X" is refused
when the skill does not. Nothing is added that the skill did not already declare.

    python devtools/knowledge/resolve_family_vocabulary.py            # show the plan
    python devtools/knowledge/resolve_family_vocabulary.py --write    # apply it
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
SKILLS = REPO / "src" / "nexus" / "data" / "knowledge" / "skills"

#: dead name -> (registry name, why that producer or kind carries the evidence the name meant)
RENAME: dict[str, tuple[str, str]] = {
    "dns": ("kind:network", "DNS records are network evidence (Zeek dns.log, Suricata dns, the capture's flows)"),
    "netstat": ("kind:network", "a connection table is network evidence (vol netscan, MemProcFS net.csv, Zeek conn)"),
    "apache": ("kind:weblogs", "ingest/linux/logs.py:71 parses Apache access and error logs (linux_log yields weblogs)"),
    "weblogs": ("kind:weblogs", "ingest/linux/logs.py:71 parses Apache access and error logs (linux_log yields weblogs)"),
    "linux": ("linux_log", "the Linux log importer's family (ingest/linux/logs.py:70)"),
}

#: dead name -> (the names one of which the skill must already declare, or () when no producer reads it; why)
DROP: dict[str, tuple[tuple[str, ...], str]] = {
    "security": (("evtx",), "an event-log channel; the skill names evtx, whose producers carry it"),
    "sysmon": (("evtx",), "an event-log channel; the skill names evtx, whose producers carry it"),
    "conn": (("zeek",), "Zeek's conn.log; the skill names zeek"),
    "headers": (("email",), "an email's headers; the skill names email"),
    "recent": (("lnk", "jumplist"), "the Recent folder's LNK files; the skill names lnk and jumplist"),
    "cmd": (("evtx", "prefetch", "powershell"), "cmd.exe use is read from process events; the skill names evtx, "
                                               "prefetch and powershell"),
    "ingest": (("vol", "kape"), "not an evidence family; the skill names vol and kape"),
    "iis": ((), "no importer or tool reads IIS logs (not exercised in v1)"),
    "firewall": ((), "no importer identifies firewall records; a firewall's syslog reaches the index as syslog rows"),
    "proxy": ((), "no importer reads proxy logs"),
    "sandbox": ((), "no importer reads sandbox reports; specimens are analysed in the specimen phase (OD-T4)"),
    # First applied as renames to generic_csv/generic_jsonl, which made any case holding generic CSV/JSONL rows
    # surface container_forensics and mobile_forensics (T18, T21; corrected 2026-10-29). Those producers are
    # containers (family_registry.yaml `container: true`): their name is no evidence.
    "csv": ((), "an output format, not evidence: scoring ignores format names (skills._NON_DISCRIMINATIVE_FAMILIES)"),
    "jsonl": ((), "an output format, not evidence: scoring ignores format names (skills._NON_DISCRIMINATIVE_FAMILIES)"),
}


def _lists(lines: list[str]) -> list[tuple[str, int, int, str]]:
    """(label, first item line, end line, item prefix) of `trigger.families` and `primary_families`."""
    found = []
    top = ""
    for i, line in enumerate(lines):
        stripped = line.rstrip("\r\n")
        if stripped and not stripped.startswith((" ", "-", "#")):
            top = stripped.split(":", 1)[0]
        if stripped == "  families:" and top == "trigger":
            prefix = "  - "
        elif stripped == "primary_families:":
            prefix = "- "
        else:
            continue
        end = i + 1
        while end < len(lines) and lines[end].startswith(prefix):
            end += 1
        found.append(("trigger.families" if prefix == "  - " else "primary_families", i + 1, end, prefix))
    return found


def plan_file(path: Path) -> tuple[list[str], list[str]]:
    """The file's new lines and the plan lines, or raise when a drop's claim does not hold."""
    raw = path.read_bytes().decode("utf-8")
    newline = "\r\n" if "\r\n" in raw else "\n"
    lines = raw.splitlines(keepends=True)
    doc = yaml.safe_load(raw) or {}
    declared = {str(f).lower() for f in ((doc.get("trigger") or {}).get("families") or [])}
    declared |= {str(f).lower() for f in (doc.get("primary_families") or [])}
    notes: list[str] = []
    for label, start, end, prefix in reversed(_lists(lines)):
        out: list[str] = []
        for line in lines[start:end]:
            name = line[len(prefix):].strip()
            low = name.lower()
            if low in RENAME:
                target, why = RENAME[low]
                notes.append(f"{doc.get('skill')}: {label} {name} -> {target} ({why})")
                name = target
            elif low in DROP:
                needs, why = DROP[low]
                if needs and not declared & set(needs):
                    raise SystemExit(f"{path.name}: dropping {name} needs one of {needs} in the skill; it has none")
                notes.append(f"{doc.get('skill')}: {label} drop {name} ({why})")
                continue
            entry = f"{prefix}{name}{newline}"
            if entry not in out:
                out.append(entry)
        lines[start:end] = out
    return lines, notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    total = 0
    for path in sorted(SKILLS.glob("*.yaml")):
        lines, notes = plan_file(path)
        if not notes:
            continue
        total += len(notes)
        for note in notes:
            print(note)
        if args.write:
            path.write_bytes("".join(lines).encode("utf-8"))
    print(f"{total} declarations {'changed' if args.write else 'to change'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
