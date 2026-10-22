"""D199: every playbook declares its evidence families, derived from what its own text names (2026-10-18).

21 of the 26 playbooks declared no `families`, so Mode 1 selected them by a family word anywhere in their text
(`query_pack._family_matched_playbooks`), and a generic word selected loosely: Web Shell for a browser-history case.

Nothing here is typed per playbook. The family vocabulary is the product's own: the folders the lane writes tool
output to (`tool_lane.py`, `network_lane.py`; staging folders excluded) and the importers' sources
(`ArtifactSource`). A playbook's families are:
* every tool it names, as a word (a tool's family is its output folder, as the lane schedules it); a family's own
  name is not read, since many are ordinary words (history, email, usb, tasks);
* every artifact it names (an artifact file's `name` under `src/nexus/data/knowledge/artifacts/`, singular or
  plural): the families of that artifact's `related_tools`;
* the families of the event-log artifacts' tools, when it names event logs (EVTX, an event log, an event ID).
A tool the lane does not run (grep, strings) gives no family. Steps of a Correlate or Document phase are not read:
they name what the evidence is checked against, not the evidence the playbook investigates.

    python devtools/knowledge/declare_playbook_families.py          (dry run: the table, for review)
    python devtools/knowledge/declare_playbook_families.py --write  (adds `families:` to the playbooks without it)
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
ARTIFACTS = REPO / "src" / "nexus" / "data" / "knowledge" / "artifacts"
PLAYBOOKS = REPO / "src" / "nexus" / "data" / "knowledge" / "discipline" / "playbooks"
LANE = REPO / "src" / "nexus" / "langgraph"
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_FOLDER = re.compile(r'(?:out_dir\(|extractions / |app_root / )"([a-z0-9_\-]+)"')
_NOT_ITS_EVIDENCE = {"correlate", "document", "report", "recommend"}
_EVENT_LOGS = re.compile(r"(?<![a-z0-9])(?:evtx|event logs?|event ids?|eid \d{3,4}|security log|4[0-9]{3})(?![a-z0-9])")


def lane_families() -> tuple[set[str], dict[str, str]]:
    """(every family the lane writes, {tool key: its family}) from the lane's own code.

    A tool the lane runs for more than one artifact (`strings` over the WMI repository and other blobs) is a helper,
    not a family of its own, and is left out.
    """
    families: set[str] = set()
    seen: dict[str, set[str]] = {}
    for src in (LANE / "tool_lane.py", LANE / "network_lane.py"):
        text = src.read_text(encoding="utf-8")
        folders = [(m.start(), m.group(1)) for m in _FOLDER.finditer(text)
                   if not m.group(1).startswith(("_", "stage"))]
        families.update(f for _pos, f in folders)
        for m in re.finditer(r'\b(?:add|add_installed|present_tool)\(\s*"([a-z0-9_\-]+)"', text):
            near = [f for pos, f in folders if pos < m.start() and m.start() - pos < 1500]
            if near:
                seen.setdefault(m.group(1), set()).add(near[-1])
    tool_family = {tool: next(iter(fams)) for tool, fams in seen.items() if len(fams) == 1}
    return families, tool_family


def catalog_tools() -> set[str]:
    """The tool catalog's names (`src/nexus/data/knowledge/tools/**/*.yaml`), lower case: Zeek, tshark, ..."""
    names = set()
    for f in (REPO / "src" / "nexus" / "data" / "knowledge" / "tools").rglob("*.yaml"):
        doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        if doc.get("name"):
            names.add(str(doc["name"]).strip().lower())
    return names


def vocabulary() -> tuple[set[str], dict[str, str]]:
    from nexus.ingest.schemas import ArtifactSource

    families, tool_family = lane_families()
    families |= {s.value for s in ArtifactSource if s.value not in ("unknown", "generic_csv", "generic_jsonl")}
    # The index's own families as the ECS map names them (the tshark flow projection is `network`).
    ecs_map = yaml.safe_load((REPO / "src" / "nexus" / "data" / "schema" / "ecs_map.yaml").read_text(encoding="utf-8"))
    families |= {str(f) for f in (ecs_map.get("family_columns") or {}) if f != "ingest"}
    # A catalogued tool whose name is a family (Zeek -> zeek) is that family.
    for name in catalog_tools():
        if name in families and name not in tool_family:
            tool_family[name] = name
    return families, tool_family


def family_of(tool: str, families: set[str], tool_family: dict[str, str]) -> str:
    key = tool.lower()
    if key in tool_family:
        return tool_family[key]
    return key if key in families else ""


def artifacts() -> list[tuple[str, list[str]]]:
    out = []
    for f in sorted(ARTIFACTS.rglob("*.yaml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        if doc.get("name"):
            out.append((str(doc["name"]).strip(), [str(t) for t in doc.get("related_tools") or []]))
    return out


def _word(term: str) -> re.Pattern[str]:
    low = re.escape(term.lower()).replace(r"\ ", r"\s+")
    alts = [low] + ([low[:-1]] if low.endswith("s") else [])
    return re.compile(rf"(?<![a-z0-9])(?:{'|'.join(alts)})(?![a-z0-9])")


def playbook_text(doc: dict) -> str:
    parts = [str(doc.get("name") or ""), str(doc.get("description") or "")]
    for key in ("triggers", "caveats", "query_terms", "query_terms_strong"):
        parts.extend(str(x) for x in doc.get(key) or [])
    for phase in doc.get("phases") or []:
        if isinstance(phase, dict) and str(phase.get("phase") or "").strip().lower() not in _NOT_ITS_EVIDENCE:
            parts.extend(str(s) for s in phase.get("steps") or [])
    return "\n".join(parts).lower()


#: Playbooks whose evidence steps name their evidence in words no artifact file or tool carries. Each family is
#: justified by the playbook's own step, quoted; the script refuses a quote the playbook does not contain, so no
#: family is invented (the precedent: `declare_families.py`, "each entry is justified by the artifact the skill's own
#: steps pivot on"). Families: the lane's folders and the importers' sources (`email` is the mail wrapper's output;
#: `azure` the M365 and Azure importers' source).
JUSTIFIED: dict[str, list[tuple[str, str]]] = {
    "c2_beacon": [("zeek", "Histogram outbound connection intervals per destination"),
                  ("suricata", "Histogram outbound connection intervals per destination"),
                  ("network", "Histogram outbound connection intervals per destination")],
    "webshell": [("mftecmd", "Find script files written to the web root and their creation time"),
                 ("evtxecmd", "Look for w3wp.exe -> cmd.exe/powershell.exe process chains"),
                 ("hayabusa", "Look for w3wp.exe -> cmd.exe/powershell.exe process chains"),
                 ("chainsaw", "Look for w3wp.exe -> cmd.exe/powershell.exe process chains")],
    "phishing_analysis": [("email", "Preserve the full .eml/.msg with headers")],
    "ransomware_impact": [("mftecmd", "Look for ransom notes (README/DECRYPT/RESTORE) and renamed extensions"),
                          ("evtxecmd", "Check for vssadmin/wmic shadow copy deletion"),
                          ("hayabusa", "Check for vssadmin/wmic shadow copy deletion"),
                          ("chainsaw", "Check for vssadmin/wmic shadow copy deletion")],
    "linux_forensics": [("authlog", "Review auth.log/secure for accepted/failed password"),
                        ("syslog", "syslog/messages"),
                        ("plaso", "Super-timeline with Plaso"),
                        ("volatility", "Volatility Linux requires a kernel")],
    "email_compromise": [("email", "Review sent items for phishing emails or fraudulent messages"),
                         ("azure", "Check mailbox rules for forwarding rules")],
}


def derive(doc: dict, arts: list[tuple[str, list[str]]], families: set[str],
           tool_family: dict[str, str], slug: str = "") -> dict[str, list[str]]:
    """{family: [what in the playbook named it]}."""
    text = playbook_text(doc)
    found: dict[str, list[str]] = {}
    for fam, quote in JUSTIFIED.get(slug, []):
        if quote.lower() not in text:
            raise SystemExit(f"{slug}: the quoted step is not in the playbook: {quote!r}")
        if fam not in families:
            raise SystemExit(f"{slug}: {fam!r} is no family the lane or an importer writes")
        found.setdefault(fam, []).append(f"step \"{quote}\"")

    def add(tool: str, why: str) -> None:
        fam = family_of(tool, families, tool_family)
        if fam:
            found.setdefault(fam, []).append(why)

    for name, tools in arts:
        if _word(name).search(text):
            for tool in tools:
                add(tool, f"artifact {name} ({tool})")
    for term in sorted({t for _n, ts in arts for t in ts} | set(tool_family)):
        if len(term) > 2 and _word(term).search(text):
            add(term, f"names {term}")
    if _EVENT_LOGS.search(text):
        # The families the lane writes from event logs, read from its own scheduling: the artifact files also list
        # Suzaku, which the lane runs on cloud logs only (Suzaku 2.x has no EVTX timeline).
        for fam in evtx_families():
            found.setdefault(fam, []).append("event logs")
    return found


def evtx_families() -> list[str]:
    """The output folders `tool_lane.schedule_evtx_parsers` writes: the event-log families."""
    text = (LANE / "tool_lane.py").read_text(encoding="utf-8")
    start = text.index("def schedule_evtx_parsers(")
    end = text.index("\ndef ", start + 1)
    return sorted({m.group(1) for m in _FOLDER.finditer(text[start:end]) if not m.group(1).startswith(("_", "stage"))})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    families, tool_family = vocabulary()
    arts = artifacts()
    for f in sorted(PLAYBOOKS.glob("*.yaml")):
        raw = f.read_text(encoding="utf-8")
        doc = yaml.safe_load(raw) or {}
        if doc.get("families"):
            print(f"  =  {f.stem}: declares {doc['families']}")
            continue
        found = derive(doc, arts, families, tool_family, f.stem)
        fams = sorted(found)
        print(f"  {'+' if fams else '!!'} {f.stem}: {fams}")
        for fam in fams:
            print(f"        {fam}: {'; '.join(sorted(set(found[fam])))[:150]}")
        if args.write and fams:
            note = "; ".join(f"{fam} <- {sorted(set(found[fam]))[0]}" for fam in fams)
            newline = "\r\n" if "\r\n" in raw else "\n"
            block = (f"# D199: derived from what this playbook names (devtools/knowledge/"
                     f"declare_playbook_families.py): {note}{newline}families: [{', '.join(fams)}]{newline}")
            f.write_bytes((raw.rstrip("\r\n") + newline + block).encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
