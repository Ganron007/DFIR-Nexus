"""Import the event-to-category table from pinned pySigma pipelines (operator decision 2026-10-12).

The pipelines map generic Sigma log-source categories (``process_creation``,
``network_connection``, ``registry_set`` ...) to the Windows event ids they mean, per Sigma
service. This script reads those mappings from the two pinned wheels in
``devtools/knowledge/pinned/`` and writes ``src/nexus/data/schema/event_categories.yaml``: one
entry per (provider, event id), with the category name the pipeline uses and the package it
came from.

The wheels are read as data. Each module is parsed with ``ast`` and only its literal
assignments are evaluated; nothing from the package is imported or run. Each wheel's SHA-256
is checked against the value reviewed here before it is read.

A second source is the Elastic Windows Security ingest pipeline (Elastic License 2.0), which
gives the logon categories the pySigma pipelines do not. Its raw YAML is never committed: ``--fetch``
caches it, gitignored, from the pinned commit, and only the rows in scope (``ELASTIC_CATEGORIES``
and ``ELASTIC_EXTRA_IDS``) reach the table.

Usage::

    python devtools/knowledge/import_event_categories.py --fetch  # cache the pinned Elastic pipeline
    python devtools/knowledge/import_event_categories.py          # write the table
    python devtools/knowledge/import_event_categories.py --check  # fail if the table is stale
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
PINNED = REPO / "devtools" / "knowledge" / "pinned"
OUT = REPO / "src" / "nexus" / "data" / "schema" / "event_categories.yaml"
CACHE = PINNED / "cache" / "security_standard-59aa0e9.yml"

#: The pinned packages: exact version, the wheel file, and the SHA-256 of that wheel as reviewed.
SOURCES = (
    {
        "package": "pysigma-pipeline-windows",
        "version": "2.0.1",
        "wheel": "pysigma_pipeline_windows-2.0.1-py3-none-any.whl",
        "sha256": "f62d1d5be64379dcb1584ea89cf3765732a25470b249f7ffac1fb9e2e2e19d80",
        "module": "sigma/pipelines/windows/windows.py",
    },
    {
        "package": "pysigma-pipeline-sysmon",
        "version": "2.0.0",
        "wheel": "pysigma_pipeline_sysmon-2.0.0-py3-none-any.whl",
        "sha256": "84575bbde5dd891882306ca1f6ce16bdc592da2e511ac8960012af2efb9d120b",
        "module": "sigma/pipelines/sysmon/sysmon.py",
    },
)

#: The provider each pipeline service's events carry in ``ecs.event.provider``. The Windows
#: pipeline names a channel by its service; these are the provider names the case index holds
#: (tests/test_event_categories.py checks them against real rows when Elasticsearch is up).
SERVICE_PROVIDER = {
    "security": "Microsoft-Windows-Security-Auditing",
    "powershell": "Microsoft-Windows-PowerShell",
    "powershell-classic": "PowerShell",
    "sysmon": "Microsoft-Windows-Sysmon",
}

#: The Elastic pipeline for Windows Security events, pinned to a commit. It is ELv2-licensed: the
#: raw file is cached (gitignored) and is not part of the repository; only derived rows are.
ELASTIC = {
    "package": "elastic-integrations-windows-security",
    "version": "59aa0e9",
    "commit": "59aa0e901d5683cb933859bb21bf4da590400e94",
    "path": "packages/windows/data_stream/forwarded/elasticsearch/ingest_pipeline/security_standard.yml",
    "sha256": "4c9aef7c941fde2b684e0db6442972545600d6a9e35b524d04bd7d0ff40f7831",
    "licence": "Elastic-2.0",
    "url": ("https://raw.githubusercontent.com/elastic/integrations/"
            "59aa0e901d5683cb933859bb21bf4da590400e94/packages/windows/data_stream/forwarded/"
            "elasticsearch/ingest_pipeline/security_standard.yml"),
}

#: The Elastic scope (operator decision 2026-10-12): every Security event the pipeline files under
#: the authentication category (12 ids), and 4672 (special privileges assigned to a new logon), the
#: one logon-time event in its iam category. The rest of iam is account management: not in scope.
ELASTIC_CATEGORIES = frozenset({"authentication"})
ELASTIC_EXTRA_IDS = frozenset({"4672"})

#: Windows' own provider manifests (D95, operator 2026-10-15), for the channels no pipeline above
#: categorises: WinRM (remote sessions, lateral movement) and Task Scheduler (persistence). Exported
#: on Windows 11 25H2 build 26200.9711 with ``wevtutil gp <provider> /ge /gm:true /f:xml`` and pinned
#: in ``pinned/manifests/``. The manifest is the authority for what each event is.
MANIFEST_BUILD = "10.0.26200.9711"
MANIFESTS = (
    {"provider": "Microsoft-Windows-WinRM", "file": "manifests/Microsoft-Windows-WinRM.xml",
     "sha256": "29ba1637e2e9cc3084627d054192888b23b9f8f85bcd2ef0b8929ae5eab8d4a6", "encoding": "utf-8"},
    {"provider": "Microsoft-Windows-TaskScheduler", "file": "manifests/Microsoft-Windows-TaskScheduler.xml",
     "sha256": "ac59aa58adced97397db925a333763b979a7f03a0c816e744605a27366d5b417", "encoding": "utf-8"},
    # D232 (operator 2026-10-16): Defender's detections and its protection settings.
    {"provider": "Microsoft-Windows-Windows Defender", "file": "manifests/Microsoft-Windows-Windows Defender.xml",
     "sha256": "8b5821ecbc447f3116b36accc5e78ee9ef8acc94ab334441fdcf767588248c7e", "encoding": "utf-8"},
    # D232: which provider logs each PowerShell and Security event, for a row that names only its channel
    # (Hayabusa's timeline). Their categories come from the pipelines above. Security-Auditing is kept as
    # wevtutil wrote it with /uni:true: its plain export is in the console's code page, not the UTF-8 it
    # declares.
    {"provider": "Microsoft-Windows-PowerShell", "file": "manifests/Microsoft-Windows-PowerShell.xml",
     "sha256": "573adc637f8a15dade1789104070f601db2a3e796d1377b21abf544cf84664d6", "encoding": "utf-8"},
    {"provider": "Microsoft-Windows-Security-Auditing", "file": "manifests/Microsoft-Windows-Security-Auditing.xml",
     "sha256": "f05d09902542c7feba4e410411e3df57297214beec763aa1e402edcb20570f9d", "encoding": "utf-16",
     "unicode": True},
    # D474 (2026-10-30): the channel each Sysmon event is logged to, for a row that names only its provider
    # (Chainsaw's hunt rows). Sysmon is not part of Windows: its manifest is Sysinternals Sysmon 15.15's own
    # (Sysmon64.exe), exported on build 10.0.26300 with the same command. Its categories come from the pipelines.
    {"provider": "Microsoft-Windows-Sysmon", "file": "manifests/Microsoft-Windows-Sysmon.xml",
     "sha256": "3e759e31e01f9a3a362a5ef0944171af0e0d3709343ebb4fcd5d8dde4f7d575f", "encoding": "utf-8",
     "version": "Sysmon 15.15"},
)

#: WinRM, event by event: its tasks mix sessions with protocol plumbing ("Request handling" also holds
#: SOAP chunk and quota events), so a task-wide rule would call plumbing a session. Each id names the
#: manifest task it must carry. Precedent for what gets a category: Graylog's WinRM content pack
#: (Illuminate 7.1: 6/80 outbound and 91 inbound sessions, authentication and authorization events;
#: operation events 132/145 left out) and JPCERT/CC, "Detecting Lateral Movement through Tracking Event
#: Logs" (2017: 6 on the source host, 91 on the destination). Where Graylog and the manifest disagree
#: (192 is an authorization failure, 1291 an AutoLogon policy note), the manifest wins.
WINRM_EVENTS = {
    # The client opens a session to a remote host ("Creating WSMan Session. The connection string is").
    "network_connection": {"WSMan Session initialize": (6, 7, 31)},
    # The server takes a remote request: a shell created for it, a host process started for its user.
    "remote_session": {"Request handling": (91, 785, 786)},
    # Credentials accepted or refused, and the authorization of the authenticated user.
    "authentication": {"User authentication": (161, 162, 164, 171, 172, 173, 1295, 1296, 1843),
                       "User authorization": (192, 193, 1537)},
}

#: Task Scheduler by manifest task: registration changes the persistence, a run executes it.
TASK_SCHEDULER_TASKS = {
    "scheduled_task_change": ("Task registered", "Task registration updated", "Task registration deleted",
                              "Task disabled", "Task registered without some triggers",
                              "Task registered without credentials"),
    "scheduled_task_run": ("Task Started", "Task completed", "Task terminated", "Created Task Process",
                           "Action started", "Action completed", "Action failed", "Action failed to start"),
}

#: Defender, event by event (D232): its manifest declares no tasks, so each id names a phrase its own
#: message must hold. The categories are ECS's: `malware` (malware detection events and alerts) and
#: `configuration` (creating, modifying or deleting the settings of an application or system). Scans,
#: health reports and updates stay uncategorised.
DEFENDER_EVENTS = {
    "malware": {
        "has detected malware or other potentially unwanted software": (1006, 1116),
        "has detected malware or potentially unwanted software using defender security intelligence": (1007, 1117),
        "error when taking action on malware or other potentially unwanted software": (1008, 1118, 1119),
        "has detected a suspicious behavior": (1015,),
        "has detected potentially unwanted application": (1160,),
    },
    "configuration": {
        "real-time protection scanning for malware and other potentially unwanted software was": (5000, 5001),
        "real-time protection feature configuration has changed": (5004,),
        "configuration has changed": (5007,),
        "scanning for spyware and other potentially unwanted software": (5009, 5010),
        "scanning for viruses": (5011, 5012),
        "tamper protection": (5013,),
    },
}


def _manifest_events(entry: dict[str, Any]) -> dict[int, dict[str, str]]:
    """The manifest's events after its SHA-256 check: id -> its task name, message and channel."""
    import xml.etree.ElementTree as ET

    path = PINNED / entry["file"]
    if not path.is_file():
        raise SystemExit(f"pinned manifest missing: {path}")
    data = path.read_bytes()
    if _sha256(data) != entry["sha256"]:
        raise SystemExit(f"{entry['file']}: SHA-256 differs from the reviewed value")
    # Parsed from bytes, so the XML declaration's own encoding is the one used.
    root = ET.fromstring(data)

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    def text(value: str | None) -> str:
        return " ".join((value or "").split())

    tasks = {el.get("value"): text(el.get("message")) for el in root.iter() if local(el.tag) == "task"}
    channels = {el.get("id"): el.get("name") or "" for el in root.iter() if local(el.tag) == "channel"}
    events: dict[int, dict[str, str]] = {}
    for el in root.iter():
        if local(el.tag) == "event" and el.get("value", "").isdigit():
            events.setdefault(int(el.get("value")), {
                "task": tasks.get(el.get("task") or "", ""),
                "message": text(el.get("message")),
                "channel": channels.get(el.get("channel") or "", ""),
            })
    return events


def _manifest(entry: dict[str, Any]) -> tuple[dict[int, str], str]:
    """The manifest's event id -> task name, after its SHA-256 check, and the file's hash."""
    return {eid: ev["task"] for eid, ev in _manifest_events(entry).items()}, entry["sha256"]


def _manifest_rows() -> list[tuple[str, int, str]]:
    """(provider, event id, category) from the pinned manifests, every rule checked against them."""
    rows: list[tuple[str, int, str]] = []
    for entry in MANIFESTS:
        events, _ = _manifest(entry)
        provider = entry["provider"]
        if provider == "Microsoft-Windows-WinRM":
            for category, by_task in WINRM_EVENTS.items():
                for task, ids in by_task.items():
                    for eid in ids:
                        if events.get(eid) != task:
                            raise SystemExit(f"{provider} {eid}: manifest task is {events.get(eid)!r}, "
                                             f"the rule expects {task!r}")
                        rows.append((provider, eid, category))
        elif provider == "Microsoft-Windows-TaskScheduler":
            for category, tasks in TASK_SCHEDULER_TASKS.items():
                missing = [t for t in tasks if t not in events.values()]
                if missing:
                    raise SystemExit(f"{provider}: no manifest task named {missing}")
                rows += [(provider, eid, category) for eid, task in sorted(events.items()) if task in tasks]
        elif provider == "Microsoft-Windows-Windows Defender":
            messages = {eid: ev["message"].lower() for eid, ev in _manifest_events(entry).items()}
            for category, by_phrase in DEFENDER_EVENTS.items():
                for phrase, ids in by_phrase.items():
                    for eid in ids:
                        if phrase not in messages.get(eid, ""):
                            raise SystemExit(f"{provider} {eid}: the manifest message does not say {phrase!r}")
                        rows.append((provider, eid, category))
        # The other manifests are read for their channels only (_channel_rows).
    return rows


def _channel_rows() -> list[dict[str, Any]]:
    """(channel, event id) -> the provider that logs it, from every pinned manifest (D232).

    A row that names only its channel (Hayabusa's timeline) is matched to its provider here, so the
    pinned category of that provider's event applies to it. A (channel, event id) two manifests claim
    stops the import.
    """
    owners: dict[tuple[str, int], str] = {}
    for entry in MANIFESTS:
        for eid, ev in _manifest_events(entry).items():
            if not ev["channel"]:
                continue
            key = (ev["channel"], eid)
            if owners.get(key, entry["provider"]) != entry["provider"]:
                raise SystemExit(f"{key}: logged by {owners[key]} and {entry['provider']}")
            owners[key] = entry["provider"]
    return [{"channel": channel, "event_id": eid, "provider": provider}
            for (channel, eid), provider in sorted(owners.items())]


#: One event id can carry several categories: the specific ones are rule-level filters on the
#: same id (Sysmon 12 is registry_add, registry_delete and registry_event). The generic one
#: names the event, so it is the one kept. Any other conflict stops the import.
GENERIC_CATEGORY = "registry_event"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _literal_assignments(source: str) -> dict[str, Any]:
    """Top-level assignments whose value is a Python literal, read with ``ast`` (never run)."""
    values: dict[str, Any] = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            name, value = node.target.id, node.value
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1
              and isinstance(node.targets[0], ast.Name)):
            name, value = node.targets[0].id, node.value
        else:
            continue
        try:
            values[name] = ast.literal_eval(value)
        except ValueError:
            continue
    return values


def _event_ids(value: Any) -> list[int]:
    return [int(v) for v in (value if isinstance(value, list) else [value])]


def _pairs(package: str, values: dict[str, Any]) -> list[tuple[str, int, str]]:
    """(provider, event id, category) rows one pipeline module declares."""
    rows: list[tuple[str, int, str]] = []
    if package == "pysigma-pipeline-windows":
        for category, spec in values["windows_generic_category_channel_mapping"].items():
            provider = SERVICE_PROVIDER[spec["service"]]
            rows += [(provider, eid, category) for eid in _event_ids(spec["EventID"])]
        for category, spec in values["generic_logsource_to_windows_audit_event_mapping"].items():
            provider = SERVICE_PROVIDER["security"]
            rows += [(provider, eid, category) for eid in _event_ids(spec["EventID"])]
    elif package == "pysigma-pipeline-sysmon":
        for category, ids in values["sysmon_generic_logsource_eventid_mapping"].items():
            provider = SERVICE_PROVIDER["sysmon"]
            rows += [(provider, eid, category) for eid in _event_ids(ids)]
    else:
        raise SystemExit(f"no mapping rule for package {package}")
    return rows


def _elastic_yaml() -> dict[str, Any]:
    """The cached Elastic pipeline, parsed as data, after its SHA-256 is checked."""
    if not CACHE.is_file():
        raise SystemExit(f"pinned Elastic pipeline is not cached ({CACHE}): run with --fetch")
    data = CACHE.read_bytes()
    if _sha256(data) != ELASTIC["sha256"]:
        raise SystemExit(f"{CACHE.name}: SHA-256 differs from the reviewed value; run with --fetch")
    return yaml.safe_load(data.decode("utf-8")) or {}


def _elastic_rows(doc: dict[str, Any]) -> list[tuple[str, int, str]]:
    """(provider, event id, category) for the Security events in scope.

    The pipeline keeps its categories in the ``params`` of its painless script processors, keyed
    by event id. A list of several categories is ordered by the pipeline: the first one is kept.
    """
    rows: list[tuple[str, int, str]] = []
    for proc in doc.get("processors") or []:
        body = proc.get("script") if isinstance(proc, dict) else None
        params = body.get("params") if isinstance(body, dict) else None
        if not isinstance(params, dict):
            continue
        for eid, spec in params.items():
            if not isinstance(spec, dict) or not spec.get("category"):
                continue
            category = str(spec["category"][0])
            if category in ELASTIC_CATEGORIES or str(eid) in ELASTIC_EXTRA_IDS:
                rows.append((SERVICE_PROVIDER["security"], int(eid), category))
    return rows


def fetch() -> Path:
    """Download the pinned Elastic pipeline into the cache; it is kept only if its SHA-256 matches."""
    with urllib.request.urlopen(ELASTIC["url"], timeout=120) as resp:
        data = resp.read()
    if _sha256(data) != ELASTIC["sha256"]:
        raise SystemExit(f"{ELASTIC['url']}: SHA-256 differs from the reviewed value; not cached")
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_bytes(data)
    return CACHE


def build() -> dict[str, Any]:
    sources: list[dict[str, str]] = []
    by_key: dict[tuple[str, int], dict[str, str]] = {}
    for src in SOURCES:
        wheel = PINNED / src["wheel"]
        if not wheel.is_file():
            raise SystemExit(f"pinned wheel missing: {wheel}")
        data = wheel.read_bytes()
        if _sha256(data) != src["sha256"]:
            raise SystemExit(f"{src['wheel']}: SHA-256 differs from the reviewed value")
        module = zipfile.ZipFile(wheel).read(src["module"]).decode("utf-8")
        values = _literal_assignments(module)
        sources.append({k: src[k] for k in ("package", "version", "sha256", "module")})
        for provider, eid, category in _pairs(src["package"], values):
            entry = by_key.setdefault((provider, eid), {"categories": {}, "package": src["package"]})
            entry["categories"][category] = src["package"]

    doc = _elastic_yaml()
    sources.append({k: ELASTIC[k] for k in ("package", "version", "commit", "path", "sha256", "licence", "url")})
    for provider, eid, category in _elastic_rows(doc):
        entry = by_key.setdefault((provider, eid), {"categories": {}, "package": ELASTIC["package"]})
        entry["categories"][category] = ELASTIC["package"]

    for manifest in MANIFESTS:
        name = f'"{manifest["provider"]}"' if " " in manifest["provider"] else manifest["provider"]
        sources.append({"package": "windows-provider-manifest", "version": manifest.get("version", MANIFEST_BUILD),
                        "provider": manifest["provider"], "path": f"devtools/knowledge/pinned/{manifest['file']}",
                        "sha256": manifest["sha256"],
                        "export": f"wevtutil gp {name} /ge /gm:true /f:xml"
                                  + (" /uni:true" if manifest.get("unicode") else "")})
    for provider, eid, category in _manifest_rows():
        entry = by_key.setdefault((provider, eid), {"categories": {}, "package": "windows-provider-manifest"})
        entry["categories"][category] = "windows-provider-manifest"

    entries = []
    for (provider, eid), entry in sorted(by_key.items()):
        names = sorted(entry["categories"])
        if len(names) > 1:
            if GENERIC_CATEGORY not in names:
                raise SystemExit(f"{provider} {eid}: several categories and no generic one: {names}")
            names = [GENERIC_CATEGORY]
        entries.append({
            "provider": provider,
            "event_id": eid,
            "category": names[0],
            "source": entry["categories"][names[0]],
        })
    return {
        "version": 1,
        "generated_by": "devtools/knowledge/import_event_categories.py",
        "note": ("Event-to-category table imported from pinned pySigma pipelines. Each event id "
                 "belongs to one category per provider. Events with no entry have no pinned "
                 "category and resolve to 'other'. Do not edit by hand."),
        "sources": sources,
        "entries": entries,
        "channels": _channel_rows(),
    }


def render(doc: dict[str, Any]) -> str:
    header = "# Generated by devtools/knowledge/import_event_categories.py. Do not edit by hand.\n"
    return header + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=120)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the committed table is stale")
    parser.add_argument("--fetch", action="store_true",
                        help="cache the pinned Elastic pipeline (gitignored), then exit")
    args = parser.parse_args(argv)
    if args.fetch:
        print(f"cached {fetch()} (sha256 {ELASTIC['sha256'][:12]}...)")
        return 0
    text = render(build())
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.is_file() else ""
        if current != text:
            print(f"{OUT.name} is stale: run import_event_categories.py without --check",
                  file=sys.stderr)
            return 1
        print(f"{OUT.name} matches the pinned pipelines")
        return 0
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT} ({text.count(chr(10))} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
