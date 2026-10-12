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

Usage::

    python devtools/knowledge/import_event_categories.py          # write the table
    python devtools/knowledge/import_event_categories.py --check  # fail if the table is stale
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import sys
import zipfile
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
PINNED = REPO / "devtools" / "knowledge" / "pinned"
OUT = REPO / "src" / "nexus" / "data" / "schema" / "event_categories.yaml"

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
    }


def render(doc: dict[str, Any]) -> str:
    header = "# Generated by devtools/knowledge/import_event_categories.py. Do not edit by hand.\n"
    return header + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=120)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the committed table is stale")
    args = parser.parse_args(argv)
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
