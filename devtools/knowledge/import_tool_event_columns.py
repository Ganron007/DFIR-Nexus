"""Generate src/nexus/data/schema/tool_event_columns.yaml from the detection tools' own files (D474, D496).

A detection tool writes each event a rule matched as a row of its own columns. To read the row back as its event
(its channel, provider, event id and event data, so the per-event table and the event's user apply to it, as they
do to EvtxECmd's and Hayabusa's rows), the columns have to be told apart, and only the tool can say which is which:

- Chainsaw 2.16.5, ``mappings/sigma-event-logs-all.yml`` (the mapping the lane passes, ``collect.paths``): each
  output column and the event path it holds (``Event ID`` <- ``Event.System.EventID``, ``Event Data`` <-
  ``Event.EventData``). A cell that holds an object is written as YAML (``src/cli.rs:937``, ``serde_yaml``).
- Zircolite 4.5.0, ``config/config.yaml``: ``mappings`` names each flattened event field by its event path, so the
  names mapped from ``Event.System.*`` are the event's System fields; an enabled transform with an alias adds a
  column of its own. ``templates/exportNDJSON.tmpl``, the output the lane reads (D496): the rule columns each line
  starts with. ``zircolite/flatten_kernel.py:24``: the ``OriginalLogfile`` column Zircolite adds to every event;
  ``zircolite/core.py:509``: the ``row_id`` its detection database numbers each event with.

Each file is read from the tool's repository at its release tag. The installed copy the lane runs is the same file,
byte for byte once line endings are set aside; ``--check`` verifies that for each tool installed here.

    python devtools/knowledge/import_tool_event_columns.py           # regenerate
    python devtools/knowledge/import_tool_event_columns.py --check   # verify the committed table and the installs
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
import urllib.request
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "src" / "nexus" / "data" / "schema" / "tool_event_columns.yaml"
SNAPSHOTS = REPO / "scratch" / "kl2b-snapshots" / "tool-event-columns"
TOOLS = REPO / "tools" / "windows" / "extra"

#: (tool, version, repository, tag, file in the repository, its installed copy or None)
SOURCES = {
    "chainsaw": ("2.16.5", "WithSecureLabs/chainsaw", "v2.16.5", {
        "mapping": ("mappings/sigma-event-logs-all.yml", TOOLS / "chainsaw" / "mappings" / "sigma-event-logs-all.yml"),
    }),
    "zircolite": ("4.5.0", "wagga40/Zircolite", "v4.5.0", {
        "config": ("config/config.yaml",
                   TOOLS / "zircolite" / "Zircolite-4.5.0-windows-x64" / "config" / "config.yaml"),
        "template": ("templates/exportNDJSON.tmpl",
                     TOOLS / "zircolite" / "Zircolite-4.5.0-windows-x64" / "templates" / "exportNDJSON.tmpl"),
        "kernel": ("zircolite/flatten_kernel.py", None),
        "core": ("zircolite/core.py", None),
    }),
}
_TEMPLATE_RULE_KEY = re.compile(r'"(\w+)":\{\{ elem\["(\w+)"\]\|tojson \}\}')
_KERNEL_ADDED = re.compile(r'event_dict\["(\w+)"\]\s*=\s*filename')
_CORE_ROW_ID = re.compile(r"CREATE TABLE logs \( (\w+) INTEGER PRIMARY KEY")


def _fetch(repo: str, tag: str, path: str) -> bytes:
    """The file at the tag, kept as a snapshot under scratch/ (rule 19) so a second run reads the same bytes."""
    snap = SNAPSHOTS / repo.replace("/", "_") / tag / path
    if snap.is_file():
        return snap.read_bytes()
    with urllib.request.urlopen(f"https://raw.githubusercontent.com/{repo}/{tag}/{path}", timeout=60) as resp:
        data = resp.read()
    snap.parent.mkdir(parents=True, exist_ok=True)
    snap.write_bytes(data)
    return data


def lf_sha256(data: bytes) -> str:
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def chainsaw_body(files: dict[str, bytes]) -> dict:
    mapping = yaml.safe_load(files["mapping"])
    columns: dict[str, str] = {}
    for group in mapping.get("groups") or []:
        for f in group.get("fields") or []:
            if f.get("visible", True) is False:
                continue
            # A field with no `name` is written under its path (`Event.System.Provider`).
            columns[str(f["to"])] = str(f.get("name") or f["to"])
    return {"columns": columns, "object_cells": "yaml"}


def zircolite_system(config: bytes) -> dict[str, str]:
    """Event path -> column for the System fields, in the tool's own direction: two paths can write one column
    (`Event.System.EventID` and its `#text` form both write `EventID`)."""
    mappings = yaml.safe_load(config).get("mappings") or {}
    return dict(sorted((str(path), str(name)) for path, name in mappings.items() if str(path).startswith("Event.System.")))


def zircolite_derived(config: bytes) -> list[str]:
    """The column each enabled transform with an alias adds."""
    doc = yaml.safe_load(config)
    enabled = set(doc.get("enabled_transforms") or []) if doc.get("transforms_enabled") else set()
    return sorted({str(t.get("alias_name")) for name, defs in (doc.get("transforms") or {}).items()
                   if name in enabled for t in defs or [] if t.get("alias") and t.get("alias_name")})


def zircolite_rule(template: bytes) -> list[str]:
    """The rule columns each NDJSON line starts with."""
    return [key for key, _ in _TEMPLATE_RULE_KEY.findall(template.decode("utf-8"))]


def _zircolite(files: dict[str, bytes]) -> dict:
    system, rule = zircolite_system(files["config"]), zircolite_rule(files["template"])
    added = list(dict.fromkeys([*_KERNEL_ADDED.findall(files["kernel"].decode("utf-8")),
                                *_CORE_ROW_ID.findall(files["core"].decode("utf-8"))]))
    if not system or not rule or len(added) < 2:
        raise SystemExit(f"zircolite: a pinned file no longer names its columns (system {len(system)}, rule {rule}, "
                         f"added {added})")
    return {"system": system, "rule": rule, "added": added, "derived": zircolite_derived(files["config"])}


def build() -> dict:
    table: dict = {}
    for tool, (version, repo, tag, wanted) in SOURCES.items():
        files = {key: _fetch(repo, tag, path) for key, (path, _installed) in wanted.items()}
        body = (chainsaw_body if tool == "chainsaw" else _zircolite)(files)
        table[tool] = {
            "version": version,
            "sources": [{"repository": repo, "tag": tag, "file": path, "sha256": lf_sha256(files[key])}
                        for key, (path, _installed) in wanted.items()],
            **body,
        }
    return table


def render(table: dict) -> str:
    head = ("# GENERATED by devtools/knowledge/import_tool_event_columns.py from each tool's own files at its release "
            "tag - do not edit\n# by hand (D474, D496). Which column of a detection tool's row is the event's "
            "system field, its event data,\n# or the tool's own; read by nexus.langgraph.tool_events.\n")
    return head + yaml.safe_dump(table, sort_keys=False, allow_unicode=True, width=120)


def check(table: dict) -> list[str]:
    problems = []
    if OUT.read_text(encoding="utf-8") != render(table):
        problems.append(f"{OUT.relative_to(REPO)} differs from what the pinned files give: regenerate it")
    for tool, (_version, _repo, _tag, wanted) in SOURCES.items():
        recorded = {s["file"]: s["sha256"] for s in table[tool]["sources"]}
        for path, installed in wanted.values():
            if installed is not None and installed.is_file() and lf_sha256(installed.read_bytes()) != recorded[path]:
                problems.append(f"{tool}: the installed {installed.relative_to(REPO)} is not {path} at its tag")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    table = build()
    if args.check:
        problems = check(table)
        print("\n".join(problems) or "ok: the table and the installed tools match their pinned files")
        return 1 if problems else 0
    OUT.write_text(render(table), encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
