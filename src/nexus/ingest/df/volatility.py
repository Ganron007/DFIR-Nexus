"""Volatility 3 / Rekall memory forensics output importer."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.ingest.base import Importer
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity

log = logging.getLogger(__name__)

MALFIND_COLS = frozenset({"pid", "process", "start", "end", "tag", "protection", "commit_charge"})
PSLIST_COLS = frozenset({"pid", "ppid", "imagefilename", "imagename", "name", "create_time", "created"})
NETSCAN_COLS = frozenset({"localaddress", "foreignaddress", "state", "pid", "owner", "offset"})


def looks_like_volatility_text(text: str) -> bool:
    head = text[:2000].lower()
    return "volatility" in head or "volshell" in head or bool(re.search(r"^\s*pid\s+", text, re.M))


def _looks_like_volatility_row(row: dict[str, Any]) -> bool:
    cols = {str(key).lower() for key in row}
    return (
        {"pid", "imagefilename"} <= cols
        or {"pid", "ppid", "offset(v)"} <= cols
        or {"protection", "commit_charge"} <= cols
        or bool({"localaddress", "foreignaddress"} & cols)
    )


def _first_json_object(text: str) -> dict[str, Any] | None:
    """Decode the first complete object from a bounded JSON prefix."""
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    value = json.loads(text[start:index + 1])
                except json.JSONDecodeError:
                    return None
                return value if isinstance(value, dict) else None
    return None


def _supported_json_payload(data: Any, *, plugin_hint: str = "") -> bool:
    """Whether parse_volatility_content can emit rows from this JSON shape."""
    hint = plugin_hint.lower()
    named_plugin = hint.startswith("windows.") or hint.startswith("linux.")
    if isinstance(data, list):
        rows = [row for row in data if isinstance(row, dict)]
        return bool(rows) and (named_plugin or any(_looks_like_volatility_row(row) for row in rows[:3]))
    if not isinstance(data, dict):
        return False
    if _looks_like_volatility_row(data):
        return True
    for plugin, value in data.items():
        if not isinstance(value, list):
            continue
        rows = [row for row in value if isinstance(row, dict)]
        if rows and (
            str(plugin).lower().startswith(("windows.", "linux."))
            or any(_looks_like_volatility_row(row) for row in rows[:3])
        ):
            return True
    return False


def _severity_for_plugin(plugin: str, row: dict[str, Any]) -> Severity:
    p = plugin.lower()
    if "malfind" in p or "inject" in p:
        return Severity.HIGH
    cmd = str(row.get("Args", row.get("CommandLine", row.get("cmdline", "")))).lower()
    if any(x in cmd for x in ("-enc", "downloadstring", "iex", "invoke-expression")):
        return Severity.HIGH
    if "netscan" in p or "netstat" in p:
        return Severity.MEDIUM
    return Severity.INFORMATIONAL


def _classify_rows(rows: list[dict[str, Any]], plugin_hint: str = "") -> str:
    if not rows:
        return "unknown"
    cols = {k.lower() for k in rows[0]}
    hint = plugin_hint.lower()
    if MALFIND_COLS.issubset(cols) or "malfind" in hint:
        return "malfind"
    if "psscan" in hint or "pslist" in hint or "pstree" in hint:
        return "pslist"
    if "cmdline" in hint:
        return "cmdline"
    # Require an address column — pid alone matches almost every plugin.
    if {"localaddress", "foreignaddress"} & cols or "netscan" in hint or "netstat" in hint:
        return "netscan"
    if PSLIST_COLS & cols:
        return "pslist"
    return plugin_hint or "volatility"


def _row_to_artifact(row: dict[str, Any], plugin: str, path: Path) -> Artifact:
    def _s(val: Any) -> str:
        return "" if val is None else str(val)

    proc = _s(
        row.get("ImageFileName")
        or row.get("ImageName")
        or row.get("Process")
        or row.get("process")
        or row.get("Owner")
        or ""
    )
    ppid = row.get("PPID", row.get("ppid"))
    parent = _s(row.get("ParentImageFileName") or row.get("Parent") or ("" if ppid is None else ppid))
    cmd = _s(row.get("Args") or row.get("CommandLine") or row.get("cmdline") or "")
    pid = row.get("PID") or row.get("pid")
    desc = f"Volatility {plugin}: {proc or 'memory row'}"
    if pid:
        desc += f" (pid={pid})"
    sev = _severity_for_plugin(plugin, row)
    technique: list[str] = []
    if "malfind" in plugin.lower():
        technique.append("T1055")
    src_ip, dst_ip = None, None
    local = str(row.get("LocalAddress") or row.get("localaddress") or "")
    foreign = str(row.get("ForeignAddress") or row.get("foreignaddress") or "")
    if local or foreign:
        src_ip = local.split(":")[0] if local else None
        dst_ip = foreign.split(":")[0] if foreign else None
    return Artifact(
        id=Artifact.new_id(),
        artifact_type=ArtifactType.NETWORK if src_ip and dst_ip else ArtifactType.PROCESS,
        source=ArtifactSource.VOLATILITY,
        timestamp=datetime.now(UTC),
        ts_synthesized=True,
        severity=sev,
        host=None,
        process_name=proc or None,
        parent_process=parent or None,
        command_line=cmd or None,
        source_ip=src_ip,
        dest_ip=dst_ip,
        description=desc,
        raw={"plugin": plugin, "row": row, "source_file": str(path)},
        technique_ids=technique,
        tags=["volatility", plugin],
    )


def parse_volatility_content(text: str, *, filename: str = "") -> list[Artifact]:
    """Parse Volatility JSON/JSONL/map or Rekall-style content into artifacts."""
    text = text.strip()
    if not text:
        return []
    artifacts: list[Artifact] = []
    path = Path(filename or "memory.json")

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # JSONL
        rows: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        plugin = _classify_rows(rows, Path(filename).stem)
        artifacts.extend(_row_to_artifact(r, plugin, path) for r in rows)
        return artifacts

    if isinstance(data, list):
        plugin = _classify_rows(data, Path(filename).stem)
        artifacts.extend(_row_to_artifact(r, plugin, path) for r in data if isinstance(r, dict))
    elif isinstance(data, dict):
        if _looks_like_volatility_row(data):
            plugin = _classify_rows([data], Path(filename).stem)
            artifacts.append(_row_to_artifact(data, plugin, path))
        else:
            for plugin, rows in data.items():
                if isinstance(rows, list):
                    for r in rows:
                        if isinstance(r, dict):
                            artifacts.append(_row_to_artifact(r, str(plugin), path))
    return artifacts


class VolatilityImporter(Importer):
    """Import Volatility 3 JSON / JSONL / plugin-map exports."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.VOLATILITY

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        if not path.is_file():
            return False
        if path.suffix.lower() not in {".json", ".jsonl", ".txt", ".log"}:
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                head = handle.read(65536)
            full_file = path.stat().st_size <= 65536
        except OSError:
            return False
        if path.suffix.lower() in {".json", ".jsonl"}:
            plugin_hint = path.stem.lower()
            try:
                data = json.loads(head) if full_file else None
            except json.JSONDecodeError:
                data = None
            if data is not None:
                return _supported_json_payload(data, plugin_hint=plugin_hint)
            if head.lstrip().startswith(("[", "{")):
                first = _first_json_object(head)
                if first is not None:
                    if _supported_json_payload(first, plugin_hint=plugin_hint):
                        return True
                    if (
                        plugin_hint.startswith(("windows.", "linux."))
                        and head.lstrip().startswith("[")
                    ):
                        return True
            for line in head.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict) and (
                    plugin_hint.startswith(("windows.", "linux."))
                    or _looks_like_volatility_row(row)
                ):
                    return True
                break
            return False
        return looks_like_volatility_text(head)

    def parse(self, path: Path) -> Iterator[Artifact]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            log.error("Cannot read %s: %s", path, e)
            return
        yield from parse_volatility_content(text, filename=path.name)
