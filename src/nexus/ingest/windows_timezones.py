"""Host timezone evidence and the pinned CLDR Windows/IANA mapping.

Timezone conversion is based on the SYSTEM hive extracted by RECmd. A task
file is associated with that hive only when both paths identify the same
Windows evidence root. Ambiguous or missing associations are left flagged as
assumptions by the caller.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import re
from datetime import UTC, datetime
from functools import lru_cache
from importlib.resources import files
from pathlib import Path, PureWindowsPath
from typing import Any
from xml.etree import ElementTree as ET
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import tzdata

from nexus.case.evidence_roots import EXPANSION_DIRNAME
from nexus.utils import atomic

log = logging.getLogger(__name__)

_CLDR_WINDOWS_ZONES = Path(__file__).resolve().parents[1] / "data" / "timezones" / "windowsZones.xml"
_CASE_TIMEZONES = Path("analysis") / "host_timezones.json"
_SYSTEM_TIMEZONE_GLOB = "*_TimeZoneInfo__SYSTEM.csv"
_META_TIME_FORMAT = "%Y%m%d%H%M%S"


@lru_cache(maxsize=1)
def windows_timezone_map() -> dict[str, str]:
    """Read the territory-neutral map from the vendored CLDR XML."""
    root = ET.parse(_CLDR_WINDOWS_ZONES).getroot()
    mapping: dict[str, str] = {}
    for node in root.findall(".//mapZone"):
        if node.get("territory") != "001":
            continue
        windows_name = str(node.get("other") or "").strip()
        iana_names = str(node.get("type") or "").split()
        if windows_name and iana_names:
            mapping[windows_name.casefold()] = iana_names[0]
    return mapping


def cldr_mapping_sha256() -> str:
    """Hash the exact vendored CLDR mapping used by the resolver."""
    digest = hashlib.sha256()
    with _CLDR_WINDOWS_ZONES.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@lru_cache(maxsize=512)
def _pinned_zoneinfo(iana_name: str) -> tuple[ZoneInfo, str]:
    """Load the exact TZif resource from the pinned tzdata package."""
    parts = iana_name.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ZoneInfoNotFoundError(iana_name)
    try:
        resource = files("tzdata.zoneinfo")
        for part in parts:
            resource = resource.joinpath(part)
        data = resource.read_bytes()
        zone = ZoneInfo.from_file(io.BytesIO(data), key=iana_name)
    except (ImportError, OSError, ValueError) as exc:
        raise ZoneInfoNotFoundError(iana_name) from exc
    return zone, hashlib.sha256(data).hexdigest()


def windows_path_root(path: str | Path) -> str | None:
    """Return the evidence-root prefix before a Windows directory component.

    Examples: ``H:\\C\\Windows\\System32\\Tasks\\x`` becomes ``h:\\c``;
    an expanded host tree keeps its full ``.../_expanded/<id>/<host>/C``
    prefix. The path is normalized for case and slash differences.
    """
    parts = PureWindowsPath(str(path).replace("/", "\\")).parts
    windows_index = next(
        (index for index, part in enumerate(parts) if part.casefold() == "windows"),
        None,
    )
    if windows_index is None or windows_index == 0:
        return None
    prefix = str(PureWindowsPath(*parts[:windows_index])).replace("/", "\\")
    return prefix.rstrip("\\").casefold() or None


def _host_from_root(root: str) -> str | None:
    parts = [part for part in PureWindowsPath(root).parts if part not in ("\\", "")]
    for index, part in enumerate(parts[:-3]):
        if part.casefold() == EXPANSION_DIRNAME:
            return parts[index + 2]
    return None


def _system_input(command: str) -> str | None:
    """Read the -d/-f input from the captured RECmd command, never execute it."""
    match = re.search(
        r"(?i)(?:^|\s)-(d|f)\s+(?:\"([^\"]+)\"|'([^']+)'|([^\s]+))",
        command,
    )
    if not match:
        return None
    option = match.group(1).casefold()
    value = next(group for group in match.groups()[1:] if group is not None).strip()
    normalized = value.replace("/", "\\").rstrip("\\").casefold()
    if option == "f":
        if PureWindowsPath(value).name.casefold() != "system":
            return None
    elif not normalized.endswith("\\windows\\system32\\config"):
        return None
    return value


def _metadata_timestamp(meta: dict[str, Any]) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(meta.get("saved_at") or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _csv_run_root(path: Path) -> Path | None:
    for parent in path.parents:
        if parent.parent.name.casefold() == "runs":
            return parent
    return None


def _metadata_for_timezone_csv(path: Path) -> tuple[dict[str, Any], Path] | None:
    """Find the RECmd call that produced this time-zone CSV by its output time."""
    run_root = _csv_run_root(path)
    if run_root is None:
        return None
    try:
        folder_time = datetime.strptime(path.parent.name[:14], _META_TIME_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None

    candidates: list[tuple[float, dict[str, Any], Path]] = []
    for meta_path in (run_root / "extractions" / "recmd").glob("*_recmd_meta.json"):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if str(meta.get("tool") or "").casefold() != "recmd":
            continue
        if not _system_input(str(meta.get("command") or "")):
            continue
        meta_time = _metadata_timestamp(meta)
        if meta_time is None:
            continue
        delta = abs((meta_time - folder_time).total_seconds())
        if delta <= 300:
            candidates.append((delta, meta, meta_path))
    if not candidates:
        return None
    candidates.sort(key=lambda row: row[0])
    closest = [row for row in candidates if row[0] == candidates[0][0]]
    roots = {
        windows_path_root(_system_input(str(row[1].get("command") or "")) or "")
        for row in closest
    }
    if len(closest) != 1 or len(roots) != 1 or None in roots:
        return None
    return closest[0][1], closest[0][2]


def _timezone_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        with path.open(encoding="utf-8-sig", errors="replace", newline="") as stream:
            for row in csv.DictReader(stream):
                name = str(row.get("ValueName") or row.get("BatchValueName") or "").strip()
                value = str(row.get("ValueData") or row.get("ValueDataRaw") or "").strip()
                if name and value and name.casefold() not in values:
                    values[name.casefold()] = value
    except OSError:
        return {}
    return values


def record_case_host_timezones(case_dir: Path) -> list[dict[str, Any]]:
    """Persist zones proven by RECmd SYSTEM-hive output, scoped to evidence roots."""
    case_dir = Path(case_dir)
    runs = case_dir / "runs"
    records: list[dict[str, Any]] = []
    if runs.is_dir():
        for run_root in sorted(path for path in runs.iterdir() if path.is_dir()):
            recmd_root = run_root / "extractions" / "recmd"
            if not recmd_root.is_dir():
                continue
            # RECmd writes each export beneath a timestamped child of its output
            # directory. Search that one level only; walking every tool output
            # once per imported task made large cases scale as tasks × run files.
            for csv_path in sorted(recmd_root.glob(f"*/{_SYSTEM_TIMEZONE_GLOB}")):
                association = _metadata_for_timezone_csv(csv_path)
                if association is None:
                    continue
                meta, _meta_path = association
                command = str(meta.get("command") or "")
                system_path = _system_input(command)
                root = windows_path_root(system_path or "")
                if root is None:
                    continue
                values = _timezone_values(csv_path)
                windows_name = values.get("timezonekeyname")
                if not windows_name:
                    continue
                iana_name = windows_timezone_map().get(windows_name.casefold())
                if not iana_name:
                    continue
                try:
                    _zone, tzif_sha256 = _pinned_zoneinfo(iana_name)
                except (ZoneInfoNotFoundError, ValueError):
                    continue
                try:
                    source = csv_path.relative_to(case_dir).as_posix()
                except ValueError:
                    source = csv_path.name
                records.append({
                    "evidence_root": root,
                    "host": _host_from_root(root),
                    "windows_timezone": windows_name,
                    "iana_timezone": iana_name,
                    "bias_minutes": _int_value(values.get("bias")),
                    "daylight_bias_minutes": _int_value(values.get("daylightbias")),
                    "source_file": source,
                    "source_sha256": _sha256_file(csv_path),
                    "mapping_source": "CLDR 48.2 / release-48-2",
                    "mapping_sha256": cldr_mapping_sha256(),
                    "timezone_data_source": "tzdata",
                    "timezone_data_version": tzdata.__version__,
                    "timezone_data_sha256": tzif_sha256,
                })

    payload = {"schema_version": 1, "records": records}
    output = case_dir / _CASE_TIMEZONES
    if records:
        encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        try:
            if not output.is_file() or output.read_text(encoding="utf-8") != encoded:
                output.parent.mkdir(parents=True, exist_ok=True)
                temporary = output.with_suffix(output.suffix + ".tmp")
                temporary.write_text(encoded, encoding="utf-8", newline="\n")
                atomic.replace(temporary, output)
        except OSError as exc:
            log.warning("Could not record case timezone evidence: %s", exc)
    return records


def _int_value(value: str | None) -> int | None:
    try:
        return int(str(value).strip(), 10) if value is not None else None
    except ValueError:
        return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def timezone_for_task(path: str | Path, records: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Resolve a task only against an unambiguous SYSTEM hive for its root."""
    root = windows_path_root(path)
    if root is None:
        return None
    matches = [record for record in records if record.get("evidence_root") == root]
    zones = {
        (record.get("windows_timezone"), record.get("iana_timezone"),
         record.get("bias_minutes"), record.get("daylight_bias_minutes"))
        for record in matches
    }
    if len(zones) != 1:
        return None
    record = matches[-1]
    return record if record.get("iana_timezone") else None
