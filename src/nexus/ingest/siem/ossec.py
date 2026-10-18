"""OSSEC alerts.log importer.

OSSEC writes each alert to ``alerts.log`` as a block, with these format strings (``OS_Log`` in
``src/analysisd/alerts/log.c``)::

    ** Alert %ld.%ld:%s - %s
    %d %s %02d %s %s%s%s
    Rule: %d (level %d) -> '%s'

the alert ID (epoch seconds and an offset), the mail flag and the groups; the year, month, day and time with the
host and location; the rule and its level; then the optional ``Src IP``, ``Src Location``, ``Src Port``, ``Dst IP``,
``Dst Location``, ``Dst Port`` and ``User`` lines, the log that matched, and the earlier events of a composite rule. A Windows agent forwards an event as a
``WinEvtLog`` line, ``<time> WinEvtLog: <channel>: <type>(<event id>): <provider>: <user>: <domain>: <computer>:
<message>``, and an extract of the log may hold those lines alone, a blank line apart (sample S06's
``ossec-alerts.log``, 2026-10-18, which no importer read). Both shapes are read: one artifact per alert block, or per
line when there are no blocks; a Windows event gets its channel, event ID, type, provider, user, domain and computer
as fields. OSSEC writes the time in the manager's local zone with no offset; by the index's policy a naive time is
UTC.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.ingest.base import Importer
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity

_TIME = r"\d{4} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2}"
ALERT_RE = re.compile(r"^\*\* Alert (?P<id>\d+\.\d+):(?P<flags>[^-]*)- ?(?P<groups>.*)$")
LOCATION_RE = re.compile(rf"^(?P<ts>{_TIME}) (?P<location>.+)$")
RULE_RE = re.compile(r"^Rule: (?P<id>\d+) \(level (?P<level>\d+)\) -> '(?P<description>.*)'\s*$")
WINEVTLOG_RE = re.compile(
    rf"^(?:(?P<ts>{_TIME}) )?WinEvtLog: (?P<channel>[^:]+): (?P<type>[A-Z_]+)\((?P<event_id>\d+)\): "
    r"(?P<provider>[^:]+): (?P<user>[^:]*): (?P<domain>[^:]*): (?P<computer>[^:]+): (?P<message>.*)$"
)
# The optional lines OSSEC's OS_Log (src/analysisd/alerts/log.c) writes between the rule and the log, in its order;
# any other line is the log itself, cut by OSSEC to 1,256 characters, then the earlier events of a composite rule.
_FIELD_RE = re.compile(r"^(?P<key>Src IP|Src Location|Src Port|Dst IP|Dst Location|Dst Port|User): (?P<value>.*)$")


def _severity(level: int | None) -> Severity:
    if level is None:
        return Severity.INFORMATIONAL
    if level >= 12:
        return Severity.CRITICAL
    if level >= 10:
        return Severity.HIGH
    if level >= 7:
        return Severity.MEDIUM
    return Severity.LOW if level >= 4 else Severity.INFORMATIONAL


def _time(text: str | None) -> datetime | None:
    try:
        return datetime.strptime(text or "", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


class OssecAlertsImporter(Importer):
    """Parser for OSSEC alerts.log, in blocks or as forwarded WinEvtLog lines."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.OSSEC

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """The first non-empty line opens an alert block or is a forwarded Windows event."""
        if not path.is_file():
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                first = next((ln for ln in (f.readline() for _ in range(20)) if ln.strip()), "")
        except OSError:
            return False
        return bool(ALERT_RE.match(first) or WINEVTLOG_RE.match(first.rstrip("\r\n")))

    def parse(self, path: Path) -> Iterator[Artifact]:
        block: list[str] = []
        for _n, line in self.read_lines(path):
            text = line.rstrip("\r\n")
            if ALERT_RE.match(text):
                if block:
                    yield from self._from_block(block)
                block = [text]
            elif block:
                block.append(text)
            elif WINEVTLOG_RE.match(text):
                yield self._artifact(text, {})
        if block:
            yield from self._from_block(block)

    def _from_block(self, lines: list[str]) -> Iterator[Artifact]:
        head = ALERT_RE.match(lines[0])
        alert: dict[str, Any] = {"alert_id": head["id"], "groups": [g for g in head["groups"].split(",") if g.strip()]}
        rest = [ln for ln in lines[1:] if ln.strip()]
        if rest and (loc := LOCATION_RE.match(rest[0])):
            alert["alert_time"], alert["location"] = loc["ts"], loc["location"]
            rest = rest[1:]
        if rest and (rule := RULE_RE.match(rest[0])):
            alert.update(rule_id=rule["id"], rule_level=int(rule["level"]), rule_description=rule["description"])
            rest = rest[1:]
        while rest and _FIELD_RE.match(rest[0]) and not WINEVTLOG_RE.match(rest[0]):
            field = _FIELD_RE.match(rest[0])
            alert[field["key"].strip().lower().replace(" ", "_")] = field["value"].strip()
            rest = rest[1:]
        yield self._artifact("\n".join(rest), alert)

    @staticmethod
    def _artifact(full_log: str, alert: dict[str, Any]) -> Artifact:
        win = WINEVTLOG_RE.match(full_log.split("\n", 1)[0])
        event: dict[str, Any] = {}
        if win:
            event = {k: v for k, v in win.groupdict().items() if k != "ts"}
            event["event_id"] = int(event["event_id"])
        ts = _time(alert.get("alert_time")) or _time(win["ts"] if win else None)
        if ts is None and alert.get("alert_id"):
            ts = datetime.fromtimestamp(int(alert["alert_id"].split(".")[0]), UTC)
        user = event.get("user") or alert.get("user") or ""
        level = alert.get("rule_level")
        description = (
            f"{event['channel']} {event['event_id']} {event['provider']} on {event['computer']}: {event['message']}"
            if win else full_log
        )
        if alert.get("rule_description"):
            description = f"OSSEC rule {alert['rule_id']} (level {level}) {alert['rule_description']}: {description}"
        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.ALERT if alert.get("rule_id") else ArtifactType.UNKNOWN,
            source=ArtifactSource.OSSEC,
            timestamp=ts or datetime.now(UTC),
            ts_synthesized=ts is None,
            severity=_severity(level),
            host=event.get("computer") or alert.get("location"),
            user=None if user in ("", "(no user)") else user,
            source_ip=alert.get("src_ip"),
            action=event.get("type"),
            description=description,
            raw={**alert, **event, "full_log": full_log},
            tags=["ossec", *(f"group.{g.strip()}" for g in alert.get("groups", [])),
                  *([f"winevtlog.{event['channel'].lower()}"] if win else [])],
        )
