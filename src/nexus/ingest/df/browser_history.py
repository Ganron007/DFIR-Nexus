"""Browser history importer.

Parses browser history databases (Chrome, Firefox, Edge). These are SQLite
databases that record every URL the user visited, when, and how many
times.

Sources supported:
- Chrome: History SQLite DB (`SELECT url, title, visit_count, last_visit_time FROM urls`)
- Edge: same schema as Chrome
- Firefox: places.sqlite (`SELECT url, title, visit_count, last_visit_date FROM moz_places`)

The browser databases use Chrome time epoch (microseconds since Jan 1, 1601)
or Firefox time (microseconds since Jan 1, 1970).
"""

from __future__ import annotations

import logging
import re
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from nexus.ingest.base import Importer
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Severity,
)

log = logging.getLogger(__name__)


class BrowserHistoryImporter(Importer):
    """Parser for Chrome / Edge / Firefox browser history databases."""

    # Chrome epoch: microseconds since January 1, 1601
    # Firefox epoch: microseconds since January 1, 1970 (Unix epoch)
    CHROME_EPOCH_OFFSET_US = 11644473600000000  # microseconds between 1601 and 1970

    SUSPICIOUS_URL_PATTERNS: list[str] = [
        r"(?i)\.onion\b",  # Tor hidden service
        r"(?i)pastebin\.com",
        r"(?i)raw\.githubusercontent\.com",
        r"(?i)bit\.ly",
        r"(?i)ngrok\.io",
        r"(?i)duckdns\.org",
        r"(?i)\.tk\b",
        r"(?i)\.ml\b",
        r"(?i)\.ga\b",
        r"(?i)\.cf\b",
        r"(?i)\.gq\b",
        r"(?i)phish",
        r"(?i)/malware/",
        r"(?i)/payload/",
        r"(?i)c2/",
        r"(?i)powershell",
        r"(?i)-enc ",
        r"(?i)base64",
        r"(?i)\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # IP-address URL
    ]

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.BROWSER_HISTORY

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: SQLite database with urls/moz_places table."""
        if not path.is_file():
            return False
        name_lower = path.name.lower()
        # Chrome/Edge: "History" (no extension) or Chrome/Edge default names
        if name_lower in {"history", "places.sqlite"}:
            return cls._probe_sqlite(path)
        # Generic
        if name_lower.endswith((".sqlite", ".sqlite3", ".db")):
            return cls._probe_sqlite(path)
        return False

    @staticmethod
    def _probe_sqlite(path: Path) -> bool:
        """Check if the SQLite file has a urls or moz_places table."""
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.Error:
            return False
        try:
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('urls', 'moz_places', 'visits', 'moz_historyvisits')"
            )
            tables = {row[0] for row in cur.fetchall()}
            conn.close()
            return bool(tables)
        except sqlite3.Error:
            return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from a browser history database."""
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.Error as e:
            log.warning("Could not open %s: %s", path, e)
            return

        try:
            # Detect browser by table presence
            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cur.fetchall()}
            if "urls" in tables:
                yield from self._parse_chrome(conn, path)
            elif "moz_places" in tables:
                yield from self._parse_firefox(conn, path)
        finally:
            conn.close()

    def _parse_chrome(self, conn: sqlite3.Connection, path: Path) -> Iterator[Artifact]:
        """Parse a Chrome/Edge history DB."""
        # urls table has: id, url, title, visit_count, typed_count, last_visit_time, hidden
        try:
            cur = conn.execute(
                """
                SELECT id, url, title, visit_count, typed_count, last_visit_time, hidden
                FROM urls
                ORDER BY last_visit_time DESC
                LIMIT 10000
                """
            )
        except sqlite3.Error as e:
            log.warning("Query failed on %s: %s", path, e)
            return
        for row in cur.fetchall():
            url_id, url, title, visit_count, typed_count, last_visit_us, hidden = row
            if hidden:
                continue  # skip hidden entries (probably chrome:// internal)
            ts = self._chrome_time_to_datetime(last_visit_us)
            yield self._make_artifact(url, title, visit_count or 0, ts, path, browser="Chrome/Edge")

    def _parse_firefox(self, conn: sqlite3.Connection, path: Path) -> Iterator[Artifact]:
        """Parse a Firefox places.sqlite."""
        try:
            cur = conn.execute(
                """
                SELECT id, url, title, visit_count, last_visit_date
                FROM moz_places
                ORDER BY last_visit_date DESC
                LIMIT 10000
                """
            )
        except sqlite3.Error as e:
            log.warning("Query failed on %s: %s", path, e)
            return
        for row in cur.fetchall():
            place_id, url, title, visit_count, last_visit_us = row
            ts = self._firefox_time_to_datetime(last_visit_us)
            yield self._make_artifact(url, title, visit_count or 0, ts, path, browser="Firefox")

    def _chrome_time_to_datetime(self, microseconds: int | None) -> datetime:
        """Convert Chrome epoch (microseconds since 1601) to UTC datetime."""
        if microseconds is None or microseconds == 0:
            return datetime.fromtimestamp(0, tz=UTC)
        try:
            seconds = (microseconds - self.CHROME_EPOCH_OFFSET_US) / 1_000_000
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (ValueError, OSError, OverflowError):
            return datetime.now(UTC)

    def _firefox_time_to_datetime(self, microseconds: int | None) -> datetime:
        """Convert Firefox epoch (microseconds since Unix) to UTC datetime."""
        if microseconds is None or microseconds == 0:
            return datetime.fromtimestamp(0, tz=UTC)
        try:
            return datetime.fromtimestamp(microseconds / 1_000_000, tz=UTC)
        except (ValueError, OSError, OverflowError):
            return datetime.now(UTC)

    def _make_artifact(
        self,
        url: str,
        title: str,
        visit_count: int,
        ts: datetime,
        path: Path,
        browser: str,
    ) -> Artifact:
        """Map a URL visit to an Artifact."""
        url_lower = url.lower()

        # Severity
        severity = Severity.INFORMATIONAL
        for pattern in self.SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url):
                severity = Severity.HIGH
                break
        # Very high visit counts on the same URL is suspicious
        if visit_count and visit_count >= 100:
            severity = max(severity, Severity.LOW, key=lambda s: ["informational", "low", "medium", "high", "critical"].index(s.value))

        # Technique IDs
        technique_ids = ["T1217"]  # Browser Information Discovery
        if any(p in url_lower for p in [".onion", "ngrok", "duckdns", "bit.ly"]):
            technique_ids.append("T1090.003")  # Multi-hop Proxy
        if any(p in url_lower for p in ["pastebin", "raw.githubusercontent"]):
            technique_ids.append("T1105")  # Ingress Tool Transfer

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.NETWORK,
            source=ArtifactSource.BROWSER_HISTORY,
            timestamp=ts,
            severity=severity,
            host=path.stem,
            description=f"{browser}: {url}" + (f" ({title})" if title else ""),
            raw={"url": url, "title": title, "visit_count": visit_count, "browser": browser},
            technique_ids=technique_ids,
            tags=["browser_history", browser.lower().replace("/", "-")],
            iocs=[url] if severity == Severity.HIGH else [],
        )
