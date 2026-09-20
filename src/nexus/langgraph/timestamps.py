"""Timestamp authority (Phase 4k.4) — per-family event-time extraction.

Policy (never guess silently):
- explicit offset / Z is honored;
- naive timestamps are treated as **UTC by policy** and flagged `tz_assumed`;
- syslog lacks a year: year comes from the case window (or current year) and is
  flagged `year_assumed`;
- unparseable stays empty — never epoch-0, never a local-time guess.

Every returned time carries its origin (`event` | `synthesized`) and precision
so queries, digests and reports can be exact about what the time means.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

# Parsed-column names that carry an event time, most specific first.
TIME_COLUMNS = (
    "timecreated", "timestamp", "eventtime", "event_time", "time", "ts",
    "lastrun", "lastruntime", "lastvisittime", "starttime", "endtime",
    "updatetimestamp", "created0x10", "created0x30", "birthdroid",
    "firstseen", "lastseen", "datetime", "date", "value",
)

_ISO_RE = re.compile(
    r"(?P<y>\d{4})-(?P<m>\d{2})-(?P<d>\d{2})"
    r"(?:[ T](?P<H>\d{2}):(?P<M>\d{2})(?::(?P<S>\d{2}))?"
    r"(?:\.(?P<frac>\d{1,9}))?"
    r"\s*(?P<tz>Z|[+-]\d{2}(?::?\d{2})?)?)?"
)
_US_RE = re.compile(
    r"\b(?P<m>\d{1,2})/(?P<d>\d{1,2})/(?P<y>\d{4})"
    r"(?:[ T](?P<H>\d{1,2}):(?P<M>\d{2})(?::(?P<S>\d{2}))?"
    r"\s*(?P<ampm>AM|PM|am|pm)?)?"
)
_SYSLOG_RE = re.compile(
    r"\b(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<d>\d{1,2})\s+(?P<H>\d{2}):(?P<M>\d{2}):(?P<S>\d{2})\b",
    re.IGNORECASE,
)
_EPOCH_RE = re.compile(r"(?<![\d.])(\d{13}|\d{10})(?!\d)(?:\.\d+)?")
_FILETIME_RE = re.compile(r"(?<!\d)(1\d{16,17})(?!\d)")

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

_MIN_YEAR = 1990
_MAX_YEAR = 2100


def _plausible(dt: datetime) -> bool:
    return _MIN_YEAR <= dt.year <= _MAX_YEAR


def _precision(frac: str) -> str:
    if not frac:
        return "s"
    return "ms" if len(frac) <= 3 else "us" if len(frac) <= 6 else "ns"


def _iso_from_match(m: re.Match[str]) -> tuple[datetime, str, bool] | None:
    frac = m.group("frac") or ""
    tz = (m.group("tz") or "").strip()
    tz_assumed = not tz
    try:
        if m.group("H") is None:
            dt = datetime(int(m.group("y")), int(m.group("m")), int(m.group("d")))
        else:
            dt = datetime(
                int(m.group("y")), int(m.group("m")), int(m.group("d")),
                int(m.group("H")), int(m.group("M")), int(m.group("S") or 0),
            )
    except ValueError:
        return None
    if tz:
        if tz == "Z":
            dt = dt.replace(tzinfo=UTC)
        else:
            offset = tz.replace(":", "")
            sign = 1 if offset.startswith("+") else -1
            hours = int(offset[1:3])
            minutes = int(offset[3:5]) if len(offset) > 3 else 0
            dt = dt.replace(tzinfo=UTC) - timedelta(
                hours=sign * hours, minutes=sign * minutes
            )
    else:
        # Policy: naive timestamps are UTC, flagged by the caller.
        dt = dt.replace(tzinfo=UTC)
    if not _plausible(dt):
        return None
    if m.group("H") is None:
        precision = "d"
    elif m.group("S") is None:
        precision = "m"
    else:
        precision = _precision(frac)
    return dt, precision, tz_assumed


def _parse_us(m: re.Match[str]) -> datetime | None:
    try:
        hour = int(m.group("H") or 0)
        if (m.group("ampm") or "").lower() == "pm" and hour < 12:
            hour += 12
        if (m.group("ampm") or "").lower() == "am" and hour == 12:
            hour = 0
        dt = datetime(
            int(m.group("y")), int(m.group("m")), int(m.group("d")),
            hour, int(m.group("M") or 0), int(m.group("S") or 0),
        )
    except ValueError:
        return None
    return dt if _plausible(dt) else None


def parse_time_value(raw: str, *, year_hint: int | None = None) -> dict | None:
    """Parse one timestamp string/number → dict or None (never a guess)."""
    text = str(raw or "").strip()
    if not text:
        return None
    m = _ISO_RE.search(text)
    if m and m.group("y"):
        got = _iso_from_match(m)
        if got:
            dt, precision, tz_assumed = got
            return {
                "dt": dt, "raw": text, "precision": precision,
                "tz_assumed": tz_assumed, "year_assumed": False,
            }
    m = _US_RE.search(text)
    if m:
        dt = _parse_us(m)
        if dt:
            return {
                "dt": dt, "raw": text,
                "precision": "s" if m.group("H") else "d",
                "tz_assumed": True, "year_assumed": False,
            }
    m = _SYSLOG_RE.search(text)
    if m:
        year = year_hint or datetime.now(UTC).year
        try:
            dt = datetime(
                year, _MONTHS[m.group("mon").lower()], int(m.group("d")),
                int(m.group("H")), int(m.group("M")), int(m.group("S")),
            )
        except ValueError:
            dt = None
        if dt and _plausible(dt):
            return {
                "dt": dt, "raw": text, "precision": "s",
                "tz_assumed": True, "year_assumed": True,
            }
    m = _FILETIME_RE.search(text)
    if m:
        dt = _from_filetime(int(m.group(1)))
        if dt is not None:
            return {
                "dt": dt, "raw": text, "precision": "ns",
                "tz_assumed": False, "year_assumed": False,
            }
    m = _EPOCH_RE.search(text)
    if m:
        dt = _from_epoch(int(m.group(1)))
        if dt is not None:
            return {
                "dt": dt, "raw": text,
                "precision": "ms" if len(m.group(1)) == 13 else "s",
                "tz_assumed": False, "year_assumed": False,
            }
    return None


def _from_epoch(value: int) -> datetime | None:
    divisor = 1 if value < 10**11 else 1000
    try:
        dt = datetime.fromtimestamp(value / divisor, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return dt if _plausible(dt) else None


def _from_filetime(value: int) -> datetime | None:
    # Windows FILETIME: 100-ns ticks since 1601-01-01.
    try:
        dt = datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=value // 10)
    except (OverflowError, ValueError):
        return None
    return dt if _plausible(dt) else None


def extract_event_ts(
    text: str,
    fields: dict[str, str] | None = None,
    *,
    year_hint: int | None = None,
) -> dict | None:
    """Best event time for a row: parsed columns first, then the raw text."""
    if fields:
        low_map = {str(k).strip().lower(): v for k, v in fields.items()}
        for col in TIME_COLUMNS:
            raw = low_map.get(col)
            if raw in (None, ""):
                continue
            got = parse_time_value(str(raw), year_hint=year_hint)
            if got:
                return got
    return parse_time_value(text or "", year_hint=year_hint)
