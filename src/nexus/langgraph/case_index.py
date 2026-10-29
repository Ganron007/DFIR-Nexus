"""N3 per-case Elasticsearch backend — same N4 hit schema as the CSV pack.

Indexes only this case's processed outputs (extractions / sift/extractions).
Never walks Evidence-files/. Offline fallback remains the CSV query pack.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import sqlite3
import tempfile
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

log = logging.getLogger(__name__)

from nexus.langgraph.ecs_normalize import normalize
from nexus.langgraph.field_registry import KEYWORD_IGNORE_ABOVE, field_text
from nexus.langgraph.match_site import classify_matched_terms
from nexus.langgraph.mft_join import resolve_usn_row
from nexus.langgraph.path_sanitize import (
    machine_roots,
    sanitize_field_map,
    sanitize_row_text,
)
from nexus.langgraph.query_pack import (
    _DATE_RE,
    _SKIP_SUFFIXES,
    EXTRACTION_PATTERNS,
    _count_fact_sites,
    _row_in_window,
    _scan_prio,
    finalize_hits,
    is_staging_copy,
    is_tool_own_log,
    iter_extraction_files,
    needle_in_text,
)
from nexus.langgraph.timestamps import NO_EVENT_TIME_FIELD, extract_event_ts

_LARGE_NEEDLES = (
    "sdelete", ".pst", ".ost", "drivefs", "googledrive", "my drive",
    "usbstor", "mimikatz", "rubeus", "psexec", "psexesvc",
    "wevtutil", "1102", "encodedcommand", "dataoverwrite",
    "rundll32", "mshta", "lsass", "schtasks", "bitsadmin",
    "security.evtx",
)
# No ignore_above on the wildcard subfields (operator decision 2026-10-11). The old 32,766-byte cap
# was our own setting, not an Elasticsearch limit: ES 8.17.4 indexes a 300 KB value in a wildcard
# field, and a substring query finds it (measured with a scratch index). None = no cap.
WILDCARD_IGNORE_ABOVE = None


def _wildcard_mapping() -> dict[str, Any]:
    """The mapping of a wildcard subfield (substring search over the whole value)."""
    if WILDCARD_IGNORE_ABOVE is None:
        return {"type": "wildcard"}
    return {"type": "wildcard", "ignore_above": WILDCARD_IGNORE_ABOVE}


#: The analyzer of ``text`` (D195). The standard tokenizer keeps a dotted name as one word, so
#: ``{"match":{"text":"lsass"}}`` found 20 of CASE-C5B04D31's 18,970 lsass rows. The word parts of
#: a name are indexed beside it (``lsass.exe`` -> ``lsass.exe``, ``lsass``, ``exe``) and the query
#: is split the same way as a graph, so ``lsass.exe`` still matches only lsass.exe and a phrase
#: such as "powershell.exe -EncodedCommand" keeps its positions. Proved on a scratch index of the
#: local ES on 2026-10-15.
FORENSIC_TEXT_ANALYZER = "forensic_text_v1"
_FORENSIC_WORD_PARTS = {
    "type": "word_delimiter_graph",
    "preserve_original": True,
    "split_on_case_change": False,
    "split_on_numerics": False,
    "generate_word_parts": True,
    "generate_number_parts": True,
    "stem_english_possessive": False,
}
_FORENSIC_TEXT_ANALYSIS = {
    "filter": {"forensic_word_parts": _FORENSIC_WORD_PARTS},
    "analyzer": {
        # Indexing flattens the graph (an index stores positions, not graphs).
        "forensic_text": {"type": "custom", "tokenizer": "standard",
                          "filter": ["forensic_word_parts", "flatten_graph", "lowercase"]},
        "forensic_text_search": {"type": "custom", "tokenizer": "standard",
                                 "filter": ["forensic_word_parts", "lowercase"]},
    },
}

# Index schema version. v2 = structured docs (host/user/event_id + parsed
# columns under fields.*) so DSL filters and aggregations push down to ES.
# A version mismatch triggers a rebuild on the next index_case()/ensure_index.
# 8: WO-17 - delimited files are indexed by CSV record (a quoted newline is
# one doc; line = the record's starting physical line). Doc counts change for
# every multi-line-cell CSV; the mismatch triggers the same rebuild.
# 8 = typed fields.* from the field registry + structured host/user/event_id.
# 9 = D34 (WO-KM1 item 1): the importer's normalized columns (process_name,
#     process_id, parent_process, command_line, file_path, file_hash_*,
#     registry_key, registry_value, action) are indexed as fields AND in the
#     row text. A bump is required, not cosmetic: an index built at v8 silently
#     omits those columns from every search, and this is exactly what the
#     reviewer proved with a mimikatz command line that could not be found.
# 10 = WO-CS1: a pure `normalize(family, fields, record)` adds `doc["ecs"]` - one
#     ECS field set per row (mapped in `data/schema/ecs_map.yaml`), ADDED beside the
#     per-tool columns. Nothing is removed, so an unnormalized doc equals the
#     schema-9 doc (the "nothing lost" acceptance).
# 11 = WO-CS1b item 1 (D37): the column-count cap dropped EvtxECmd's `Payload`
#     (27 columns, Payload LAST), so no EventData or derived `ecs` field was ever
#     produced. The cap is raised past the widest real output (JLECmd: 43) and the
#     per-value cap from 300 to 4096; event_data.ScriptBlockText may reach 32 KB.
# v12 (2026-10-11): no cap or cut on valid evidence (walked files, row text, field values,
# columns); a header only for delimited tables (.csv/.tsv); .tsv is walked; host/user carry
# ignore_above, so a long value cannot reject its document.
# v13 (2026-10-11): the wildcard subfields carry no ignore_above, so a substring search reaches a
# row of any length (see WILDCARD_IGNORE_ABOVE). An index built before it must be rebuilt.
# v14 (2026-10-13, D120): an event time is a time column's whole value, or a time read from the row's text; a bare
# number inside text is never a time. An index built before it carries fabricated times and must be rebuilt.
# v15 (2026-10-17, D260): .NET's JSON date, /Date(<ms>)/, is a time column's whole value. An index built before it has
# no time on any DeepBlueCLI row and must be rebuilt.
# v16 (2026-10-18, D271): `fields` holds column names, not paths (`subobjects: false`): Zeek's `id.orig_h` beside the
# importers' `id` column made Elasticsearch reject every Zeek row with an address. An index built before it must be
# rebuilt.
# v17 (2026-10-18, D287): a tool family's host and user come from the columns its ECS map names (Zeek's HTTP Host
# header and FTP default, Hindsight's cookie domains are no row's host or user). An index built before it must be
# rebuilt.
# v18 (2026-10-18, D250): an imported capture's DNS packets carry their query name (`dns_query`,
# `ecs.dns.question.name`). An index built before it must be rebuilt.
# v19 (2026-10-26, D399/D402/D403): `fields.*` types are those the field registry checked on populated values (a
# contradicted type is text), the date formats read what the tools write, flags are `true`/`false`, `ts_raw` is the
# time as written, nfdump's summary is its own record, and keyword sub-fields hold up to 8,191 characters. An index
# built before it silently left values out of typed and keyword fields and must be rebuilt.
# v20 (2026-10-29, D470/D471): MemProcFS's columns are read per table (an event row's channel, code, record and host; a
# connection's addresses; a scheduled task's principal id is no account), and a Windows event's user is the pinned
# EvtxECmd map's `UserName` whichever tool read the event. An index built before it has no channel on any event read
# from memory, so every stored Windows-event query missed those rows, and must be rebuilt.
INDEX_SCHEMA_VERSION = 20

# JSON-family artifacts are line records (NDJSON/JSONL), never delimited tables.
_JSON_RECORD_SUFFIXES = (".json", ".jsonl", ".ndjson")
# No column, field value or row text is capped (operator decision 2026-10-11: valid evidence is
# not cut). The mapping's keyword copies are bounded by ignore_above; the analyzed text, the
# stored row text and fields.* keep every value whole.

# ES rejects monolithic term scans ("Query rewrite failed: too many clauses"):
# every needle expands to 2-3 clauses (match_phrase + fields.* multi_match +
# text.wc wildcard, and wildcard rewrite expands further). Whole-case scans
# (100+ needles) are therefore CHUNKED: each chunk is a separate query and the
# results merge. Never silently drop terms — if a chunk still fails it is split
# and retried, and anything that cannot be queried is recorded in `stats`.
_MAX_ES_TERMS_PER_QUERY = 40


class IndexMissing(RuntimeError):
    """Case index not created yet — CSV pack should be used."""


def es_url() -> str:
    return (os.environ.get("NEXUS_ES_URL") or "").strip().rstrip("/")


def index_name(case_id: str) -> str:
    raw = re.sub(r"[^a-z0-9-]", "-", (case_id or "unknown").lower())
    raw = re.sub(r"-+", "-", raw).strip("-") or "unknown"
    return f"nexus-case-{raw}"


#: Elasticsearch endpoints whose answer is read-only: a dropped connection is safe to send again (D219).
_READ_ONLY_ES_ENDPOINTS = frozenset({"_search", "_count", "_msearch", "_field_caps", "_mapping",
                                     "_mappings", "_validate"})
_SHARED_CLIENTS: dict[str, Any] = {}
_SHARED_LOCK = threading.Lock()


def _read_only_request(request: Any) -> bool:
    if request.method in ("GET", "HEAD"):
        return True
    if request.method == "POST":
        parts = [p for p in request.url.path.split("/") if p]
        return bool(parts) and parts[-1] in _READ_ONLY_ES_ENDPOINTS
    return False


def _reset_retry_transport(inner: Any) -> Any:
    """A transport that sends a read-only request once more when Elasticsearch dropped its connection.

    A write (bulk, delete, index creation) is never resent: it may have been applied (D219).
    """
    import httpx

    class _ResetRetryTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            try:
                return inner.handle_request(request)
            except (httpx.ReadError, httpx.WriteError, httpx.RemoteProtocolError):
                if not _read_only_request(request):
                    raise
                log.debug("ES dropped the connection on %s %s; sending once more",
                          request.method, request.url.path)
                return inner.handle_request(request)

        def close(self) -> None:
            inner.close()

    return _ResetRetryTransport()


class _SharedClient:
    """The pooled client, used as `with _client() as c:` or directly; neither closes the pool."""

    def __init__(self, client: Any):
        self._client = client

    def __enter__(self) -> Any:
        return self._client

    def __exit__(self, *_exc: Any) -> bool:
        return False

    def close(self) -> None:
        """The pool outlives its callers; a caller's close is not the pool's."""

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def _client():
    """The pooled client of the configured Elasticsearch, one per URL (D219).

    Every call used to open its own client: a new TCP connection for each request, two per search.
    A Mode 2 run sends hundreds of searches and the suite thousands; through the Docker port forwarder
    such churn ended in `WinError 10054` resets (a stored-query test, 2026-10-15). The connections are
    now kept and reused, and a read-only request whose connection was dropped is sent once more.
    """
    import httpx

    url = es_url()
    if not url:
        raise IndexMissing("NEXUS_ES_URL is empty")
    parsed = urlparse(url)
    if parsed.hostname in {"192.168.77.50", "elk"}:
        raise RuntimeError("N3 must not point at the CADRE elk SIEM (.50)")
    with _SHARED_LOCK:
        client = _SHARED_CLIENTS.get(url)
        if client is None or client.is_closed:
            transport = _reset_retry_transport(httpx.HTTPTransport(retries=1))
            client = httpx.Client(base_url=url, timeout=120.0, transport=transport)
            _SHARED_CLIENTS[url] = client
    return _SharedClient(client)


# A full purge deletes every document of the case in one request. At millions of rows it runs longer than
# the 120 s client default; the clear then reported a timeout after it had removed the documents
# (CASE-C5B04D31, 2026-10-11), and the index was left empty. The purge gets a timeout that fits its work.
_PURGE_TIMEOUT_S = 1800.0


# Availability probe cache — an ES URL that is configured but unreachable
# (black-holed SYN, VPN down) must not stall every query: probe with a short
# connect timeout and cache the result briefly (WP-review 2026-09-14).
_es_probe_cache: tuple[float, bool] | None = None
_ES_PROBE_TTL = 30.0
_ES_PROBE_TIMEOUT = 5.0
_ES_PROBE_CONNECT = 3.0


def elasticsearch_ready() -> bool:
    """True when Elasticsearch is configured and reachable (never raises)."""
    try:
        return bool(es_available())
    except Exception:  # noqa: BLE001
        return False


def es_available() -> bool:
    global _es_probe_cache
    if not es_url():
        return False
    import time

    now = time.monotonic()
    if _es_probe_cache is not None and now - _es_probe_cache[0] < _ES_PROBE_TTL:
        return _es_probe_cache[1]
    import httpx

    available = False
    try:
        parsed = urlparse(es_url())
        if parsed.hostname in {"192.168.77.50", "elk"}:
            raise RuntimeError("N3 must not point at the CADRE elk SIEM (.50)")
        with httpx.Client(base_url=es_url(),
                          timeout=httpx.Timeout(_ES_PROBE_TIMEOUT, connect=_ES_PROBE_CONNECT)) as client:
            r = client.get("/")
            available = bool(r.status_code == 200 and "version" in r.json())
    except Exception:  # noqa: BLE001 — unreachable ES means "not available"
        available = False
    _es_probe_cache = (now, available)
    return available


def _case_year_hint(case_dir: Path) -> int | None:
    """Syslog year hint from the case window (never a blind local guess)."""
    try:
        from nexus.langgraph.query_pack import load_case_intake, parse_intake_window

        start, _end = parse_intake_window(load_case_intake(case_dir))
        return start.year if start else None
    except Exception:  # noqa: BLE001 — hint is optional
        return None


def _ts_from_line(line: str) -> str | None:
    m = _DATE_RE.search(line)
    if not m:
        return None
    stamp = m.group(1)
    if m.group(2):
        return f"{stamp}T{m.group(2)}Z"
    return f"{stamp}T00:00:00Z"


def _should_keep_large_line(low: str, extra_needles: list[str]) -> bool:
    if any(needle_in_text(low, n) for n in extra_needles):
        return True
    return any(needle_in_text(low, n) for n in _LARGE_NEEDLES)


def _index_small_prio(path: Path) -> tuple:
    n = str(path).lower()
    if "bmc-tools" in n or "bitmap" in n:
        return (90, n)
    return _scan_prio(path)


def _index_large_prio(path: Path) -> tuple:
    n = str(path).lower()
    for i, hint in enumerate(
        ("hayabusa", "evtx", "usn", "mftecmd", "pecmd", "amcache", "srum")
    ):
        if hint in n:
            return (i, n)
    return (40, n)


def _split_row(line: str) -> list[str]:
    """CSV/TSV row split (quotes survive); whitespace fallback."""
    import csv
    import io

    sep = "\t" if ("\t" in line and "," not in line) else ","
    try:
        return next(csv.reader(io.StringIO(line), delimiter=sep))
    except (csv.Error, StopIteration):
        return line.split(sep)


#: Files read as CSV/TSV records (WO-17). A quoted cell containing newlines is
#: ONE record; ``.log``/``.txt`` keep the physical-line path on purpose (an
#: unbalanced quote in a log line must not stop the file).
_DELIMITED_SUFFIXES = (".csv", ".tsv")


def _is_delimited(path: Path) -> bool:
    """True for .csv/.tsv (transparent ``.gz``)."""
    name = path.name.lower()
    if name.endswith(".gz"):
        name = name[:-3]
    return name.endswith(_DELIMITED_SUFFIXES)


def iter_record_rows(fh, delimiter: str = ",", *, on_fallback=None):
    """Yield ``(start_line, raw_text, cells)`` per CSV/TSV record (WO-17/D63).

    ``start_line`` is the record's first physical line - what the doc's and a
    hit's ``line`` carry - and ``raw_text`` preserves the original quoting.
    Streaming: a spooled temporary file buffers the current record and spills
    to disk without discarding it when the record is larger than memory's
    preferred working size.

    There is no application-defined record-size limit. On malformed CSV, the
    reader falls back to physical-line rows from the malformed record through
    EOF so later rows remain searchable. Cells are ``None`` on fallback rows.
    ``on_fallback(start_line, reason)`` is called once.
    """
    import csv
    import io
    import sys
    import tempfile

    with contextlib.suppress(OverflowError):  # the CSV parser's platform integer limit
        csv.field_size_limit(sys.maxsize)
    line_no = 0
    record_start = 1
    in_quotes = False
    at_field_start = True
    with tempfile.SpooledTemporaryFile(
        max_size=1024 * 1024, mode="w+t", encoding="utf-8", newline="",
    ) as spool:

        def _fallback(reason: str, start: int) -> Iterator[tuple[int, str, None]]:
            if on_fallback is not None:
                on_fallback(start, reason)
            spool.seek(0)
            current_line = start
            for physical_line in spool:
                yield current_line, physical_line, None
                current_line += 1
            for physical_line in fh:
                yield current_line, physical_line, None
                current_line += 1

        for physical_line in fh:
            line_no += 1
            spool.write(physical_line)
            pos = 0
            while pos < len(physical_line):
                char = physical_line[pos]
                if in_quotes:
                    if char == '"':
                        if pos + 1 < len(physical_line) and physical_line[pos + 1] == '"':
                            pos += 2
                            continue
                        in_quotes = False
                        at_field_start = False
                elif char == delimiter or char in "\r\n":
                    at_field_start = True
                elif char == '"' and at_field_start:
                    in_quotes = True
                else:
                    at_field_start = False
                pos += 1
            if in_quotes:
                continue

            spool.seek(0)
            raw = spool.read()
            try:
                cells = next(csv.reader(io.StringIO(raw), delimiter=delimiter, strict=True))
            except StopIteration:
                cells = []
            except csv.Error as exc:
                yield from _fallback(f"csv error: {exc}", record_start)
                return
            yield record_start, raw, cells
            record_start = line_no + 1
            at_field_start = True
            spool.seek(0)
            spool.truncate(0)

        if line_no >= record_start:
            if in_quotes:
                yield from _fallback("unterminated quoted field at end of file", record_start)
            else:
                spool.seek(0)
                raw = spool.read()
                try:
                    cells = next(csv.reader(io.StringIO(raw), delimiter=delimiter, strict=True))
                except StopIteration:
                    cells = []
                except csv.Error as exc:
                    yield from _fallback(f"csv error: {exc}", record_start)
                else:
                    yield record_start, raw, cells


def _fields_from_values(header: list[str], values: list[str]) -> dict[str, str]:
    """Parsed columns for one row, at FULL value length (WO-CS1b item 1 / D37).

    No per-value truncation here: `normalize()` and the index must read the
    full parsed row, or an EvtxECmd `Payload` may be cut and EventData lost.
    """
    out: dict[str, str] = {}
    for name, value in zip(header, values, strict=False):
        v = str(value).strip()
        if v and not str(name).startswith("_"):
            out[str(name)] = v
    return out


def _stored_field_values(fields: dict[str, str] | None) -> dict[str, str]:
    """The field map stored under ``doc["fields"]``: every value whole (operator decision 2026-10-11)."""
    return {str(k): str(v) for k, v in (fields or {}).items()}


def _row_fields(line: str, header: list[str] | None) -> dict[str, str]:
    """Parsed columns for one row (schema v2: indexed under ``fields.*``)."""
    if not header:
        return {}
    return _fields_from_values(header, _split_row(line))


def _nfdump_summary(records):
    """nfdump's ``Summary`` block as one record under its own header, with no event time (D402)."""
    summary_header: list[str] | None = None
    for start, raw, cells in records:
        if cells is None or not any(str(c).strip() for c in cells):
            continue
        if summary_header is None:
            summary_header = [str(c).strip() for c in cells]
            continue
        fields = _fields_from_values(summary_header, cells)
        fields[NO_EVENT_TIME_FIELD] = "true"
        yield start, raw, fields
        return


def iter_indexable_rows(
    path: Path,
    fh,
    header: list[str] | None,
    *,
    stats: dict | None = None,
    file_label: str = "",
):
    """``(line_no, raw_text, row_fields)`` per indexable row of an open file.

    WO-17: delimited files WITH a header (``.csv``/``.tsv``) are read as CSV
    records - a quoted newline is one row and ``line_no`` is the row's starting
    physical line; JSON families stay physical-line records; everything else
    keeps the line-based path. The header row and blank rows are skipped.

    WO-22: malformed CSV falls back to physical-line rows and the fallback
    (file, line, reason) is recorded in ``stats["csv_fallback"]``. Valid
    records have no application-defined length limit.
    """
    # D118 (2026-10-13): a YARA report is one record per match block, not one per line.
    if _yara_report(path):
        yield from _yara_blocks(fh)
        return
    # D117 (2026-10-13): a Zeek TSV log is one record per data line; its `#` lines are the header block.
    zeek = _zeek_header(path)
    if zeek is not None:
        for i, line in enumerate(fh, start=1):
            if not line.strip() or line.startswith("#"):
                continue
            yield i, line, _zeek_row_fields(line, zeek)
        return
    is_csv = bool(header) and _is_delimited(path) and not _is_json_records(path)
    if is_csv:
        name = path.name.lower()
        delim = "\t" if (name.endswith(".tsv") or name.endswith(".tsv.gz")) else ","

        def _on_fallback(start: int, reason: str) -> None:
            if stats is not None:
                stats.setdefault("csv_fallback", []).append({
                    "file": file_label or path.name,
                    "line": start,
                    "reason": reason,
                })

        from nexus.ingest.network.nfdump import (
            is_nfdump_summary_marker,
            looks_like_nfdump_csv_header,
        )

        untimed = _untimed_csv(path, header)
        nfdump = looks_like_nfdump_csv_header(header)
        records = iter(iter_record_rows(fh, delimiter=delim, on_fallback=_on_fallback))
        first = True
        for start, raw, cells in records:
            if first:
                first = False  # the header record
                continue
            if nfdump and cells is not None and is_nfdump_summary_marker(cells):
                # D402: nfdump's flows end here; the totals that follow have their own header.
                yield from _nfdump_summary(records)
                return
            if cells is None:  # WO-22 fallback row: no reliable columns
                if not raw.strip():
                    continue
                yield start, raw, _no_time_if(untimed, _row_fields(raw, header))
                continue
            if not any(str(c).strip() for c in cells):
                continue
            yield start, raw, _no_time_if(untimed, _fields_from_values(header, cells))
        return
    json_records = _is_json_records(path)
    for i, line in enumerate(fh, start=1):
        if i == 1 and header is not None:
            continue
        if not line.strip():
            continue
        row = _record_fields(line, flatten=_is_suricata_eve(path)) if json_records else _row_fields(line, header)
        if json_records and _is_registry_value(row):
            row[NO_EVENT_TIME_FIELD] = "true"
        # A Suricata stats event is the engine's counters, stamped when the engine ran, not an event of the evidence
        # (D273).
        if json_records and str(row.get("event_type") or "") == "stats" and _is_suricata_eve(path):
            row[NO_EVENT_TIME_FIELD] = "true"
        yield i, line, row


# TA-Z (2026-10-24): MFTECmd 2026.10's `$LogFile` CSV, one row per log record (pinned README at 2919ded, "$LogFile").
# A log record carries no time of its own; CreatedOn..LastAccessedOn are the file times its data holds (19,761 of
# T06's 138,736 rows), so the free-text fallback must not read one of them as the record's time.
_LOGFILE_RECORD_COLUMNS = frozenset({"lsn", "transactionid", "transactionfirstlsn", "redooperation", "undooperation"})


def _untimed_csv(path: Path, header: list[str] | None) -> bool:
    """True for a CSV whose rows name no event time of their own.

    A YARA CSV's dates are the rule's and the process's (D120, 2026-10-13); a `$LogFile` record's are the file's.
    """
    if path.name.lower() == "yara.csv":
        return True
    columns = {str(c).strip().lstrip("﻿").lower() for c in header or ()}
    return columns >= _LOGFILE_RECORD_COLUMNS


def _no_time_if(untimed: bool, fields: dict[str, str]) -> dict[str, str]:
    if untimed:
        fields[NO_EVENT_TIME_FIELD] = "true"
    return fields


def _is_registry_value(fields: dict[str, str]) -> bool:
    """A MemProcFS registry value row has no write time of its own. Only a key carries one (``lastwrite``) (D120)."""
    return fields.get("class") == "REG" and fields.get("type") == "value"


# D117 (2026-10-13): a Zeek TSV log names its columns in a `#fields` line; the `#` lines above it are the header block.
# An unset cell is `-` and an empty one is `(empty)`: neither is a value, so neither is stored.
_ZEEK_EMPTY = frozenset({"-", "(empty)", ""})


def _zeek_header(path: Path) -> list[str] | None:
    """The column names of a Zeek TSV log (its ``#fields`` line), or None when the file is not one."""
    if not path.name.lower().endswith((".log", ".log.gz")):
        return None
    try:
        with _open_text_auto(path) as fh:
            for n, line in enumerate(fh):
                if n >= 40:
                    break
                if line.startswith("#fields"):
                    return line.rstrip("\r\n").split("\t")[1:]
                if not line.startswith("#"):
                    return None
    except OSError:
        return None
    return None


def _zeek_row_fields(line: str, header: list[str]) -> dict[str, str]:
    """One Zeek TSV record as fields. Unset and empty cells are not stored."""
    out: dict[str, str] = {}
    # A row with more cells than the header keeps the header's columns; a short row keeps the cells it has.
    for name, value in zip(header, line.rstrip("\r\n").split("\t"), strict=False):
        if value not in _ZEEK_EMPTY:
            out[name] = value
    return out


# D118 (2026-10-13): a MemProcFS YARA report writes each match as a block. `Match Index:` opens the block, `Label: value`
# lines carry the rule and its process context, and `Matches:` opens the string addresses and a hexdump. A block is one
# record: its fields are its labels with their spaces removed, and its text is the whole block.
_YARA_START = "Match Index:"


def _yara_report(path: Path) -> bool:
    """True when the file is a MemProcFS YARA report: its first non-blank line opens a match block."""
    try:
        with _open_text_auto(path) as fh:
            for n, line in enumerate(fh):
                if n >= 20:
                    break
                if line.strip():
                    return line.lstrip().startswith(_YARA_START)
    except OSError:
        return False
    return False


def _yara_block_fields(lines: list[str]) -> dict[str, str]:
    """The header labels of one match block: its ``Label: value`` lines before ``Matches:``, labels without spaces."""
    out: dict[str, str] = {}
    for line in lines:
        text = line.rstrip("\r\n")
        if text.startswith("Matches:"):
            break
        label, sep, value = text.partition(":")
        name = "".join(label.split())
        if sep and name and not name.startswith("-") and value.strip():
            out[name] = value.strip()
    # The rule's dates (Creation_date, Last_modified) and the process's start time are not the time of the match: a
    # YARA report names no match time, so the block has no event time (D120, 2026-10-13).
    out[NO_EVENT_TIME_FIELD] = "true"
    return out


def _yara_blocks(fh) -> Iterator[tuple[int, str, dict[str, str]]]:
    """``(starting line, block text, fields)`` for each match block of an open YARA report."""
    block: list[str] = []
    start = 0
    for i, line in enumerate(fh, start=1):
        if line.startswith(_YARA_START):
            if "".join(block).strip():
                yield start, "".join(block), _yara_block_fields(block)
            block, start = [], i
        block.append(line)
    if "".join(block).strip():
        yield start, "".join(block), _yara_block_fields(block)


# D119 (2026-10-13): Volatility writes its output as JSON lines in a `.txt` file. The name says text; the content says
# records. A `.txt` file is read as records when each of its first non-blank lines is one JSON object.
def _json_lines_text(path: Path) -> bool:
    """True when a `.txt` file's first non-blank lines are each one JSON object."""
    seen = 0
    try:
        with _open_text_auto(path) as fh:
            for n, line in enumerate(fh):
                if n >= 40:
                    break
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    return False
                if not isinstance(obj, dict):
                    return False
                seen += 1
                if seen >= 3:
                    break
    except OSError:
        return False
    return seen > 0


def _is_suricata_eve(path: Path) -> bool:
    """True for Suricata's eve.json, whose nested keys are flattened into dotted field names (D117)."""
    return path.name.lower().startswith("eve.json")


def _collect_scalars(obj: dict, prefix: str, out: dict[str, str], flatten: bool) -> None:
    """The scalar values of one JSON object. With ``flatten`` a nested object contributes its scalars under dotted names."""
    for name, value in obj.items():
        key = f"{prefix}{name}"
        if str(name).startswith("_"):
            continue
        if isinstance(value, dict):
            if flatten:
                _collect_scalars(value, f"{key}.", out, flatten)
            continue
        if isinstance(value, list) or value in (None, ""):
            continue
        out[key] = str(value)


def _is_json_records(path: Path) -> bool:
    """True for JSON/JSONL/NDJSON artifacts (transparent ``.gz``), and for a ``.txt`` whose lines are JSON objects (D119)."""
    name = path.name.lower()
    if name.endswith(".gz"):
        name = name[:-3]
    if name.endswith(_JSON_RECORD_SUFFIXES):
        return True
    return name.endswith(".txt") and _json_lines_text(path)


def _record_fields(line: str, flatten: bool = False) -> dict[str, str]:
    """Scalar fields of one JSON record line ({} when it is not a dict). ``flatten`` (D117) keeps nested scalars as dotted names.

    Mirrors ``_row_fields`` for NDJSON artifacts, so ``fields.*`` and the
    host/user/event extraction work for JSON exactly as they do for CSV.
    """
    stripped = line.strip()
    if not stripped or stripped[0] != "{":
        return {}
    try:
        obj = json.loads(stripped)
    except ValueError:
        return {}
    if not isinstance(obj, dict):
        return {}
    out: dict[str, str] = {}
    _collect_scalars(obj, "", out, flatten)
    return out


def _pick_field(fields: dict[str, str], keys: frozenset[str]) -> str:
    """First non-empty field value whose column name matches (case-insensitive).

    ``keys`` is a prebuilt frozenset of lowercased names (module constant), so the
    hot path allocates nothing per call and the name match is a single set lookup
    rather than a per-field ``.lower()`` + membership scan (WO-R0F item 1: this ran
    3x per row across millions of rows).
    """
    for name, value in fields.items():
        if value and name.lower() in keys:
            return str(value)
    return ""


_HOST_KEYS = frozenset(("computer", "computername", "host", "hostname"))
_USER_KEYS = frozenset((
    "user", "username", "userid", "account", "accountname",
    "targetuser", "sourceuser", "user_name",
))
_EVENT_KEYS = frozenset(("eventid", "event_id", "eventcode"))


def _host_user_event(
    fields: dict[str, str], family: str = "", importer: bool = False, table: str = "",
    ecs: dict[str, Any] | None = None,
) -> tuple[str, str, str]:
    """A row's host, user and event id. The user the row's ECS layer typed (``ecs``) is its user: a Windows event's
    from the pinned map, whichever tool read the event (D471), a table's account column (D470). A tool family whose ECS
    map names its host and user columns is otherwise read only through those (D287: Zeek's `host` is an HTTP Host
    header, its FTP `user` default `<unknown>`; D470: MemProcFS's, per table, so a scheduled task's principal id is no
    account); otherwise, and for a row the importer pass wrote, by the generic column names."""
    from nexus.langgraph.ecs_normalize import declared_host_user, is_absent

    typed = str(((ecs or {}).get("user") or {}).get("name") or "")
    declared = None if importer else declared_host_user(family, table)
    if declared is not None:
        host_cols, user_cols = declared

        def _first(cols: tuple[str, ...]) -> str:
            return next((str(fields[c]) for c in cols if fields.get(c) and not is_absent(family, c, fields[c])), "")

        return _first(host_cols), typed or _first(user_cols), _pick_field(fields, _EVENT_KEYS)
    host = _pick_field(fields, _HOST_KEYS)
    user = typed
    if not user:
        for name, value in fields.items():
            if value and name.lower() in _USER_KEYS:
                user = str(value)
                if name == "UserName" and fields.get("Channel") and fields.get("EventId"):
                    # EvtxECmd's UserName is its map's template rendered (`Context: %UserContext%`,
                    # `%domain%\%user% (%sid%)`): the user is what the map placed in it (D214).
                    from nexus.langgraph.evtx_templates import map_value

                    user = map_value(fields["Channel"], fields["EventId"], name, user)
                break
    event = _pick_field(fields, _EVENT_KEYS)
    return host, user, event


def _index_rel(path: Path, root: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")


def _text_encoding(head: bytes) -> str:
    """The encoding of a tool's text output, from its first bytes (D207).

    Windows tools write UTF-16: Mplog-Parser's CSVs and the WER reports carry the UTF-16LE BOM. Read
    as UTF-8 they became text with a NUL after every character, so CASE-C5B04D31's 310 such files
    (Defender's detections and threat actions among them) indexed as rows no search could match,
    and their column names reached the field sheet as ``\\x00a\\x00c\\x00t...``.
    """
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    # UTF-16LE with no BOM: ASCII text with a NUL after every character.
    odd, even = head[1::2], head[0::2]
    if len(head) >= 8 and odd and odd.count(0) == len(odd) and even.count(0) == 0:
        return "utf-16-le"
    return "utf-8"


def _open_text_auto(path: Path):
    """Text open with transparent gzip decompression (EH-11) and the file's own encoding (D207)."""
    if str(path).lower().endswith(".gz"):
        import gzip

        with gzip.open(path, "rb") as raw:
            head = raw.read(64)
        return gzip.open(path, "rt", encoding=_text_encoding(head), errors="replace")
    with path.open("rb") as raw:
        head = raw.read(64)
    return path.open(encoding=_text_encoding(head), errors="replace")


def _index_header(path: Path) -> list[str] | None:
    """Header columns of line 1 when it is a header; else None.

    A delimited table (.csv/.tsv) has a header when line 1 holds a comma or a tab. A line-based
    file (.txt, .log) has one only when line 1 is tab-separated, as a Zeek "#fields" table is:
    a comma in a sentence is not a header. DeepBlueCLI writes its detection summary and status
    lines as sentences on line 1, and five of them were dropped when any comma counted
    (CASE-C5B04D31). JSON/JSONL/NDJSON files are line records, never tables: a JSON object on
    line 1 contains commas, and treating it as a header consumed the first record (a 198-record
    DeepBlueCLI file indexed 197 docs, the first detection lost).
    """
    if _is_json_records(path):
        return None
    first = ""
    try:
        with _open_text_auto(path) as fh:
            first = fh.readline().strip()
    except OSError:
        return None
    if not first:
        return None
    if _is_delimited(path):
        if "," not in first and "\t" not in first:
            return None
    elif "\t" not in first:
        return None
    # A TSV header is split on tabs: a column name may contain a comma.
    is_tsv = path.name.lower().endswith((".tsv", ".tsv.gz"))
    cells = first.split("\t") if is_tsv else _split_row(first)
    return [c.strip().lstrip("\ufeff").strip('"') for c in cells]


def iter_index_doc_batches(
    case_dir: Path,
    extra_needles: list[str] | None = None,
    only_files: set[str] | None = None,
    stats: dict[str, Any] | None = None,
    batch_size: int | None = None,
    run_id: str = "",
):
    """Yield batches of index documents for EVERY row of EVERY indexable file.

    EH-11: streaming (no full-list materialization), no software row/file
    caps, transparent .gz, and no ">80MB matching-lines-only" reduction —
    every row is indexed.
    """
    case_dir = Path(case_dir)
    # ``extra_needles`` is accepted for API compatibility; EH-11 indexes all
    # rows, so no matching-only filtering remains.
    _ = extra_needles
    if batch_size is None:
        try:
            batch_size = int(os.environ.get("NEXUS_INDEX_BATCH", "4000"))
        except ValueError:
            batch_size = 4000
    batch = batch_size if batch_size > 0 else 4000
    caps: dict[str, Any] = {
        "docs_capped": False,
        "families_capped": [],
        "files_capped": 0,
        "capped_files": [],
        "large_files_skipped": 0,
    }
    seen: set[str] = set()
    # WO-3: per-file accepted/deduped counts, so the reconciler can compare a
    # file's own record count with what the index took from it.
    file_counts: dict[str, dict[str, int]] = {}
    out: list[dict[str, Any]] = []
    total = 0
    year_hint = _case_year_hint(case_dir)
    # Compute the machine-path roots ONCE per scan (not per field per row).
    # `sanitize_field_map` re-resolves them otherwise — a Windows realpath syscall
    # per field hung the profiler on large corpora (WO-R0F item 1).
    sanitize_roots = machine_roots(case_dir)
    ts_cov: dict[str, dict[str, int]] = {}

    def _cov(fam: str) -> dict[str, int]:
        return ts_cov.setdefault(fam, {
            "present": 0, "missing": 0, "synthesized": 0,
            "tz_assumed": 0, "year_assumed": 0,
        })

    def _add(path: Path, root: Path, fam: str, i: int, line: str,
             fields: dict[str, str] | None = None, count_key: str | None = None, importer: bool = False) -> bool:
        nonlocal total
        # Source/provenance columns carry the machine path the parser read
        # (EvtxECmd SourceFile, RECmd HivePath, ...) — that is routing
        # metadata, never evidence text. Replace those values outright and
        # normalize remaining machine prefixes (raw files untouched).
        text = sanitize_row_text(
            line.strip(), fields, case_dir, roots=sanitize_roots,
            family=fam
        )
        key = hashlib.sha1(
            f"{fam}\x00{path}\x00{i}\x00{text}".encode("utf-8", "replace")
        ).hexdigest()
        rel = _index_rel(path, root)
        # count_key: the imported store holds every importer's rows in one file, so its rows are
        # counted per family (``<family>/artifacts.jsonl``). A family then reads in the per-file
        # counts like any other folder (WO-TA item 4: scheduled tasks as family ``tasks``).
        rec = file_counts.setdefault(count_key or rel, {"docs": 0, "deduped": 0})
        if key in seen:
            rec["deduped"] += 1
            return False
        seen.add(key)
        rec["docs"] += 1
        doc: dict[str, Any] = {
            "case_id": case_dir.name,
            "family": fam,
            "file": rel,
            "line": i,
            "text": text,
        }
        if fields:
            # WO-CS1b item 1 (D37): the field map is sanitized at full length; the
            # ECS normalization reads THAT (a 1,326-char EvtxECmd Payload must reach
            # it whole). Every parsed field is stored whole in `doc["fields"]`.
            full_fields = sanitize_field_map(fields, case_dir, roots=sanitize_roots,
                                             family=fam)
            # WO-CS1: one common ECS field set, ADDED beside the per-tool columns. It is read first: the row's
            # user is the one it types (D471).
            ecs = normalize(fam, full_fields, None, importer=importer, table=path.name)
            host, user, event = _host_user_event(full_fields, fam, importer, table=path.name, ecs=ecs)
            doc["fields"] = _stored_field_values(full_fields)
            if host:
                doc["host"] = host.lower()
            if user:
                doc["user"] = user.lower()
            if event:
                doc["event_id"] = str(event)
            if ecs:
                doc["ecs"] = ecs
        else:
            ecs = normalize(fam, fields, None, importer=importer, table=path.name)
            if ecs:
                doc["ecs"] = ecs
        # 4k.4: parsed time columns first (TimeCreated/ts/…), then row text;
        # offsets honored, naive == UTC (flagged), syslog year flagged.
        ts_info = extract_event_ts(text, fields, year_hint=year_hint)
        cov = _cov(fam)
        if ts_info:
            doc["ts"] = ts_info["dt"].astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            doc["ts_raw"] = str(ts_info["raw"])
            synth = bool(fields) and str(fields.get("ts_synthesized") or "").lower() in {
                "true", "1", "yes",
            }
            doc["ts_src"] = "synthesized" if synth else "event"
            doc["ts_precision"] = ts_info["precision"]
            explicit_tz = bool(fields) and str(
                fields.get("ts_tz_assumed") or ""
            ).lower() in {"true", "1", "yes"}
            if ts_info["tz_assumed"] or explicit_tz:
                doc["ts_tz_assumed"] = True
            explicit_year = bool(fields) and str(
                fields.get("ts_year_assumed") or ""
            ).lower() in {"true", "1", "yes"}
            if ts_info["year_assumed"] or explicit_year:
                doc["ts_year_assumed"] = True
            cov["present"] += 1
            if synth:
                cov["synthesized"] += 1
            if ts_info["tz_assumed"] or explicit_tz:
                cov["tz_assumed"] += 1
            explicit_year_flag = bool(fields) and str(
                fields.get("ts_year_assumed") or ""
            ).lower() in {"true", "1", "yes"}
            if ts_info["year_assumed"] or explicit_year_flag:
                cov["year_assumed"] += 1
        else:
            cov["missing"] += 1
        out.append(doc)
        total += 1
        return True

    scan_stats = stats if stats is not None else {}
    file_stats: dict[str, Any] = {}
    for path, root, fam in iter_extraction_files(case_dir, stats=file_stats, run_id=run_id):
        if only_files is not None and _index_rel(path, root) not in only_files:
            continue
        header = _index_header(path)
        try:
            with _open_text_auto(path) as fh:
                for i, line, row_fields in iter_indexable_rows(
                    path, fh, header, stats=scan_stats,
                    file_label=_index_rel(path, root)
                ):
                    # D116 (2026-10-13): a USN row's parent directory comes from the MFT of the same run.
                    row_fields = resolve_usn_row(path, row_fields)
                    _add(path, root, fam, i, line, row_fields)
                    if len(out) >= batch:
                        yield out
                        out = []
        except OSError as exc:
            scan_stats.setdefault("files_unreadable", []).append({
                "file": _index_rel(path, root), "error": str(exc),
            })
            continue
    # Imported non-host evidence (network/cloud/TI): clean searchable rows from
    # the case artifact store, family = source. The raw store JSONL is never
    # indexed — this projection is (CSV-scanner parity).
    ingest_store = case_dir / "ingest" / "artifacts.jsonl"
    ingest_wanted = only_files is None or "ingest/artifacts.jsonl" in only_files
    if ingest_store.is_file() and ingest_wanted:
        from nexus.langgraph.query_pack import iter_ingest_records

        for n, fam, text, _ts, record in iter_ingest_records(case_dir):
            art_fields: dict[str, str] = {}
            for key_name in (
                "source", "artifact_type", "severity", "timestamp", "host",
                "user", "source_ip", "source_port", "dest_ip", "dest_port",
                "protocol", "description",
                "ts_synthesized", "ts_year_assumed", "ts_tz_assumed",
            ):
                value = record.get(key_name)
                if value not in (None, "", []):
                    art_fields[key_name] = field_text(value)
            # D34 (WO-KM1 item 1): the importer's normalized columns. They were
            # computed by the importer and stored in ``raw``, but only the
            # envelope above reached the index - so an artifact's process,
            # command line, parent, file path, hashes and registry key were
            # neither a field nor text. An examiner searching ``mimikatz`` in a
            # command line got nothing, which contradicts 4k.2 "index
            # everything". Every one of these goes in BOTH as a ``fields.*``
            # value (so it filters exactly) and in the row text (so a plain
            # full-text search finds it).
            #
            # ``process_id`` is an int in the schema; the index types these as
            # keyword/date only, so it is projected as text like the rest.
            for key_name in (
                "process_name", "process_id", "parent_process", "command_line",
                "file_path", "file_hash_md5", "file_hash_sha1",
                "file_hash_sha256", "registry_key", "registry_value", "action",
            ):
                value = record.get(key_name)
                if value not in (None, "", []):
                    art_fields[key_name] = field_text(value)
            # WO-8: task definitions carry typed fields inside ``raw``; project
            # the ones the field registry types (keyword / date / boolean) so a
            # scheduled-task investigation can filter instead of substring-search.
            raw = record.get("raw") if isinstance(record, dict) else None
            if isinstance(raw, dict):
                actions = [a for a in (raw.get("actions") or []) if isinstance(a, dict)]
                first_action = actions[0] if actions else {}
                triggers = [t for t in (raw.get("triggers") or []) if isinstance(t, dict)]
                first_trigger = triggers[0] if triggers else {}
                for key_name, value in (
                    ("task_uri", raw.get("uri")),
                    ("task_author", raw.get("author")),
                    ("task_registration_date", raw.get("registration_date")),
                    ("task_timezone_assumed", raw.get("timezone_assumed")),
                    ("task_timezone_key_name", raw.get("timezone_key_name")),
                    ("task_timezone_iana", raw.get("timezone_iana")),
                    ("principal_user_id", raw.get("principal_user_id")),
                    ("run_level", raw.get("run_level")),
                    ("logon_type", raw.get("logon_type")),
                    ("task_hidden", raw.get("hidden")),
                    ("task_enabled", raw.get("enabled")),
                    ("action_command", first_action.get("command")),
                    ("action_arguments", first_action.get("arguments")),
                    ("working_directory", first_action.get("working_directory")),
                    ("com_handler_class_id", raw.get("com_handler_class_id")),
                    ("trigger_type", first_trigger.get("type")),
                    ("trigger_start_boundary", first_trigger.get("start_boundary")),
                    ("trigger_enabled", first_trigger.get("enabled")),
                    # D250: an imported capture's DNS query name.
                    ("dns_query", raw.get("dns_query")),
                ):
                    if value not in (None, "", []):
                        art_fields[key_name] = field_text(value)
            family_key =(fam.replace("/", "_").replace("\\", "_") or "ingest")
            _add(ingest_store, case_dir, fam, n, text, art_fields or None,
                 count_key=f"{family_key}/artifacts.jsonl", importer=True)
            if len(out) >= batch:
                yield out
                out = []
    caps["ts_coverage"] = ts_cov
    caps["file_counts"] = file_counts
    scan_stats.update(caps)
    if out:
        yield out


def iter_index_docs(
    case_dir: Path,
    extra_needles: list[str] | None = None,
    only_files: set[str] | None = None,
    stats: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Collecting wrapper over ``iter_index_doc_batches`` (tests/small callers).

    Production paths stream batches — do not call this on very large cases.
    """
    docs: list[dict[str, Any]] = []
    for batch in iter_index_doc_batches(
        case_dir, extra_needles, only_files=only_files, stats=stats
    ):
        docs.extend(batch)
    return docs


def _bulk_ndjson(
    index: str,
    docs: list[dict[str, Any]],
    *,
    id_field: str = "",
) -> str:
    lines: list[str] = []
    import json

    for doc in docs:
        # Full-text hash (EH-8): a prefix would let rows differing only after
        # char 80 share an _id and overwrite each other. Callers that already
        # have a unique id (timeline event_id) pass it; the hash ignores
        # fields those docs do not carry, so every event would collapse to one.
        explicit = str(doc.get(id_field) or "") if id_field else ""
        _id = explicit or hashlib.sha1(
            f"{doc.get('family')}\x00{doc.get('file')}\x00{doc.get('line')}\x00"
            f"{doc.get('text', '')}".encode()
        ).hexdigest()
        lines.append(json.dumps({"index": {"_index": index, "_id": _id}}))
        lines.append(json.dumps(doc, default=str))
    return "\n".join(lines) + "\n"


def _mapping_body() -> dict[str, Any]:
    """Schema v5 — explicit typed ``fields.*`` from the shipped field registry.

    T4: typed properties come from ``data/schema/field_registry.yaml`` (built
    from the validated tool-run catalog); ES never guesses (date/numeric
    detection off), malformed values are skipped per-field, and unmapped
    columns still land through the dynamic template as ``text + kw``.
    """
    from nexus.langgraph.field_registry import field_properties

    props = field_properties()
    # A column's name is its own field, dots and all (D271): with sub-objects on, Zeek's `id.orig_h` became the path
    # `fields.id` -> `orig_h`, the importers' `id` column had typed `fields.id` as text, and Elasticsearch rejected
    # every Zeek conn, dns, http and files row of sample S04 (3,556 rows).
    fields_spec: dict[str, Any] = {"type": "object", "subobjects": False}
    if props:
        fields_spec["properties"] = props
    return {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            # "N/A" in a long/date column skips that field only; the doc and
            # its _source stay complete (P1-adjacent honesty, not a dropped row).
            "index.mapping.ignore_malformed": True,
            # 694 registry columns + keyword subfields exceed the 1000 default.
            "index.mapping.total_fields.limit": 10000,
            "analysis": _FORENSIC_TEXT_ANALYSIS,
        },
        "mappings": {
            # The analyzer is recorded, not versioned: a version bump makes every reader treat an
            # older index as legacy (no field catalog, no ES aggregations) and the next indexing
            # call drop it. An index built before keeps the standard analyzer until it is rebuilt.
            "_meta": {"schema_version": INDEX_SCHEMA_VERSION, "text_analyzer": FORENSIC_TEXT_ANALYZER},
            "date_detection": False,
            "numeric_detection": False,
            "dynamic_templates": [
                {
                    "fields_strings": {
                        "path_match": "fields.*",
                        "match_mapping_type": "string",
                        "mapping": {
                            "type": "text",
                            "fields": {"kw": {"type": "keyword", "ignore_above": KEYWORD_IGNORE_ABOVE}},
                        },
                    }
                },
                {
                    # WO-CS1: an ECS event-data name (`ecs.winlog.event_data.<Name>`)
                    # is keyword + wildcard so it filters exactly and searches by pattern.
                    "ecs_event_data_strings": {
                        "path_match": "ecs.winlog.event_data.*",
                        "match_mapping_type": "string",
                        "mapping": {
                            "type": "keyword",
                            "ignore_above": KEYWORD_IGNORE_ABOVE,
                            "fields": {"wc": _wildcard_mapping()},
                        },
                    }
                },
                {
                    # WO-CS1: remaining ECS strings are keyword (so `term` and
                    # `wildcard` work on the base name the WO's acceptance names),
                    # with a `text` subfield for a phrase query.
                    "ecs_strings": {
                        "path_match": "ecs.*",
                        "match_mapping_type": "string",
                        "mapping": {
                            "type": "keyword",
                            "ignore_above": KEYWORD_IGNORE_ABOVE,
                            "fields": {
                                "wc": _wildcard_mapping(),
                                "text": {"type": "text"},
                            },
                        },
                    }
                },
            ],
            "properties": {
                "case_id": {"type": "keyword"},
                "family": {"type": "keyword"},
                "file": {"type": "keyword"},
                "line": {"type": "integer"},
                "host": {"type": "keyword", "ignore_above": KEYWORD_IGNORE_ABOVE},
                "user": {"type": "keyword", "ignore_above": KEYWORD_IGNORE_ABOVE},
                "event_id": {"type": "keyword"},
                "text": {
                    "type": "text",
                    "analyzer": "forensic_text",
                    "search_analyzer": "forensic_text_search",
                    "fields": {"wc": _wildcard_mapping()},
                },
                "ts": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
                # Phase 4k.4 — timestamp authority: raw text, origin,
                # precision and the "we had to assume" flags.
                "ts_raw": {"type": "keyword", "ignore_above": 64},
                "ts_src": {"type": "keyword"},
                "ts_precision": {"type": "keyword"},
                "ts_tz_assumed": {"type": "boolean"},
                "ts_year_assumed": {"type": "boolean"},
                "fields": fields_spec,
                # WO-CS1: the common ECS field set, added beside the tool columns.
                "ecs": {"type": "object", "dynamic": True},
            },
        },
    }


_schema_cache: dict[str, tuple[float, int]] = {}
_fields_props_cache: dict[str, tuple[float, list[str]]] = {}
_SCHEMA_CACHE_TTL = 60.0


def index_schema_version(case_id: str) -> int:
    """Current mapping's _meta.schema_version (0 = missing/unreadable)."""
    name = index_name(case_id)
    try:
        with _client() as client:
            r = client.get(f"/{name}/_mapping")
            if r.status_code != 200:
                return 0
            mappings = (r.json().get(name) or {}).get("mappings") or {}
            meta = mappings.get("_meta") or {}
            return int(meta.get("schema_version") or 0)
    except Exception:  # noqa: BLE001 — absent index/unreachable ES → legacy path
        return 0


def _schema_version_cached(case_id: str) -> int:
    import time

    now = time.monotonic()
    cached = _schema_cache.get(case_id)
    if cached and (now - cached[0]) < _SCHEMA_CACHE_TTL:
        return cached[1]
    version = index_schema_version(case_id)
    _schema_cache[case_id] = (now, version)
    return version


def fields_property_names(case_id: str) -> list[str]:
    """Parsed column names present in ``fields.*`` (cached 60 s)."""
    import time

    now = time.monotonic()
    cached = _fields_props_cache.get(case_id)
    if cached and (now - cached[0]) < _SCHEMA_CACHE_TTL:
        return cached[1]
    names: list[str] = []
    name = index_name(case_id)
    try:
        with _client() as client:
            r = client.get(f"/{name}/_mapping")
            if r.status_code == 200:
                props = ((r.json().get(name) or {}).get("mappings") or {}).get(
                    "properties", {}
                )
                names = list((props.get("fields") or {}).get("properties", {}).keys())
    except Exception:  # noqa: BLE001
        names = []
    _fields_props_cache[case_id] = (now, names)
    return names


def ensure_index(case_id: str) -> str:
    name = index_name(case_id)
    with _client() as client:
        exists = client.head(f"/{name}")
        if exists.status_code == 200:
            if _schema_version_cached(case_id) >= INDEX_SCHEMA_VERSION:
                return name
            # Schema upgrade — drop and recreate; index_case() repopulates.
            client.delete(f"/{name}")
            _schema_cache.pop(case_id, None)
            _fields_props_cache.pop(case_id, None)
        r = client.put(f"/{name}", json=_mapping_body())
        if r.status_code >= 400:
            raise RuntimeError(f"create index failed: {r.status_code} {r.text[:300]}")
    return name


def _chunks(items: list[str], size: int) -> list[list[str]]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def _index_file_keys(case_dir: Path, run_id: str = ""):
    """Yield ``(key, path)`` for every indexable file (B6 / WO-A5 digests).

    The ingest store is keyed as ``ingest/artifacts.jsonl`` to match the doc
    ``file`` value (a bare ``artifacts.jsonl`` key made incremental indexing
    blind to imported evidence). When the same rel path exists in several
    roots, the first root that resolves it wins — matching the doc ``file``
    value the indexer actually wrote.
    """
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    extractions = resolve_tools_extractions(case_dir, run_id)
    roots = [extractions, extractions.parent / "sift" / "extractions", case_dir / "ingest"]
    seen: dict[str, Path] = {}
    for path in iter_index_files(case_dir, run_id):
        for root in roots:
            try:
                rel = str(path.relative_to(root)).replace("\\", "/")
            except ValueError:
                continue
            if root == case_dir / "ingest":
                rel = f"ingest/{rel}"
            seen.setdefault(rel, path)
            break
    yield from seen.items()


def _index_file_mtimes(case_dir: Path, run_id: str = "") -> dict[str, float]:
    """Doc ``file`` value -> mtime_ns for every indexable file (B6).

    When the same rel path exists in several roots, the MAX mtime wins so any
    copy's update still triggers a reindex.
    """
    out: dict[str, float] = {}
    for rel, path in _index_file_keys(case_dir, run_id):
        with contextlib.suppress(OSError):
            mtime = float(path.stat().st_mtime_ns)
            out[rel] = max(out.get(rel, 0.0), mtime)
    return out


def _index_file_digests(case_dir: Path, run_id: str = "") -> dict[str, str]:
    """Doc ``file`` value -> SHA-256 for every indexable file (WO-A5).

    Stored with the index state so ``nexus index verify`` can prove the rows
    in the index still match the files on disk. Large files stream.
    """
    import hashlib

    out: dict[str, str] = {}
    for rel, path in _index_file_keys(case_dir, run_id):
        try:
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            out[rel] = h.hexdigest()
        except OSError as exc:
            log.warning("index digest failed for %s: %s", rel, exc)
    return out


def _bulk_insert(
    client,
    name: str,
    docs: list[dict[str, Any]],
    chunk: int = 2000,
    *,
    id_field: str = "",
    rejected: dict[str, dict[str, Any]] | None = None,
) -> int:
    """Bulk-index docs; returns the number of item-level errors.

    ``rejected`` collects, per file, how many of its rows Elasticsearch refused and the first reason (D271): the
    count alone was kept, and the run said every row was indexed.
    """
    errors = 0
    for i in range(0, len(docs), chunk):
        part = docs[i:i + chunk]
        body = _bulk_ndjson(name, part, id_field=id_field)
        r = client.post("/_bulk", content=body, headers={"Content-Type": "application/x-ndjson"})
        if r.status_code >= 400:
            raise RuntimeError(f"bulk failed: {r.status_code} {r.text[:300]}")
        payload = r.json()
        if payload.get("errors"):
            for doc, item in zip(part, payload.get("items") or [], strict=False):
                error = (item.get("index") or {}).get("error")
                if not error:
                    continue
                errors += 1
                if rejected is not None:
                    entry = rejected.setdefault(str(doc.get("file") or ""), {"rows": 0, "reason": ""})
                    entry["rows"] += 1
                    entry["reason"] = entry["reason"] or str(
                        (error.get("reason") if isinstance(error, dict) else error) or "")[:300]
    return errors


def index_case(
    case_dir: Path,
    extra_needles: list[str] | None = None,
    *,
    incremental: bool = False,
    run_id: str = "",
) -> dict[str, Any]:
    """Build (or incrementally refresh) the case's N3 index.

    ``run_id`` names the tools run whose output is indexed. The lane passes the run it is building:
    that run is committed only at the report step, and an unnamed resolution indexes the run
    committed before it (CASE-C5B04D31, 2026-10-11). Empty means the committed run, as readers see it.

    ``incremental=True`` only re-indexes files whose mtime advanced since the
    last build and purges docs for files that disappeared — the autoindex path
    used to delete and rebuild the entire case on every run (B6). Falls back to
    a full rebuild when there is no usable prior state or the index is empty.
    An EMPTY resolution over a populated index is refused (``purge_refused``):
    that is a resolver/run-pointer failure, not deleted evidence.
    """
    case_dir = Path(case_dir)
    started_at = datetime.now(UTC)
    # Only the examiner's ingest folder. Tool output already lands in a
    # family-named subfolder, and moving files during the lane would race the
    # tool that is still writing them.
    from nexus.ingest.fingerprint import place_loose_csvs

    place_loose_csvs(case_dir / "ingest")
    name = ensure_index(case_dir.name)
    import json

    out = case_dir / "analysis"
    out.mkdir(parents=True, exist_ok=True)
    state_file = out / "index_state.json"
    prior: dict[str, Any] = {}
    if state_file.is_file():
        try:
            loaded = json.loads(state_file.read_text(encoding="utf-8"))
            prior = loaded if isinstance(loaded, dict) else {}
        except (OSError, ValueError):
            prior = {}
    prior_mtimes = prior.get("file_mtimes") or {}
    current_mtimes = _index_file_mtimes(case_dir, run_id) if incremental else {}
    # A different run from the one indexed (the lane's new run, or a retry over another) replaces the
    # index. Its documents are dropped with the index in one step, not file by file: a per-file delete
    # over millions of documents from the superseded run takes far longer than an empty index.
    prior_source = str(prior.get("source_extractions") or "")
    current_source = _source_extractions_text(case_dir, run_id)
    replaces_run = bool(prior_source and current_source and prior_source != current_source)

    use_incremental = bool(incremental and prior_mtimes and current_mtimes and not replaces_run)
    # R09: an mtime is not content identity. Archive extraction and preserved
    # timestamps can keep an mtime while the bytes change, so the change set also
    # compares each file's digest with the stored baseline (and reindexes any file
    # that has no baseline digest). The digests are computed once, here.
    prior_digests: dict[str, str] = prior.get("file_sha256s") or {}
    current_digests: dict[str, str] = _index_file_digests(case_dir, run_id) if use_incremental else {}
    baseline_digests: dict[str, str] | None = None
    if use_incremental:
        with _client() as client:
            head = client.head(f"/{name}")
            count_resp = client.post(f"/{name}/_count")
            if head.status_code != 200 or count_resp.status_code >= 400:
                use_incremental = False
            else:
                try:
                    indexed_docs = int(count_resp.json().get("count") or 0)
                except ValueError:
                    indexed_docs = 0
                if indexed_docs <= 0 or indexed_docs != int(prior.get("docs") or -1):
                    # Fresh/empty index → full rebuild. A doc-count mismatch
                    # also means a previous run failed mid-way — heal instead
                    # of blessing the reduced index as current.
                    use_incremental = False

    if use_incremental:
        changed = {
            rel for rel, mtime in current_mtimes.items()
            if mtime > float(prior_mtimes.get(rel, -1))
            or rel not in prior_digests
            or current_digests.get(rel) != prior_digests.get(rel)
        }
        removed = set(prior_mtimes) - set(current_mtimes)
        errors = 0
        rejected: dict[str, dict[str, Any]] = {}
        # A resolution of ZERO indexable files is never "the examiner deleted
        # every artifact" — it is a resolver/run-pointer failure (e.g. a
        # --from-case run that owns no extractions). Purging here would make
        # the case read as empty evidence: refuse and keep the index.
        purge_refused = not current_mtimes and bool(prior_mtimes)
        purge_refused_reason = ""
        if purge_refused:
            purge_refused_reason = (
                "zero indexable files resolved while "
                f"{len(prior_mtimes)} are indexed — purge refused"
            )
            log.error("incremental reindex purge refused: %s", purge_refused_reason)
            docs_total = int(prior.get("docs") or 0)
        else:
            with _client() as client:
                for batch in _chunks(sorted(removed | changed), 100):
                    cleared = client.post(
                        f"/{name}/_delete_by_query",
                        params={"refresh": "true", "conflicts": "proceed"},
                        json={"query": {"terms": {"file": batch}}},
                    )
                    if cleared.status_code >= 400:
                        raise RuntimeError(
                            f"incremental delete failed: {cleared.status_code} {cleared.text[:300]}"
                        )
                cap_stats: dict[str, Any] = {}
                docs = 0
                errors = 0
                rejected: dict[str, dict[str, Any]] = {}
                for batch_docs in iter_index_doc_batches(
                    case_dir, only_files=changed, stats=cap_stats, run_id=run_id
                ):
                    docs += len(batch_docs)
                    errors += _bulk_insert(client, name, batch_docs, rejected=rejected)
                refreshed = client.post(f"/{name}/_refresh")
                if refreshed.status_code >= 400:
                    raise RuntimeError(
                        f"index refresh failed: {refreshed.status_code} {refreshed.text[:300]}"
                    )
                count_resp = client.post(f"/{name}/_count")
                try:
                    docs_total = int(count_resp.json().get("count") or 0)
                except ValueError:
                    docs_total = prior.get("docs", 0)
        prior_coverage = {}
        prior_counts: dict[str, Any] = {}
        try:
            prior_meta = json.loads(
                (out / "es_index.json").read_text(encoding="utf-8")
            )
            prior_coverage = prior_meta.get("ts_coverage") or {}
            prior_counts = prior_meta.get("file_counts") or {}
        except (OSError, ValueError):
            prior_coverage = {}
            prior_counts = {}
        # WO-3: per-file counts survive for untouched files; changed files get
        # a fresh count and removed files drop out.
        # The imported store's per-family keys (``<family>/artifacts.jsonl``) all come from one
        # file: when that file changes or goes, every one of them is stale, not only one.
        store_changed = bool({"ingest/artifacts.jsonl"} & (set(changed) | set(removed)))
        merged_counts = {
            rel: entry for rel, entry in prior_counts.items()
            if rel not in removed and rel not in changed
            and not (store_changed and str(rel).endswith("/artifacts.jsonl"))
        }
        merged_counts.update(cap_stats.get("file_counts") or {})
        # R09: the baseline advances only for files whose documents are in the index.
        # A refused purge keeps the prior baseline; a bulk error drops the changed
        # files from it, so the next run reindexes them instead of blessing them.
        baseline_digests = {k: v for k, v in current_digests.items() if k not in removed}
        if purge_refused:
            baseline_digests = dict(prior_digests)
        elif errors:
            for rel in changed:
                baseline_digests.pop(rel, None)
        with _client() as client:
            unindexed = unindexed_field_values(client, name)
        meta = {
            "index": name,
            "docs": docs_total,
            "errors": errors,
            "rejected": rejected,
            "unindexed_field_values": unindexed,
            "case_id": case_dir.name,
            "url": es_url(),
            "incremental": True,
            "files_reindexed": sorted(changed),
            "files_removed": sorted(removed),
            "purge_refused": purge_refused,
            "purge_refused_reason": purge_refused_reason,
            # Coverage is only exact on full rebuilds; an incremental pass
            # keeps the prior full picture rather than replacing it with a
            # partial one (4k.4.3 review fix).
            "ts_coverage": prior_coverage or cap_stats.get("ts_coverage") or {},
            "file_counts": merged_counts,
            "caps": cap_stats,
            "capped": bool(
                cap_stats.get("docs_capped")
                or cap_stats.get("families_capped")
                or cap_stats.get("files_capped")
            ),
        }
    else:
        cap_stats = {}
        docs_total = 0
        errors = 0
        rejected: dict[str, dict[str, Any]] = {}
        purge_refused = False
        purge_refused_reason = ""
        # The full branch used to purge unconditionally. On an EMPTY resolution
        # over a populated index that is not a rebuild — it is evidence loss
        # from a resolver/run-pointer failure (seen live: a --from-case run
        # that owns no extractions zeroed a 128k-doc index). Refuse and keep.
        resolved_mtimes = _index_file_mtimes(case_dir, run_id)
        with _client() as client:
            count_resp = client.post(f"/{name}/_count")
            try:
                existing_docs = int(count_resp.json().get("count") or 0)
            except ValueError:
                existing_docs = 0
            if not resolved_mtimes and existing_docs > 0 and prior_mtimes:
                purge_refused = True
                purge_refused_reason = (
                    "zero indexable files resolved while "
                    f"{existing_docs} docs are indexed — full-rebuild purge refused"
                )
                log.error("index purge refused: %s", purge_refused_reason)
                docs_total = existing_docs
            else:
                # The whole index is replaced: dropping it removes every document in one request, and
                # ensure_index recreates it with the mapping. A match-all delete reaches the same empty
                # index much more slowly over millions of documents.
                dropped = client.delete(f"/{name}", timeout=_PURGE_TIMEOUT_S)
                if dropped.status_code >= 400 and dropped.status_code != 404:
                    raise RuntimeError(
                        f"index drop failed: {dropped.status_code} {dropped.text[:300]}"
                    )
                name = ensure_index(case_dir.name)
                errors = 0
                rejected: dict[str, dict[str, Any]] = {}
                # EH-11: stream batches — a million-row case must not be
                # materialized in memory before the first bulk request.
                for batch_docs in iter_index_doc_batches(case_dir, stats=cap_stats, run_id=run_id):
                    docs_total += len(batch_docs)
                    errors += _bulk_insert(client, name, batch_docs, rejected=rejected)
                    if docs_total % 50_000 < len(batch_docs):
                        log.info("indexed %d docs…", docs_total)
                refreshed = client.post(f"/{name}/_refresh")
                if refreshed.status_code >= 400:
                    raise RuntimeError(
                        f"index refresh failed: {refreshed.status_code} {refreshed.text[:300]}"
                    )
            unindexed = unindexed_field_values(client, name)
        meta = {
            "index": name,
            "docs": docs_total,
            "errors": errors,
            "rejected": rejected,
            # D399: values a typed column could not hold, per field. They stay in `_source` and `text`, but a query
            # on that field cannot match them; the gate shows this instead of letting it pass silently.
            "unindexed_field_values": unindexed,
            "case_id": case_dir.name,
            "url": es_url(),
            "incremental": False,
            "purge_refused": purge_refused,
            "purge_refused_reason": purge_refused_reason,
            "ts_coverage": cap_stats.get("ts_coverage") or {},
            "file_counts": cap_stats.get("file_counts") or {},
            "caps": cap_stats,
            "capped": bool(
                cap_stats.get("docs_capped")
                or cap_stats.get("families_capped")
                or cap_stats.get("files_capped")
            ),
        }

    # WO-TA item 10: the build's own duration (purge, load, refresh), recorded beside the counts so the
    # speed of indexing is measured here, not inferred from when the state file was last written.
    meta["index_started_at"] = started_at.isoformat()
    meta["index_seconds"] = round((datetime.now(UTC) - started_at).total_seconds(), 1)
    (out / "es_index.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    write_index_state(
        case_dir, meta,
        file_mtimes=current_mtimes or _index_file_mtimes(case_dir, run_id),
        file_sha256s=baseline_digests,
        run_id=run_id,
    )
    # WO-TA item 9: the gate is re-derived from what the index now holds. The index stands even if
    # this fails; the gate then keeps its last state, and the log says why.
    try:
        from nexus.langgraph.lane_gate import reconcile_after_index

        reconcile_after_index(
            case_dir, meta.get("file_counts") or {}, run_id=run_id,
            unindexed_field_values=meta.get("unindexed_field_values"),
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("gate reconciliation after indexing failed: %s", exc)
    _schema_cache.pop(case_dir.name, None)
    _fields_props_cache.pop(case_dir.name, None)
    with contextlib.suppress(Exception):
        from nexus.langgraph.field_catalog import invalidate_catalog

        invalidate_catalog(case_dir.name)
    with contextlib.suppress(Exception):
        from nexus.tools.evidence_index import invalidate_mappings_cache

        invalidate_mappings_cache(case_dir.name)
    return meta


def delete_index(case_id: str) -> dict[str, Any]:
    """Best-effort delete of a case's ES index (case cleanup path).

    Never raises: ES may be down or the index may not exist. Callers report
    ``deleted``/``reason`` honestly. ES data is rebuildable from the case's
    extraction outputs, so cleanup is safe.
    """
    name = index_name(case_id)
    if not es_url():
        return {"index": name, "deleted": False, "reason": "NEXUS_ES_URL unset"}
    try:
        with _client() as client:
            r = client.delete(f"/{name}")
            if r.status_code == 404:
                return {"index": name, "deleted": False, "reason": "index absent"}
            if r.status_code >= 400:
                return {
                    "index": name, "deleted": False,
                    "reason": f"{r.status_code} {r.text[:120]}",
                }
        _schema_cache.pop(case_id, None)
        _fields_props_cache.pop(case_id, None)
        with contextlib.suppress(Exception):
            from nexus.langgraph.field_catalog import invalidate_catalog

            invalidate_catalog(case_id)
        with contextlib.suppress(Exception):
            from nexus.tools.evidence_index import invalidate_mappings_cache

            invalidate_mappings_cache(case_id)
        return {"index": name, "deleted": True, "reason": ""}
    except Exception as exc:  # noqa: BLE001 — cleanup must never block
        return {"index": name, "deleted": False, "reason": f"{type(exc).__name__}: {exc}"}


def _newest_extraction_mtime(case_dir: Path) -> float:
    """Newest mtime across this case's processed outputs (0 when none).

    Uses ``iter_index_files`` so the ingest artifact store and files beyond
    the small-scan cap still count — anything the indexer reads can make the
    index stale.
    """
    newest = 0.0
    for path in iter_index_files(case_dir):
        try:
            newest = max(newest, path.stat().st_mtime)
        except OSError:
            continue
    return newest


def _source_extractions_text(case_dir: Path, run_id: str = "") -> str:
    try:
        from nexus.langgraph.pipeline_runs import resolve_tools_extractions

        return str(resolve_tools_extractions(case_dir, run_id))
    except Exception:  # noqa: BLE001 - an unresolvable case records no source
        return ""


def unindexed_field_values(client: Any, name: str) -> dict[str, dict[str, Any]]:
    """Per field, the documents whose value the field could not hold (`_ignored`), with the field's mapped type.

    `index.mapping.ignore_malformed` keeps such a document whole and leaves only that value out of the field index,
    without a word (D399: 32,146 NetFlow rows had no queryable source or destination address); a keyword field leaves
    out a value longer than its `ignore_above` (D403). This is the count, and the type says which of the two it was.
    """
    body = {"size": 0, "aggs": {"ignored": {"terms": {"field": "_ignored", "size": 500}}}}
    try:
        resp = client.post(f"/{name}/_search", json=body)
        buckets = ((resp.json().get("aggregations") or {}).get("ignored") or {}).get("buckets") or []
    except Exception:  # noqa: BLE001 - the count is a report; the index stands without it
        return {}
    counts = {str(b.get("key")): int(b.get("doc_count") or 0) for b in buckets}
    types: dict[str, str] = {}
    if counts:
        try:
            mapped = client.get(f"/{name}/_mapping/field/{','.join(counts)}").json()
            for spec in ((mapped.get(name) or {}).get("mappings") or {}).values():
                for full, body_ in (spec.get("mapping") or {}).items():
                    types[str(spec.get("full_name") or full)] = str((body_ or {}).get("type") or "")
        except Exception:  # noqa: BLE001
            types = {}
    return {field: {"docs": docs, "type": types.get(field, "")} for field, docs in counts.items()}


def write_index_state(
    case_dir: Path,
    meta: dict[str, Any],
    *,
    file_mtimes: dict[str, float] | None = None,
    file_sha256s: dict[str, str] | None = None,
    run_id: str = "",
) -> None:
    """Persist index freshness state for staleness detection + incremental B6.

    WO-A5: the SHA-256 of every indexed source file is stored alongside the
    mtimes so ``nexus index verify`` can prove post-index modification.
    """
    import json
    from datetime import UTC, datetime

    case_dir = Path(case_dir)
    newest = _newest_extraction_mtime(case_dir)
    state = {
        "indexed_at": datetime.now(UTC).isoformat(),
        "newest_extraction_mtime": newest,
        "docs": meta.get("docs", 0),
        "index": meta.get("index", ""),
        "url": es_url(),
        "file_mtimes": file_mtimes if file_mtimes is not None else _index_file_mtimes(case_dir, run_id),
        "file_sha256s": file_sha256s if file_sha256s is not None else _index_file_digests(case_dir, run_id),
        # R13: the exact extractions folder the rows were read from (the run indexed), so verify
        # re-hashes that run's files, not whichever run is newest later.
        "source_extractions": _source_extractions_text(case_dir, run_id),
        "capped": bool(meta.get("capped")),
        "caps": meta.get("caps") or {},
    }
    out = case_dir / "analysis"
    out.mkdir(parents=True, exist_ok=True)
    (out / "index_state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")


def index_stale(case_dir: Path) -> tuple[bool, dict[str, Any]]:
    """True when extractions are newer than the last index build.

    Returns (stale, info). info is empty when the case was never indexed.
    """
    case_dir = Path(case_dir)
    state_file = case_dir / "analysis" / "index_state.json"
    if not state_file_exists(state_file):
        return True, {"reason": "never indexed"}
    try:
        import json

        state = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True, {"reason": "unreadable index state"}
    newest = _newest_extraction_mtime(case_dir)
    indexed_at = float(state.get("newest_extraction_mtime") or 0)
    if newest > indexed_at + 1:  # 1s tolerance for filesystem jitter
        return True, {
            "reason": "extractions newer than index",
            "indexed_at": state.get("indexed_at", ""),
            "newest_extraction": newest,
        }
    return False, {"indexed_at": state.get("indexed_at", ""), "docs": state.get("docs")}


def state_file_exists(path: Path) -> bool:
    return path.is_file()


def iter_index_files(case_dir: Path, run_id: str = "") -> list[Path]:
    """Files the indexer walks (for mtime staleness checks).

    Applies the same ledger/meta skip rules as iter_extraction_files and
    includes ingest/artifacts.jsonl because the indexer projects its rows.
    """
    case_dir = Path(case_dir)
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    extractions = resolve_tools_extractions(case_dir, run_id)
    tools_run_dir = extractions.parent
    roots = [extractions, tools_run_dir / "sift" / "extractions", case_dir / "ingest"]
    out: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        pats = EXTRACTION_PATTERNS
        for pat in pats:
            for p in root.rglob(pat):
                if p.name.startswith("_") or p.name.endswith(_SKIP_SUFFIXES) or is_tool_own_log(p, root):
                    continue
                if is_staging_copy(p, root):
                    continue
                out.append(p)
    return out


# ---------------------------------------------------------------------------
# WP 4j.31/4j.32 — N4 AST → Elasticsearch push-down + native aggregations
# ---------------------------------------------------------------------------

def _term_clause(term: str, search_fields: bool = False) -> dict[str, Any]:
    """One N4 term as ES: analyzed phrase + substring wildcard (parity).

    Wildcard metacharacters are escaped like the legacy path, and **numeric
    terms keep only the phrase clause** — ``*1102*`` matches inside hashes and
    file sizes (the CSV backend's ``needle_in_text`` has a hex-boundary guard
    this query cannot express), which both invents false rows and starves
    genuine hits out of the fetch cap.

    ``search_fields`` adds the schema-v2 parsed columns (``fields.*``) so a
    term that lives in a structured column matches even when the raw line is
    compact (imported evidence). The row-side re-check receives the same
    parsed values, so ES and CSV stay identical.
    """
    t = str(term or "").strip()
    if not t:
        return {"match_none": {}}
    should: list[dict[str, Any]] = [{"match_phrase": {"text": t}}]
    if search_fields:
        # lenient: schema v5 types numeric/date columns explicitly — a phrase
        # query over `fields.*` must not 400 on them (lenient skips the fields
        # that cannot parse the value) while matching every text column.
        should.append({
            "multi_match": {
                "query": t, "fields": ["fields.*"], "type": "phrase", "lenient": True,
            }
        })
    if not t.isdigit():
        safe = t.lower().replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
        should.append({
            "wildcard": {
                "text.wc": {"value": f"*{safe}*", "case_insensitive": True}
            }
        })
    return {"bool": {"should": should, "minimum_should_match": 1}}


_ES_NUMERIC = frozenset({
    "long", "integer", "short", "byte", "double", "float", "half_float",
    "scaled_float", "unsigned_long",
})
_ES_DATE = frozenset({"date", "date_nanos"})


def _row_match_fields(src: dict[str, Any]) -> dict[str, str]:
    """Envelope + parsed columns as the row-side filter map (CSV parity)."""
    out: dict[str, str] = {}
    for key in ("family", "file", "line", "host", "user", "event_id", "ts"):
        value = src.get(key)
        if value not in (None, ""):
            out[key] = str(value)
    fields = src.get("fields")
    if isinstance(fields, dict):
        for name, value in fields.items():
            out.setdefault(str(name), str(value))
    return out


def _filter_to_es(f: dict[str, Any], catalog: dict[str, Any] | None) -> list[dict[str, Any]]:
    """One typed catalog filter → ES clauses (type-aware, hard errors)."""
    from nexus.langgraph.query_dsl import QuerySyntaxError

    name = str(f.get("name") or "")
    op = str(f.get("op") or "contains")
    entry = (catalog or {}).get(name)
    core_path = bool(f.get("path")) and not str(f["path"]).startswith("fields.")
    if catalog is not None and entry is None and not core_path:
        from nexus.langgraph.field_catalog import suggest_field

        hints = suggest_field(catalog, name)
        raise QuerySyntaxError(
            f"unknown field {name!r}"
            + (f" — did you mean {', '.join(hints)}?" if hints else "")
        )
    resolved = str((entry or {}).get("name") or f.get("resolved") or name)
    ftype = str((entry or {}).get("type") or f.get("type") or "text")
    # Path comes from the catalog/filter (core columns are top-level; parsed
    # columns live under fields.*). Never synthesise fields.<core>.
    path = str(f.get("path") or (entry or {}).get("path") or f"fields.{resolved}")
    has_kw = bool(f.get("has_kw", (entry or {}).get("has_kw", True)))
    kw = f"{path}.kw" if has_kw else path
    is_text = path == "text"

    if op == "exists":
        return [{"exists": {"field": kw}}]
    if op == "in":
        values = [str(v) for v in (f.get("values") or []) if str(v).strip()]
        if not values:
            return [{"match_none": {}}]
        target = kw
        return [{
            "bool": {
                "should": [
                    {"term": {target: {"value": v, "case_insensitive": True}}}
                    for v in values
                ],
                "minimum_should_match": 1,
            }
        }]
    if op == "eq":
        if is_text:
            return [{"match_phrase": {"text": str(f.get("value") or "")}}]
        return [{"term": {kw: {"value": str(f.get("value") or ""),
                               "case_insensitive": True}}}]
    if op == "ne":
        return [{"bool": {"must_not": [
            {"term": {kw: {"value": str(f.get("value") or ""),
                           "case_insensitive": True}}}
        ]}}]
    if op == "contains":
        needle = str(f.get("value") or "")
        target = "text.wc" if is_text else kw
        if "*" not in needle and "?" not in needle:
            needle = f"*{needle}*"
        safe = needle.replace("\\", "\\\\").replace('"', '\\"')
        return [{"wildcard": {target: {"value": safe, "case_insensitive": True}}}]
    # comparisons need a numeric/date field
    if ftype not in _ES_NUMERIC | _ES_DATE:
        raise QuerySyntaxError(
            f"operator {op!r} needs a numeric/date field — {resolved!r} is "
            f"{ftype or 'text'}; use = / contains instead"
        )

    def _bound(value: Any) -> Any:
        if value in (None, ""):
            return None
        if ftype in _ES_NUMERIC:
            try:
                number = float(value)
            except (TypeError, ValueError):
                raise QuerySyntaxError(
                    f"{resolved!r} is numeric but {value!r} is not a number"
                ) from None
            return int(number) if number.is_integer() else number
        return str(value)

    if op == "range":
        rng: dict[str, Any] = {}
        lo, hi = _bound(f.get("lo")), _bound(f.get("hi"))
        if lo is not None:
            rng["gte"] = lo
        if hi is not None:
            rng["lte"] = hi
        if not rng:
            raise QuerySyntaxError("range needs at least one bound (a..b)")
        return [{"range": {path: rng}}]
    bound = _bound(f.get("value"))
    if bound is None:
        raise QuerySyntaxError(f"operator {op!r} needs a value")
    return [{"range": {path: {op: bound}}}]


def ast_to_es(query: Any | None, terms: list[str] | None = None,
              match_all: bool = False, search_fields: bool = False,
              catalog: dict[str, Any] | None = None) -> dict[str, Any]:
    """Translate a parsed N4 query into ONE Elasticsearch query (schema v2).

    Field filters push down to real fields: ``family:`` → term on keyword,
    ``file:`` → wildcard on the file keyword, ``host:/user:/event:`` → term on
    the structured keyword PLUS substring wildcard (CSV parity). Terms search
    the row text and — when ``search_fields`` (schema v2) — the parsed
    ``fields.*`` columns too. A row-side ``row_matches`` re-check after the
    fetch keeps both backends identical.

    The term list is NOT truncated here: callers that scan many terms must
    chunk (`query_index` does) — silently dropping terms turns "checked,
    absent" into a lie.
    """
    if query is None or (hasattr(query, "is_empty") and query.is_empty()):
        if terms:
            should = [_term_clause(t, search_fields) for t in terms if str(t).strip()]
            if should:
                return {"bool": {"should": should, "minimum_should_match": 1}}
        return {"match_all": {}}

    must = [_term_clause(t, search_fields) for t in getattr(query, "and_terms", [])]
    should = [_term_clause(t, search_fields) for t in getattr(query, "or_terms", [])]
    must_not = [_term_clause(t, search_fields) for t in getattr(query, "not_terms", [])]
    filt: list[dict[str, Any]] = []
    for fname, fvalue in (getattr(query, "fields", {}) or {}).items():
        value = str(fvalue or "").strip()
        if not value:
            continue
        if fname == "family":
            filt.append({"term": {"family": value.lower()}})
        elif fname == "file":
            filt.append({
                "wildcard": {"file": {"value": f"*{value.lower()}*", "case_insensitive": True}}
            })
        elif fname in {"ts", "time", "timestamp", "date", "eventtime"}:
            # A non-date value on the date field is an ES parse 400 (and the
            # whole search dies to CSV) — treat it as a text match instead.
            filt.append(_term_clause(value, True))
        else:
            key_field = {"host": "host", "user": "user", "event": "event_id"}.get(
                fname, fname
            )
            filt.append({
                "bool": {
                    "should": [
                        {"term": {key_field: value.lower()}},
                        {
                            "wildcard": {
                                "text.wc": {
                                    "value": f"*{value.lower()}*",
                                    "case_insensitive": True,
                                }
                            }
                        },
                    ],
                    "minimum_should_match": 1,
                }
            })
    ts_start = getattr(query, "ts_start", None)
    ts_end = getattr(query, "ts_end", None)
    if ts_start is not None or ts_end is not None:
        rng: dict[str, str] = {}
        if ts_start is not None:
            rng["gte"] = ts_start.isoformat()
        if ts_end is not None:
            rng["lte"] = ts_end.isoformat()
        filt.append({"range": {"ts": rng}})
    for tf in getattr(query, "filters", None) or []:
        filt.extend(_filter_to_es(tf, catalog))
    regex = getattr(query, "regex", None)
    if regex is not None:
        filt.append({
            "regexp": {
                "text.wc": {"value": regex.pattern, "case_insensitive": True}
            }
        })
    body: dict[str, Any] = {}
    if must:
        body["must"] = must
    if should:
        body["should"] = should
        body["minimum_should_match"] = 1
    if must_not:
        body["must_not"] = must_not
    if filt:
        body["filter"] = filt
    return {"bool": body} if body else {"match_all": {}}


_AGG_DIRECT = {
    "family": "family", "file": "file",
    "host": "host", "machine": "host", "computer": "host",
    "user": "user", "account": "user",
    "event": "event_id", "event_id": "event_id", "eventid": "event_id",
}


def _resolve_agg_field(case_id: str, field: str) -> str | None:
    """Map an N4 aggregation field to a concrete ES keyword/date path."""
    low = (field or "").strip().lower()
    if low in _AGG_DIRECT:
        return _AGG_DIRECT[low]
    for name in fields_property_names(case_id):
        if name.lower() == low:
            return f"fields.{name}.kw"
    return None


def es_aggregate(
    case_dir: Path,
    dsl: str = "",
    field: str = "host",
    top: int = 0,
    bucket: str = "",
    match_all: bool = False,
    window: tuple[Any, Any] | None = None,
    with_spans: bool = False,
) -> dict[str, Any] | None:
    """ES-native aggregation (terms / date_histogram) on a schema-v2 index.

    Returns None when not applicable (legacy index, unknown field, ES error,
    empty DSL without match_all) — the caller then uses the deterministic
    Python computation, which keeps the intake-term semantics for empty DSLs.
    """
    case_dir = Path(case_dir)
    case_id = case_dir.name
    if not es_available() or _schema_version_cached(case_id) < INDEX_SCHEMA_VERSION:
        return None
    if not str(dsl or "").strip() and not match_all:
        # The Python path treats an empty DSL as "intake terms", not match-all.
        return None
    from nexus.langgraph.query_dsl import QuerySyntaxError, parse_query

    try:
        from nexus.langgraph.field_catalog import case_field_catalog

        _catalog = case_field_catalog(case_dir)
    except Exception:  # noqa: BLE001 — catalog is best-effort here
        _catalog = None
    try:
        parsed = parse_query(dsl, catalog=_catalog)
    except QuerySyntaxError:
        return None
    agg_field = _resolve_agg_field(case_id, field)
    if agg_field is None:
        return None

    try:
        es_query = ast_to_es(parsed, match_all=match_all, catalog=_catalog)
    except QuerySyntaxError:
        return None
    # The intake window applies here exactly as it does in query_index — an
    # aggregation must never count out-of-window rows.
    start, end = (window or (None, None))
    if start is not None and end is not None:
        window_filter = {
            "bool": {
                "should": [
                    {"range": {"ts": {"gte": start.isoformat(), "lte": end.isoformat()}}},
                    {"bool": {"must_not": {"exists": {"field": "ts"}}}},
                ],
                "minimum_should_match": 1,
            }
        }
        if "bool" in es_query:
            es_query["bool"].setdefault("filter", []).append(window_filter)
        else:
            es_query = {"bool": {"must": [es_query], "filter": [window_filter]}}

    # Composite aggregation pages all distinct values/buckets. `size` is the
    # Elasticsearch response batch size; `after_key` is followed until every
    # bucket has been returned, so the batch size never truncates the census.
    source = (
        {"time": {"date_histogram": {"field": "ts", "calendar_interval": bucket}}}
        if bucket in ("day", "hour")
        else {"value": {"terms": {"field": agg_field}}}
    )
    composite: dict[str, Any] = {"size": 1000, "sources": [source]}
    bucket_rows: list[dict[str, Any]] = []
    try:
        with _client() as client:
            after: dict[str, Any] | None = None
            while True:
                composite_body = dict(composite)
                if after:
                    composite_body["after"] = after
                agg: dict[str, Any] = {"composite": composite_body}
                if with_spans and bucket not in ("day", "hour"):
                    agg["aggs"] = {
                        "first": {"min": {"field": "ts"}},
                        "last": {"max": {"field": "ts"}},
                    }
                body = {
                    "size": 0,
                    "track_total_hits": True,
                    "query": es_query,
                    "aggs": {"v": agg},
                }
                r = client.post(f"/{index_name(case_id)}/_search", json=body)
                if r.status_code >= 400:
                    return None
                data = r.json()
                result = (data.get("aggregations") or {}).get("v") or {}
                bucket_rows.extend(result.get("buckets") or [])
                next_after = result.get("after_key")
                if not next_after:
                    break
                if next_after == after:
                    raise RuntimeError("Elasticsearch composite aggregation cursor did not advance")
                after = next_after
    except Exception:  # noqa: BLE001 — fall back to the exhaustive Python path
        return None

    total = int(((data.get("hits") or {}).get("total") or {}).get("value") or 0)
    if bucket in ("day", "hour"):
        bucket_map: dict[str, int] = {}
        for b in bucket_rows:
            raw = str((b.get("key") or {}).get("time") or "")
            if not raw:
                raw = str(b.get("key_as_string") or "")
            # Composite date keys are epoch milliseconds; normalize to the
            # same ISO hour/day keys as the Python path.
            if raw.isdigit():
                raw = datetime.fromtimestamp(int(raw) / 1000, tz=UTC).isoformat()
            key = raw[:13] + ":00" if bucket == "hour" and len(raw) >= 13 else raw[:10]
            if key:
                bucket_map[key] = int(b.get("doc_count") or 0)
        return {
            "field": field,
            "rows_scanned": total,
            "values_seen": len(bucket_rows),
            "distinct": len(bucket_rows),
            "distinct_approximate": False,
            "top": [],
            "buckets": dict(sorted(bucket_map.items())),
            "backend": "elasticsearch",
        }
    ranked = []
    for b in bucket_rows:
        item: dict[str, Any] = {
            "value": str((b.get("key") or {}).get("value")),
            "count": int(b.get("doc_count") or 0),
        }
        if with_spans:
            first = (b.get("first") or {}).get("value_as_string") or ""
            last = (b.get("last") or {}).get("value_as_string") or ""
            if first:
                item["first_seen"] = first
            if last:
                item["last_seen"] = last
        ranked.append(item)
    ranked.sort(key=lambda item: (-item["count"], item["value"]))
    all_ranked = ranked
    if top > 0:
        ranked = ranked[:top]
    return {
        "field": field,
        "rows_scanned": total,
        "values_seen": sum(b["count"] for b in all_ranked),
        "distinct": len(all_ranked),
        "distinct_approximate": False,
        "top": ranked,
        "buckets": None,
        "backend": "elasticsearch",
    }


def query_index(
    case_dir: Path,
    terms: list[str],
    window: tuple[datetime | None, datetime | None],
    priority_terms: list[str] | None = None,
    query: Any | None = None,
    match_all: bool = False,
    stats: dict[str, Any] | None = None,
    catalog: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    case_dir = Path(case_dir)
    name = index_name(case_dir.name)
    needles = [t.lower() for t in terms if t.strip()]
    if not needles and query is None and not match_all:
        return []
    if stats is not None:
        stats.update({
            "mode": "terms",
            "terms_requested": len(needles),
            "terms_queried": 0,
            "terms_failed": [],
            "chunk_queries": 0,
            "chunks_split": 0,
        })
    from nexus.langgraph.query_pack import _CLOUD_TERMS, _WEAK_TERMS, _strong_set

    strong = _strong_set(priority_terms if priority_terms is not None else terms)
    core = [t for t in needles if t in (strong - _CLOUD_TERMS)]
    cloud = [t for t in needles if t in _CLOUD_TERMS]
    rest = [t for t in needles if t not in core and t not in cloud]
    start, end = window
    filt: list[dict[str, Any]] = []
    if start is not None and end is not None:
        filt.append({
            "bool": {
                "should": [
                    {"range": {"ts": {"gte": start.isoformat(), "lte": end.isoformat()}}},
                    {"bool": {"must_not": {"exists": {"field": "ts"}}}},
                ],
                "minimum_should_match": 1,
            }
        })

    def _should_for(subset: list[str]) -> list[dict[str, Any]]:
        should: list[dict[str, Any]] = []
        for t in subset:
            boost = 10.0 if t in strong - _CLOUD_TERMS else 3.0 if t in _CLOUD_TERMS else 1.0
            if t in _WEAK_TERMS:
                boost = 1.0
            safe = t.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
            should.append({
                "wildcard": {
                    "text.wc": {
                        "value": f"*{safe}*",
                        "case_insensitive": True,
                        "boost": boost,
                    }
                }
            })
            should.append({"match_phrase": {"text": {"query": t, "boost": boost}}})
        return should

    class _SearchFailure(RuntimeError):
        def __init__(self, status: int, message: str):
            super().__init__(message)
            self.status = status

    def _search(client, subset: list[str], size: int) -> list[dict[str, Any]]:
        if not subset and query is None and not match_all:
            return []
        page_size = max(1, min(int(size or 400), 1000))
        body = {
            "size": page_size,
            "query": {
                "bool": {
                    "should": _should_for(subset) or [{"match_all": {}}],
                    "minimum_should_match": 1 if subset else 0,
                    "filter": filt,
                }
            },
        }
        rows: list[dict[str, Any]] = []
        search_after: list[Any] | None = None
        while True:
            request = {**body, "sort": ["_doc"], "track_total_hits": False}
            if search_after:
                request["search_after"] = search_after
            r = client.post(f"/{name}/_search", json=request)
            if r.status_code >= 400:
                raise _SearchFailure(
                    r.status_code,
                    f"search failed: {r.status_code} {r.text[:300]} "
                    f"| query={json.dumps(request)[:600]}",
                )
            page = r.json().get("hits", {}).get("hits", [])
            rows.extend(page)
            if len(page) < page_size:
                break
            search_after = page[-1].get("sort")
            if not search_after:
                raise RuntimeError("full Elasticsearch page omitted its search_after cursor")
        return rows

    with _client() as client:
        head = client.head(f"/{name}")
        if head.status_code != 200:
            raise IndexMissing(f"no index {name}")
        search_fields = False
        if _schema_version_cached(case_dir.name) >= INDEX_SCHEMA_VERSION:
            # WP 4j.31/4j-H.10: pushed-down search. A parsed query (fields/
            # bool/regex) is one request; a raw term SCAN is chunked because a
            # monolithic 100+-needle bool query is rejected by ES ("too many
            # clauses"). Every chunk is queried, results merge, and any term
            # that still cannot be queried is recorded in `stats` — the
            # retrieval layer never reports an unqueried needle as 0 hits.
            try:
                search_fields = bool(fields_property_names(case_dir.name))
            except Exception:  # noqa: BLE001 — fall back to text-only search
                search_fields = False

            def _post_search_all(body: dict[str, Any]) -> list[dict[str, Any]]:
                """Page through every matching row; page size never limits results."""
                page_size = max(1, min(int(body.get("size") or 400), 1000))
                rows: list[dict[str, Any]] = []
                search_after: list[Any] | None = None
                while True:
                    request = {**body, "size": page_size,
                               "sort": ["_doc"], "track_total_hits": False}
                    if search_after:
                        request["search_after"] = search_after
                    r = client.post(f"/{name}/_search", json=request)
                    if r.status_code >= 400:
                        raise _SearchFailure(
                            r.status_code,
                            f"search failed: {r.status_code} {r.text[:300]} "
                            f"| query={json.dumps(request)[:600]}",
                        )
                    page = r.json().get("hits", {}).get("hits", [])
                    rows.extend(page)
                    if stats is not None:
                        stats["search_pages"] = int(stats.get("search_pages") or 0) + 1
                    if len(page) < page_size:
                        break
                    search_after = page[-1].get("sort")
                    if not search_after:
                        raise RuntimeError(
                            "full Elasticsearch page omitted its search_after cursor"
                        )
                return rows

            if query is not None and not (
                hasattr(query, "is_empty") and query.is_empty()
            ):
                if stats is not None:
                    stats["mode"] = "dsl"
                    stats["terms_queried"] = len(needles)
                hits_raw = _post_search_all({
                    "size": 400,
                    "query": _with_filt(
                        ast_to_es(query, search_fields=search_fields,
                                  catalog=catalog),
                        filt,
                    ),
                })
                if stats is not None:
                    stats["hits_fetched"] = len(hits_raw)
            elif not needles:
                if stats is not None:
                    stats["mode"] = "match_all"
                hits_raw = _post_search_all({"size": 400,
                                             "query": _with_filt({"match_all": {}}, filt)})
                if stats is not None:
                    stats["hits_fetched"] = len(hits_raw)
            else:
                hits_raw = []
                queue = [
                    needles[i:i + _MAX_ES_TERMS_PER_QUERY]
                    for i in range(0, len(needles), _MAX_ES_TERMS_PER_QUERY)
                ]
                while queue:
                    chunk = queue.pop(0)
                    if not chunk:
                        continue
                    if stats is not None:
                        stats["chunk_queries"] += 1
                    try:
                        page_rows = _post_search_all({
                            "size": 400,
                            "query": _with_filt(
                                ast_to_es(None, terms=chunk,
                                          search_fields=search_fields),
                                filt,
                            ),
                        })
                    except _SearchFailure as exc:
                        if exc.status >= 400 and len(chunk) > 1:
                            # Clause/rewrite limit hit — split and retry, never drop.
                            mid = len(chunk) // 2
                            queue.insert(0, chunk[mid:])
                            queue.insert(0, chunk[:mid])
                            if stats is not None:
                                stats["chunks_split"] += 1
                            continue
                        # Even a single term failed — record it honestly.
                        log.warning(
                            "ES term scan failed (%s) for %r: %s",
                            exc.status, chunk, str(exc)[:200],
                        )
                        if stats is not None:
                            stats["terms_failed"].extend(chunk)
                        continue
                    hits_raw.extend(page_rows)
                    if stats is not None:
                        stats["terms_queried"] += len(chunk)
                if stats is not None:
                    stats["hits_fetched"] = len(hits_raw)
        else:
            hits_raw = []
            # One search per strong term so SRUM USB/cloud volume cannot bury sdelete/PST.
            for t in core:
                hits_raw.extend(_search(client, [t], 200))
            for t in cloud:
                hits_raw.extend(_search(client, [t], 80))
            for i in range(0, len(rest), _MAX_ES_TERMS_PER_QUERY):
                hits_raw.extend(_search(client, rest[i:i + _MAX_ES_TERMS_PER_QUERY], 400))
            if not hits_raw and (query is not None or match_all):
                # DSL-only query (fields/regex, no terms) or explicit match-all:
                # scan the index once.
                hits_raw.extend(_search(client, [], 400))

    hits: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in hits_raw:
        hit = _shape_es_hit(
            row, start, end, needles, strong, query, match_all,
            search_fields, seen, stats=stats,
        )
        if hit is not None:
            hits.append(hit)
    if stats is not None:
        stats["hits_returned"] = len(hits)
        stats["hits_capped"] = False
    return finalize_hits(hits, terms, priority_terms)

def _with_filt(query: dict[str, Any], filt: list[dict[str, Any]]) -> dict[str, Any]:
    if not filt:
        return query
    return {"bool": {"must": [query], "filter": filt}}


def _index_window_filter(window) -> list[dict[str, Any]]:
    """Same intake-window filter as query_index (shared by count/iter)."""
    start, end = window or (None, None)
    if start is None or end is None:
        return []
    return [{
        "bool": {
            "should": [
                {"range": {"ts": {"gte": start.isoformat(), "lte": end.isoformat()}}},
                {"bool": {"must_not": {"exists": {"field": "ts"}}}},
            ],
            "minimum_should_match": 1,
        }
    }]


def _index_search_fields(case_id: str) -> bool:
    with contextlib.suppress(Exception):
        return bool(fields_property_names(case_id))
    return False


class _HitKeySet(Protocol):
    def __contains__(self, key: tuple[str, str]) -> bool: ...

    def add(self, key: tuple[str, str]) -> None: ...


class _DiskHitKeys:
    """Exact row-identity deduplication with bounded RAM, regardless of row count."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def __contains__(self, key: tuple[str, str]) -> bool:
        return self.connection.execute(
            "SELECT 1 FROM hit_keys WHERE file = ? AND line = ?", key,
        ).fetchone() is not None

    def add(self, key: tuple[str, str]) -> None:
        self.connection.execute("INSERT OR IGNORE INTO hit_keys VALUES (?, ?)", key)


@contextlib.contextmanager
def _bounded_hit_keys():
    # This temporary database contains query bookkeeping, never case/evidence data.
    # Preserve the existing (file, line) identity across pages and term chunks.
    with tempfile.TemporaryDirectory(prefix="nexus-hit-keys-") as folder:
        connection = sqlite3.connect(str(Path(folder) / "keys.sqlite"))
        try:
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("PRAGMA synchronous=OFF")
            connection.execute("PRAGMA cache_size=-2048")
            connection.execute(
                "CREATE TABLE hit_keys (file TEXT, line TEXT, PRIMARY KEY (file, line)) WITHOUT ROWID"
            )
            yield _DiskHitKeys(connection)
        finally:
            connection.close()


def _shape_es_hit(
    row: dict[str, Any],
    start,
    end,
    needles: list[str],
    strong: set[str],
    query: Any | None,
    match_all: bool,
    search_fields: bool,
    seen: _HitKeySet,
    *,
    stats: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """The shared stored-document to N4-hit contract for both ES query paths."""
    src = row.get("_source") or {}
    text = str(src.get("text") or "")
    if start is not None and end is not None:
        if _DATE_RE.search(text):
            if not _row_in_window(text, start, end):
                return None
        else:
            ts_raw = src.get("ts")
            if ts_raw not in (None, ""):
                try:
                    from datetime import UTC as _UTC

                    dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=_UTC)
                    if not (start <= dt <= end):
                        return None
                except ValueError:
                    pass
    low = text.lower()
    fam = str(src.get("family") or "other")
    file_rel = str(src.get("file") or "")
    fields_map = src.get("fields") or {}
    fields_low = ""
    if search_fields and isinstance(fields_map, dict) and fields_map:
        fields_low = " ".join(str(v) for v in fields_map.values() if v is not None)
    classified: dict[str, Any] = {
        "signal": [], "facts": [], "weak": [], "sites": [],
    }
    if query is not None:
        from nexus.langgraph.query_dsl import row_matches

        ok, matched = row_matches(
            query, line_lower=low, family=fam, file_rel=file_rel,
            extra_text=fields_low, row_ts=str(src.get("ts") or ""),
            row_fields=_row_match_fields(src),
        )
        if not ok:
            return None
    else:
        # Same match-site awareness as the CSV path (parity).
        candidates = [
            t for t in needles
            if needle_in_text(low, t) or (fields_low and needle_in_text(fields_low.lower(), t))
        ]
        classified = classify_matched_terms(fam, fields_map, text, candidates)
        _count_fact_sites(stats, classified)
        matched = classified["signal"]
        if not matched and not classified["facts"]:
            if not match_all:
                return None
            matched = ["*"]
    key = (file_rel, str(src.get("line") or 0))
    if key in seen:
        return None
    seen.add(key)
    hit: dict[str, Any] = {
        "family": fam,
        "file": key[0],
        "line": key[1],
        "terms": ",".join(matched),
        "terms_list": matched,
        "text": text,
        "fields": fields_map if isinstance(fields_map, dict) else {},
    }
    if classified.get("facts"):
        hit["fact_terms"] = classified["facts"]
        hit["fact_sites"] = classified["sites"]
    if classified.get("weak"):
        hit["weak_terms"] = classified["weak"]
    for key_name in ("host", "user", "event_id", "ts"):
        value = src.get(key_name)
        if value not in (None, ""):
            hit[key_name] = value
    return hit


def _index_query_terms(
    needles: list[str], strong: set[str], query: Any | None,
    match_all: bool, search_fields: bool,
    catalog: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Query fragments for chunked term scans (one per chunk) or the DSL."""
    if query is not None and not (hasattr(query, "is_empty") and query.is_empty()):
        return [ast_to_es(query, search_fields=search_fields, catalog=catalog)]
    if not needles:
        return [{"match_all": {}}]
    return [
        ast_to_es(None, terms=needles[i:i + _MAX_ES_TERMS_PER_QUERY],
                  search_fields=search_fields)
        for i in range(0, len(needles), _MAX_ES_TERMS_PER_QUERY)
    ]


def iter_index_hits(
    case_dir: Path,
    terms: list[str],
    window: tuple[datetime | None, datetime | None],
    priority_terms: list[str] | None = None,
    query: Any | None = None,
    match_all: bool = False,
    page: int = 1000,
    stats: dict[str, Any] | None = None,
    catalog: dict[str, Any] | None = None,
) -> Iterator[dict[str, Any]]:
    """Stream EVERY matching ES row (EH-12) — no 400-row search cap.

    Pages with ``search_after`` over ``_doc`` so a 10M-hit case exports/
    counts without materializing or truncating. Chunk failures raise in
    explicit-ES mode; in auto mode the caller decides the fallback.
    """
    case_dir = Path(case_dir)
    name = index_name(case_dir.name)
    needles = [t.lower() for t in terms if t.strip()]
    if not needles and query is None and not match_all:
        return
    from nexus.langgraph.query_pack import _strong_set

    strong = _strong_set(priority_terms if priority_terms is not None else terms)
    start, end = window or (None, None)
    filt = _index_window_filter(window)
    size = max(100, min(int(page or 1000), 5000))
    with _client() as client, _bounded_hit_keys() as seen:
        head = client.head(f"/{name}")
        if head.status_code != 200:
            raise IndexMissing(f"no index {name}")
        search_fields = _index_search_fields(case_dir.name)
        chunks = _index_query_terms(needles, strong, query, match_all,
                                    search_fields, catalog=catalog)
        for base in chunks:
            q: dict[str, Any] = base
            if filt:
                q = {"bool": {"must": [base], "filter": filt}}
            search_after: list[Any] | None = None
            while True:
                body: dict[str, Any] = {
                    "size": size,
                    "query": q,
                    "sort": ["_doc"],
                    "track_total_hits": False,
                }
                if search_after:
                    body["search_after"] = search_after
                r = client.post(f"/{name}/_search", json=body)
                if r.status_code >= 400:
                    # An export/appendix that silently drops a chunk is
                    # worse than an error the operator can act on (EH-12).
                    raise RuntimeError(
                        f"exhaustive search failed: {r.status_code} {r.text[:200]}"
                    )
                rows = r.json().get("hits", {}).get("hits", [])
                if not rows:
                    break
                for row in rows:
                    hit = _shape_es_hit(
                        row, start, end, needles, strong, query, match_all,
                        search_fields, seen,
                    )
                    if hit is not None:
                        yield hit
                search_after = rows[-1].get("sort")
                if len(rows) < size:
                    break
        if stats is not None:
            stats["backend"] = "elasticsearch"
            stats["exhaustive"] = True


def count_index(
    case_dir: Path,
    terms: list[str],
    window: tuple[datetime | None, datetime | None],
    priority_terms: list[str] | None = None,
    query: Any | None = None,
    match_all: bool = False,
    stats: dict[str, Any] | None = None,
    catalog: dict[str, Any] | None = None,
) -> tuple[int, bool]:
    """Exact matched-row count via ES ``_count`` (EH-12). ``(count, exact)``.

    Term mode counts per chunk (``_count`` has the same clause limits as
    search); a still-failing chunk is recorded in ``stats['terms_failed']``
    and makes the result a lower bound rather than a silently wrong number.
    """
    case_dir = Path(case_dir)
    name = index_name(case_dir.name)
    needles = [t.lower() for t in terms if t.strip()]
    if not needles and query is None and not match_all:
        return 0, True
    from nexus.langgraph.query_pack import _strong_set

    strong = _strong_set(priority_terms if priority_terms is not None else terms)
    filt = _index_window_filter(window)
    total = 0
    exact = True
    with _client() as client:
        head = client.head(f"/{name}")
        if head.status_code != 200:
            raise IndexMissing(f"no index {name}")
        search_fields = _index_search_fields(case_dir.name)
        chunks = _index_query_terms(needles, strong, query, match_all,
                                    search_fields, catalog=catalog)
        queue = list(chunks)
        while queue:
            base = queue.pop(0)
            q: dict[str, Any] = base
            if filt:
                q = {"bool": {"must": [base], "filter": filt}}
            r = client.post(f"/{name}/_count", json={"query": q})
            if r.status_code >= 400:
                bool_body = base.get("bool") if isinstance(base.get("bool"), dict) else {}
                needle_chunk = bool_body.get("should") or []
                only_should = set(bool_body) <= {"should", "minimum_should_match"}
                if only_should and len(needle_chunk) > 8:
                    # Split and retry — never drop clauses.
                    mid = len(needle_chunk) // 2
                    queue.insert(0, {"bool": {"should": needle_chunk[mid:],
                                              "minimum_should_match": 1}})
                    queue.insert(0, {"bool": {"should": needle_chunk[:mid],
                                              "minimum_should_match": 1}})
                    continue
                exact = False
                if stats is not None:
                    stats.setdefault("terms_failed", []).append(
                        r.text[:120] or str(r.status_code)
                    )
                continue
            total += int(r.json().get("count") or 0)
    if stats is not None:
        stats["backend"] = "elasticsearch"
        stats["count_exact"] = exact
    return total, exact
