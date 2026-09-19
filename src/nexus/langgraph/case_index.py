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
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger(__name__)

from nexus.langgraph.query_pack import (
    _DATE_RE,
    _MAX_FILTERED_SCAN_BYTES,
    _MAX_LINE,
    _SKIP_SUFFIXES,
    _row_in_window,
    _scan_prio,
    finalize_hits,
    iter_extraction_files,
    needle_in_text,
)
from nexus.langgraph.timestamps import extract_event_ts

_LARGE_NEEDLES = (
    "sdelete", ".pst", ".ost", "drivefs", "googledrive", "my drive",
    "usbstor", "mimikatz", "rubeus", "psexec", "psexesvc",
    "wevtutil", "1102", "encodedcommand", "dataoverwrite",
    "rundll32", "mshta", "lsass", "schtasks", "bitsadmin",
    "security.evtx",
)
def _env_index_int(name: str, default: int) -> int:
    """Index-knob int; 0 means UNLIMITED (EH-11: no evidence loss by default).

    Operators can reinstate guards with NEXUS_INDEX_MAX_DOCS /
    NEXUS_INDEX_SMALL_DOCS / NEXUS_INDEX_PER_FAMILY_CAP /
    NEXUS_INDEX_PER_FILE_CAP; when set, the caps are reported honestly in
    ``es_index.json``/``index_state.json`` (``capped``/``caps``).
    """
    import os

    try:
        value = int(os.environ.get(name, "") or default)
    except ValueError:
        value = default
    return max(0, value)


_MAX_LARGE = _MAX_FILTERED_SCAN_BYTES
_MAX_DOCS = _env_index_int("NEXUS_INDEX_MAX_DOCS", 0)
_MAX_DOCS_SMALL = _env_index_int("NEXUS_INDEX_SMALL_DOCS", 0)
_MAX_DOCS_PER_FAMILY = _env_index_int("NEXUS_INDEX_PER_FAMILY_CAP", 0)
_MAX_DOCS_PER_FILE = _env_index_int("NEXUS_INDEX_PER_FILE_CAP", 0)
WILDCARD_IGNORE_ABOVE = 32766

# Index schema version. v2 = structured docs (host/user/event_id + parsed
# columns under fields.*) so DSL filters and aggregations push down to ES.
# A version mismatch triggers a rebuild on the next index_case()/ensure_index.
INDEX_SCHEMA_VERSION = 3

_MAX_INDEX_FIELDS = 24
_MAX_INDEX_FIELD_VALUE = 300

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


def _client():
    import httpx

    url = es_url()
    if not url:
        raise IndexMissing("NEXUS_ES_URL is empty")
    parsed = urlparse(url)
    if parsed.hostname in {"192.168.77.50", "elk"}:
        raise RuntimeError("N3 must not point at the CADRE elk SIEM (.50)")
    return httpx.Client(base_url=url, timeout=120.0)


# Availability probe cache — an ES URL that is configured but unreachable
# (black-holed SYN, VPN down) must not stall every query: probe with a short
# connect timeout and cache the result briefly (WP-review 2026-09-14).
_es_probe_cache: tuple[float, bool] | None = None
_ES_PROBE_TTL = 30.0
_ES_PROBE_TIMEOUT = 5.0
_ES_PROBE_CONNECT = 3.0


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


def _row_fields(line: str, header: list[str] | None) -> dict[str, str]:
    """Parsed columns for one row (schema v2: indexed under ``fields.*``)."""
    if not header:
        return {}
    values = _split_row(line)
    out: dict[str, str] = {}
    for name, value in list(zip(header, values, strict=False))[:_MAX_INDEX_FIELDS]:
        v = str(value).strip()[:_MAX_INDEX_FIELD_VALUE]
        if v and not str(name).startswith("_"):
            out[str(name)] = v
    return out


def _pick_field(fields: dict[str, str], keys: tuple[str, ...]) -> str:
    """First non-empty field value whose column name matches (case-insensitive)."""
    wanted = set(keys)
    for name, value in fields.items():
        if name.lower() in wanted and value:
            return str(value)
    return ""


def _host_user_event(fields: dict[str, str]) -> tuple[str, str, str]:
    host = _pick_field(fields, ("computer", "computername", "host", "hostname"))
    user = _pick_field(
        fields,
        ("user", "username", "userid", "account", "accountname",
         "targetuser", "sourceuser", "user_name"),
    )
    event = _pick_field(fields, ("eventid", "event_id", "eventcode"))
    return host, user, event


def _index_rel(path: Path, root: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")


def _open_text_auto(path: Path):
    """Text open with transparent gzip decompression (EH-11)."""
    if str(path).lower().endswith(".gz"):
        import gzip

        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open(encoding="utf-8", errors="replace")


def _index_header(path: Path) -> list[str] | None:
    """Header columns when line 1 looks like CSV/TSV; else None."""
    first = ""
    try:
        with _open_text_auto(path) as fh:
            first = fh.readline().strip()
    except OSError:
        return None
    if first and ("," in first or "\t" in first):
        return [c.strip().lstrip("\ufeff").strip('"') for c in _split_row(first)]
    return None


def iter_index_doc_batches(
    case_dir: Path,
    extra_needles: list[str] | None = None,
    only_files: set[str] | None = None,
    stats: dict[str, Any] | None = None,
    batch_size: int | None = None,
):
    """Yield batches of index documents for EVERY row of EVERY indexable file.

    EH-11: streaming (no full-list materialization), no per-file/family/total
    caps unless the operator sets them (0 = unlimited), transparent .gz, and
    no ">80MB matching-lines-only" reduction — every row is indexed.
    """
    case_dir = Path(case_dir)
    # ``extra_needles`` is accepted for API compatibility; EH-11 indexes all
    # rows, so no matching-only filtering remains.
    _ = extra_needles
    batch = batch_size or _env_index_int("NEXUS_INDEX_BATCH", 4000) or 4000
    caps: dict[str, Any] = {
        "docs_capped": False,
        "families_capped": [],
        "files_capped": 0,
        "large_files_skipped": 0,
    }
    seen: set[str] = set()
    family_counts: dict[str, int] = {}
    out: list[dict[str, Any]] = []
    total = 0
    stop = False
    year_hint = _case_year_hint(case_dir)
    ts_cov: dict[str, dict[str, int]] = {}

    def _cov(fam: str) -> dict[str, int]:
        return ts_cov.setdefault(fam, {
            "present": 0, "missing": 0, "synthesized": 0,
            "tz_assumed": 0, "year_assumed": 0,
        })

    def _add(path: Path, root: Path, fam: str, i: int, line: str,
             fields: dict[str, str] | None = None) -> bool:
        nonlocal total
        text = line.strip()[:_MAX_LINE]
        key = hashlib.sha1(
            f"{fam}\x00{path}\x00{i}\x00{text}".encode("utf-8", "replace")
        ).hexdigest()
        if key in seen:
            return False
        seen.add(key)
        rel = _index_rel(path, root)
        doc: dict[str, Any] = {
            "case_id": case_dir.name,
            "family": fam,
            "file": rel,
            "line": i,
            "text": text,
        }
        if fields:
            host, user, event = _host_user_event(fields)
            doc["fields"] = fields
            if host:
                doc["host"] = host.lower()[:120]
            if user:
                doc["user"] = user.lower()[:120]
            if event:
                doc["event_id"] = str(event)[:40]
        # 4k.4: parsed time columns first (TimeCreated/ts/…), then row text;
        # offsets honored, naive == UTC (flagged), syslog year flagged.
        ts_info = extract_event_ts(text, fields, year_hint=year_hint)
        cov = _cov(fam)
        if ts_info:
            doc["ts"] = ts_info["dt"].astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            doc["ts_raw"] = str(ts_info["raw"])[:64]
            synth = bool(fields) and str(fields.get("ts_synthesized") or "").lower() in {
                "true", "1", "yes",
            }
            doc["ts_src"] = "synthesized" if synth else "event"
            doc["ts_precision"] = ts_info["precision"]
            if ts_info["tz_assumed"]:
                doc["ts_tz_assumed"] = True
            if ts_info["year_assumed"]:
                doc["ts_year_assumed"] = True
            cov["present"] += 1
            if synth:
                cov["synthesized"] += 1
            if ts_info["tz_assumed"]:
                cov["tz_assumed"] += 1
            if ts_info["year_assumed"]:
                cov["year_assumed"] += 1
        else:
            cov["missing"] += 1
        out.append(doc)
        total += 1
        return True

    file_stats: dict[str, Any] = {}
    for path, root, fam in iter_extraction_files(case_dir, stats=file_stats):
        if only_files is not None and _index_rel(path, root) not in only_files:
            continue
        if _MAX_DOCS_PER_FAMILY and family_counts.get(fam, 0) >= _MAX_DOCS_PER_FAMILY:
            if fam not in caps["families_capped"]:
                caps["families_capped"].append(fam)
            continue
        header = _index_header(path)
        try:
            with _open_text_auto(path) as fh:
                for i, line in enumerate(fh, start=1):
                    if i == 1 and ("," in line or "\t" in line):
                        continue
                    if _MAX_DOCS and total >= _MAX_DOCS:
                        caps["docs_capped"] = True
                        stop = True
                        break
                    if _MAX_DOCS_PER_FILE and (i - 1) >= _MAX_DOCS_PER_FILE:
                        caps["files_capped"] += 1
                        break
                    if _add(path, root, fam, i, line, _row_fields(line, header)):
                        family_counts[fam] = family_counts.get(fam, 0) + 1
                    if len(out) >= batch:
                        yield out
                        out = []
        except OSError:
            continue
        if stop:
            break
    # Imported non-host evidence (network/cloud/TI): clean searchable rows from
    # the case artifact store, family = source. The raw store JSONL is never
    # indexed — this projection is (CSV-scanner parity).
    ingest_store = case_dir / "ingest" / "artifacts.jsonl"
    ingest_wanted = only_files is None or "ingest/artifacts.jsonl" in only_files
    if ingest_store.is_file() and ingest_wanted and not stop:
        from nexus.langgraph.query_pack import iter_ingest_records

        for n, fam, text, _ts, record in iter_ingest_records(case_dir):
            if _MAX_DOCS and total >= _MAX_DOCS:
                caps["docs_capped"] = True
                break
            if _MAX_DOCS_PER_FAMILY and family_counts.get(fam, 0) >= _MAX_DOCS_PER_FAMILY:
                if fam not in caps["families_capped"]:
                    caps["families_capped"].append(fam)
                continue
            art_fields: dict[str, str] = {}
            for key_name in (
                "source", "artifact_type", "severity", "timestamp", "host",
                "user", "source_ip", "source_port", "dest_ip", "dest_port",
                "protocol", "description",
                "ts_synthesized", "ts_year_assumed",
            ):
                value = record.get(key_name)
                if value not in (None, "", []):
                    art_fields[key_name] = str(value)[:_MAX_INDEX_FIELD_VALUE]
            if _add(ingest_store, case_dir, fam, n, text, art_fields or None):
                family_counts[fam] = family_counts.get(fam, 0) + 1
            if len(out) >= batch:
                yield out
                out = []
    caps["ts_coverage"] = ts_cov
    if stats is not None:
        stats.update(caps)
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


def _bulk_ndjson(index: str, docs: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    import json

    for doc in docs:
        # Full-text hash (EH-8): a prefix would let rows differing only after
        # char 80 share an _id and overwrite each other.
        _id = hashlib.sha1(
            f"{doc.get('family')}\x00{doc.get('file')}\x00{doc.get('line')}\x00"
            f"{doc.get('text', '')}".encode()
        ).hexdigest()
        lines.append(json.dumps({"index": {"_index": index, "_id": _id}}))
        lines.append(json.dumps(doc, default=str))
    return "\n".join(lines) + "\n"


def _mapping_body() -> dict[str, Any]:
    """Schema v2 — structured fields so DSL filters/aggregations push down."""
    return {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "_meta": {"schema_version": INDEX_SCHEMA_VERSION},
            "dynamic_templates": [
                {
                    "fields_strings": {
                        "path_match": "fields.*",
                        "match_mapping_type": "string",
                        "mapping": {
                            "type": "text",
                            "fields": {"kw": {"type": "keyword", "ignore_above": 1024}},
                        },
                    }
                }
            ],
            "properties": {
                "case_id": {"type": "keyword"},
                "family": {"type": "keyword"},
                "file": {"type": "keyword"},
                "line": {"type": "integer"},
                "host": {"type": "keyword"},
                "user": {"type": "keyword"},
                "event_id": {"type": "keyword"},
                "text": {
                    "type": "text",
                    "fields": {"wc": {"type": "wildcard", "ignore_above": WILDCARD_IGNORE_ABOVE}},
                },
                "ts": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
                # Phase 4k.4 — timestamp authority: raw text, origin,
                # precision and the "we had to assume" flags.
                "ts_raw": {"type": "keyword", "ignore_above": 64},
                "ts_src": {"type": "keyword"},
                "ts_precision": {"type": "keyword"},
                "ts_tz_assumed": {"type": "boolean"},
                "ts_year_assumed": {"type": "boolean"},
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


def _index_file_mtimes(case_dir: Path) -> dict[str, float]:
    """Doc ``file`` value -> mtime_ns for every indexable file (B6).

    The ingest store is keyed as ``ingest/artifacts.jsonl`` to match the doc
    ``file`` value (a bare ``artifacts.jsonl`` key made incremental indexing
    blind to imported evidence). When the same rel path exists in several
    roots, the MAX mtime wins so any copy's update still triggers a reindex.
    """
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    extractions = resolve_tools_extractions(case_dir)
    roots = [extractions, extractions.parent / "sift" / "extractions", case_dir / "ingest"]
    out: dict[str, float] = {}
    for path in iter_index_files(case_dir):
        for root in roots:
            try:
                rel = str(path.relative_to(root)).replace("\\", "/")
            except ValueError:
                continue
            if root == case_dir / "ingest":
                rel = f"ingest/{rel}"
            with contextlib.suppress(OSError):
                mtime = float(path.stat().st_mtime_ns)
                out[rel] = max(out.get(rel, 0.0), mtime)
            break
    return out


def _bulk_insert(client, name: str, docs: list[dict[str, Any]], chunk: int = 2000) -> int:
    """Bulk-index docs; returns the number of item-level errors."""
    errors = 0
    for i in range(0, len(docs), chunk):
        body = _bulk_ndjson(name, docs[i:i + chunk])
        r = client.post("/_bulk", content=body, headers={"Content-Type": "application/x-ndjson"})
        if r.status_code >= 400:
            raise RuntimeError(f"bulk failed: {r.status_code} {r.text[:300]}")
        payload = r.json()
        if payload.get("errors"):
            errors += sum(
                1 for item in payload.get("items") or []
                if item.get("index", {}).get("error")
            )
    return errors


def index_case(
    case_dir: Path,
    extra_needles: list[str] | None = None,
    *,
    incremental: bool = False,
) -> dict[str, Any]:
    """Build (or incrementally refresh) the case's N3 index.

    ``incremental=True`` only re-indexes files whose mtime advanced since the
    last build and purges docs for files that disappeared — the autoindex path
    used to delete and rebuild the entire case on every run (B6). Falls back to
    a full rebuild when there is no usable prior state, the index is empty
    (fresh schema), or a file set is empty.
    """
    case_dir = Path(case_dir)
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
    current_mtimes = _index_file_mtimes(case_dir) if incremental else {}

    use_incremental = bool(incremental and prior_mtimes and current_mtimes)
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
        }
        removed = set(prior_mtimes) - set(current_mtimes)
        errors = 0
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
            for batch_docs in iter_index_doc_batches(
                case_dir, only_files=changed, stats=cap_stats
            ):
                docs += len(batch_docs)
                errors += _bulk_insert(client, name, batch_docs)
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
        meta = {
            "index": name,
            "docs": docs_total,
            "errors": errors,
            "case_id": case_dir.name,
            "url": es_url(),
            "incremental": True,
            "files_reindexed": sorted(changed),
            "files_removed": sorted(removed),
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
        with _client() as client:
            cleared = client.post(
                f"/{name}/_delete_by_query",
                params={"refresh": "true", "conflicts": "proceed"},
                json={"query": {"match_all": {}}},
            )
            if cleared.status_code >= 400:
                raise RuntimeError(
                    f"index clear failed: {cleared.status_code} {cleared.text[:300]}"
                )
            errors = 0
            # EH-11: stream batches — a million-row case must not be
            # materialized in memory before the first bulk request.
            for batch_docs in iter_index_doc_batches(case_dir, stats=cap_stats):
                docs_total += len(batch_docs)
                errors += _bulk_insert(client, name, batch_docs)
                if docs_total % 50_000 < len(batch_docs):
                    log.info("indexed %d docs…", docs_total)
            refreshed = client.post(f"/{name}/_refresh")
            if refreshed.status_code >= 400:
                raise RuntimeError(
                    f"index refresh failed: {refreshed.status_code} {refreshed.text[:300]}"
                )
        meta = {
            "index": name,
            "docs": docs_total,
            "errors": errors,
            "case_id": case_dir.name,
            "url": es_url(),
            "incremental": False,
            "ts_coverage": cap_stats.get("ts_coverage") or {},
            "caps": cap_stats,
            "capped": bool(
                cap_stats.get("docs_capped")
                or cap_stats.get("families_capped")
                or cap_stats.get("files_capped")
            ),
        }

    (out / "es_index.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    write_index_state(case_dir, meta, file_mtimes=current_mtimes or _index_file_mtimes(case_dir))
    _schema_cache.pop(case_dir.name, None)
    _fields_props_cache.pop(case_dir.name, None)
    with contextlib.suppress(Exception):
        from nexus.tools.evidence_index import invalidate_mappings_cache

        invalidate_mappings_cache(case_dir.name)
    return meta


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


def write_index_state(
    case_dir: Path,
    meta: dict[str, Any],
    *,
    file_mtimes: dict[str, float] | None = None,
) -> None:
    """Persist index freshness state for staleness detection + incremental B6."""
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
        "file_mtimes": file_mtimes if file_mtimes is not None else _index_file_mtimes(case_dir),
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


def iter_index_files(case_dir: Path) -> list[Path]:
    """Files the indexer walks (for mtime staleness checks).

    Applies the same ledger/meta skip rules as iter_extraction_files and
    includes ingest/artifacts.jsonl because the indexer projects its rows.
    """
    case_dir = Path(case_dir)
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    extractions = resolve_tools_extractions(case_dir)
    tools_run_dir = extractions.parent
    roots = [extractions, tools_run_dir / "sift" / "extractions", case_dir / "ingest"]
    out: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        pats = ("*.csv", "*.txt", "*.json", "*.jsonl", "*.log") if root.name == "ingest" else ("*.csv", "*.txt", "*.json", "*.jsonl")
        for pat in pats:
            for p in root.rglob(pat):
                if p.name.startswith("_") or p.name.endswith(_SKIP_SUFFIXES):
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
        should.append({
            "multi_match": {"query": t, "fields": ["fields.*"], "type": "phrase"}
        })
    if not t.isdigit():
        safe = t.lower().replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
        should.append({
            "wildcard": {
                "text.wc": {"value": f"*{safe}*", "case_insensitive": True}
            }
        })
    return {"bool": {"should": should, "minimum_should_match": 1}}


def ast_to_es(query: Any | None, terms: list[str] | None = None,
              match_all: bool = False, search_fields: bool = False) -> dict[str, Any]:
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
    top: int = 20,
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
        parsed = parse_query(dsl)
    except QuerySyntaxError:
        return None
    agg_field = _resolve_agg_field(case_id, field)
    if agg_field is None:
        return None

    es_query = ast_to_es(parsed, match_all=match_all)
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

    body: dict[str, Any] = {
        "size": 0,
        "track_total_hits": True,
        "query": es_query,
    }
    size = max(1, min(int(top or 20), 100))
    if bucket in ("day", "hour"):
        body["aggs"] = {
            "v": {"date_histogram": {"field": "ts", "calendar_interval": bucket}}
        }
    else:
        terms: dict[str, Any] = {"field": agg_field, "size": size}
        if with_spans:
            # first/last-seen per value — the digest's entity timeline.
            terms["order"] = {"_count": "desc"}
        body["aggs"] = {
            "v": {"terms": terms},
            "distinct": {
                "cardinality": {"field": agg_field, "precision_threshold": 40000}
            },
        }
        if with_spans:
            body["aggs"]["v"]["aggs"] = {
                "first": {"min": {"field": "ts"}},
                "last": {"max": {"field": "ts"}},
            }

    try:
        with _client() as client:
            r = client.post(f"/{index_name(case_id)}/_search", json=body)
            if r.status_code >= 400:
                return None
            data = r.json()
    except Exception:  # noqa: BLE001 — fall back to the Python path
        return None

    total = int(((data.get("hits") or {}).get("total") or {}).get("value") or 0)
    buckets = ((data.get("aggregations") or {}).get("v") or {}).get("buckets") or []
    if bucket in ("day", "hour"):
        bucket_map: dict[str, int] = {}
        for b in buckets:
            raw = str(b.get("key_as_string") or "")
            # "2026-01-01T10:00" / "2026-01-01" — matches _time_buckets keys.
            key = raw[:13] + ":00" if bucket == "hour" and len(raw) >= 13 else raw[:10]
            if key:
                bucket_map[key] = int(b.get("doc_count") or 0)
        return {
            "field": field,
            "rows_scanned": total,
            "values_seen": len(buckets),
            "distinct": len(buckets),
            "distinct_approximate": False,
            "top": [],
            "buckets": bucket_map,
            "backend": "elasticsearch",
        }
    ranked = []
    for b in buckets:
        item: dict[str, Any] = {
            "value": str(b.get("key")), "count": int(b.get("doc_count") or 0)
        }
        if with_spans:
            first = (b.get("first") or {}).get("value_as_string") or ""
            last = (b.get("last") or {}).get("value_as_string") or ""
            if first:
                item["first_seen"] = first[:19]
            if last:
                item["last_seen"] = last[:19]
        ranked.append(item)
    distinct = int(
        ((data.get("aggregations") or {}).get("distinct") or {}).get("value") or 0
    )
    return {
        "field": field,
        "rows_scanned": total,
        "values_seen": sum(b["count"] for b in ranked),
        "distinct": distinct,
        "distinct_approximate": True,
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
) -> list[dict[str, str]]:
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
        for t in subset[:40]:
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

    def _search(client, subset: list[str], size: int) -> list[dict[str, Any]]:
        if not subset and query is None and not match_all:
            return []
        body = {
            "size": size,
            "query": {
                "bool": {
                    "should": _should_for(subset) or [{"match_all": {}}],
                    "minimum_should_match": 1 if subset else 0,
                    "filter": filt,
                }
            },
        }
        r = client.post(f"/{name}/_search", json=body)
        if r.status_code >= 400:
            raise RuntimeError(
                f"search failed: {r.status_code} {r.text[:300]} "
                f"| query={json.dumps(body)[:600]}"
            )
        return r.json().get("hits", {}).get("hits", [])

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

            def _post_search(body: dict[str, Any]):
                r = client.post(f"/{name}/_search", json=body)
                if r.status_code >= 400:
                    # ES 400s name the parse failure but not the offending
                    # clause — carry a compact body so the next occurrence is
                    # diagnosable from the log alone (EH-13 honesty).
                    raise RuntimeError(
                        f"search failed: {r.status_code} {r.text[:300]} "
                        f"| query={json.dumps(body)[:600]}"
                    )
                return r

            if query is not None and not (
                hasattr(query, "is_empty") and query.is_empty()
            ):
                if stats is not None:
                    stats["mode"] = "dsl"
                    stats["terms_queried"] = len(needles)
                r = _post_search({
                    "size": 400,
                    "query": ast_to_es(query, search_fields=search_fields),
                })
                hits_raw = r.json().get("hits", {}).get("hits", [])
                if stats is not None:
                    stats["hits_fetched"] = len(hits_raw)
                    stats["hits_capped"] = len(hits_raw) >= 400
            elif not needles:
                if stats is not None:
                    stats["mode"] = "match_all"
                r = _post_search({"size": 400, "query": {"match_all": {}}})
                hits_raw = r.json().get("hits", {}).get("hits", [])
                if stats is not None:
                    stats["hits_fetched"] = len(hits_raw)
                    stats["hits_capped"] = len(hits_raw) >= 400
            else:
                hits_raw = []
                full_pages = 0
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
                    r = client.post(
                        f"/{name}/_search",
                        json={
                            "size": 400,
                            "query": ast_to_es(None, terms=chunk,
                                               search_fields=search_fields),
                        },
                    )
                    if r.status_code >= 400 and len(chunk) > 1:
                        # Clause/rewrite limit hit — split and retry, never drop.
                        mid = len(chunk) // 2
                        queue.insert(0, chunk[mid:])
                        queue.insert(0, chunk[:mid])
                        if stats is not None:
                            stats["chunks_split"] += 1
                        continue
                    if r.status_code >= 400:
                        # Even a single term failed — record it honestly.
                        log.warning(
                            "ES term scan failed (%s) for %r: %s",
                            r.status_code, chunk, r.text[:200],
                        )
                        if stats is not None:
                            stats["terms_failed"].extend(chunk)
                        continue
                    page = r.json().get("hits", {}).get("hits", [])
                    if len(page) >= 400:
                        full_pages += 1
                    hits_raw.extend(page)
                    if stats is not None:
                        stats["terms_queried"] += len(chunk)
                if stats is not None:
                    stats["hits_fetched"] = len(hits_raw)
                    stats["hits_capped"] = full_pages > 0
        else:
            hits_raw = []
            # One search per strong term so SRUM USB/cloud volume cannot bury sdelete/PST.
            for t in core:
                hits_raw.extend(_search(client, [t], 200))
            for t in cloud:
                hits_raw.extend(_search(client, [t], 80))
            hits_raw.extend(_search(client, rest, 400))
            if not hits_raw and (query is not None or match_all):
                # DSL-only query (fields/regex, no terms) or explicit match-all:
                # scan the index once.
                hits_raw.extend(_search(client, [], 400))

    hits: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in hits_raw:
        src = row.get("_source") or {}
        text = str(src.get("text") or "")
        if start is not None and end is not None:
            # CSV parity: any date in the row text inside the window keeps the
            # row (multi-date rows are common). The structured `ts` is
            # authoritative ONLY when the raw text carries no date at all —
            # imported rows would otherwise leak in as "no date = kept"
            # regardless of their real timestamp.
            if _DATE_RE.search(text):
                if not _row_in_window(text, start, end):
                    continue
            else:
                ts_raw = src.get("ts")
                if ts_raw not in (None, ""):
                    try:
                        from datetime import UTC as _UTC

                        dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=_UTC)
                        if not (start <= dt <= end):
                            continue
                    except ValueError:
                        pass  # unparsable ts → keep (keyword row without date)
        low = text.lower()
        fam = str(src.get("family") or "other")
        file_rel = str(src.get("file") or "")
        # Schema-v2 parsed columns ride along for the row-side re-check so a
        # term that only lives in fields.* still passes ES→CSV parity.
        fields_map = src.get("fields") or {}
        fields_low = ""
        if search_fields and isinstance(fields_map, dict) and fields_map:
            fields_low = " ".join(
                str(v) for v in fields_map.values() if v is not None
            )
        if query is not None:
            from nexus.langgraph.query_dsl import row_matches

            ok, matched = row_matches(
                query, line_lower=low, family=fam, file_rel=file_rel,
                extra_text=fields_low,
            )
            if not ok:
                continue
            matched = matched[:6]
        else:
            matched = [t for t in needles
                       if needle_in_text(low, t) or (fields_low and needle_in_text(fields_low.lower(), t))]
            if not matched:
                if not match_all:
                    continue
                matched = ["*"]
        key = (str(src.get("file") or ""), str(src.get("line") or 0))
        if key in seen:
            continue
        seen.add(key)
        hit: dict[str, Any] = {
            "family": fam,
            "file": key[0],
            "line": key[1],
            "terms": ",".join(matched[:6]),
            # Structured matched needles — the primary (ES) path used to omit
            # this, so every downstream consumer comma-split it again (EH-8).
            "terms_list": matched[:6],
            "text": text[:_MAX_LINE],
        }
        for key_name in ("host", "user", "event_id", "ts"):
            value = src.get(key_name)
            if value not in (None, ""):
                hit[key_name] = value
        hits.append(hit)
    if stats is not None:
        from nexus.langgraph.query_pack import _MAX_HITS_TOTAL as _total_cap

        stats["hits_returned"] = min(len(hits), _total_cap)
        # merged chunks trimmed by finalize = counts are lower bounds
        if len(hits) > _total_cap or stats.get("hits_capped"):
            stats["hits_capped"] = True
    return finalize_hits(hits, terms, priority_terms)

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


def _shape_es_hit(
    row: dict[str, Any],
    start,
    end,
    needles: list[str],
    strong: set[str],
    query: Any | None,
    match_all: bool,
    search_fields: bool,
    seen: set[tuple[str, str]],
) -> dict[str, Any] | None:
    """One ES source row -> N4 hit, replicating query_index semantics exactly."""
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
    if query is not None:
        from nexus.langgraph.query_dsl import row_matches

        ok, matched = row_matches(
            query, line_lower=low, family=fam, file_rel=file_rel,
            extra_text=fields_low, row_ts=str(src.get("ts") or ""),
        )
        if not ok:
            return None
        matched = matched[:6]
    else:
        matched = [
            t for t in needles
            if needle_in_text(low, t) or (fields_low and needle_in_text(fields_low.lower(), t))
        ]
        if not matched:
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
        "terms": ",".join(matched[:6]),
        "terms_list": matched[:6],
        "text": text[:_MAX_LINE],
    }
    for key_name in ("host", "user", "event_id", "ts"):
        value = src.get(key_name)
        if value not in (None, ""):
            hit[key_name] = value
    return hit


def _index_query_terms(
    needles: list[str], strong: set[str], query: Any | None,
    match_all: bool, search_fields: bool,
) -> list[dict[str, Any]]:
    """Query fragments for chunked term scans (one per chunk) or the DSL."""
    if query is not None and not (hasattr(query, "is_empty") and query.is_empty()):
        return [ast_to_es(query, search_fields=search_fields)]
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
    with _client() as client:
        head = client.head(f"/{name}")
        if head.status_code != 200:
            raise IndexMissing(f"no index {name}")
        search_fields = _index_search_fields(case_dir.name)
        seen: set[tuple[str, str]] = set()
        chunks = _index_query_terms(needles, strong, query, match_all, search_fields)
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
        chunks = _index_query_terms(needles, strong, query, match_all, search_fields)
        queue = list(chunks)
        while queue:
            base = queue.pop(0)
            q: dict[str, Any] = base
            if filt:
                q = {"bool": {"must": [base], "filter": filt}}
            r = client.post(f"/{name}/_count", json={"query": q})
            if r.status_code >= 400:
                needle_chunk = base.get("bool", {}).get("should") or []
                if len(needle_chunk) > 8:
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
