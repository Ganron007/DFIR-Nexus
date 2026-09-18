"""N3 per-case Elasticsearch backend — same N4 hit schema as the CSV pack.

Indexes only this case's processed outputs (extractions / sift/extractions).
Never walks Evidence-files/. Offline fallback remains the CSV query pack.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from nexus.langgraph.query_pack import (
    _DATE_RE,
    _MAX_FILTERED_SCAN_BYTES,
    _MAX_FULL_SCAN_BYTES,
    _MAX_LINE,
    _SKIP_SUFFIXES,
    _family,
    _row_in_window,
    _scan_prio,
    finalize_hits,
    iter_extraction_files,
    needle_in_text,
)

_LARGE_NEEDLES = (
    "sdelete", ".pst", ".ost", "drivefs", "googledrive", "my drive",
    "usbstor", "mimikatz", "rubeus", "psexec", "psexesvc",
    "wevtutil", "1102", "encodedcommand", "dataoverwrite",
    "rundll32", "mshta", "lsass", "schtasks", "bitsadmin",
    "security.evtx",
)
_MAX_LARGE = _MAX_FILTERED_SCAN_BYTES
_MAX_DOCS = 250_000
_MAX_DOCS_SMALL = 150_000
_MAX_DOCS_PER_FAMILY = 12_000
_MAX_DOCS_PER_FILE = 80_000
WILDCARD_IGNORE_ABOVE = 32766

# Index schema version. v2 = structured docs (host/user/event_id + parsed
# columns under fields.*) so DSL filters and aggregations push down to ES.
# A version mismatch triggers a rebuild on the next index_case()/ensure_index.
INDEX_SCHEMA_VERSION = 2

_MAX_INDEX_FIELDS = 24
_MAX_INDEX_FIELD_VALUE = 300


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


def iter_index_docs(
    case_dir: Path,
    extra_needles: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Documents for this case only. Large files (>80MB) keep matching rows."""
    case_dir = Path(case_dir)
    extra = [t.lower() for t in (extra_needles or []) if t.strip()]
    docs: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add(
        path: Path,
        root: Path,
        fam: str,
        i: int,
        line: str,
        fields: dict[str, str] | None = None,
    ) -> None:
        text = line.strip()[:_MAX_LINE]
        key = hashlib.sha1(
            f"{fam}:{path}:{i}:{text[:80]}".encode("utf-8", "replace")
        ).hexdigest()
        if key in seen:
            return
        seen.add(key)
        rel = str(path.relative_to(root)).replace("\\", "/")
        doc = {
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
        ts = _ts_from_line(line)
        if ts:
            doc["ts"] = ts
        docs.append(doc)

    header_cache: dict[str, list[str] | None] = {}

    def _header_for(path: Path) -> list[str] | None:
        key = str(path)
        if key not in header_cache:
            first = ""
            try:
                with path.open(encoding="utf-8", errors="replace") as fh:
                    first = fh.readline().strip()
            except OSError:
                first = ""
            if first and ("," in first or "\t" in first):
                header_cache[key] = [
                    c.strip().lstrip("\ufeff").strip('"') for c in _split_row(first)
                ]
            else:
                header_cache[key] = None
        return header_cache[key]

    family_counts: dict[str, int] = {}

    small_files = list(iter_extraction_files(case_dir))
    small_files.sort(key=lambda item: _index_small_prio(item[0]))
    for path, root, fam in small_files:
        if len(docs) >= _MAX_DOCS_SMALL:
            break
        if family_counts.get(fam, 0) >= _MAX_DOCS_PER_FAMILY:
            continue
        header = _header_for(path)
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, start=1):
                    if i == 1 and ("," in line or "\t" in line):
                        continue
                    if family_counts.get(fam, 0) >= _MAX_DOCS_PER_FAMILY:
                        break
                    before = len(docs)
                    _add(path, root, fam, i, line, _row_fields(line, header))
                    if len(docs) > before:
                        family_counts[fam] = family_counts.get(fam, 0) + 1
                    if i >= _MAX_DOCS_PER_FILE or len(docs) >= _MAX_DOCS_SMALL:
                        break
        except OSError:
            continue

    # Imported non-host evidence (network/cloud/TI): clean searchable rows from
    # the case artifact store, family = source (suricata/zeek/...). The raw
    # store JSONL is never indexed — this projection is (CSV-scanner parity).
    from nexus.langgraph.query_pack import iter_ingest_records

    ingest_store = case_dir / "ingest" / "artifacts.jsonl"
    if ingest_store.is_file():
        for n, fam, text, _ts, record in iter_ingest_records(case_dir):
            if len(docs) >= _MAX_DOCS:
                break
            if family_counts.get(fam, 0) >= _MAX_DOCS_PER_FAMILY:
                continue
            art_fields: dict[str, str] = {}
            for key_name in (
                "source", "artifact_type", "severity", "timestamp", "host",
                "user", "source_ip", "source_port", "dest_ip", "dest_port",
                "protocol", "description",
            ):
                value = record.get(key_name)
                if value not in (None, "", []):
                    art_fields[key_name] = str(value)[:_MAX_INDEX_FIELD_VALUE]
            before = len(docs)
            _add(ingest_store, case_dir, fam, n, text, art_fields or None)
            if len(docs) > before:
                family_counts[fam] = family_counts.get(fam, 0) + 1

    # Hayabusa / MFT / EVTX above the small-file cap: index matching rows only.
    # Always reserved — small CSVs must not consume the whole 250k budget.
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    extractions = resolve_tools_extractions(case_dir)
    for root in (extractions, extractions.parent / "sift" / "extractions"):
        if not root.is_dir() or len(docs) >= _MAX_DOCS:
            break
        files: list[Path] = []
        for pat in ("*.csv", "*.txt"):
            files.extend(root.rglob(pat))
        for path in sorted(set(files), key=_index_large_prio):
            if path.name.startswith("_") or path.name.endswith(_SKIP_SUFFIXES):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size <= _MAX_FULL_SCAN_BYTES or size > _MAX_LARGE:
                continue
            fam = _family(path, root)
            kept = 0
            try:
                with path.open(encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh, start=1):
                        low = line.lower()
                        if not _should_keep_large_line(low, extra):
                            continue
                        _add(path, root, fam, i, line)
                        kept += 1
                        if kept >= _MAX_DOCS_PER_FILE or len(docs) >= _MAX_DOCS:
                            break
            except OSError:
                continue
    return docs[:_MAX_DOCS]


def _bulk_ndjson(index: str, docs: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    import json

    for doc in docs:
        _id = hashlib.sha1(
            f"{doc.get('family')}:{doc.get('file')}:{doc.get('line')}:"
            f"{doc.get('text', '')[:80]}".encode()
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


def index_case(case_dir: Path, extra_needles: list[str] | None = None) -> dict[str, Any]:
    case_dir = Path(case_dir)
    docs = iter_index_docs(case_dir, extra_needles)
    name = ensure_index(case_dir.name)
    import json

    chunk = 2000
    errors = 0
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
        for i in range(0, len(docs), chunk):
            body = _bulk_ndjson(name, docs[i:i + chunk])
            r = client.post("/_bulk", content=body, headers={"Content-Type": "application/x-ndjson"})
            if r.status_code >= 400:
                raise RuntimeError(f"bulk failed: {r.status_code} {r.text[:300]}")
            payload = r.json()
            if payload.get("errors"):
                errors += sum(1 for item in payload.get("items") or [] if item.get("index", {}).get("error"))
        refreshed = client.post(f"/{name}/_refresh")
        if refreshed.status_code >= 400:
            raise RuntimeError(
                f"index refresh failed: {refreshed.status_code} {refreshed.text[:300]}"
            )
    meta = {
        "index": name,
        "docs": len(docs),
        "errors": errors,
        "case_id": case_dir.name,
        "url": es_url(),
    }
    out = case_dir / "analysis"
    out.mkdir(parents=True, exist_ok=True)
    (out / "es_index.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    write_index_state(case_dir, meta)
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


def write_index_state(case_dir: Path, meta: dict[str, Any]) -> None:
    """Persist index freshness state for staleness detection."""
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
    """
    if query is None or (hasattr(query, "is_empty") and query.is_empty()):
        if terms:
            should = [_term_clause(t, search_fields) for t in terms[:40] if str(t).strip()]
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
) -> list[dict[str, str]]:
    case_dir = Path(case_dir)
    name = index_name(case_dir.name)
    needles = [t.lower() for t in terms if t.strip()]
    if not needles and query is None and not match_all:
        return []
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
            raise RuntimeError(f"search failed: {r.status_code} {r.text[:300]}")
        return r.json().get("hits", {}).get("hits", [])

    with _client() as client:
        head = client.head(f"/{name}")
        if head.status_code != 200:
            raise IndexMissing(f"no index {name}")
        search_fields = False
        if _schema_version_cached(case_dir.name) >= INDEX_SCHEMA_VERSION:
            # WP 4j.31: one pushed-down query — field filters on real fields,
            # terms/phrases/regex in ES (no per-term search loop). The intake
            # window is NOT pre-filtered here: a row may carry several dates
            # and the row-side `_row_in_window` check owns windowing, which
            # keeps ES and CSV results identical.
            try:
                search_fields = bool(fields_property_names(case_dir.name))
            except Exception:  # noqa: BLE001 — fall back to text-only search
                search_fields = False
            es_query = ast_to_es(query, terms=needles, match_all=match_all,
                                 search_fields=search_fields)
            body = {"size": 400, "query": es_query}
            r = client.post(f"/{name}/_search", json=body)
            if r.status_code >= 400:
                raise RuntimeError(f"search failed: {r.status_code} {r.text[:300]}")
            hits_raw = r.json().get("hits", {}).get("hits", [])
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
            # The structured ts is authoritative when present: imported rows
            # often carry no date inside `text`, and treating "no date in
            # text" as in-window would leak out-of-window imported rows.
            window_ok = False
            ts_raw = src.get("ts")
            if ts_raw:
                try:
                    from datetime import UTC as _UTC

                    dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=_UTC)
                    if not (start <= dt <= end):
                        continue
                    window_ok = True
                except ValueError:
                    window_ok = False
            if not window_ok and not _row_in_window(text, start, end):
                continue
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
            "text": text[:_MAX_LINE],
        }
        for key_name in ("host", "user", "event_id", "ts"):
            value = src.get(key_name)
            if value not in (None, ""):
                hit[key_name] = value
        hits.append(hit)
    return finalize_hits(hits, terms, priority_terms)

