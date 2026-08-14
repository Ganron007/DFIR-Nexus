"""N3 per-case Elasticsearch backend — same N4 hit schema as the CSV pack.

Indexes only this case's processed outputs (extractions / sift/extractions).
Never walks Evidence-files/. Offline fallback remains the CSV query pack.
"""

from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from nexus.langgraph.query_pack import (
    _DATE_RE,
    _MAX_LINE,
    _SKIP_SUFFIXES,
    _family,
    _row_in_window,
    _scan_prio,
    finalize_hits,
    iter_extraction_files,
)

_LARGE_NEEDLES = (
    "sdelete", ".pst", ".ost", "drivefs", "googledrive", "my drive",
    "usbstor", "prefetch", ".exe", "mimikatz", "rubeus", "psexec",
)
_MAX_LARGE = 400 * 1024 * 1024
_MAX_DOCS = 250_000
_MAX_DOCS_PER_FILE = 80_000
WILDCARD_IGNORE_ABOVE = 32766


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


def es_available() -> bool:
    if not es_url():
        return False
    try:
        with _client() as client:
            r = client.get("/")
            return r.status_code == 200 and "version" in r.json()
    except Exception:
        return False


def _ts_from_line(line: str) -> str | None:
    m = _DATE_RE.search(line)
    if not m:
        return None
    stamp = m.group(1)
    if m.group(2):
        return f"{stamp}T{m.group(2)}Z"
    return f"{stamp}T00:00:00Z"


def _should_keep_large_line(low: str, extra_needles: list[str]) -> bool:
    if any(n in low for n in extra_needles):
        return True
    return any(n in low for n in _LARGE_NEEDLES)


def iter_index_docs(
    case_dir: Path,
    extra_needles: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Documents for this case only. Large files (>80MB) keep matching rows."""
    case_dir = Path(case_dir)
    extra = [t.lower() for t in (extra_needles or []) if t.strip()]
    docs: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add(path: Path, root: Path, fam: str, i: int, line: str) -> None:
        text = line.strip()[:_MAX_LINE]
        key = hashlib.sha1(f"{path}:{i}:{text[:80]}".encode("utf-8", "replace")).hexdigest()
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
        ts = _ts_from_line(line)
        if ts:
            doc["ts"] = ts
        docs.append(doc)

    for path, root, fam in iter_extraction_files(case_dir):
        if len(docs) >= _MAX_DOCS:
            break
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, start=1):
                    if i == 1 and ("," in line or "\t" in line):
                        continue
                    _add(path, root, fam, i, line)
                    if i >= _MAX_DOCS_PER_FILE or len(docs) >= _MAX_DOCS:
                        break
        except OSError:
            continue

    # MFT-class files skipped by the CSV pack: index matching rows only.
    for root in (case_dir / "extractions", case_dir / "sift" / "extractions"):
        if not root.is_dir() or len(docs) >= _MAX_DOCS:
            break
        files: list[Path] = []
        for pat in ("*.csv", "*.txt"):
            files.extend(root.rglob(pat))
        for path in sorted(set(files), key=_scan_prio):
            if path.name.startswith("_") or path.name.endswith(_SKIP_SUFFIXES):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size <= 80 * 1024 * 1024 or size > _MAX_LARGE:
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
            f"{doc.get('file')}:{doc.get('line')}:{doc.get('text', '')[:80]}".encode()
        ).hexdigest()
        lines.append(json.dumps({"index": {"_index": index, "_id": _id}}))
        lines.append(json.dumps(doc, default=str))
    return "\n".join(lines) + "\n"


def ensure_index(case_id: str) -> str:
    name = index_name(case_id)
    mapping = {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "case_id": {"type": "keyword"},
                "family": {"type": "keyword"},
                "file": {"type": "keyword"},
                "line": {"type": "integer"},
                "text": {
                    "type": "text",
                    "fields": {"wc": {"type": "wildcard", "ignore_above": WILDCARD_IGNORE_ABOVE}},
                },
                "ts": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
            }
        },
    }
    with _client() as client:
        exists = client.head(f"/{name}")
        if exists.status_code == 200:
            client.delete(f"/{name}")
        r = client.put(f"/{name}", json=mapping)
        if r.status_code >= 400:
            raise RuntimeError(f"create index failed: {r.status_code} {r.text[:300]}")
    return name


def index_case(case_dir: Path, extra_needles: list[str] | None = None) -> dict[str, Any]:
    case_dir = Path(case_dir)
    docs = iter_index_docs(case_dir, extra_needles)
    name = ensure_index(case_dir.name)
    if not docs:
        return {"index": name, "docs": 0, "case_id": case_dir.name}
    import json

    chunk = 2000
    errors = 0
    with _client() as client:
        for i in range(0, len(docs), chunk):
            body = _bulk_ndjson(name, docs[i:i + chunk])
            r = client.post("/_bulk", content=body, headers={"Content-Type": "application/x-ndjson"})
            if r.status_code >= 400:
                raise RuntimeError(f"bulk failed: {r.status_code} {r.text[:300]}")
            payload = r.json()
            if payload.get("errors"):
                errors += sum(1 for item in payload.get("items") or [] if item.get("index", {}).get("error"))
        client.post(f"/{name}/_refresh")
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
    return meta


def query_index(
    case_dir: Path,
    terms: list[str],
    window: tuple[datetime | None, datetime | None],
    priority_terms: list[str] | None = None,
) -> list[dict[str, str]]:
    case_dir = Path(case_dir)
    name = index_name(case_dir.name)
    needles = [t.lower() for t in terms if t.strip()]
    if not needles:
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
        if not subset:
            return []
        body = {
            "size": size,
            "query": {
                "bool": {
                    "should": _should_for(subset),
                    "minimum_should_match": 1,
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
        # One search per strong term so SRUM USB/cloud volume cannot bury sdelete/PST.
        hits_raw = []
        for t in core:
            hits_raw.extend(_search(client, [t], 200))
        for t in cloud:
            hits_raw.extend(_search(client, [t], 80))
        hits_raw.extend(_search(client, rest, 400))

    hits: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in hits_raw:
        src = row.get("_source") or {}
        text = str(src.get("text") or "")
        if start is not None and end is not None and not _row_in_window(text, start, end):
            continue
        low = text.lower()
        matched = [t for t in needles if t in low]
        if not matched:
            continue
        key = (str(src.get("file") or ""), str(src.get("line") or 0))
        if key in seen:
            continue
        seen.add(key)
        hits.append({
            "family": str(src.get("family") or "other"),
            "file": key[0],
            "line": key[1],
            "terms": ",".join(matched[:6]),
            "text": text[:_MAX_LINE],
        })
    return finalize_hits(hits, terms, priority_terms)

