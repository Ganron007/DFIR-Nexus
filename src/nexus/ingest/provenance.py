"""Append-only importer provenance keyed by the artifact store's content identity."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

LEDGER_NAME = "_importer_provenance.jsonl"
LEDGER_REL = f"ingest/{LEDGER_NAME}"


def artifact_key(d: dict[str, Any]) -> tuple:
    """The existing ingest deduplication identity, independent of parser metadata."""
    raw = d.get("raw")
    raw_hash = ""
    if raw not in (None, "", {}):
        raw_hash = hashlib.sha1(str(raw).encode("utf-8", "replace")).hexdigest()[:16]
    return (
        d.get("source"), d.get("artifact_type"), None if raw_hash else d.get("timestamp"),
        d.get("src_ip") or d.get("source_ip"), d.get("source_port"), d.get("dest_ip"),
        d.get("dest_port"), d.get("protocol"), d.get("user"), d.get("file_path"),
        d.get("process_name"), str(d.get("description") or d.get("details") or ""), raw_hash,
    )


def artifact_key_digest(record: dict[str, Any]) -> str:
    """A stable ledger key derived from exactly the same identity as deduplication."""
    key = json.dumps(artifact_key(record), ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def ledger_path(case_dir: Path) -> Path:
    return Path(case_dir) / "ingest" / LEDGER_NAME


def importer_leaves(chains: list[list[str]]) -> list[str]:
    """The actual leaf parsers of recorded execution chains, in stable order."""
    return sorted({chain[-1] for chain in chains if chain})


_LEDGER_CACHE: dict[str, tuple[int, int, dict[str, set[tuple[str, ...]]]]] = {}


def load_provenance(case_dir: Path) -> dict[str, set[tuple[str, ...]]]:
    """Read all distinct observed chains; malformed entries must not be hidden."""
    path = ledger_path(case_dir)
    try:
        stat = path.stat()
    except FileNotFoundError:
        _LEDGER_CACHE.pop(str(path), None)
        return {}
    cached = _LEDGER_CACHE.get(str(path))
    if cached and cached[:2] == (stat.st_mtime_ns, stat.st_size):
        return cached[2]
    chains: dict[str, set[tuple[str, ...]]] = {}
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            try:
                row = json.loads(line)
                key, chain = row["key"], row["chain"]
                if (not isinstance(key, str) or len(key) != 64 or not isinstance(chain, list)
                        or not chain or not all(isinstance(item, str) and item for item in chain)):
                    raise ValueError("invalid key or chain")
            except (ValueError, TypeError, KeyError) as exc:
                raise ValueError(f"invalid importer provenance at {path}:{number}") from exc
            chains.setdefault(key, set()).add(tuple(chain))
    _LEDGER_CACHE[str(path)] = (stat.st_mtime_ns, stat.st_size, chains)
    return chains


def append_provenance(case_dir: Path, records: list[dict[str, Any]]) -> None:
    """Record each actual parser chain once, including on deduplicated re-imports."""
    path = ledger_path(case_dir)
    existing = load_provenance(case_dir)
    pending: dict[str, set[tuple[str, ...]]] = {}
    additions: list[str] = []
    for record in records:
        chain = record.get("importer_chain") or []
        if not chain:
            continue
        if not isinstance(chain, list) or not all(isinstance(item, str) and item for item in chain):
            raise ValueError("invalid importer chain")
        key = artifact_key_digest(record)
        value = tuple(chain)
        if value not in existing.get(key, set()) and value not in pending.get(key, set()):
            pending.setdefault(key, set()).add(value)
            additions.append(json.dumps({"key": key, "chain": chain}, ensure_ascii=False))
    if additions:
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write("\n".join(additions) + "\n")
        for key, values in pending.items():
            existing.setdefault(key, set()).update(values)
        stat = path.stat()
        _LEDGER_CACHE[str(path)] = (stat.st_mtime_ns, stat.st_size, existing)
