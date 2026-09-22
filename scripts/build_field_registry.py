"""Build the shipped field registry (schema v5) from the ES-mapping catalog.

Reads Evidence-files/ES-Mapping/es_mappings/*.yaml (the observed, validated
tool-run catalog) and emits src/nexus/data/schema/field_registry.yaml:

- per-family columns (for reference + tests)
- the merged global column map the case index uses for explicit ``fields.*``
  properties (one index holds all families, so names must unify)

Conflict policy (documented, deterministic):
  int-only (long/integer/short/byte)      -> long
  int + double/float                      -> double
  keyword + text/object                   -> text  (indexed text+kw)
  anything else mixed                     -> text  (safe: searchable, typed
                                             numeric/date operators degrade)

Usage:
  python scripts/build_field_registry.py --report   # inspect conflicts only
  python scripts/build_field_registry.py            # write the registry
"""
from __future__ import annotations

import argparse
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
SRC_DIR = REPO / "Evidence-files" / "ES-Mapping" / "es_mappings"
OUT = REPO / "src" / "nexus" / "data" / "schema" / "field_registry.yaml"

INT_TYPES = {"long", "integer", "short", "byte", "unsigned_long"}
FLOAT_TYPES = {"double", "float", "half_float", "scaled_float"}
TEXT_TYPES = {"keyword", "text", "object", "ip", "wildcard"}
SKIP_STEMS = {"ingest-generic_csv", "ingest-generic_jsonl"}  # schema-on-read by design
# Columns whose real semantics are numeric even when some catalog typed them text.
NUMERIC_CONFLICT_ALLOW = {"source_port", "dest_port", "process_id", "pid", "ppid"}
TEMPORAL_SUFFIXES = (
    "timestamp", "time", "date", "datetime", "createdon", "modifiedon",
    "creationdate", "lastwrite", "starttime", "endtime", "eventtime",
)


def _temporal_name(name: str) -> bool:
    low = name.lower().replace("_", "")
    return any(low.endswith(sfx) for sfx in TEMPORAL_SUFFIXES)
# index family hint list (query_pack._FAMILY_HINTS) wins; stems match it for tools


def _norm_type(raw: str) -> str:
    t = str(raw or "").strip().lower()
    if t in INT_TYPES:
        return "long"
    if t in FLOAT_TYPES:
        return "double"
    if t == "boolean":
        return "boolean"
    if t in {"date", "date_nanos"}:
        return "date"
    return "text"


def _unify(name: str, types: set[str]) -> tuple[str, bool]:
    """(merged type, conflict?) for one column name across families.

    Numeric/date win over text only for columns where that is the real
    semantics (ports / process ids, temporal names) — those become typed and
    malformed values are dropped from the index (still in ``_source``). Every
    other mixed column resolves to text so it stays searchable everywhere.
    """
    if len(types) == 1:
        return next(iter(types)), False
    if types <= {"long"}:
        return "long", False
    if types <= {"long", "double"}:
        return "double", True
    if types <= {"text"}:
        return "text", False
    if types <= {"text", "keyword"}:
        return "text", False
    numeric = types & {"long", "double"}
    rest = types - numeric
    if numeric and rest <= {"text", "keyword"}:
        if name.lower() in NUMERIC_CONFLICT_ALLOW:
            return ("double" if "double" in numeric else "long"), True
        return "text", True
    if "date" in types and (types - {"date"}) <= {"text", "keyword"}:
        if _temporal_name(name):
            return "date", True
        return "text", True
    if numeric:
        return ("double" if "double" in numeric else "long"), True
    return "text", True


def _parse_catalog(path: Path) -> dict | None:
    """Tolerant parser for the semi-YAML catalog (notes/examples may be unquoted).

    Returns {"obsolete": bool, "blocked": bool, "validated": bool|None,
             "fields": [(name, es_type), ...]} or None when unusable.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    doc: dict = {"obsolete": False, "blocked": False, "validated": None, "fields": []}
    lines = text.splitlines()
    current: dict[str, str] | None = None
    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line[:1].isspace():
            m = re.match(r"^(obsolete|blocked|validated|field_catalog)\s*:\s*(.*)$", stripped, re.I)
            if m:
                key, val = m.group(1).lower(), m.group(2).strip().strip('"').lower()
                if key in ("obsolete", "blocked", "validated"):
                    doc[key] = val.startswith("true")
                elif key == "field_catalog":
                    doc["no_fields"] = val.startswith("null")
            continue
        # Any list item (top-level fields, vol plugins, srumecmd tables, suzaku)
        m = re.match(r"^-\s*([A-Za-z_][\w.]*)\s*:\s*(.*?)\s*$", stripped)
        if m:
            if current and current.get("name") and current.get("es_type"):
                doc["fields"].append(current)
            current = {m.group(1).lower(): m.group(2).strip().strip('"')}
            continue
        m = re.match(r"^([A-Za-z_][\w.]*)\s*:\s*(.*?)\s*$", stripped)
        if m and current is not None:
            key = m.group(1).lower()
            if key in {"name", "es_type", "type", "plugin"}:
                current[key] = m.group(2).strip().strip('"')
            continue
    if current and current.get("name") and current.get("es_type"):
        doc["fields"].append(current)
    return doc


def load_rows() -> tuple[dict[str, dict[str, str]], list[str]]:
    families: dict[str, dict[str, str]] = {}
    skipped: list[str] = []
    for path in sorted(SRC_DIR.glob("*.yaml")):
        stem = path.stem
        if stem in SKIP_STEMS:
            skipped.append(f"{stem} (schema-on-read by design)")
            continue
        doc = _parse_catalog(path)
        if doc is None:
            skipped.append(f"{stem} (unreadable)")
            continue
        if doc.get("obsolete") or doc.get("blocked") or doc.get("validated") is False:
            skipped.append(f"{stem} (obsolete/blocked/unvalidated)")
            continue
        if doc.get("no_fields"):
            skipped.append(f"{stem} (no fields — text/extraction tool)")
            continue
        cols: dict[str, str] = {}
        for entry in doc.get("fields") or []:
            name = str(entry.get("name") or "").strip()
            if not name or name.startswith("_"):
                continue
            cols[name] = _norm_type(str(entry.get("es_type") or ""))
        if cols:
            families[stem] = cols
        else:
            skipped.append(f"{stem} (no parseable fields)")
    return families, skipped


def merge(families: dict[str, dict[str, str]]) -> tuple[dict[str, dict], list[dict]]:
    by_name: dict[str, dict] = {}
    conflicts: list[dict] = []
    for fam, cols in families.items():
        for name, ctype in cols.items():
            row = by_name.setdefault(name, {"types": set(), "families": []})
            row["types"].add(ctype)
            row["families"].append(fam)
    out: dict[str, dict] = {}
    for name, row in sorted(by_name.items()):
        merged, conflict = _unify(name, set(row["types"]))
        out[name] = {
            "type": merged,
            "families": sorted(row["families"]),
            "observed_types": sorted(row["types"]),
        }
        if conflict:
            conflicts.append({
                "name": name,
                "resolved": merged,
                "observed": sorted(row["types"]),
                "families": sorted(row["families"])[:8],
            })
    return out, conflicts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", action="store_true", help="print conflicts, do not write")
    args = ap.parse_args()

    families, skipped = load_rows()
    columns, conflicts = merge(families)
    print(f"families: {len(families)}   merged columns: {len(columns)}   conflicts: {len(conflicts)}")
    for c in conflicts[:25]:
        print(f"  {c['name']!r}: {c['observed']} -> {c['resolved']}  [{', '.join(c['families'])}]")
    if len(conflicts) > 25:
        print(f"  ... and {len(conflicts) - 25} more")
    if skipped:
        print(f"skipped: {len(skipped)}")
        for s in skipped[:12]:
            print(f"  - {s}")

    if args.report:
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "generated": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "Evidence-files/ES-Mapping/es_mappings (validated tool-run catalog)",
        "policy": (
            "one case index holds all families: int-only->long; int+double->double; "
            "numeric/date win over text only for ports/process-ids/temporal names "
            "(malformed values dropped from the index, still in _source); any other "
            "mix->text so the column stays searchable everywhere"
        ),
        "counts": {
            "families": len(families),
            "columns": len(columns),
            "conflicts": len(conflicts),
        },
        "columns": {name: {"type": r["type"], "families": r["families"]}
                    for name, r in columns.items()},
        "conflicts": conflicts,
        "families": {fam: cols for fam, cols in sorted(families.items())},
    }
    OUT.write_text(
        "# GENERATED by scripts/build_field_registry.py - do not edit by hand.\n"
        + yaml.safe_dump(payload, sort_keys=False, allow_unicode=True, width=100),
        encoding="utf-8",
    )
    print(f"wrote {OUT.relative_to(REPO)} ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
