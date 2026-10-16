"""IC-6 / IC-7 (Part 9): prove every stored skill-step and analytic query on real rows.

Each compiled query runs through the agents' own ES surface (`es_native.es_search`):

* on the **control index** (`build_control_corpus.py`: public EVTX parsed by the lane's EvtxECmd, and the
  ES-Mapping tool outputs) - the **positive control**: the query must return at least one real row, and
  the first row is recorded with the file it came from and that file's SHA-256;
* on **CASE-C5B04D31** - a count only, the **flood** measure (more than 100,000 rows is a flood for a
  search step; an aggregate step counts values instead of returning rows). No row of the case is read or
  stored.

A query that the surface had to normalize is recorded: a stored query must already be in final form.
The record is `devtools/knowledge/step-controls.json`; `tests/test_ic6_step_controls.py` checks every
stored query against it by hash, so a query changed without being proved again fails.

    python devtools/knowledge/prove_step_controls.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "src"))

SKILLS_DIR = REPO / "src" / "nexus" / "data" / "knowledge" / "skills"
ANALYTICS = REPO / "src" / "nexus" / "data" / "knowledge" / "needles" / "behavioral_analytics.yaml"
CORPUS = HERE / "control-corpus.json"
RECORD = HERE / "step-controls.json"
CONTROL_CASE = "IC6-CONTROLS"
MEASURE_CASE = "CASE-C5B04D31"
FLOOD = 100_000


def query_hash(es: Any, aggs: Any = None) -> str:
    blob = json.dumps({"es": es, "aggs": aggs}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _items() -> list[tuple[str, str, dict[str, Any]]]:
    """(id, kind, item) for every stored query: skill steps, then analytics."""
    out: list[tuple[str, str, dict[str, Any]]] = []
    for path in sorted(SKILLS_DIR.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for step in doc.get("steps") or []:
            if isinstance(step, dict) and isinstance(step.get("es"), dict):
                out.append((f"skill:{doc.get('skill')}/{step.get('name')}", str(step.get("kind") or "search"), step))
    doc = yaml.safe_load(ANALYTICS.read_text(encoding="utf-8")) or {}
    for analytic in doc.get("packs") or []:
        if isinstance(analytic, dict) and isinstance(analytic.get("es"), dict):
            out.append((f"analytic:{analytic.get('id')}", str(analytic.get("kind") or "search"), analytic))
    return out


def _refusal(result: dict[str, Any]) -> str:
    """Why the surface refused: the fields it could not match (a case without that log has no such field)."""
    terms = result.get("failed_terms") or []
    named = sorted({f"{t.get('field')} ({t.get('reason')})" for t in terms if isinstance(t, dict)})
    return "; ".join(named) or str(result.get("error") or "degraded")[:200]


def prove() -> dict[str, Any]:
    from nexus.langgraph.es_native import es_aggregate, es_search

    sha = {f["path"]: f["sha256"] for f in json.loads(CORPUS.read_text(encoding="utf-8"))["files"]}
    record: dict[str, Any] = {"control_case": CONTROL_CASE, "measure_case": MEASURE_CASE, "flood": FLOOD,
                              "items": {}}
    for ident, kind, item in _items():
        es, aggs = item["es"], item.get("es_aggs")
        entry: dict[str, Any] = {"kind": kind, "query_sha": query_hash(es, aggs)}
        try:
            ctl = es_search(CONTROL_CASE, es, size=1)
            entry["control_total"] = int(ctl.get("total") or 0)
            if ctl.get("error") or ctl.get("degraded"):
                # A refusal answers total 0; it is not "no row matched".
                entry["control_refused"] = _refusal(ctl)
            if ctl.get("normalized"):
                entry["normalized"] = ctl["normalized"]
            hits = ctl.get("hits") or []
            if hits:
                hit = hits[0]
                src = hit.get("_source") if isinstance(hit.get("_source"), dict) else hit
                rel = str(src.get("file") or "")
                path = rel if rel.startswith("ingest/") else "extractions/" + rel
                entry["control_row"] = {"family": src.get("family"), "file": src.get("file"),
                                        "line": src.get("line"), "file_sha256": sha.get(path, "")}
            if kind == "aggregate" and aggs:
                agg = es_aggregate(CONTROL_CASE, aggs, es)
                buckets = ((agg.get("aggregations") or {}).get("by") or {}).get("buckets") or []
                entry["control_buckets"] = len(buckets)
        except Exception as exc:  # noqa: BLE001 - a failed query is recorded, never read as zero
            entry["control_error"] = f"{type(exc).__name__}: {exc}"[:300]
        try:
            case = es_search(MEASURE_CASE, es, size=1)
            entry["case_total"] = int(case.get("total") or 0)
            if case.get("error") or case.get("degraded"):
                entry["case_refused"] = _refusal(case)
        except Exception as exc:  # noqa: BLE001
            entry["case_error"] = f"{type(exc).__name__}: {exc}"[:300]
        record["items"][ident] = entry
    return record


def summary(record: dict[str, Any]) -> dict[str, Any]:
    items = record["items"]
    out = {"items": len(items), "proved": 0, "no_control": [], "errors": [], "refused": [], "floods": [],
           "normalized": []}
    for ident, e in items.items():
        if e.get("control_error") or e.get("case_error"):
            out["errors"].append(ident)
        elif e.get("control_refused"):
            out["refused"].append(f"{ident}: {e['control_refused']}")
        elif e.get("control_total", 0) >= 1:
            out["proved"] += 1
        else:
            out["no_control"].append(ident)
        if e.get("kind") == "search" and e.get("case_total", 0) > FLOOD:
            out["floods"].append(f"{ident} ({e['case_total']:,})")
        if e.get("normalized"):
            out["normalized"].append(ident)
    return out


def main() -> int:
    if not os.environ.get("NEXUS_ES_URL"):
        os.environ["NEXUS_ES_URL"] = "http://127.0.0.1:9200"
    record = prove()
    record["summary"] = summary(record)
    RECORD.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    s = record["summary"]
    print(f"{s['items']} stored queries: {s['proved']} proved on real rows; {len(s['no_control'])} without a "
          f"control; {len(s['refused'])} refused on the control index; {len(s['errors'])} errors; "
          f"{len(s['floods'])} search floods; {len(s['normalized'])} normalized")
    for key in ("no_control", "refused", "errors", "floods", "normalized"):
        for line in s[key]:
            print(f"  {key}: {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
