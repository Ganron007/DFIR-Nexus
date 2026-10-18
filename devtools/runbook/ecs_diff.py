"""What a build makes of indexed rows: their host, user and ECS fields, per family, for comparing two builds.

A change to how a row's host, user or ECS fields are derived (`case_index._host_user_event`,
`ecs_normalize.normalize`) is measured this way before it is committed (TIER1-WORK-ORDERS Part 10, P6): `dump`
with the current code and with the change over the same rows, then `diff`. Every family whose values change is
listed with examples; only the families the fix names may change.

    python devtools/runbook/ecs_diff.py dump --src <tree>/src --out before.jsonl [--per-family 300]
    python devtools/runbook/ecs_diff.py dump --src <worktree>/src --out after.jsonl [--per-family 300]
    python devtools/runbook/ecs_diff.py diff before.jsonl after.jsonl

The rows are read from Elasticsearch (every `nexus-case-*` index, up to N rows per family, in a stable order),
so both dumps see the same rows. A row from the importer pass (`ingest/.../artifacts.jsonl`) is passed as one.
"""
from __future__ import annotations

import argparse
import inspect
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.request import Request, urlopen

ES = "http://localhost:9200"
KEYS = ("host", "user", "ecs.host.name", "ecs.user.name")


def _es(path: str, body: dict) -> dict:
    req = Request(f"{ES}/{path}", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())


def _dig(doc: dict, dotted: str):
    node = doc
    for part in dotted.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def dump(src: str, out: Path, per_family: int) -> int:
    sys.path.insert(0, src)
    from nexus.langgraph import case_index, ecs_normalize  # noqa: PLC0415

    hue_params = inspect.signature(case_index._host_user_event).parameters
    norm_params = inspect.signature(ecs_normalize.normalize).parameters
    families = _es("nexus-case-*/_search", {"size": 0, "aggs": {"i": {"terms": {"field": "_index", "size": 200}, "aggs": {
        "f": {"terms": {"field": "family", "size": 200}}}}}})["aggregations"]["i"]["buckets"]
    n = 0
    with out.open("w", encoding="utf-8") as fh:
        for ib in families:
            index = ib["key"]
            for fb in ib["f"]["buckets"]:
                hits = _es(f"{index}/_search", {
                    "size": per_family, "sort": [{"_doc": "asc"}],
                    "query": {"term": {"family": fb["key"]}}, "_source": ["family", "file", "fields"],
                })["hits"]["hits"]
                for h in hits:
                    s = h["_source"]
                    fam, fields = s.get("family") or "", s.get("fields") or {}
                    importer = str(s.get("file") or "").startswith("ingest/") and str(s.get("file")).endswith(
                        "artifacts.jsonl")
                    kw = {"family": fam} if "family" in hue_params else {}
                    host, user, _event = case_index._host_user_event(fields, **kw)
                    nkw = {"importer": importer} if "importer" in norm_params else {}
                    ecs = ecs_normalize.normalize(fam, fields, None, **nkw)
                    row = {"index": index, "id": h["_id"], "family": fam, "importer": importer,
                           "host": host.lower() if host else "", "user": user.lower() if user else "",
                           "ecs.host.name": _dig({"ecs": ecs}, "ecs.host.name") or "",
                           "ecs.user.name": _dig({"ecs": ecs}, "ecs.user.name") or ""}
                    fh.write(json.dumps(row) + "\n")
                    n += 1
    print(f"{n} row(s) -> {out}")
    return 0


def diff(before: Path, after: Path) -> int:
    def load(p: Path) -> dict[tuple[str, str], dict]:
        return {(r["index"], r["id"]): r for r in map(json.loads, p.read_text(encoding="utf-8").splitlines())}

    a, b = load(before), load(after)
    changed: dict[tuple[str, str], Counter] = defaultdict(Counter)
    examples: dict[tuple[str, str], list[str]] = defaultdict(list)
    for key, old in a.items():
        new = b.get(key)
        if new is None:
            continue
        for k in KEYS:
            if old[k] != new[k]:
                group = (old["family"], k)
                changed[group][f"{old[k]!r} -> {new[k]!r}"] += 1
                if len(examples[group]) < 3:
                    examples[group].append(f"{key[0]} {key[1]}")
    print(f"{len(a)} row(s) compared; {len(changed)} (family, field) pair(s) change")
    for (fam, k), counts in sorted(changed.items()):
        print(f"  {fam} {k}: {sum(counts.values())} row(s)")
        for change, n in counts.most_common(4):
            print(f"      {n:>5}  {change[:160]}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("dump")
    d.add_argument("--src", required=True)
    d.add_argument("--out", required=True, type=Path)
    d.add_argument("--per-family", type=int, default=300)
    c = sub.add_parser("diff")
    c.add_argument("before", type=Path)
    c.add_argument("after", type=Path)
    args = ap.parse_args()
    return dump(args.src, args.out, args.per_family) if args.cmd == "dump" else diff(args.before, args.after)


if __name__ == "__main__":
    raise SystemExit(main())
