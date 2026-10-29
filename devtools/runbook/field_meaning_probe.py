"""What a memory case's index answers by field meaning (TA-5, D468-D471). Read only.

    python devtools/runbook/field_meaning_probe.py CASE-4387EB47

Prints one JSON object: the MemProcFS event rows and how many carry a channel and an envelope user, the rows a
stored Windows-event query (lateral_movement's service-install step) returns, task principal ids read as users, rows
from the MemProcFS wrapper's own tables, typed memory connections, 4672 rows with a user, and the host identity's
machine accounts. T22 before D469-D471 (index of 2026-10-25): 42,931 / 0 / 0, 0 hits, 57, 76,118, 0, 0.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

from nexus.langgraph.es_native import _client_and_index

REPO = Path(__file__).resolve().parents[2]
SKILL = REPO / "src" / "nexus" / "data" / "knowledge" / "skills" / "lateral_movement.yaml"


def _service_install_query() -> dict:
    """The stored ES query of the skill step that reads System 7045 and Security 4697."""
    def walk(node):
        if isinstance(node, dict):
            if "es_source" in node and "4697" in json.dumps(node["es_source"]):
                yield node["es_source"]
            for value in node.values():
                yield from walk(value)
        elif isinstance(node, list):
            for value in node:
                yield from walk(value)

    return next(walk(yaml.safe_load(SKILL.read_text(encoding="utf-8"))))


def main(case_id: str) -> int:
    client, name = _client_and_index(case_id)

    def count(query: dict) -> int:
        with client() as c:
            resp = c.post(f"/{name}/_count", json={"query": query})
            resp.raise_for_status()
            return int(resp.json()["count"])

    mem = {"term": {"family": "memprocfs"}}
    events = {"wildcard": {"file": "*/csv/eventlog.csv"}}
    out = {
        "memory event rows": count({"bool": {"filter": [mem, events]}}),
        "memory event rows with ecs.winlog.channel": count(
            {"bool": {"filter": [mem, events, {"exists": {"field": "ecs.winlog.channel"}}]}}),
        "memory event rows with an envelope user": count(
            {"bool": {"filter": [mem, events, {"exists": {"field": "user"}}]}}),
        "stored service-install query (lateral_movement 7045/4697) hits": count(_service_install_query()),
        "envelope user author/users": count({"terms": {"user": ["author", "users"]}}),
        "memprocfs rows from the wrapper's own tables": count(
            {"bool": {"filter": [mem], "must_not": [{"wildcard": {"file": "*/forensic/*"}},
                                                    {"wildcard": {"file": "*sysinfo.csv"}}]}}),
        "memory connections with ecs.destination.ip": count(
            {"bool": {"filter": [mem, {"wildcard": {"file": "*/forensic/csv/net.csv"}},
                                 {"exists": {"field": "ecs.destination.ip"}}]}}),
        "4672 rows with ecs.user.name": count(
            {"bool": {"filter": [{"term": {"event_id": "4672"}}, {"exists": {"field": "ecs.user.name"}}]}}),
    }
    from nexus.analysis.host_identity import machine_accounts

    out["machine accounts"] = machine_accounts(REPO / "cases" / case_id)
    print(json.dumps(out, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
