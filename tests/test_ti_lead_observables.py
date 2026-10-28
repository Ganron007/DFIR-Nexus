"""D455/D456: threat intel takes typed observables from lead rows; the digest carries no stale TI.

The fixture holds rows captured from CASE-4387EB47 (T22, one memory image) on 2026-10-28. A pattern
sweep of every row typed each of the first six as an IOC; T22's census gave 8,337 such values and
Mode 1 spent hours sending them to external providers. Only the Volatility netscan row has a typed
remote address.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus.langgraph import ti_context
from nexus.langgraph.typed_entities import OBSERVABLE_KINDS, observable_kind, observables_from_ecs

_FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "t22_d455_rows.json").read_text(encoding="utf-8"))
_ROWS = [r["_source"] for r in _FIXTURE["rows"]]
_LEAD = _FIXTURE["lead"]


def _row_texts(source: dict) -> list[str]:
    return [str(source.get("text") or "")] + [str(v) for v in (source.get("fields") or {}).values()]


def test_the_pattern_rule_typed_every_captured_row_as_an_ioc():
    """The witness: what the removed whole-case sweep did with these rows."""
    found = [{k: v for k, v in ti_context.extract_iocs(_row_texts(s)).items() if v} for s in _ROWS]
    assert found[0] == {"sha256": ["5ead046fc3c3fe0c4042c2124fc1e387d5913802200ee695781845564818226e"]}
    assert found[1] == {"sha1": ["abe70cb8ccc48e02d4fe25b1237327d64114666b"]}
    assert found[2] == {"md5": ["73ba54f8e32e5a940ac29c831f8664aa"]}
    assert found[3]["md5"] == ["0a312f7d91a45f323e2988aaf603b655"]
    assert found[4] == {"md5": ["0ab5c62238e1d50114000000743dd83b"]}
    assert found[5] == {"ipv4": ["3.10.0.0"]}


def test_only_a_typed_field_makes_an_observable():
    typed = [{k: sorted(v) for k, v in observables_from_ecs(s.get("ecs")).items() if v}
             for s in _ROWS]
    assert typed[:6] == [{}] * 6
    # The netscan row's private local address is not an observable; its public remote one is.
    assert _ROWS[6]["ecs"]["source"]["ip"] == "172.16.6.101"
    assert typed[6] == {"ipv4": ["52.114.132.73"]}


@pytest.mark.parametrize(("path", "kind"), [
    ("ecs.process.hash.sha256", "sha256"),
    ("file.hash.md5", "md5"),
    ("ecs.destination.ip", "ipv4"),
    ("ecs.source.ip", "ipv4"),
    ("ecs.dns.question.name", "domain"),
    ("ecs.url.full", "url"),
    ("ecs.winlog.event_data.Hashes", None),
    ("ecs.winlog.event_data.DestinationIp", None),
    ("ecs.process.name", None),
    ("ecs.file.path", None),
])
def test_observable_kind_is_the_field_meaning(path, kind):
    assert observable_kind(path) == kind


def _fake_index(monkeypatch, docs):
    """The index as the lead-row reader sees it: the captured stored documents."""
    def iter_sources(case_id, query, source):
        pairs = {(c["bool"]["filter"][0]["term"]["file"], str(c["bool"]["filter"][1]["term"]["line"]))
                 for c in query["bool"]["should"]}
        for doc in docs:
            if (doc["file"], str(doc["line"])) in pairs:
                yield doc

    monkeypatch.setattr(ti_context, "iter_sources", iter_sources)


def _fake_aggregations(monkeypatch, docs, types):
    """The typed fields' exact aggregations, computed from the captured stored documents."""
    from nexus.langgraph import es_native, typed_entities

    def value_of(doc, field):
        node = doc
        for part in field.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        return node

    def counts(case_id, field, query):
        found = {}
        for doc in docs:
            value = value_of(doc, field)
            if value not in (None, ""):
                entry = found.setdefault(str(value), {"value": str(value), "count": 0, "families": [],
                                                      "source_file": doc["file"]})
                entry["count"] += 1
                if doc["family"] not in entry["families"]:
                    entry["families"].append(doc["family"])
        return list(found.values())

    monkeypatch.setattr(es_native, "_field_types", lambda case_id: types)
    monkeypatch.setattr(typed_entities, "_field_value_counts", counts)


def test_a_real_lead_selects_only_the_rows_it_cites(monkeypatch):
    _fake_index(monkeypatch, _ROWS + _FIXTURE["lead_docs"])
    selection = ti_context.select_lead_observables("CASE-4387EB47", [_LEAD])
    assert (selection["leads"], selection["lead_rows"], selection["rows_found"]) == (1, 4, 4)
    # The YARA rows name a process and a rule, no typed observable; the netscan row is not cited.
    assert selection["iocs"] == {kind: [] for kind in OBSERVABLE_KINDS}
    assert ti_context.lead_locations([_LEAD]) == {
        (row["loc"].rpartition(":")[0], row["loc"].rpartition(":")[2]): [_LEAD["subject"]]
        for row in _LEAD["rows"]
    }


def test_the_case_inventory_takes_the_same_typed_fields(monkeypatch):
    """FM-2/FM-7: the inventory is the typed fields' values; the rows' text types nothing."""
    from nexus.langgraph.entity_inventory import build_entity_inventory, render_inventory_markdown

    _fake_aggregations(monkeypatch, _ROWS, {
        "ecs.destination.ip": "keyword", "ecs.source.ip": "keyword", "ecs.process.name": "keyword",
        "fields.Text": "text", "host": "keyword", "user": "keyword"})
    inv = build_entity_inventory("CASE-4387EB47")
    assert inv["ipv4"] == [{"value": "52.114.132.73", "count": 1, "families": ["vol"],
                            "source_file": _ROWS[6]["file"]}]
    for kind in ("sha256", "sha1", "md5", "domain", "url", "process", "executable", "host", "user"):
        assert inv[kind] == [], kind
    assert inv["fields"]["ipv4"] == ["ecs.destination.ip", "ecs.source.ip"]
    rendered = render_inventory_markdown(inv)
    assert "EVERY" not in rendered and "a reference, not a checklist" in rendered
    assert "- ipv4: 1 distinct (ecs.destination.ip, ecs.source.ip)" in rendered


def test_known_good_hashes_never_reach_a_provider(monkeypatch):
    sent = []
    selection = {"leads": 1, "lead_rows": 1, "rows_found": 1, "sources": {},
                 "iocs": {"sha256": ["a" * 64, "b" * 64], "sha1": [], "md5": [], "ipv4": ["52.114.132.73"],
                          "domain": [], "url": []}}
    monkeypatch.setattr(ti_context, "known_good_hashes", lambda values: {"a" * 64: [r"\windows\system32\x.dll"]})
    monkeypatch.setattr(ti_context, "enrich_iocs", lambda values: sent.extend(values) or [])
    context = ti_context.build_case_ti_context(selection)
    assert sent == ["b" * 64, "52.114.132.73"]
    assert context["iocs"] == sent
    assert "in the local known-good baseline (not sent out): 1" in context["markdown"]


def test_no_lead_observable_means_no_provider_call(monkeypatch):
    monkeypatch.setattr(ti_context, "enrich_iocs", lambda values: pytest.fail("no lookup expected"))
    selection = {"leads": 191, "lead_rows": 285, "rows_found": 285, "sources": {},
                 "iocs": {kind: [] for kind in OBSERVABLE_KINDS}}
    context = ti_context.build_case_ti_context(selection)
    assert context["results"] == []
    assert "285 evidence row(s) cited by 191 lead(s)" in context["markdown"]


def test_the_digest_does_not_carry_an_earlier_runs_ti(tmp_path):
    from nexus.langgraph.case_digest import build_case_digest, render_digest_markdown

    case = tmp_path / "CASE-D456"
    (case / "analysis").mkdir(parents=True)
    (case / "analysis" / "ti_context.md").write_text("# Threat-intel context\nSTALE PREVIOUS RUN\n",
                                                     encoding="utf-8")
    digest = build_case_digest(case, brief={})
    assert "ti_context_md" not in digest
    assert "STALE PREVIOUS RUN" not in render_digest_markdown(digest)
