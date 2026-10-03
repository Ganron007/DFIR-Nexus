"""WO-K3 — anomaly lead generators.

Two things these tests must prove, because the work order names them:

* a fixture with one rare service and one wrong-parent `lsass` yields **those
  two** leads, each with its evidence rows and its audit ids;
* a benign fixture yields **no ancestry lead** — FD-004, an absent or neutral
  baseline is never escalated.

Plus the properties a lead source needs to be usable: deterministic output, and
a lead file that round-trips.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.analysis.leads import (
    Lead,
    build_leads,
    read_leads,
    registry_fields,
)

# The field names the fixtures use. Injected so the test does not depend on
# which families the shipped registry happens to carry.
FIELDS = {"Service Name", "Process Name", "Parent Process Name"}


class FakeProbe:
    """A probe with no Elasticsearch and no triage DB behind it."""

    def __init__(self, spans=None, calls=None, verdicts=None, buckets=None):
        self._spans = spans or {}
        self._calls = calls or []
        self._verdicts = verdicts or {}
        self._buckets = buckets or []
        self.aggregate_calls: list[dict] = []

    def aggregate(self, **kwargs):
        self.aggregate_calls.append(dict(kwargs))
        field_name = str(kwargs.get("field") or "")
        if kwargs.get("dsl"):
            # The pair aggregation for ancestry.
            pairs = {}
            for call in self._calls:
                pairs.setdefault(call["process"], []).append(call.get("parent", ""))
            return {
                "buckets": [
                    {"key": p, "parents": {"buckets": [{"key": pn} for pn in parents if pn]}}
                    for p, parents in pairs.items()
                ],
                "audit_id": "nexus-lead-pairs",
            }
        return {
            "top": self._spans.get(field_name, []),
            "buckets": self._buckets,
            "audit_id": f"nexus-lead-{field_name.replace(' ', '-').lower()}",
        }

    def observed_calls(self, process_field="ImageFileName", parent_field="ParentImage"):
        # Mirror the real probe: the aggregation's audit id rides on each pair.
        result = self.aggregate(dsl="pairs", field=process_field, top=200, match_all=True)
        audit_id = str((result or {}).get("audit_id") or "")
        out = []
        for call in self._calls:
            out.append({**call, "audit_id": audit_id})
        return out

    def process_check(self, **kwargs):
        return self._verdicts.get(str(kwargs.get("process_name") or ""), {})


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-LEADS"
    (case / "analysis").mkdir(parents=True, exist_ok=True)
    return case


def test_a_rare_service_and_a_wrong_parent_lsass_are_both_raised(tmp_path):
    """The work order's own fixture, asserted lead by lead."""
    case = _case(tmp_path)
    probe = FakeProbe(
        spans={
            "Service Name": [{"value": "evil_svc", "count": 1}],
            "Process Name": [{"value": "lsass", "count": 12},
                             {"value": "explorer", "count": 900}],
        },
        calls=[{"process": "lsass", "parent": "evil_svc"}],
        verdicts={"lsass": {"verdict": "SUSPICIOUS", "parent_name": "evil_svc",
                            "reason": "parent is on the baseline's suspicious list"}},
    )
    leads = build_leads(case, probe=probe, known_fields=FIELDS)
    by_kind = {lead.kind: lead for lead in leads}

    assert "rarity" in by_kind, [lead.kind for lead in leads]
    rare = [lead for lead in leads if lead.kind == "rarity"]
    assert [lead.subject for lead in rare] == ["evil_svc"], rare

    assert "ancestry" in by_kind, [lead.kind for lead in leads]
    ancestry = by_kind["ancestry"]
    assert ancestry.subject == "lsass"
    assert "evil_svc" in ancestry.detail
    assert ancestry.score == 0.9

    # Every lead carries its rows and its audit ids.
    for lead in leads:
        assert lead.rows, f"{lead.kind} lost its rows"
        assert lead.audit_ids, f"{lead.kind} lost its audit ids"
        assert all(str(a).strip() for a in lead.audit_ids)


def test_a_benign_fixture_raises_no_ancestry_lead(tmp_path):
    """Nothing disagrees with the baseline, so there is no lead to raise."""
    case = _case(tmp_path)
    probe = FakeProbe(
        spans={"Process Name": [{"value": "lsass", "count": 12},
                                {"value": "explorer", "count": 900}]},
        calls=[{"process": "lsass", "parent": "wininit"}],
        verdicts={},  # no baseline disagreement
    )
    leads = build_leads(case, probe=probe, known_fields=FIELDS)
    assert [lead for lead in leads if lead.kind == "ancestry"] == []


def test_an_unknown_verdict_is_never_escalated(tmp_path):
    """FD-004: UNKNOWN is neutral. Only a real disagreement becomes a lead."""
    case = _case(tmp_path)
    probe = FakeProbe(
        spans={"Process Name": [{"value": "unknown_tool", "count": 3}]},
        calls=[{"process": "unknown_tool", "parent": "cmd"}],
        verdicts={"unknown_tool": {"verdict": "UNKNOWN", "reason": "not in baseline"}},
    )
    leads = build_leads(case, probe=probe, known_fields=FIELDS)
    assert [lead for lead in leads if lead.kind == "ancestry"] == []


def test_leads_are_deterministic_and_round_trip(tmp_path):
    """Two builds over the same index must agree, and the file must reload."""
    case = _case(tmp_path)
    spans = {
        "Service Name": [{"value": "b_svc", "count": 1}, {"value": "a_svc", "count": 1}],
        "Process Name": [{"value": "rare.exe", "count": 1}],
    }
    first = build_leads(case, probe=FakeProbe(spans=spans), known_fields=FIELDS)
    stored = (case / "analysis" / "leads.jsonl").read_text(encoding="utf-8")
    second = build_leads(case, probe=FakeProbe(spans=spans), known_fields=FIELDS)
    assert (case / "analysis" / "leads.jsonl").read_text(encoding="utf-8") == stored
    assert [lead.to_dict() for lead in first] == [lead.to_dict() for lead in second]

    reloaded = read_leads(case)
    assert len(reloaded) == len(first)
    assert {item["subject"] for item in reloaded} == {lead.subject for lead in first}


def test_a_field_the_case_does_not_carry_is_not_probed(tmp_path):
    """Guessing a field name would silently return nothing and look benign."""
    case = _case(tmp_path)
    probe = FakeProbe(spans={"Service Name": [{"value": "evil_svc", "count": 1}]})
    build_leads(case, probe=probe, known_fields={"Service Name"})
    probed = {str(call.get("field")) for call in probe.aggregate_calls}
    assert "Service Name" in probed
    assert "Process Name" not in probed, probed


def test_a_broken_probe_kind_does_not_lose_the_others(tmp_path):
    """One unavailable layer must not take the whole lead set with it."""
    case = _case(tmp_path)

    class HalfBroken(FakeProbe):
        def aggregate(self, **kwargs):
            if kwargs.get("dsl"):
                raise RuntimeError("dsl unsupported on this backend")
            return super().aggregate(**kwargs)

    probe = HalfBroken(spans={"Service Name": [{"value": "evil_svc", "count": 1}]})
    leads = build_leads(case, probe=probe, known_fields=FIELDS)
    assert [lead.subject for lead in leads if lead.kind == "rarity"] == ["evil_svc"]


def test_burst_needs_a_real_spike(tmp_path):
    case = _case(tmp_path)
    flat = FakeProbe(buckets=[{"key_as_string": f"h{i}", "count": 30} for i in range(6)])
    assert [lead for lead in build_leads(case, probe=flat, known_fields=FIELDS)
            if lead.kind == "burst"] == []

    spiky = FakeProbe(buckets=[
        {"key_as_string": "h0", "count": 30},
        {"key_as_string": "h1", "count": 4000},
        {"key_as_string": "h2", "count": 30},
    ])
    bursts = [lead for lead in build_leads(case, probe=spiky, known_fields=FIELDS)
              if lead.kind == "burst"]
    assert len(bursts) == 1 and bursts[0].rows[0]["count"] == 4000


def test_a_lead_serialises_without_losing_provenance(tmp_path):
    lead = Lead(kind="rarity", subject="x", family="Service Name", detail="d",
                rows=({"a": 1},), audit_ids=("nexus-1",), score=1.0)
    payload = json.loads(json.dumps(lead.to_dict()))
    assert payload["audit_ids"] == ["nexus-1"]
    assert payload["rows"] == [{"a": 1}]


def test_the_shipped_registry_names_the_fields_rarity_probes():
    """The candidate field names must resolve, or K3 finds nothing on real cases.

    Four of the first seven names were stale (`Process Name`, `Task Name`,
    `Parent Process Name`, `Logon Source` are not registry columns) - every one a
    silent no-op that would have read as "no anomalies". This pins that the
    concept table keeps at least a useful majority resolvable.
    """
    known = registry_fields(Path("."))
    if not known:
        return  # registry not built in this checkout; the injected-field tests cover the logic
    from nexus.analysis.leads import RARITY_CONCEPTS, resolve_concept

    resolved = {
        concept: resolve_concept(concept, known) for concept, _ in RARITY_CONCEPTS
    }
    present = {c: f for c, f in resolved.items() if f}
    assert len(present) >= 4, f"only {present} of the concept table resolves: {resolved}"
    # The three that were verified by hand against the registry.
    assert resolved["service"] == "Service Name"
    assert resolved["executable"] in ("Executable", "ExecutableName")
    assert resolved["account"] in ("User", "UserName", "TargetUserName")
    # And the process concept must land on something a real family carries.
    assert resolved["process"] in ("ImageFileName", "Process", "Image", "ExecutableName")
