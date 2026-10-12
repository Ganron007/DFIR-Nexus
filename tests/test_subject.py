"""A finding's subject is derived from the rows it cites, by one rule for every mode (2026-10-12).

The rule is checked on real rows: documents the case index holds, shaped the way a search shapes
them, when Elasticsearch is up. The placeholders and precedence are checked on the values those
rows carry. Nothing here writes to a case.
"""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

import pytest
import yaml

from nexus.langgraph import es_native
from nexus.langgraph.event_categories import OTHER, known_categories
from nexus.langgraph.evidence_rows import evidence_rows_for_hits
from nexus.langgraph.subject import (
    GROUP_OF_CATEGORY,
    derive_subject,
    present,
    subject_fields,
    subject_key,
)

ES_URL = os.environ.get("NEXUS_ES_URL", "http://127.0.0.1:9200")
INDEX = os.environ.get("NEXUS_TEST_EVIDENCE_INDEX", "nexus-case-case-c5b04d31")
PRINCIPAL_TYPES = {"process", "account", "address", "file", "registry", "host"}


def _real_hits(query: dict, size: int = 40) -> list[dict]:
    body = json.dumps({"size": size, "query": query}).encode("utf-8")
    req = urllib.request.Request(f"{ES_URL}/{INDEX}/_search", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
    except Exception:  # noqa: BLE001 - no index or no server: nothing real to check
        pytest.skip(f"Elasticsearch index {INDEX} is not reachable")
    hits = [es_native._shape_hit(h["_source"]) for h in data.get("hits", {}).get("hits", [])]
    if not hits:
        pytest.skip(f"no documents match the query in {INDEX}")
    return hits


def _row(hit: dict) -> dict:
    return evidence_rows_for_hits([hit])[0]


# ---- the pure rules ---------------------------------------------------------------------------

def test_placeholders_the_logs_write_are_not_subjects():
    # Observed in the case index: `-\-` for an empty account, `%%1833` for an unresolved message
    # code, `S-1-0-0` for the null SID. None of them names anything.
    assert present("-\\-") == ""
    assert present("%%1833") == ""
    assert present("S-1-0-0") == ""
    assert present("  ") == ""
    assert present("rd01.shieldbase.com") == "rd01.shieldbase.com"


def test_the_logon_target_is_the_account_and_a_placeholder_is_skipped():
    fields = subject_fields({"user.name": "shieldbase\\RD01$", "user.target.name": "SYSTEM"})
    assert fields["account"] == "SYSTEM"
    assert subject_fields({"user.name": "-\\-"}) == {}


def test_every_pinned_category_has_a_subject_group():
    # A new category in the pinned table needs a decision about its subject here.
    assert set(GROUP_OF_CATEGORY) == known_categories()


def test_the_subject_key_needs_a_subject():
    assert subject_key({}, OTHER) == ""
    assert subject_key({"type": "host", "value": "rd01"}, "other") == "host:rd01|other"
    # The same identity however the type and value are written.
    assert subject_key({"type": "EventID", "value": " 1004 "}, None) == subject_key(
        {"type": "event_id", "value": "1004"}, "other")


def test_the_event_id_is_never_the_subject_type():
    rows = [{"loc": "a.csv:1", "event_id": "4624", "host": "RD01"}]
    assert derive_subject(rows) == {"entity": {"type": "host", "value": "rd01"}, "category": OTHER}


def test_rows_with_no_subject_give_no_entity():
    assert derive_subject([]) == {"entity": {}, "category": OTHER}
    assert derive_subject([{"loc": "a:1", "detail": "a sentence"}]) == {"entity": {}, "category": OTHER}


# ---- the rule on real rows --------------------------------------------------------------------

def test_a_process_creation_names_its_image_on_real_rows():
    hits = _real_hits({"bool": {"filter": [
        {"term": {"family": "evtxecmd"}}, {"term": {"ecs.event.code": "4688"}},
        {"exists": {"field": "ecs.process.executable"}}]}}, size=60)
    with_image = [h for h in hits if (h.get("ecs") or {}).get("process.executable")]
    if not with_image:
        pytest.skip("no 4688 document in the index carries a process image")
    for hit in with_image:
        derived = derive_subject([_row(hit)])
        assert derived["category"] == "process_creation"
        assert derived["entity"] == {"type": "process",
                                     "value": hit["ecs"]["process.executable"].lower()}


def test_a_logon_names_the_target_account_on_real_rows():
    hits = _real_hits({"bool": {"filter": [{"term": {"ecs.event.code": "4624"}}]}})
    with_target = [h for h in hits if (h.get("ecs") or {}).get("user.target.name")]
    if not with_target:
        pytest.skip("no 4624 document in the index carries a target account")
    for hit in with_target:
        derived = derive_subject([_row(hit)])
        # A logon's pinned category is authentication (the Elastic pipeline, D94); the account rule names it.
        assert derived["category"] == "authentication"
        assert derived["entity"]["type"] == "account"
        assert derived["entity"]["value"] == hit["ecs"]["user.target.name"].lower()


def test_a_row_without_account_or_address_falls_back_to_its_host_on_real_rows():
    hits = _real_hits({"bool": {"filter": [{"term": {"family": "evtxecmd"}}]}})
    bare = [h for h in hits
            if not (h.get("ecs") or {}).get("user.target.name")
            and not (h.get("ecs") or {}).get("user.name")
            and h.get("host")]
    if not bare:
        pytest.skip("no bare evtxecmd document in the index")
    for hit in bare:
        derived = derive_subject([_row(hit)])
        assert derived["entity"]["type"] in {"host", "process", "account", "address"}
        if derived["entity"]["type"] == "host":
            assert derived["entity"]["value"] == hit["host"].lower()


def test_no_real_row_names_an_event_id_as_its_subject():
    hits = _real_hits({"match_all": {}}, size=60)
    for hit in hits:
        derived = derive_subject([_row(hit)])
        assert derived["entity"].get("type", "") in PRINCIPAL_TYPES | {""}


def test_the_same_rows_give_the_same_subject_in_any_order():
    hits = _real_hits({"bool": {"filter": [{"term": {"family": "evtxecmd"}}]}}, size=12)
    rows = [_row(h) for h in hits]
    assert derive_subject(rows) == derive_subject(list(reversed(rows)))


def test_the_majority_category_decides_the_subject_order():
    proc = _real_hits({"bool": {"filter": [
        {"term": {"family": "evtxecmd"}}, {"term": {"ecs.event.code": "4688"}},
        {"exists": {"field": "ecs.process.executable"}}]}}, size=60)
    logons = _real_hits({"bool": {"filter": [
        {"term": {"family": "evtxecmd"}}, {"term": {"ecs.event.code": "4624"}},
        {"exists": {"field": "ecs.user.target.name"}}]}}, size=60)
    proc = [h for h in proc if (h.get("ecs") or {}).get("process.executable")]
    logons = [h for h in logons if (h.get("ecs") or {}).get("user.target.name")]
    if not proc or len(logons) < 2:
        pytest.skip("not enough real 4688 and 4624 rows in the index for a majority")
    rows = [_row(proc[0]), _row(logons[0]), _row(logons[1])]
    derived = derive_subject(rows)
    # Two of three rows are logons (authentication, D94), so the majority is authentication and the account rule decides.
    assert derived["category"] == "authentication"
    assert derived["entity"]["type"] == "account"


# ---- the stored draft ---------------------------------------------------------------------------

AUDIT_ID = "nexus-gate-bot-20260101-001"


def _case_with_audit(tmp_path: Path) -> Path:
    """A case with one real audit entry, as staging requires (the same shape the duplicate tests use)."""
    case = tmp_path / "CASE-SUBJ00001"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text(
        yaml.safe_dump({"case_id": "CASE-SUBJ00001", "name": "subject", "status": "created",
                        "severity": "medium"}),
        encoding="utf-8",
    )
    (case / "findings.json").write_text("[]", encoding="utf-8")
    (case / "audit").mkdir(parents=True, exist_ok=True)
    (case / "audit" / "nexus.jsonl").write_text(
        json.dumps({"audit_id": AUDIT_ID, "tool": "es_search", "case_id": "CASE-SUBJ00001"}) + "\n",
        encoding="utf-8",
    )
    return case


def test_the_stored_draft_keeps_its_subject_and_category_and_the_category_separates_duplicates(
    tmp_path: Path,
):
    """record_finding stores the subject and category, and the duplicate key sees the category: the
    same entity under another category is a different subject, not a duplicate."""
    from nexus.case_manager import CaseManager

    case = _case_with_audit(tmp_path)
    draft = {
        "title": "Host rd01 is named by the cited rows",
        "observation": "the cited row names the host",
        "interpretation": "the host is the subject of the cited rows",
        "confidence": "LOW",
        "confidence_justification": "one source",
        "severity": "MEDIUM",
        "audit_ids": [AUDIT_ID],
        "evidence": [{"detail": "cited row", "loc": "x.csv:1", "host": "rd01"}],
        "run_id": "M2-subject-1",
        "provenance": {"mode": 2},
        "entity": {"type": "host", "value": "rd01"},
        "category": "other",
    }
    first = CaseManager().record_finding(draft, case_dir=case)
    assert first["status"] not in ("ERROR", "VALIDATION_FAILED"), first
    (stored,) = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    assert stored["entity"] == {"type": "host", "value": "rd01"}
    assert stored["category"] == "other"

    other_category = {**draft, "run_id": "M3-subject-1", "category": "process_creation"}
    second = CaseManager().record_finding(other_category, case_dir=case)
    assert not second.get("duplicate"), second
    assert len(json.loads((case / "findings.json").read_text(encoding="utf-8"))) == 2
