"""EH-9 — audit-id ↔ evidence linkage.

FD-001 stops being mechanical: a finding may only cite audit ids whose calls
actually reference the finding's evidence families/files. No unrelated
fallbacks anywhere in the chain.
"""
from __future__ import annotations

import json
from pathlib import Path


def _case(tmp_path: Path, name: str = "CASE-LINK") -> Path:
    case = tmp_path / name
    (case / "extractions").mkdir(parents=True)
    (case / "audit").mkdir(parents=True)
    return case


def _ledger(case: Path, rows: list[dict]) -> None:
    (case / "extractions" / "_tool_lane_ledger.json").write_text(
        json.dumps(rows), encoding="utf-8"
    )


def _audit_entry(case: Path, **entry) -> None:
    entry.setdefault("ts", "2026-09-19T00:00:00+00:00")
    entry.setdefault("source", "mcp")
    (case / "audit" / "nexus.jsonl").write_text(
        json.dumps(entry) + "\n", encoding="utf-8"
    )


def test_ledger_linkage_exact_family_match(tmp_path):
    from nexus.langgraph.audit_linkage import linked_audit_ids

    case = _case(tmp_path)
    _ledger(case, [
        {"tool": "hayabusa", "status": "OK", "audit_id": "hayabusa-tester-20260919-001",
         "output_files": [{"path": str(case / "extractions" / "hayabusa" / "evtx-timeline.csv")}]},
        {"tool": "evtxecmd", "status": "OK", "audit_id": "evtxecmd-tester-20260919-002",
         "output_files": [{"path": str(case / "extractions" / "evtxecmd" / "out.csv")}]},
    ])
    hay = linked_audit_ids(case, {"hayabusa"})
    assert "hayabusa-tester-20260919-001" in hay
    assert "evtxecmd-tester-20260919-002" not in hay
    # no unrelated fallback: an unknown family links to nothing
    assert linked_audit_ids(case, {"unmappedfam"}) == []


def test_ingest_audit_log_linkage(tmp_path):
    """Importers audit with tool=ingest_auto and result_summary.source=<family>."""
    from nexus.langgraph.audit_linkage import is_linked, linked_audit_ids

    case = _case(tmp_path)
    _audit_entry(
        case, tool="ingest_auto", audit_id="ingest_auto-tester-20260919-003",
        params={"path": str(case / "in" / "eve.json"), "source": ""},
        result_summary={"success": True, "artifacts": 5, "source": "suricata"},
    )
    assert linked_audit_ids(case, {"suricata"}) == ["ingest_auto-tester-20260919-003"]
    assert linked_audit_ids(case, {"zeek"}) == []
    assert is_linked(case, "ingest_auto-tester-20260919-003", {"suricata"}, []) is True
    assert is_linked(case, "ingest_auto-tester-20260919-003", {"zeek"}, []) is False


def test_file_basename_linkage(tmp_path):
    from nexus.langgraph.audit_linkage import linked_audit_ids

    case = _case(tmp_path)
    _ledger(case, [
        {"tool": "mftecmd", "status": "OK", "audit_id": "mftecmd-tester-20260919-004",
         "output_files": [{"path": str(case / "extractions" / "mftecmd" / "$MFT.csv")}]},
    ])
    assert "mftecmd-tester-20260919-004" in linked_audit_ids(
        case, set(), files=["mftecmd/$MFT.csv"]
    )
    assert linked_audit_ids(case, set(), files=["other/nothere.csv"]) == []


def test_linkage_cache_invalidates_on_mtime(tmp_path):
    from nexus.langgraph.audit_linkage import linkage_map

    case = _case(tmp_path)
    _ledger(case, [{"tool": "hayabusa", "status": "OK", "audit_id": "hayabusa-tester-20260919-005"}])
    assert set(linkage_map(case)) == {"hayabusa-tester-20260919-005"}
    # a new audit entry must show up (mtime stamp changes)
    _audit_entry(case, tool="ingest_auto", audit_id="ingest_auto-tester-20260919-006",
                 result_summary={"source": "zeek"})
    assert set(linkage_map(case)) == {"hayabusa-tester-20260919-005", "ingest_auto-tester-20260919-006"}


def test_n4_finding_candidates_have_no_unrelated_audit_padding(tmp_path, monkeypatch):
    """The salvage path used to attach the first OK audit id of ANY tool when
    no family match existed. It must now produce no audit_ids at all."""
    from nexus.langgraph import query_pack
    from nexus.langgraph.query_pack import n4_finding_candidates

    case = _case(tmp_path)
    _ledger(case, [
        {"tool": "evtxecmd", "status": "OK", "audit_id": "evtxecmd-tester-20260919-002"},
    ])
    hit = {
        "family": "suricata", "file": "suricata/eve.json", "line": "2",
        "text": "sdelete.exe observed", "terms": "sdelete", "terms_list": ["sdelete"],
    }
    monkeypatch.setattr(query_pack, "n4_hits", lambda *a, **k: ([hit], "csv"))
    monkeypatch.setattr(query_pack, "load_case_intake", lambda d: {})
    monkeypatch.setattr(query_pack, "collect_query_terms", lambda i: ["x"])
    monkeypatch.setattr(query_pack, "collect_playbook_query_terms", lambda i: ["x"])
    candidates = n4_finding_candidates(case)
    assert candidates
    assert candidates[0]["audit_ids"] == []

    # once the ingest run is audited, the same hit links
    _audit_entry(case, tool="ingest_auto", audit_id="ingest_auto-tester-20260919-003",
                 result_summary={"source": "suricata"})
    candidates2 = n4_finding_candidates(case)
    assert candidates2[0]["audit_ids"] == ["ingest_auto-tester-20260919-003"]


def test_finding_payload_pads_only_linked_ids():
    from nexus.langgraph.llm_pipeline import _finding_tool_payload

    payload = _finding_tool_payload(
        {"title": "x", "observation": "y", "interpretation": "z"},
        ["hayabusa-tester-20260919-007", "evtxecmd-tester-20260919-008"],
        linked_ids={"hayabusa-tester-20260919-007"},
    )
    assert payload["audit_ids"] == ["hayabusa-tester-20260919-007"]
    # empty linkage → no padding at all
    payload2 = _finding_tool_payload(
        {"title": "x", "observation": "y", "interpretation": "z"},
        ["evtxecmd-tester-20260919-008"],
        linked_ids=set(),
    )
    assert payload2["audit_ids"] == []


def test_score_provenance_downgrades_unlinked_ids(tmp_path):
    from nexus.case_manager import CaseManager

    case = _case(tmp_path)
    _audit_entry(case, tool="evtxecmd", audit_id="evtxecmd-tester-20260919-002",
                 source="mcp", params={"case_id": case.name})

    unrelated = {
        "title": "hayabusa claim",
        "evidence": [{"source": "hayabusa/evtx-timeline.csv", "detail": "row"}],
        "audit_ids": ["evtxecmd-tester-20260919-002"],
    }
    mgr = CaseManager()
    scored = mgr._score_provenance(unrelated, case)
    assert scored["grade"] == "PARTIAL"
    assert scored["unlinked"] == ["evtxecmd-tester-20260919-002"]
    assert "do not reference" in scored["detail"]

    linked = {
        "title": "evtx claim",
        "evidence": [{"source": "evtxecmd/out.csv", "detail": "row"}],
        "audit_ids": ["evtxecmd-tester-20260919-002"],
    }
    scored2 = mgr._score_provenance(linked, case)
    assert scored2["grade"] == "FULL"
    assert scored2["unlinked"] == []
