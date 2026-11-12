"""Tests for Stage D / RB-D1: Post-N8 Ingestion Lane Alignment & Incremental Evidence.

Enforces:
1. Incremental evidence registration on an existing case.
2. Ingestion and indexing of multi-source evidence (Windows + Network / SIEM / Logs).
3. Preservation of existing state and case history across incremental additions.
4. Mode re-execution with informed/independent context in the same case.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from nexus.analysis.context_policy import context_sections, normalize_policy, prior_context
from nexus.case import evidence_service
from nexus.case.compat import get_sqlite_manager
from nexus.langgraph.case_index import index_case
from nexus.langgraph.pipeline_runs import create_run


@pytest.fixture
def case_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cases_root = tmp_path / "cases"
    cases_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)

    mgr = get_sqlite_manager()
    case = mgr.create_case(name="case-rb-d1", description="RB-D1 test case", created_by="examiner")
    cid = case.to_dict()["id"]
    case_dir = cases_root / cid
    case_dir.mkdir(parents=True, exist_ok=True)
    return mgr, cid, case_dir


def test_incremental_evidence_registration_and_indexing(case_env, tmp_path):
    mgr, cid, case_dir = case_env

    # 1. Register primary evidence (e.g. Windows log)
    ev1_path = tmp_path / "evtx_log.evtx"
    ev1_path.write_bytes(b"ElfFile\x00" + b"A" * 512)
    reg1 = evidence_service.register_evidence(case_dir, str(ev1_path), "Initial EVTX evidence", "examiner")
    assert reg1["status"] == "registered"
    assert reg1["evidence_id"]

    # Initial evidence list
    ev_list1 = mgr.list_evidence(cid)
    assert len(ev_list1) == 1
    assert ev_list1[0].file_path == str(ev1_path)

    # 2. Add an ingestion artifact to the case ingest store (Stage 2)
    ingest_dir = case_dir / "ingest"
    ingest_dir.mkdir(parents=True, exist_ok=True)
    artifacts_file = ingest_dir / "artifacts.jsonl"
    art1 = {
        "artifact_id": "art-001",
        "timestamp": "2026-11-12T10:00:00Z",
        "timestamp_epoch_ns": 1794477600000000000,
        "source": "wevtutil",
        "family": "evtx",
        "fields": {"event_id": 4624, "target_user": "alice", "ecs.host.name": "host-01"},
    }
    artifacts_file.write_text(json.dumps(art1) + "\n", encoding="utf-8")

    # Create tools run for initial pass
    run1 = create_run(case_dir, "tools", evidence_paths=[str(ev1_path)])
    assert run1.run_id

    # Mock Elasticsearch client context
    mock_es = MagicMock()
    mock_es.indices.exists.return_value = True

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"count": 1}

    mock_es.post.return_value = mock_resp
    mock_es.delete.return_value = mock_resp
    mock_es.get.return_value = mock_resp
    mock_es.head.return_value = mock_resp

    mock_client_ctx = MagicMock()
    mock_client_ctx.__enter__.return_value = mock_es
    mock_client_ctx.__exit__.return_value = False

    # Initial indexing pass
    with patch("nexus.langgraph.case_index.ensure_index", return_value="nexus-case-test"), \
         patch("nexus.langgraph.case_index.indexed_timestamp_coverage", return_value={}), \
         patch("nexus.langgraph.case_index._client", return_value=mock_client_ctx), \
         patch("nexus.langgraph.case_index._bulk_insert", return_value=0):
        res1 = index_case(case_dir, incremental=False, run_id=run1.run_id)
        assert res1["errors"] == 0
        assert res1["docs"] >= 1
        assert res1["incremental"] is False

    # 3. Incrementally add secondary evidence (Network / Zeek / SIEM)
    ev2_path = tmp_path / "zeek_conn.log"
    ev2_path.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\n"
        "1794477650.000000\tC12345\t10.0.0.5\t49152\t192.168.1.1\t443\ttcp\tssl\n",
        encoding="utf-8",
    )
    reg2 = evidence_service.register_evidence(case_dir, str(ev2_path), "Secondary Zeek log", "examiner")
    assert reg2["status"] == "registered"

    ev_list2 = mgr.list_evidence(cid)
    assert len(ev_list2) == 2

    # Append second artifact to artifacts.jsonl
    art2 = {
        "artifact_id": "art-002",
        "timestamp": "2026-11-12T10:00:50Z",
        "timestamp_epoch_ns": 1794477650000000000,
        "source": "zeek",
        "family": "zeek",
        "fields": {"source_ip": "10.0.0.5", "destination_ip": "192.168.1.1", "destination_port": 443},
    }
    with open(artifacts_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(art2) + "\n")

    # 4. Incremental indexing refresh on the run
    with patch("nexus.langgraph.case_index.ensure_index", return_value="nexus-case-test"), \
         patch("nexus.langgraph.case_index.indexed_timestamp_coverage", return_value={}), \
         patch("nexus.langgraph.case_index._client", return_value=mock_client_ctx), \
         patch("nexus.langgraph.case_index._bulk_insert", return_value=0):
        res2 = index_case(case_dir, incremental=True, run_id=run1.run_id)
        assert res2["errors"] == 0
        assert res2["incremental"] is True

    # 5. Verify index state records multiple evidence families
    index_state_file = case_dir / "analysis" / "index_state.json"
    assert index_state_file.exists()
    state_data = json.loads(index_state_file.read_text(encoding="utf-8"))
    assert state_data["docs"] >= 1
    assert "indexed_at" in state_data
    assert "file_mtimes" in state_data
    assert "file_sha256s" in state_data


def test_mode_informed_context_preserves_prior_candidates(case_env):
    """When a mode re-runs in informed context after new evidence, prior findings and reports are preserved."""
    mgr, cid, case_dir = case_env

    # 1. Simulate prior findings stored in the case
    findings_file = case_dir / "findings.json"
    findings_file.write_text(
        json.dumps([
            {
                "id": "F-001",
                "title": "Suspicious Logon Event",
                "status": "DRAFT",
                "severity": "HIGH",
                "observation": "Logon by user alice from external host",
                "evidence": ["row-4624-001"],
            }
        ]),
        encoding="utf-8",
    )

    reports_dir = case_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_file = reports_dir / "REPORT.md"
    report_file.write_text("# Case Interim Report\nInitial findings identify suspicious logon.", encoding="utf-8")

    # 2. Check context normalization
    assert normalize_policy("INFORMED") == "informed"
    assert normalize_policy("independent") == "independent"
    assert normalize_policy("unknown_policy") == "independent"

    # 3. Check prior context resolution
    ctx = prior_context(case_dir)
    assert ctx["report_present"] is True
    assert ctx["draft_count"] == 1
    assert ctx["drafts"][0]["title"] == "Suspicious Logon Event"
    assert "Initial findings identify suspicious logon" in ctx["report"]

    # 4. In informed policy, context sections include the prior context section
    sections_informed = context_sections(case_dir, "informed")
    assert any(name == "prior_analysis_context" for _pri, name, _text in sections_informed)
    prior_text = next(text for _pri, name, text in sections_informed if name == "prior_analysis_context")
    assert "Prior report" in prior_text
    assert "Initial findings identify suspicious logon" in prior_text

    # 5. In independent policy, context sections strictly exclude prior context
    sections_independent = context_sections(case_dir, "independent")
    assert not any(name == "prior_analysis_context" for _pri, name, _text in sections_independent)
