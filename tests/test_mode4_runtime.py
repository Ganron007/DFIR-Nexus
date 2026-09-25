"""Mode 4 concurrent runtime: reducers, disputes, caps, Elasticsearch refusal."""
from __future__ import annotations

import json
from pathlib import Path

from nexus.langgraph.mode4_runtime import (
    accept_claim,
    add_board,
    plan_spawns,
    run_mode4,
)


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-M4"
    case.mkdir()
    (case / "analysis").mkdir()
    return case


def _claim(entity: str, polarity: str, audit: str, kind: str = "presence") -> dict:
    return {
        "entity_type": "host",
        "entity_value": entity,
        "claim_kind": kind,
        "polarity": polarity,
        "value": "4624" if polarity == "affirm" else "none",
        "audit_ids": [audit],
        "confidence": "MEDIUM",
        "confidence_justification": "row cited",
    }


def test_parallel_board_reducer_keeps_both_writers():
    left = [{"agent_id": "a", "claims": []}]
    right = [{"agent_id": "b", "claims": []}]
    merged = add_board(left, right)
    assert [row["agent_id"] for row in merged] == ["a", "b"]


def test_claim_without_audit_id_is_rejected():
    reason = accept_claim({"claim_kind": "presence", "entity_type": "host", "entity_value": "ws01"})
    assert reason.startswith("FD-001")


def test_attribution_claim_is_rejected():
    reason = accept_claim({
        "claim_kind": "attribution",
        "entity_type": "user",
        "entity_value": "alice",
        "audit_ids": ["a1"],
        "confidence_justification": "because",
    })
    assert reason.startswith("FD-003")


def test_elasticsearch_required(tmp_path, monkeypatch):
    monkeypatch.delenv("NEXUS_ES_URL", raising=False)
    record = run_mode4(_case(tmp_path), "who logged on", es_ok=False)
    assert record["status"] == "failed"
    assert record["stop_reason"] == "elasticsearch_required"


def test_two_seats_publish_without_clobber(tmp_path):
    def seat(spawn, _board, step):
        role = spawn["role"]
        return {
            "entry_id": f"{role}-{step}",
            "agent_id": f"{role}-{step}",
            "role": role,
            "family": spawn.get("family") or "",
            "superstep": step,
            "claims": [_claim("ws01", "affirm", f"audit-{role}")] if role == "evidence" else [],
            "open_questions": [],
        }

    record = run_mode4(
        _case(tmp_path),
        "logons on ws01",
        families=[("evtx", 10), ("mft", 3)],
        seat_fn=seat,
        es_ok=True,
    )
    roles = {entry["role"] for entry in record["board"]}
    assert "evidence" in roles
    assert "correlation" in roles
    assert "pattern" in roles
    assert record["status"] == "completed"
    assert record["candidates"]
    assert record["candidates"][0]["audit_ids"] == ["audit-evidence"]


def test_dispute_is_not_a_candidate(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_MODE4_MAX_REDISPATCH", "0")
    monkeypatch.setenv("NEXUS_MODE4_SETTLE_SUPERSTEPS", "1")

    def seat(spawn, _board, step):
        polarity = "affirm" if spawn["role"] == "evidence" else "deny"
        return {
            "entry_id": f"{spawn['role']}-{step}",
            "agent_id": f"{spawn['role']}-{step}",
            "role": spawn["role"],
            "family": "evtx",
            "superstep": step,
            "claims": [_claim("ws01", polarity, f"audit-{spawn['role']}")],
            "open_questions": [],
        }

    record = run_mode4(
        _case(tmp_path),
        "was ws01 used",
        families=[("evtx", 4)],
        seat_fn=seat,
        es_ok=True,
    )
    assert record["disputes"]
    assert record["candidates"] == []
    assert any(gap.startswith("unresolved") for gap in record["gaps"])


def test_stop_before_next_superstep(tmp_path):
    case = _case(tmp_path)

    def seat(spawn, _board, step):
        return {
            "entry_id": f"{spawn['role']}-{step}",
            "agent_id": spawn["role"],
            "role": spawn["role"],
            "family": "",
            "superstep": step,
            "claims": [],
            "open_questions": [],
        }

    from nexus.langgraph import mode4_runtime as m4

    original = m4.read_controls

    def controls(case_dir, run_id):
        flags = original(case_dir, run_id)
        flags["stop_requested"] = True
        return flags

    m4.read_controls = controls
    try:
        record = run_mode4(case, "stop me", families=[("evtx", 1)], seat_fn=seat, es_ok=True)
    finally:
        m4.read_controls = original
    assert record["status"] == "stopped"
    assert record["stop_reason"] == "examiner_stop"


def test_plan_spawns_reserves_correlation_and_pattern():
    spawns = plan_spawns([("evtx", 9), ("mft", 8), ("proxy", 7)], max_agents=4, question="q")
    roles = [item["role"] for item in spawns]
    assert roles.count("evidence") == 2
    assert roles[-2:] == ["correlation", "pattern"]


def test_run_record_roundtrip(tmp_path):
    record = run_mode4(_case(tmp_path), "q", families=[("evtx", 1)], es_ok=True)
    path = tmp_path / "CASE-M4" / "analysis" / "mode4_runs" / f"{record['run_id']}.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["run_id"] == record["run_id"]
    assert saved["product_mode"] == "multi-agent"
