"""Mode 3 concurrent runtime: reducers, disputes, caps, Elasticsearch refusal."""
from __future__ import annotations

import json
from pathlib import Path

from nexus.modes.multi_agent import (
    accept_claim,
    add_board,
    plan_spawns,
    run_mode3,
)


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-M3"
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
    record = run_mode3(_case(tmp_path), "who logged on", es_ok=False)
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

    record = run_mode3(
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
    monkeypatch.setenv("NEXUS_MODE3_MAX_REDISPATCH", "0")
    monkeypatch.setenv("NEXUS_MODE3_SETTLE_SUPERSTEPS", "1")

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

    record = run_mode3(
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

    from nexus.modes import multi_agent as m4

    original = m4.read_controls

    def controls(case_dir, run_id):
        flags = original(case_dir, run_id)
        flags["stop_requested"] = True
        return flags

    m4.read_controls = controls
    try:
        record = run_mode3(case, "stop me", families=[("evtx", 1)], seat_fn=seat, es_ok=True)
    finally:
        m4.read_controls = original
    assert record["status"] == "stopped"
    assert record["stop_reason"] == "examiner_stop"


def test_plan_spawns_reserves_correlation_and_pattern():
    spawns = plan_spawns([("evtx", 9), ("mft", 8), ("proxy", 7)], max_agents=4, question="q")
    roles = [item["role"] for item in spawns]
    assert roles.count("evidence") == 2
    assert roles[-2:] == ["correlation", "pattern"]


def test_steering_is_stored_with_the_mode3_run(tmp_path):
    from nexus.modes.multi_agent import append_mode3_steering, read_mode3_steering

    case = _case(tmp_path)
    record = run_mode3(case, "q", families=[("evtx", 1)], es_ok=True)
    append_mode3_steering(case, record["run_id"], "check the proxy log")
    rows = read_mode3_steering(case, record["run_id"])
    assert rows[-1]["text"] == "check the proxy log"
    assert (case / "analysis" / "mode3_runs" / f"{record['run_id']}.steering.jsonl").is_file()
    assert not (case / "analysis" / "mode2_runs" / f"{record['run_id']}.steering.jsonl").exists()


def test_run_record_roundtrip(tmp_path):
    record = run_mode3(_case(tmp_path), "q", families=[("evtx", 1)], es_ok=True)
    path = tmp_path / "CASE-M3" / "analysis" / "mode3_runs" / f"{record['run_id']}.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["run_id"] == record["run_id"]
    assert saved["product_mode"] == "multi-agent"


def test_display_labels_final_three_modes():
    from nexus.langgraph.mode_mapping import display_product_mode

    assert display_product_mode(1)["product_label"] == "Mode 1 \u2014 LLM"
    assert display_product_mode(2)["product_label"] == "Mode 2 \u2014 Multi-role"
    assert display_product_mode(3)["product_label"] == "Mode 3 \u2014 Multi-agent"
    assert display_product_mode(1)["depth"] == "llm"
    assert display_product_mode(2)["depth"] == "multi_role"
    assert display_product_mode(3)["depth"] == "multi_agent"
    assert "error" in display_product_mode(9)


class _StubModel:
    """First reply is a terminal claims JSON (no tool calls)."""

    def invoke(self, _messages):
        class _Resp:
            content = json.dumps({
                "claims": [{
                    "entity_type": "host", "entity_value": "ws01",
                    "claim_kind": "presence", "polarity": "affirm",
                    "value": "4624", "audit_ids": ["audit-1"],
                    "confidence": "LOW",
                    "confidence_justification": "row cited",
                }],
                "open_questions": [],
            })
        return _Resp()


def test_one_audit_writer_per_run(tmp_path, monkeypatch):
    import nexus.audit as audit_mod

    created = []
    real = audit_mod.AuditWriter

    class _Counting(real):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created.append(self)

    monkeypatch.setattr(audit_mod, "AuditWriter", _Counting)
    record = run_mode3(
        _case(tmp_path), "q", families=[("evtx", 3)],
        model=_StubModel(), es_ok=True,
    )
    assert record["status"] == "completed"
    assert len(created) == 1, f"one writer per run expected, got {len(created)}"
    assert record["board"], "seats must publish entries"


def test_steering_spawns_a_seat(tmp_path):
    from nexus.modes import multi_agent as m4

    case = _case(tmp_path)
    m4.append_mode3_steering(case, "M3-steer", "chase host WS01 before settling")
    seen = []

    def seat(spawn, _board, step):
        seen.append(dict(spawn))
        return {
            "entry_id": f"{spawn['role']}-{step}",
            "agent_id": f"{spawn['role']}-{step}",
            "role": spawn["role"], "family": spawn.get("family") or "",
            "superstep": step, "claims": [], "open_questions": [],
        }

    record = run_mode3(
        case, "q", run_id="M3-steer", families=[("evtx", 1)],
        seat_fn=seat, es_ok=True,
    )
    assert any("WS01" in str(spawn.get("question") or "") for spawn in seen)
    kinds = [event["event_type"] for event in m4.read_run_events(case, "M3-steer")]
    assert "supervisor.steer" in kinds
    assert record["status"] == "completed"


def test_pause_and_resume_roundtrip(tmp_path):
    from nexus.modes import multi_agent as m4

    case = _case(tmp_path)
    calls = {"n": 0}

    def seat(spawn, _board, step):
        calls["n"] += 1
        if calls["n"] == 1:
            m4.mark_paused(case, "M3-pause", True)
        return {
            "entry_id": f"{spawn['role']}-{step}",
            "agent_id": f"{spawn['role']}-{step}",
            "role": spawn["role"], "family": spawn.get("family") or "",
            "superstep": step, "claims": [], "open_questions": [],
        }

    record = run_mode3(
        case, "q", run_id="M3-pause", families=[("evtx", 1)],
        seat_fn=seat, es_ok=True,
    )
    assert record["status"] == "paused"
    assert record.get("resume_state"), "pause must persist a resumable snapshot"

    resumed = m4.resume_mode3(case, "M3-pause", seat_fn=seat, es_ok=True)
    assert resumed["status"] == "completed"
    assert resumed["stop_reason"] in {"settled", "completed"}


def test_resume_refuses_terminal(tmp_path):
    from nexus.modes import multi_agent as m4

    case = _case(tmp_path)

    def seat(spawn, _board, step):
        return {
            "entry_id": f"{spawn['role']}-{step}",
            "agent_id": f"{spawn['role']}-{step}",
            "role": spawn["role"], "family": spawn.get("family") or "",
            "superstep": step, "claims": [], "open_questions": [],
        }

    record = run_mode3(
        case, "q", run_id="M3-done", families=[("evtx", 1)],
        seat_fn=seat, es_ok=True,
    )
    assert record["status"] == "completed"
    out = m4.resume_mode3(case, "M3-done", seat_fn=seat, es_ok=True)
    assert out.get("error")
    assert out["status"] == "completed"


class _SpawnModel:
    """Supervisor-only stub: returns a fixed JSON spawn list."""

    def __init__(self, content: str):
        self._content = content

    def invoke(self, _messages):
        content = self._content

        class _Resp:
            pass

        _Resp.content = content
        return _Resp()


def _recording_seat():
    seen: list[dict] = []

    def seat(spawn, _board, step):
        seen.append(dict(spawn))
        return {
            "entry_id": f"{spawn['role']}-{step}",
            "agent_id": f"{spawn['role']}-{step}",
            "role": spawn["role"], "family": spawn.get("family") or "",
            "superstep": step, "claims": [], "open_questions": [],
        }

    return seen, seat


def test_model_supervisor_chooses_team(tmp_path):
    from nexus.modes import multi_agent as m4

    case = _case(tmp_path)
    seen, seat = _recording_seat()
    model = _SpawnModel(json.dumps({"spawns": [
        {"role": "evidence", "family": "mft", "why": "registry hives"},
        {"role": "correlation", "family": "", "why": "ties hosts"},
    ]}))
    record = run_mode3(
        case, "q", run_id="M3-model", families=[("evtx", 10), ("mft", 5)],
        model=model, seat_fn=seat, es_ok=True,
    )
    families = {str(spawn.get("family") or "") for spawn in seen}
    assert "mft" in families, "model-chosen family must be spawned"
    assert "evtx" not in families, "model did not choose evtx"
    assert record["status"] == "completed"
    spawn_events = [
        event for event in m4.read_run_events(case, "M3-model")
        if event["event_type"] == "supervisor.spawn"
    ]
    assert spawn_events and spawn_events[0]["data"]["chosen_by"] == "model"


def test_model_supervisor_bad_output_falls_back(tmp_path):
    from nexus.modes import multi_agent as m4

    case = _case(tmp_path)
    seen, seat = _recording_seat()
    model = _SpawnModel("this is not json at all")
    record = run_mode3(
        case, "q", run_id="M3-fallback", families=[("evtx", 10), ("mft", 5)],
        model=model, seat_fn=seat, es_ok=True,
    )
    assert record["status"] == "completed"
    kinds = {(str(spawn.get("role") or ""), str(spawn.get("family") or ""))
             for spawn in seen}
    assert ("evidence", "evtx") in kinds
    assert ("correlation", "") in kinds
    assert ("pattern", "") in kinds
    spawn_events = [
        event for event in m4.read_run_events(case, "M3-fallback")
        if event["event_type"] == "supervisor.spawn"
    ]
    assert spawn_events[0]["data"]["chosen_by"] == "deterministic"


def test_stage_mode3_labels_drafts_and_keeps_event_stream(tmp_path):
    """Multi-agent staging: DRAFTs are labeled mode3, the finding.staged event
    stays on the Mode 3 stream the board tails, and the staging bridge in
    mode2_runs must not hijack the multi-role latest-run pointer."""
    from nexus.audit import AuditWriter
    from nexus.modes.multi_agent import _persist, read_run_events, stage_mode3
    from nexus.modes.multi_role import latest_run_id as mode2_latest

    case = _case(tmp_path)
    (case / "audit").mkdir(exist_ok=True)
    (case / "CASE.yaml").write_text("name: m3\nstatus: active\n", encoding="utf-8")
    audit_id = AuditWriter("nexus", audit_dir=case / "audit").log(
        tool="es_search",
        params={"family": "evtxecmd", "file": "a.csv", "query": "logon"},
        result_summary={"total": 1},
        source="portal",
    )
    run_id = "M3-stage-test"
    _persist(case, run_id, {
        "run_id": run_id, "case_id": case.name, "question": "q",
        "status": "completed", "product_mode": "multi-agent",
        "board": [], "disputes": [],
        "candidates": [{
            "title": "Board candidate", "observation": "o",
            "interpretation": "i", "confidence": "LOW",
            "confidence_justification": "one audited query",
            "audit_ids": [audit_id],
        }],
        "gaps": [],
    })
    result = stage_mode3(case, run_id)
    assert result["staged_count"] == 1
    rows = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    staged = [f for f in rows if f.get("run_id") == run_id]
    assert staged and staged[0]["status"] == "DRAFT"
    assert staged[0]["source"] == "mode3"
    assert any(e["event_type"] == "finding.staged"
               for e in read_run_events(case, run_id))
    assert not (case / "analysis" / "mode2_runs" / f"{run_id}.jsonl").exists()
    assert mode2_latest(case) == ""
