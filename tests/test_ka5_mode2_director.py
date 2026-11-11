"""Tests for WO-KA5 / T2-34: Mode 2 LLM Investigation Director.

Tests:
- _model_supervisor_for_mode2 parsing and error handling.
- plan_work_orders with model supervisor (director_source == "model").
- plan_work_orders fallback on model failure or None (director_source == "rule_fallback").
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from nexus.modes import multi_role as m2


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-KA5"
    (case / "analysis").mkdir(parents=True)
    (case / "audit").mkdir()
    (case / "CASE.yaml").write_text("name: ka5\nstatus: active\n", encoding="utf-8")
    return case


def test_model_supervisor_for_mode2_success(tmp_path):
    """Model supervisor returns valid structured work orders."""
    mock_model = MagicMock()
    orders_payload = {
        "orders": [
            {
                "role": "evidence",
                "family": "hayabusa",
                "task": "Investigate logon anomalies",
                "why": "High volume of failed logons",
            },
            {
                "role": "correlation",
                "family": "",
                "task": "Correlate IP 10.0.0.5 across families",
                "why": "Pivot IP identified in auth events",
            },
            {
                "role": "pattern",
                "family": "",
                "task": "Map to T1078 Valid Accounts",
                "why": "Potential credential abuse",
            },
        ]
    }
    mock_resp = MagicMock()
    mock_resp.content = json.dumps(orders_payload)
    mock_model.invoke.return_value = mock_resp

    spawns = m2._model_supervisor_for_mode2(
        mock_model,
        case_dir=tmp_path,
        question="Was there credential abuse?",
        families=[("hayabusa", 50), ("evtxecmd", 20)],
        leads=[],
        max_orders=5,
    )
    assert len(spawns) == 3
    assert spawns[0]["role"] == "evidence"
    assert spawns[0]["family"] == "hayabusa"
    assert spawns[1]["role"] == "correlation"
    assert spawns[2]["role"] == "pattern"


def test_model_supervisor_for_mode2_invalid_json(tmp_path):
    """Model supervisor gracefully falls back to empty list on unparseable response."""
    mock_model = MagicMock()
    mock_resp = MagicMock()
    mock_resp.content = "I am not able to output valid JSON for this query."
    mock_model.invoke.return_value = mock_resp

    spawns = m2._model_supervisor_for_mode2(
        mock_model,
        case_dir=tmp_path,
        question="Investigate host",
        families=[("hayabusa", 10)],
        leads=[],
        max_orders=3,
    )
    assert spawns == []


def test_model_supervisor_for_mode2_exception(tmp_path):
    """Model supervisor catches LLM exceptions and returns empty list."""
    mock_model = MagicMock()
    mock_model.invoke.side_effect = RuntimeError("Rate limit exceeded")

    spawns = m2._model_supervisor_for_mode2(
        mock_model,
        case_dir=tmp_path,
        question="Investigate host",
        families=[("hayabusa", 10)],
        leads=[],
        max_orders=3,
    )
    assert spawns == []


def test_plan_work_orders_with_model_success(tmp_path):
    """plan_work_orders creates work orders from model director with director_source='model'."""
    case = _case(tmp_path)
    mock_model = MagicMock()
    orders_payload = {
        "orders": [
            {
                "role": "evidence",
                "family": "hayabusa",
                "task": "Examine security alerts",
                "why": "Critical alerts present",
            },
            {
                "role": "correlation",
                "family": "",
                "task": "Pivot on compromised user admin01",
                "why": "Cross-host corroboration",
            },
        ]
    }
    mock_resp = MagicMock()
    mock_resp.content = json.dumps(orders_payload)
    mock_model.invoke.return_value = mock_resp

    events = []
    sink = m2.EventSink(case, "M2-test", callback=events.append)

    with patch(
        "nexus.langgraph.backbone.backbone_call",
        return_value={"family_rows": {"hayabusa": 100, "evtxecmd": 50}},
    ):
        orders = m2.plan_work_orders(
            case,
            "Investigate breach",
            run_id="M2-test",
            sink=sink,
            model=mock_model,
            max_orders=4,
        )

    assert len(orders) == 2
    assert all(o.director_source == "model" for o in orders)
    assert orders[0].role == "evidence"
    assert orders[0].family == "hayabusa"
    assert orders[1].role == "correlation"

    # Verify event emission includes model source
    planned_events = [e for e in events if e.get("event_type") == "director.planned"]
    assert len(planned_events) == 1
    assert planned_events[0].get("data", {}).get("source") == "model"


def test_plan_work_orders_fallback_on_model_failure(tmp_path):
    """plan_work_orders falls back to rule director when model fails."""
    case = _case(tmp_path)
    mock_model = MagicMock()
    mock_model.invoke.side_effect = RuntimeError("API unavailable")

    events = []
    sink = m2.EventSink(case, "M2-test", callback=events.append)

    with patch(
        "nexus.langgraph.backbone.backbone_call",
        return_value={"family_rows": {"hayabusa": 100, "evtxecmd": 50}},
    ):
        orders = m2.plan_work_orders(
            case,
            "Investigate breach",
            run_id="M2-test",
            sink=sink,
            model=mock_model,
            max_orders=4,
        )

    assert len(orders) > 0
    assert all(o.director_source == "rule_fallback" for o in orders)


def test_plan_work_orders_model_none_uses_rule_fallback(tmp_path):
    """plan_work_orders uses rule fallback when model=None."""
    case = _case(tmp_path)
    events = []
    sink = m2.EventSink(case, "M2-test", callback=events.append)

    with patch(
        "nexus.langgraph.backbone.backbone_call",
        return_value={"family_rows": {"hayabusa": 100, "evtxecmd": 50}},
    ):
        orders = m2.plan_work_orders(
            case,
            "Investigate breach",
            run_id="M2-test",
            sink=sink,
            model=None,
            max_orders=4,
        )

    assert len(orders) > 0
    assert all(o.director_source == "rule_fallback" for o in orders)
