"""WP 4j.1 tests — hit interpretation layer.

Every hit/alert carries "what this means + what to check next" pulled from
the matching skill (look_for / corroborate / negative / caveats), family-
matched playbook caveats, and an optional RAG methodology chunk.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient


def _mkcase(tmp_path: Path) -> Path:
    """Minimal case dir with tools extractions + ledger (same shape as
    test_briefing_skills._mkcase)."""
    case = tmp_path / "CASE-T1"
    ext = case / "extractions"
    ext.mkdir(parents=True)
    (ext / "hayabusa_alerts.csv").write_text(
        "Timestamp,Computer,Channel,EventID,Level,RuleTitle,OtherDetails\n"
        "2026-08-10 14:32:01,WS01,Sec,4688,critical,LSASS Memory Access,powershell.exe\n"
        "2026-08-10 14:33:02,WS01,Sec,1102,high,Security Log Cleared,wevtutil\n"
        "2026-08-10 14:40:00,WS01,Sec,4688,low,Benign Process,notepad.exe\n",
        encoding="utf-8",
    )
    (ext / "evtx_security.csv").write_text(
        "TimeCreated,EventID,Computer,TargetUserName,IpAddress\n"
        "2026-08-10 14:32:05,4624,WS01,analyst_t1,10.0.0.5\n",
        encoding="utf-8",
    )
    (ext / "_tool_lane_ledger.json").write_text(
        json.dumps([{"tool": "hayabusa", "status": "OK", "family": "hayabusa"}]),
        encoding="utf-8",
    )
    (case / "CASE.yaml").write_text("question: was lsass dumped\n", encoding="utf-8")
    return case


def _lsass_hit() -> dict:
    return {
        "family": "hayabusa",
        "file": "hayabusa_alerts.csv",
        "line": "2",
        "terms": "lsass",
        "text": "2026-08-10 14:32:01,WS01,Sec,4688,critical,LSASS Memory Access,powershell.exe",
        "fields": {
            "Level": "critical",
            "RuleTitle": "LSASS Memory Access",
            "MitreTags": "T1003.001",
            "Computer": "WS01",
        },
        "host": "WS01",
    }


def test_interpret_hit_matches_lsass_skill():
    """A hayabusa LSASS-access alert interprets against the lsass skill."""
    from nexus.langgraph.interpret import interpret_hit

    out = interpret_hit(None, _lsass_hit())
    names = [s["name"] for s in out["skills"]]
    assert "lsass_credential_access" in names
    assert out["meaning"], "expected a meaning string"
    assert "LSASS" in out["meaning"] or "credential" in out["meaning"].lower()
    assert out["look_for"], "expected look_for guidance"
    assert "T1003.001" in out["techniques"]
    assert "skills" in out["sources"]


def test_interpret_hit_matched_step_look_for():
    """The matched skill step's look_for text reaches the examiner."""
    from nexus.langgraph.interpret import interpret_hit

    out = interpret_hit(None, _lsass_hit())
    lsass = next(s for s in out["skills"] if s["name"] == "lsass_credential_access")
    assert lsass["matched_steps"], "expected at least one matched step"
    # the sysmon_lsass_access step query mentions lsass.exe — token overlap
    assert any("GrantedAccess" in st["look_for"] or "lsass" in st["look_for"].lower()
               for st in lsass["matched_steps"])
    assert out["pivots"], "expected pivot field hints"


def test_interpret_hit_negative_and_caveats():
    """Skill negative-evidence + caveats surface for FD-004 discipline."""
    from nexus.langgraph.interpret import interpret_hit

    out = interpret_hit(None, _lsass_hit())
    assert out["negative"], "expected negative-evidence text"
    assert out["caveats"], "expected at least one caveat"
    assert "confidence_rules" in out and out["confidence_rules"]


def test_interpret_hit_alert_skill_linkage():
    """WP 4j.2: matched skills explain why + confirm/refute next steps."""
    from nexus.langgraph.interpret import interpret_hit

    out = interpret_hit(None, _lsass_hit())
    lsass = next(s for s in out["skills"] if s["name"] == "lsass_credential_access")
    # why-matched is surfaced (technique T1003.001 drives the match)
    assert lsass.get("why"), "expected match reasons"
    assert any("T1003.001" in w for w in lsass["why"])
    # confirm steps carry an action already executed + what to verify
    assert lsass.get("confirm"), "expected confirm steps"
    assert any(c.get("query") or c.get("look_for") for c in lsass["confirm"])
    # refute = the skill's negative-evidence statement
    assert lsass.get("refute")
    assert lsass.get("description")
    assert isinstance(lsass.get("confidence"), dict)


def test_interpret_hit_confirm_corroborate_present():
    """Confirm rows expose corroboration so a hit becomes a guided to-do."""
    from nexus.langgraph.interpret import interpret_hit

    out = interpret_hit(None, _lsass_hit())
    all_confirm = [c for s in out["skills"] for c in (s.get("confirm") or [])]
    assert all_confirm, "expected confirm rows across matched skills"
    assert any(c.get("corroborate") for c in all_confirm)


def test_interpret_hit_learn_block():
    """WP 4j.4: plain-language 'why this matters' teaching block."""
    from nexus.langgraph.interpret import interpret_hit

    out = interpret_hit(None, _lsass_hit())
    learn = out.get("learn") or {}
    assert learn, "expected a learn block"
    assert learn.get("headline"), "expected a headline"
    assert learn.get("why_matters"), "expected why-matters bullets"
    # T1003.001 maps to a named ATT&CK technique with its FD-004 caveat
    tech = {t["id"]: t for t in learn.get("technique") or []}
    assert "T1003.001" in tech
    assert tech["T1003.001"]["name"]
    assert tech["T1003.001"]["caveat"]
    assert "technique" in learn.get("sources", [])


def test_interpret_hit_learn_unknown_family():
    """No skill/technique → still a shaped (non-crashing) learn block."""
    from nexus.langgraph.interpret import interpret_hit

    out = interpret_hit(None, {"family": "zeek", "terms": "x", "text": "conn row"})
    learn = out.get("learn") or {}
    assert "headline" in learn and "why_matters" in learn


def test_interpret_hit_unknown_family_no_crash():
    """A family with no skills still returns a shaped payload."""
    from nexus.langgraph.interpret import interpret_hit

    out = interpret_hit(None, {"family": "zeek", "terms": "x", "text": "conn log row"})
    assert out["skills"] == []
    assert "zeek" in out["meaning"]


def test_interpret_hit_empty_hit():
    from nexus.langgraph.interpret import interpret_hit

    out = interpret_hit(None, {})
    assert out["skills"] == []
    assert out["look_for"] == []


def test_briefing_alerts_carry_interpret(tmp_path):
    """WP 4j.1 surface: briefing alert rows embed the interpretation."""
    from nexus.langgraph.briefing import case_briefing

    b = case_briefing(_mkcase(tmp_path))
    by_title = {a["title"]: a for a in b["alerts"]}
    lsass = by_title.get("LSASS Memory Access")
    assert lsass is not None
    it = lsass.get("interpret") or {}
    names = [s["name"] for s in it.get("skills", [])]
    assert "lsass_credential_access" in names
    assert it["look_for"]
    # log-clearing alert should match its own skill
    cleared = by_title.get("Security Log Cleared")
    assert cleared is not None
    cit = cleared.get("interpret") or {}
    cnames = [s["name"] for s in cit.get("skills", [])]
    assert "log_clearing" in cnames


def test_briefing_alert_skill_linkage_shape(tmp_path):
    """WP 4j.2 surface: briefing alert skills expose confirm/refute."""
    from nexus.langgraph.briefing import case_briefing

    b = case_briefing(_mkcase(tmp_path))
    by_title = {a["title"]: a for a in b["alerts"]}
    it = (by_title.get("LSASS Memory Access") or {}).get("interpret") or {}
    lsass = next(s for s in it.get("skills", []) if s["name"] == "lsass_credential_access")
    assert lsass.get("why")
    assert lsass.get("confirm")
    assert lsass.get("refute")
    assert lsass.get("confidence")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """TestClient with isolated case root + a pre-made case."""
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    from nexus.dashboard.app import create_dashboard

    dashboard = create_dashboard()
    app = Starlette(routes=dashboard)
    return TestClient(app)


def test_hit_interpret_endpoint(client, tmp_path):
    """POST /portal/api/hit/interpret returns the interpretation payload."""
    case = _mkcase(tmp_path)
    # register the case in the isolated store, then scope via header
    r = client.post("/portal/api/case/create", json={"name": "T1"})
    cid = r.json()["case_id"]
    import shutil

    case_dir = tmp_path / "cases" / cid
    if case_dir.exists():
        shutil.rmtree(case_dir)
    shutil.copytree(case, case_dir)

    r = client.post(
        "/portal/api/hit/interpret",
        json={"hit": _lsass_hit(), "rag": False},
        headers={"X-Nexus-Case": cid},
    )
    assert r.status_code == 200
    body = r.json()
    names = [s["name"] for s in body["skills"]]
    assert "lsass_credential_access" in names
    assert body["look_for"]
    # WP 4j.2: linkage fields survive the endpoint round-trip
    lsass = next(s for s in body["skills"] if s["name"] == "lsass_credential_access")
    assert lsass.get("why") and lsass.get("confirm") and lsass.get("refute")


def test_hit_interpret_endpoint_requires_hit(client, tmp_path):
    case = _mkcase(tmp_path)
    r = client.post("/portal/api/case/create", json={"name": "T2"})
    cid = r.json()["case_id"]
    import shutil

    case_dir = tmp_path / "cases" / cid
    if case_dir.exists():
        shutil.rmtree(case_dir)
    shutil.copytree(case, case_dir)

    r = client.post(
        "/portal/api/hit/interpret", json={}, headers={"X-Nexus-Case": cid}
    )
    assert r.status_code == 400
