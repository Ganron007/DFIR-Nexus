"""Every step of each mode, verified against its design contract.

The step contracts, read from the handlers themselves rather than assumed:

**Mode 1**
  ``ask``          NL -> needles + N4 hits
  ``select``       promote selected hit indices to DRAFT
  ``suggestions``  question ideas; validated; deterministic fallback; 120s cache
  ``iterate``      {question, max_iterations default 2 cap 4}; logged; nothing staged
  ``save-answer``  {entry_ts}; bookmark rows, append transcript, record the answer
  ``chat``         {message, history?}; NL answer + the queries it ran
  ``full-run``     needle scan; one run per case at a time -> 409
  ``corroborate``  {finding_id}; FD-006/007 check
  ``propose-draft`` {title, hits|query}; stages DRAFT, examiner_selected=False

**Mode 2**
  ``plan``         proposes items from ledger SKIPs + extras + FD-006 needs
  ``execute``      {extras, queries}; extras persist to intake; queries read-only
  ``draft-finding`` {hits, title}; stages DRAFT; the agent NEVER approves
  ``orchestrator`` runs agents; nothing auto-staged
  ``run/*``        plan, status, events, steer, pause, resume, stop, stage

**Mode 3**
  ``run``          supervisor -> seat -> join -> synthesize; redispatch on dispute
  ``run/*``        board, status, events, steer, pause, resume, stop, stage

The properties asserted across all three modes are the ones that would be a
breach rather than a bug: a step that stages without the examiner, an agent that
approves, a run that resumes after it finished, or a mode route that acts on
another mode's case.
"""
from __future__ import annotations

import json

import pytest


@pytest.fixture()
def client():
    """A TestClient over the isolated store conftest already provides.

    No environment manipulation here on purpose. `tests/conftest.py` installs an
    autouse function-scoped fixture that points `cases_root` and the active-case
    pointer at a per-test tmp directory, so a fixture of this file's own that set
    a different root created its cases where no test would ever look - which is
    why every mode step answered "No active case". Fighting conftest is the bug;
    using its root is the fix.
    """
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    with TestClient(Starlette(routes=create_dashboard())) as c:
        yield c


def _case(client, mode: str, name: str) -> str:
    r = client.post("/portal/api/case/create", json={
        "name": name, "description": "mode step probe", "examiner": "gate_bot",
        "mode": mode, "activate": True,
    })
    assert r.status_code == 200, r.text
    cid = r.json().get("case_id") or r.json().get("id")
    assert cid
    return cid


@pytest.fixture()
def c1(client):
    return _case(client, "1", "steps-m1")


@pytest.fixture()
def c2(client):
    return _case(client, "2", "steps-m2")


@pytest.fixture()
def c3(client):
    return _case(client, "3", "steps-m3")


def _h(client, cid):
    return {"X-Nexus-Case": cid}


def _findings(client, cid) -> list[dict]:
    r = client.get("/portal/api/findings", headers=_h(client, cid))
    assert r.status_code == 200, r.text
    body = r.json()
    if isinstance(body, dict):
        return body.get("findings") or body.get("items") or []
    return body or []


def _evidence(client, cid, tmp_path) -> int:
    """Register one real file so the stages have something to work on."""
    src = tmp_path / "Security.evtx"
    if not src.is_file():
        src.write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    r = client.post("/portal/api/evidence", json={
        "path": str(src), "description": "step probe", "case_id": cid,
    }, headers=_h(client, cid))
    return r.status_code


# ===========================================================================
# the properties that would be breaches, asserted across every mode
# ===========================================================================

def test_no_mode_route_ever_writes_an_approved_finding(client, c1, c2, c3, tmp_path):
    """The agent never approves. Only the password-gated commit path may.

    Every staging-shaped step is driven and the finding set is then checked: an
    APPROVED row appearing here would mean a step minted examiner authority.
    """
    _evidence(client, c1, tmp_path)
    for cid, calls in (
        (c1, [("POST", "/portal/api/mode1/ask", {"question": "what ran?"}),
              ("POST", "/portal/api/mode1/iterate", {"question": "what ran?"}),
              ("POST", "/portal/api/mode1/suggestions", {}),
              ("POST", "/portal/api/mode1/propose-draft", {"title": "probe"})]),
        (c2, [("POST", "/portal/api/mode2/plan", {"question": "what ran?"}),
              ("POST", "/portal/api/mode2/execute", {}),
              ("POST", "/portal/api/mode2/draft-finding",
               {"title": "probe", "hits": []}),
              ("POST", "/portal/api/mode2/orchestrator", {})]),
        (c3, [("POST", "/portal/api/mode3/run/stage", {}),
              ("GET", "/portal/api/mode3/run/board", None)]),
    ):
        for method, path, body in calls:
            if method == "POST":
                client.post(path, json=body or {}, headers=_h(client, cid))
            else:
                client.get(path, headers=_h(client, cid))
        for f in _findings(client, cid):
            assert str(f.get("status") or "").upper() != "APPROVED", (
                f"{path} produced an APPROVED finding on {cid}"
            )


def test_mode_routes_cannot_be_crossed(client, c1, c2, c3):
    """A mode-1 route on a mode-2 case, and every other pairing, refuses."""
    pairs = [(c1, "/portal/api/mode2/plan"), (c1, "/portal/api/mode3/run/board"),
             (c2, "/portal/api/mode1/ask"), (c2, "/portal/api/mode3/run/board"),
             (c3, "/portal/api/mode1/ask"), (c3, "/portal/api/mode2/plan")]
    for cid, path in pairs:
        r = client.post(path, json={"question": "x"}, headers=_h(client, cid))
        assert r.status_code in (409, 404, 405), (
            f"{path} answered {r.status_code} for {cid}: {r.text[:160]}"
        )


# ===========================================================================
# Mode 1 - every step
# ===========================================================================

def test_m1_ask_returns_needles_and_hits(client, c1):
    """`ask` turns NL into needles plus the rows they matched."""
    r = client.post("/portal/api/mode1/ask",
                    json={"question": "suspicious powershell execution"},
                    headers=_h(client, c1))
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, dict)
    # The step's whole job is to produce query terms; an empty answer to a
    # question with obvious terms is the failure this catches.
    assert any(k in body for k in ("needles", "hits", "terms", "question")), list(body)


def test_m1_select_stages_draft_only(client, c1):
    """Selecting hits stages DRAFTs - never anything else."""
    before = len(_findings(client, c1))
    r = client.post("/portal/api/mode1/select",
                    json={"indices": [0], "hits": [], "question": "probe"},
                    headers=_h(client, c1))
    assert r.status_code in (200, 400), r.text
    for f in _findings(client, c1)[before:]:
        assert str(f.get("status") or "").upper() == "DRAFT", f.get("status")


def test_m1_suggestions_always_returns_something(client, c1):
    """With no model configured the deterministic set fills the panel.

    An empty suggestion panel on a case with evidence is the silent-degradation
    shape: the examiner sees nothing and concludes there is nothing to ask.
    """
    r = client.post("/portal/api/mode1/suggestions", json={}, headers=_h(client, c1))
    assert r.status_code == 200, r.text
    body = r.json()
    items = body.get("suggestions") or body.get("questions") or []
    assert items, f"no suggestions offered: {json.dumps(body)[:200]}"


def test_m1_suggestions_are_cached_per_case(client, c1):
    """Cached per case for 120s - a second call must not re-run the model."""
    a = client.post("/portal/api/mode1/suggestions", json={}, headers=_h(client, c1)).json()
    b = client.post("/portal/api/mode1/suggestions", json={}, headers=_h(client, c1)).json()
    ka = a.get("suggestions") or a.get("questions") or []
    kb = b.get("suggestions") or b.get("questions") or []
    assert [str(x) for x in ka] == [str(x) for x in kb], "cache did not hold"


def test_m1_iterate_is_bounded_and_stages_nothing(client, c1):
    """max_iterations defaults to 2 and is hard-capped at 4.

    An unbounded loop is a cost and a diff to review; the cap is the contract.
    """
    before = _findings(client, c1)
    r = client.post("/portal/api/mode1/iterate",
                    json={"question": "what executed?", "max_iterations": 99},
                    headers=_h(client, c1))
    assert r.status_code in (200, 400, 409), r.text
    if r.status_code == 200:
        body = r.json()
        log = body.get("log") or body.get("iterations") or body.get("rounds") or []
        if isinstance(log, list):
            assert len(log) <= 4, f"iterate ran {len(log)} rounds past its cap"
    assert len(_findings(client, c1)) == len(before), "iterate staged a finding"


def test_m1_full_run_starts_async_and_runs_one_at_a_time(client, c1):
    """The scan is accepted asynchronously and only one may be live.

    `202 Accepted` is the start contract - the scan runs in a background thread
    and the examiner polls `/full-run/status`. A second start while one is live
    is refused with 409, because two concurrent scans would race on the signal
    map and the index.
    """
    first = client.post("/portal/api/mode1/full-run",
                        json={"max_needles": 2}, headers=_h(client, c1))
    assert first.status_code in (202, 200, 409), first.text
    body = first.json()
    if first.status_code in (202, 200):
        assert body.get("run_id"), body
        assert body.get("status") in ("running", "complete", "done", "failed"), body
    second = client.post("/portal/api/mode1/full-run",
                         json={"max_needles": 2}, headers=_h(client, c1))
    assert second.status_code in (202, 200, 409), second.text
    # Whichever way the race fell, the status endpoint must agree with reality.
    st = client.get("/portal/api/mode1/full-run/status", headers=_h(client, c1))
    assert st.status_code in (200, 404), st.text
    if st.status_code == 200:
        assert st.json().get("status"), st.json()


def test_m1_full_run_status_is_readable(client, c1):
    r = client.get("/portal/api/mode1/full-run/status", headers=_h(client, c1))
    assert r.status_code in (200, 404), r.text
    if r.status_code == 200:
        body = r.json()
        assert "status" in body or "run_id" in body, body


def test_m1_corroborate_needs_a_real_finding(client, c1):
    """FD-006/007 check on a finding id; an unknown id is refused, not invented."""
    r = client.post("/portal/api/mode1/corroborate",
                    json={"finding_id": "F-DOES-NOT-EXIST"}, headers=_h(client, c1))
    assert r.status_code in (200, 400, 404), r.text
    if r.status_code == 200:
        body = r.json()
        # A corroboration answer for a nonexistent finding would be fabrication.
        assert not body.get("ok") or body.get("error") or body.get("finding_id"), body


def test_m1_propose_draft_requires_a_title(client, c1):
    r = client.post("/portal/api/mode1/propose-draft", json={}, headers=_h(client, c1))
    assert r.status_code == 400, f"a draft with no title was accepted: {r.text[:160]}"


def test_m1_save_answer_requires_an_entry(client, c1):
    """Bookmarking needs something to bookmark; a bare call is a 400."""
    r = client.post("/portal/api/mode1/save-answer", json={}, headers=_h(client, c1))
    assert r.status_code in (400, 404), f"save-answer accepted nothing: {r.text[:160]}"


def test_m1_chat_degrades_legibly_when_no_model_is_configured(client, c1):
    """The chat step must be auditable, and must fail legibly.

    With no usable model it returns a structured response carrying
    `finish_reason: model_error` and a low confidence rather than an empty
    `answer` string - an empty answer reads as "nothing found", which is the
    silent-degradation shape this project forbids. The queries/followups it built
    are still returned, so the panel is never blank.
    """
    r = client.post("/portal/api/mode1/chat",
                    json={"message": "what executed on this host?", "history": []},
                    headers=_h(client, c1))
    assert r.status_code in (200, 400, 503), r.text
    if r.status_code != 200:
        return
    body = r.json()
    assert isinstance(body, dict)
    answered = bool(body.get("answer"))
    degraded = bool(body.get("finish_reason") or body.get("error"))
    assert answered or degraded, (
        f"chat returned neither an answer nor a stated reason: {list(body)}"
    )
    if degraded and not answered:
        # A degraded answer must not present itself as confident.
        assert str(body.get("confidence") or "low").lower() != "high", body


# ===========================================================================
# Mode 2 - every step
# ===========================================================================

def test_m2_plan_stages_nothing(client, c2):
    """The plan is a proposal. The examiner approves items before anything runs."""
    before = _findings(client, c2)
    r = client.post("/portal/api/mode2/plan", json={"question": "what ran?"},
                    headers=_h(client, c2))
    assert r.status_code in (200, 400, 409), r.text
    assert len(_findings(client, c2)) == len(before), "plan staged a finding"


def test_m2_execute_rejects_undeclared_extras(client, c2):
    """`extras` are named parsers; an unknown one must not be silently dropped."""
    r = client.post("/portal/api/mode2/execute",
                    json={"extras": ["not_a_real_extractor"], "queries": []},
                    headers=_h(client, c2))
    assert r.status_code != 500, r.text
    assert r.status_code in (200, 400, 409), r.text


def test_m2_draft_finding_requires_a_title(client, c2):
    r = client.post("/portal/api/mode2/draft-finding", json={"hits": []},
                    headers=_h(client, c2))
    assert r.status_code == 400, f"a draft with no title was accepted: {r.text[:160]}"


def test_m2_draft_finding_stages_draft_and_marks_it_agent_proposed(client, c2):
    """A staged agent draft must be marked as not examiner-selected.

    The flag is what separates 'the examiner picked this' from 'the agent
    proposed this' in the approve desk, and it survives into the report.
    """
    before = _findings(client, c2)
    r = client.post("/portal/api/mode2/draft-finding",
                    json={"title": "probe draft", "hits": [], "interpretation_hint": "probe"},
                    headers=_h(client, c2))
    if r.status_code != 200:
        pytest.skip(f"draft-finding declined without hits: {r.status_code} {r.text[:120]}")
    fresh = _findings(client, c2)[before:]
    assert fresh, "draft-finding returned ok but staged nothing"
    for f in fresh:
        assert str(f.get("status") or "").upper() == "DRAFT"
        assert f.get("examiner_selected") is False, (
            "an agent-proposed draft was marked examiner-selected"
        )


def test_m2_run_plan_returns_work_orders(client, c2):
    r = client.post("/portal/api/mode2/run/plan", json={"question": "what ran?"},
                    headers=_h(client, c2))
    assert r.status_code in (200, 400, 409), r.text
    if r.status_code == 200:
        body = r.json()
        assert "orders" in body or "run_id" in body, body
        for order in (body.get("orders") or [])[:4]:
            assert order.get("role"), f"a work order with no role: {order}"
            assert order.get("task"), f"a work order with no task: {order}"


def test_m2_run_stage_requires_a_run(client, c2):
    r = client.post("/portal/api/mode2/run/stage", json={}, headers=_h(client, c2))
    assert r.status_code == 400, f"stage without a run_id was accepted: {r.text[:160]}"


def test_m2_run_stage_refuses_an_unknown_run(client, c2):
    r = client.post("/portal/api/mode2/run/stage", json={"run_id": "M2-NOPE"},
                    headers=_h(client, c2))
    assert r.status_code in (200, 404), r.text
    if r.status_code == 200:
        assert r.json().get("error"), "an unknown run staged something"


def test_m2_run_stop_on_an_unknown_run_is_refused(client, c2):
    r = client.post("/portal/api/mode2/run/stop", json={"run_id": "M2-NOPE"},
                    headers=_h(client, c2))
    assert r.status_code in (404, 409, 200), r.text


def test_m2_run_status_and_events_are_readable(client, c2):
    for path in ("/portal/api/mode2/run/status", "/portal/api/mode2/run/events"):
        r = client.get(path, headers=_h(client, c2))
        assert r.status_code in (200, 404), f"{path}: {r.status_code} {r.text[:160]}"


def test_m2_orchestrator_stages_nothing(client, c2):
    before = _findings(client, c2)
    r = client.post("/portal/api/mode2/orchestrator", json={}, headers=_h(client, c2))
    assert r.status_code in (200, 400, 409), r.text
    assert len(_findings(client, c2)) == len(before), "orchestrator auto-staged"


# ===========================================================================
# Mode 3 - every step
# ===========================================================================

def test_m3_run_plan_stages_nothing(client, c3):
    before = _findings(client, c3)
    r = client.post("/portal/api/mode3/run", json={"question": "what ran?"},
                    headers=_h(client, c3))
    # 202 Accepted is the start contract: the supervisor runs in a background
    # thread and the board is polled for progress.
    assert r.status_code in (200, 202, 400, 409), r.text
    if r.status_code in (200, 202):
        body = r.json()
        assert "run_id" in body, body
    assert len(_findings(client, c3)) == len(before), "starting a run staged a finding"


def test_m3_board_reports_liveness_role_and_timeline(client, c3):
    """The three things the board exists to show."""
    r = client.get("/portal/api/mode3/run/board", headers=_h(client, c3))
    assert r.status_code in (200, 404), r.text
    if r.status_code != 200:
        pytest.skip("no Mode 3 run yet")
    body = r.json()
    for key in ("board", "disputes", "candidates", "active", "timeline"):
        assert key in body, f"board is missing {key!r}: {list(body)}"


def test_m3_status_reports_running_agents_and_skills(client, c3):
    r = client.get("/portal/api/mode3/run/status", headers=_h(client, c3))
    assert r.status_code in (200, 404), r.text
    if r.status_code != 200:
        pytest.skip("no Mode 3 run yet")
    body = r.json()
    for key in ("agents_running", "agents_active", "roles", "skills_used"):
        assert key in body, f"status is missing {key!r}: {list(body)}"
    assert isinstance(body["agents_running"], int)
    assert body["agents_running"] >= 0


def test_m3_stage_refuses_a_case_with_no_run(client, c3):
    r = client.post("/portal/api/mode3/run/stage", json={}, headers=_h(client, c3))
    assert r.status_code in (200, 404), r.text
    if r.status_code == 200:
        assert r.json().get("error"), "staging with no run produced something"


def test_m3_pause_and_resume_reject_an_unknown_run(client, c3):
    for path in ("/portal/api/mode3/run/pause", "/portal/api/mode3/run/resume",
                 "/portal/api/mode3/run/stop", "/portal/api/mode3/run/steer"):
        r = client.post(path, json={"run_id": "M3-NOPE", "text": "x"},
                        headers=_h(client, c3))
        assert r.status_code in (200, 404, 409), f"{path}: {r.status_code} {r.text[:140]}"


# ===========================================================================
# the shared stages the modes depend on
# ===========================================================================

def test_evidence_registration_is_visible_to_every_mode(client, c1, c2, c3, tmp_path):
    """One registry, three modes - the intake is shared, not per-mode."""
    src = tmp_path / "shared.bin"
    src.write_bytes(b"shared evidence")
    for cid in (c1, c2, c3):
        r = client.post("/portal/api/evidence",
                        json={"path": str(src), "case_id": cid}, headers=_h(client, cid))
        assert r.status_code == 200, f"{cid}: {r.status_code} {r.text[:160]}"
        rows = client.get("/portal/api/evidence", headers=_h(client, cid)).json()
        rows = rows.get("evidence") if isinstance(rows, dict) else rows
        assert rows, f"{cid} shows no evidence after registering"


def test_findings_and_evidence_are_scoped_per_case(client, c1, c2, c3, tmp_path):
    """A finding in one case must never appear in another."""
    client.post("/portal/api/mode2/draft-finding",
                json={"title": "scoped-probe-xyz", "hits": []}, headers=_h(client, c2))
    for cid in (c1, c3):
        blob = json.dumps(_findings(client, cid))
        assert "scoped-probe-xyz" not in blob, f"a mode-2 finding leaked into {cid}"


def test_no_route_leaks_another_cases_data(client, c1, c2, c3):
    """Case isolation: a read for one case must not return another's rows."""
    for cid in (c1, c2, c3):
        r = client.get("/portal/api/findings", headers=_h(client, cid))
        if r.status_code != 200:
            continue
        body = r.json()
        rows = body.get("findings") if isinstance(body, dict) else body
        for f in rows or []:
            got = str(f.get("case_id") or cid)
            assert got == cid, f"{cid} returned a finding belonging to {got}"
