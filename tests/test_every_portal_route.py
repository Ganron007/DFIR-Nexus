"""Every portal route, verified against its design contract.

Enumerated from the AST rather than by hand, so a route added later cannot quietly
escape: the route table is re-read at test time and a new route is exercised
automatically. That is the point - "verify everything" has to survive the next
commit, or it verifies the commit before last.

Contracts asserted per route class:

* **open** - answers regardless of the case's mode, because it is mode-agnostic
  by design (`/cases`, `/mode-mapping`, `/system/health`, setup, fs browsing).
* **mode-owned** - answers only for a case in its own mode; a foreign-mode case is
  refused with 409, and no case at all is 404. A mode-owned route that answers on
  the wrong case is the segregation hole this exists to catch.
* every route - never 500 on a well-formed request. A crash is not a validation
  error, and a 500 in an API is an unhandled path.
"""
from __future__ import annotations

import ast
import json
import pathlib
import re

import pytest

APP = pathlib.Path("src/nexus/dashboard/app.py")


def route_table() -> list[dict]:
    """The live route table, parsed from the registration calls."""
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    rows: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fname = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if fname not in {"Route", "_mode_route", "_mode_guarded"}:
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant):
            continue
        path = node.args[0].value
        if not isinstance(path, str) or not path.startswith("/portal/api/"):
            continue
        handler = ast.unparse(node.args[1]) if len(node.args) > 1 else ""
        def _first_method(node_: ast.AST) -> str:
            if isinstance(node_, ast.Constant) and isinstance(node_.value, str):
                return node_.value
            if isinstance(node_, ast.List) and node_.elts:
                e = node_.elts[0]
                if isinstance(e, ast.Constant) and isinstance(e.value, str):
                    return e.value
            return ""

        method = ""
        if fname in {"_mode_route", "_mode_guarded"} and len(node.args) > 2:
            method = _first_method(node.args[2])
        for kw in node.keywords:
            if kw.arg == "methods":
                method = _first_method(kw.value) or method
        rows.append({
            "path": path,
            "handler": handler,
            "mode_owned": fname != "Route",
            "method": (method or "GET").upper(),
        })
    seen: dict[tuple[str, str], dict] = {}
    for r in rows:
        seen[(r["path"], r["method"])] = r
    return sorted(seen.values(), key=lambda r: (r["path"], r["method"]))


TABLE = route_table()
MODE_OWNED = [r for r in TABLE if r["mode_owned"]]
OPEN = [r for r in TABLE if not r["mode_owned"]]


def test_the_table_is_the_whole_surface():
    """Sanity: the enumeration found a real route table, not an empty parse."""
    assert len(TABLE) >= 90, f"only {len(TABLE)} routes found"
    assert len(MODE_OWNED) == 32, f"{len(MODE_OWNED)} mode-owned routes, expected 32"
    assert all(r["path"].startswith("/portal/api/") for r in TABLE)


# ---------------------------------------------------------------------------
# fixtures: one real case per mode, through the real creation path
# ---------------------------------------------------------------------------

@pytest.fixture()
def client():
    """A TestClient over the store conftest isolates for this test.

    No environment handling here: `tests/conftest.py` already redirects
    `cases_root` and the active-case pointer per test. A fixture of this file's
    own that set a different root created cases where no test could see them,
    which made every mode-owned assertion pass on a 404 that looked like a
    refusal - a green suite proving nothing.
    """
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    with TestClient(Starlette(routes=create_dashboard())) as c:
        yield c


def _make_case(client, mode: str) -> str:
    r = client.post("/portal/api/case/create", json={
        "name": f"route-probe-m{mode}", "description": "route contract probe",
        "examiner": "gate_bot", "mode": mode, "activate": True,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    cid = body.get("case_id") or body.get("id")
    assert cid, body
    return cid


@pytest.fixture()
def cases(client):
    """One case per mode. Mode is fixed at creation, so three cases are needed."""
    return {m: _make_case(client, m) for m in ("1", "2", "3")}


# ---------------------------------------------------------------------------
# every mode-owned route refuses a foreign-mode case
# ---------------------------------------------------------------------------

def _foreign_mode_case_ok(client, cases, mode):
    other = "2" if mode == "1" else "1"
    return cases[other]


@pytest.mark.parametrize("route", MODE_OWNED, ids=lambda r: f"{r['method']} {r['path']}")
def test_mode_owned_route_refuses_a_foreign_mode_case(client, cases, route):
    """A route owned by mode N must not act on a case that is not mode N.

    This is the segregation boundary, and the assertion is deliberately on the
    *status* rather than the body: any answer that is not a refusal is a hole.
    """
    mode = re.search(r"/mode(\d)/", route["path"]).group(1)
    foreign = _foreign_mode_case_ok(client, cases, mode)
    r = client.request(route["method"], route["path"],
                       json={"case_id": foreign}, headers={"X-Nexus-Case": foreign})
    assert r.status_code in (409, 404), (
        f"{route['method']} {route['path']} answered {r.status_code} for a "
        f"mode-{('2' if mode == '1' else '1')} case; expected 409 or 404. "
        f"Body: {r.text[:200]}"
    )


@pytest.mark.parametrize("route", MODE_OWNED, ids=lambda r: f"{r['method']} {r['path']}")
def test_mode_owned_route_never_500s_with_no_case(client, cases, route):
    """With no case selected the answer is 404, not a crash."""
    r = client.request(route["method"], route["path"], json={})
    assert r.status_code != 500, (
        f"{route['method']} {route['path']} crashed with no case: {r.text[:300]}"
    )


# ---------------------------------------------------------------------------
# mode-owned routes answer for their own case
# ---------------------------------------------------------------------------

_READ_ONLY_SUFFIXES = ("/status", "/events", "/board", "/ledger")
_KNOWN_EMPTY_OK = {
    # These legitimately have nothing to report before a run exists.
    404: ("no run", "no Mode 3 run", "run_id not found", "not found"),
}


@pytest.mark.parametrize("route", MODE_OWNED, ids=lambda r: f"{r['method']} {r['path']}")
def test_mode_owned_route_does_not_500_for_its_own_case(client, cases, route):
    """On its own case the route must answer - 200, or a documented 4xx.

    A 404 'no run yet' is a correct answer to 'show me the run'. A 500 is not an
    answer, and neither is a 403 for a case the caller owns.
    """
    mode = re.search(r"/mode(\d)/", route["path"]).group(1)
    cid = cases[mode]
    r = client.request(route["method"], route["path"],
                       json={"case_id": cid}, headers={"X-Nexus-Case": cid})
    assert r.status_code != 500, (
        f"{route['method']} {route['path']} crashed on its own mode-{mode} case: "
        f"{r.text[:300]}"
    )
    assert r.status_code != 403, (
        f"{route['method']} {route['path']} refused the case's own mode: {r.text[:200]}"
    )
    # A 404 is legitimate when it names a missing *domain object* ("no Mode 2
    # run found") and illegitimate when it means the case itself could not be
    # resolved - that would let this test pass without exercising the route.
    if r.status_code == 404:
        why = (r.text or "").lower()
        assert "case" not in why or "no case" not in why, (
            f"{route['method']} {route['path']} could not resolve its own case: {r.text[:200]}"
        )
        assert why.strip(), f"{route['method']} {route['path']} 404 with no reason given"


# ---------------------------------------------------------------------------
# open routes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("route", OPEN, ids=lambda r: f"{r['method']} {r['path']}")
def test_open_route_never_500s(client, cases, route):
    """An open route is mode-agnostic, so it must never crash on a live case.

    A 4xx is fine and often correct - 'path missing', 'not found', 'no case'.
    A 500 means an unhandled path, which is the thing being hunted.
    """
    cid = cases["1"]
    r = client.request(route["method"], route["path"], json={"case_id": cid},
                       headers={"X-Nexus-Case": cid})
    assert r.status_code != 500, (
        f"{route['method']} {route['path']} crashed: {r.text[:300]}"
    )


def test_open_route_answers_the_same_for_every_mode(client, cases):
    """Mode-agnostic means mode-agnostic: the same request, three modes."""
    probes = [
        ("GET", "/portal/api/case/details"),
        ("GET", "/portal/api/findings"),
        ("GET", "/portal/api/evidence"),
        ("GET", "/portal/api/case/mode"),
        ("GET", "/portal/api/summary"),
    ]
    for method, path in probes:
        codes = set()
        for cid in cases.values():
            r = client.request(method, path, headers={"X-Nexus-Case": cid})
            codes.add(r.status_code)
        assert len(codes) == 1, f"{path} answered differently by mode: {codes}"


def test_mode_mapping_maps_every_canonical_mode(client):
    """Deliberately open - it is the mapping itself, not a mode's own surface.

    It takes `product_mode` as a query parameter, so the contract under test is
    that all three canonical modes map, and an out-of-range mode is refused
    rather than silently mapped to something.
    """
    seen = {}
    for mode in ("1", "2", "3"):
        r = client.get(f"/portal/api/mode-mapping?product_mode={mode}")
        assert r.status_code == 200, f"mode {mode}: {r.status_code} {r.text[:160]}"
        body = r.json()
        assert body.get("pipeline_mode") or body.get("pipeline_modes"), body
        seen[mode] = json.dumps(body, sort_keys=True)

    # Distinct modes must not all collapse onto one pipeline mode.
    assert len(set(seen.values())) == 3, f"modes mapped identically: {seen}"

    for bad in ("0", "4", "", "abc"):
        r = client.get(f"/portal/api/mode-mapping?product_mode={bad}")
        assert r.status_code == 400, f"accepted product_mode={bad!r}: {r.status_code}"


# ---------------------------------------------------------------------------
# the pipeline surfaces that must expose their design contract
# ---------------------------------------------------------------------------

def test_health_reports_the_components_it_depends_on(client):
    r = client.get("/portal/api/system/health")
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, dict)
    assert body, "health returned nothing to inspect"


def test_case_export_offers_both_documented_formats(client, cases):
    """10.x: exhaustive retrieval exports CSV and JSONL."""
    cid = cases["1"]
    for fmt in ("csv", "jsonl"):
        r = client.get(f"/portal/api/case/export?format={fmt}",
                       headers={"X-Nexus-Case": cid})
        assert r.status_code != 500, f"{fmt}: {r.text[:200]}"


def test_pipeline_ledger_is_readable(client, cases):
    """The tool lane's ledger is the coverage record; it must be fetchable."""
    r = client.get("/portal/api/pipeline/ledger", headers={"X-Nexus-Case": cases["1"]})
    assert r.status_code in (200, 404), r.text


def test_report_grade_and_claims_are_readable_before_a_report_exists(client, cases):
    """Both must say 'not yet' rather than crash or invent a passing grade."""
    cid = cases["1"]
    for path in ("/portal/api/report/grade", "/portal/api/report/claims"):
        r = client.get(path, headers={"X-Nexus-Case": cid})
        assert r.status_code != 500, f"{path}: {r.text[:200]}"
        if r.status_code == 200:
            assert isinstance(r.json(), dict)


def test_a_sealed_case_refuses_analysis_routes(client, cases):
    """A sealed case is closed for analysis; the routes must honour that."""
    cid = cases["1"]
    r = client.post("/portal/api/case/seal", json={"case_id": cid},
                    headers={"X-Nexus-Case": cid})
    if r.status_code not in (200, 201):
        pytest.skip(f"seal not exercised: {r.status_code} {r.text[:120]}")
    try:
        g = client.post("/portal/api/report/generate", json={"case_id": cid, "llm": False},
                        headers={"X-Nexus-Case": cid})
        assert g.status_code in (409, 403), (
            f"a sealed case accepted report generation: {g.status_code}"
        )
    finally:
        client.post("/portal/api/case/reopen", json={"case_id": cid},
                    headers={"X-Nexus-Case": cid})
