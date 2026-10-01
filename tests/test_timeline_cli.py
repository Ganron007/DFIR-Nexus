"""A10: the timeline CLI (``nexus timeline build|query|export``).

The property worth pinning here is the failure mode: a down backend must not
print ``0 events``, because an examiner reads that as "nothing happened at that
time" and stops looking.
"""
from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from nexus.cli.timeline_cmd import app

runner = CliRunner()


def _case(tmp_path, case_id: str = "CASE-TLCLI01"):
    """A case directory, with the CLI pointed at it."""

    root = tmp_path / "cases"
    (root / case_id / "analysis").mkdir(parents=True, exist_ok=True)
    import nexus.cli.timeline_cmd as cmd

    # The CLI reads settings inside the function body, so it resolves the
    # module attribute at call time - repointing that is enough, and the real
    # cases_root (already redirected by conftest) is left alone.
    cmd.settings = type("S", (), {"cases_root": root})
    return root / case_id


def _event(event_id: str, ts: str, **over) -> dict:
    row = {
        "event_id": event_id,
        "ts": ts,
        "ts_desc": "Created0x10",
        "ts_src": "column",
        "family": "mftecmd",
        "host": "WS01",
        "user": "bob",
        "artifact": "mftecmd.csv",
        "source_file": "mft/mftecmd.csv",
        "source_line": 42,
        "audit_id": "nx-1",
    }
    row.update(over)
    return row


class _Resp:
    def __init__(self, payload: dict) -> None:
        self.status_code = 200
        self._payload = payload

    def json(self) -> dict:
        return self._payload


class _FakeES:
    def __init__(self, rows: list[dict], total: int | None = None,
                 exact: bool = True) -> None:
        self.rows = rows
        self.total = len(rows) if total is None else total
        self.exact = exact
        self.requests: list[dict] = []

    def post(self, path: str, json=None):  # noqa: A002 - httpx API
        body = json or {}
        self.requests.append(body)
        for clause in (body.get("query", {}).get("bool", {}).get("filter") or []):
            if "term" in clause:
                field, value = next(iter(clause["term"].items()))
                self.rows = [r for r in self.rows if r.get(field) == value]
            if "range" in clause:
                field, bounds = next(iter(clause["range"].items()))
                self.rows = [
                    r for r in self.rows
                    if (not bounds.get("gte") or r.get(field, "") >= bounds["gte"])
                    and (not bounds.get("lte") or r.get(field, "") <= bounds["lte"])
                ]
        after = body.get("search_after")
        rows = self.rows
        if after:
            after_id = after[1] if len(after) > 1 else after[0]
            ids = [r.get("event_id") for r in rows]
            if after_id in ids:
                rows = rows[ids.index(after_id) + 1:]
        size = int(body.get("size") or 10)
        return _Resp({
            "hits": {
                "total": {
                    "value": self.total,
                    "relation": "eq" if self.exact else "gte",
                },
                "hits": [{"_source": r} for r in rows[:size]],
            }
        })

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return None


class _DeadES:
    def post(self, *_a, **_kw):
        raise ConnectionError("connection refused")

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return None


@pytest.fixture
def es(monkeypatch):
    import nexus.langgraph.case_index as ci

    def install(fake):
        monkeypatch.setattr(ci, "_client", lambda: fake)
        return fake

    return install


# --------------------------------------------------------------------------
# query
# --------------------------------------------------------------------------

def test_query_prints_events_in_order(tmp_path, es):
    case = _case(tmp_path)
    es(_FakeES([
        _event("e1", "2026-09-29T13:00:00Z"),
        _event("e2", "2026-09-29T14:00:00Z"),
    ]))
    result = runner.invoke(app, ["query", "--case", case.name])
    assert result.exit_code == 0, result.output
    lines = [line for line in result.output.splitlines() if line.strip()]
    assert "showing 2 of 2" in lines[-1]
    assert lines[0].startswith("2026-09-29T13:00:00")
    assert "mftecmd" in lines[0]


def test_query_never_prints_a_fake_zero_when_es_is_down(tmp_path, es):
    case = _case(tmp_path)
    es(_DeadES())
    result = runner.invoke(app, ["query", "--case", case.name])
    assert result.exit_code == 1
    assert "unavailable" in result.output.lower()
    assert "showing 0" not in result.output
    assert "of 0" not in result.output


def test_query_marks_an_inexact_total(tmp_path, es):
    case = _case(tmp_path)
    es(_FakeES([_event("e1", "2026-09-29T13:00:00Z")], total=10000, exact=False))
    result = runner.invoke(app, ["query", "--case", case.name])
    assert "not exact" in result.output


def test_query_filters_by_family(tmp_path, es):
    case = _case(tmp_path)
    fake = es(_FakeES([
        _event("e1", "2026-09-29T13:00:00Z", family="mftecmd"),
        _event("e2", "2026-09-29T14:00:00Z", family="evtx"),
    ]))
    result = runner.invoke(app, ["query", "--case", case.name, "--family", "evtx"])
    assert result.exit_code == 0
    assert fake.requests[-1]["query"]["bool"]["filter"] == [{"term": {"family": "evtx"}}]
    assert "showing 1 of 2" in result.output


def test_query_filters_a_time_window(tmp_path, es):
    case = _case(tmp_path)
    fake = es(_FakeES([_event("e1", "2026-09-29T13:00:00Z")]))
    runner.invoke(app, [
        "query", "--case", case.name,
        "--since", "2026-09-01T00:00:00Z", "--until", "2026-10-01T00:00:00Z",
    ])
    bounds = fake.requests[-1]["query"]["bool"]["filter"][0]["range"]["ts"]
    assert bounds == {"gte": "2026-09-01T00:00:00Z", "lte": "2026-10-01T00:00:00Z"}


def test_query_descending_is_a_reversed_sort_not_a_rescan(tmp_path, es):
    case = _case(tmp_path)
    fake = es(_FakeES([_event("e1", "2026-09-29T13:00:00Z")]))
    runner.invoke(app, ["query", "--case", case.name, "--order", "desc"])
    assert fake.requests[-1]["sort"][0]["ts"]["order"] == "desc"


def test_query_json_carries_the_honesty_flags(tmp_path, es):
    case = _case(tmp_path)
    es(_FakeES([_event("e1", "2026-09-29T13:00:00Z")]))
    result = runner.invoke(app, ["query", "--case", case.name, "--json"])
    body = json.loads(result.output)
    assert body["exact"] is True
    assert body["capped"] is False
    assert body["rows"][0]["event_id"] == "e1"


def test_a_cursor_from_another_case_is_refused(tmp_path, es):
    case = _case(tmp_path)
    es(_FakeES([_event("e1", "2026-09-29T13:00:00Z")]))
    from nexus.dashboard.timeline_api import encode_cursor

    cursor = encode_cursor("CASE-OTHER", ["2026-01-01T00:00:00Z", "e1"])
    result = runner.invoke(app, ["query", "--case", case.name, "--cursor", cursor])
    assert result.exit_code == 1
    assert "different case" in result.output


# --------------------------------------------------------------------------
# export
# --------------------------------------------------------------------------

def test_export_writes_every_row_to_a_file(tmp_path, es):
    case = _case(tmp_path)
    es(_FakeES([_event("e1", "2026-09-29T13:00:00Z"), _event("e2", "2026-09-29T14:00:00Z")]))
    out = tmp_path / "timeline.csv"
    result = runner.invoke(app, ["export", "--case", case.name, "--out", str(out)])
    assert result.exit_code == 0, result.output
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("event_id,ts,ts_desc")
    assert len(lines) == 3
    assert "exported 2 event(s)" in result.output


def test_export_pages_through_a_large_result(tmp_path, es):
    """More rows than one page: the export must not stop at the first page."""
    case = _case(tmp_path)
    rows = [_event(f"e{i:03d}", f"2026-09-29T13:{i // 60:02d}:{i % 60:02d}Z") for i in range(2500)]
    es(_FakeES(rows))
    out = tmp_path / "big.csv"
    result = runner.invoke(app, ["export", "--case", case.name, "--out", str(out)])
    assert result.exit_code == 0, result.output
    written = out.read_text(encoding="utf-8").splitlines()
    assert len(written) == 2501, "header + every row"
    assert "exported 2500 event(s)" in result.output


def test_export_fails_loudly_rather_than_writing_an_empty_file(tmp_path, es):
    case = _case(tmp_path)
    es(_DeadES())
    out = tmp_path / "empty.csv"
    result = runner.invoke(app, ["export", "--case", case.name, "--out", str(out)])
    assert result.exit_code == 1
    assert "unavailable" in result.output.lower()


# --------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------

def test_build_reports_a_down_backend(tmp_path, monkeypatch):
    case = _case(tmp_path)
    import nexus.langgraph.case_index as ci

    monkeypatch.setattr(ci, "es_url", lambda: "http://127.0.0.1:9200")
    monkeypatch.setattr(
        ci, "_client", lambda: (_ for _ in ()).throw(ConnectionError("refused"))
    )
    result = runner.invoke(app, ["build", "--case", case.name])
    assert result.exit_code == 1
    assert "Not built" in result.output


def test_build_names_the_families_it_skipped(tmp_path, monkeypatch, es):
    """Silence about a skipped family would read as 'no activity'."""
    case = _case(tmp_path)
    import nexus.langgraph.timeline_events as te

    monkeypatch.setattr(te, "needs_rebuild", lambda _c: True)
    monkeypatch.setattr(te, "ensure_events_index", lambda cid: f"nexus-{cid}-events")
    monkeypatch.setattr(
        te, "_index_doc_stream",
        lambda _c, skipped: skipped.update({"prefetchnot": 12}) or iter(()),
    )
    import nexus.langgraph.case_index as ci

    es(_FakeES([]))
    monkeypatch.setattr(ci, "es_url", lambda: "http://127.0.0.1:9200")
    monkeypatch.setattr(ci, "_bulk_insert", lambda *a, **kw: 0)

    result = runner.invoke(app, ["build", "--case", case.name])
    assert result.exit_code == 0, result.output
    assert "Skipped families" in result.output
    assert "prefetchnot" in result.output


def test_build_refuses_a_traversing_case_id(tmp_path):
    _case(tmp_path)
    result = runner.invoke(app, ["build", "--case", "../../etc"])
    assert result.exit_code == 1
    assert "Invalid case id" in result.output


def test_an_unknown_case_is_refused_not_created(tmp_path):
    _case(tmp_path)
    result = runner.invoke(app, ["query", "--case", "CASE-DOESNOT"])
    assert result.exit_code == 1
    assert "Case not found" in result.output
