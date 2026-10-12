"""D113: the recompute of stored EVTX ``ecs`` after a map change (``ecs_recompute.py``).

The rows are the public fixture (EvtxECmd output of the BabyShark, DeepBlueCLI and Hayabusa attack samples). A stored
document is built the way the indexer builds it, under the map as it was before D113, so the recompute must add
exactly the leaves the change adds and nothing else. ES is not reached: the search and the bulk write are fakes.
"""
from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from unittest import mock

import pytest

from nexus.langgraph import ecs_normalize
from nexus.langgraph import ecs_recompute as rc
from nexus.langgraph.case_index import _index_header, _open_text_auto, iter_indexable_rows
from nexus.langgraph.path_sanitize import machine_roots, sanitize_field_map

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cs1b_evtx_real_rows.csv"

# (EventId, RecordNumber) of the public rows the D113 map change applies to.
NEW_ROWS = [("4634", "3355"), ("4634", "3360"), ("4776", "2"), ("4776", "7")]


def _place_extraction(case_dir: Path, family: str = "evtxecmd", name: str = "evtx.csv") -> Path:
    """The fixture as one extraction of one run, at the place the recompute looks for extractions."""
    folder = case_dir / "runs" / "RUN-TEST" / "extractions" / family
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    shutil.copyfile(FIXTURE, path)
    return path


def _rows_by_event(path: Path) -> dict[tuple[str, str], tuple[int, dict[str, str]]]:
    """(EventId, RecordNumber) -> (starting line, fields), read by the indexer's own row reader."""
    header = _index_header(path)
    rows: dict[tuple[str, str], tuple[int, dict[str, str]]] = {}
    with _open_text_auto(path) as fh:
        for start, _raw, fields in iter_indexable_rows(path, fh, header, file_label=path.name):
            rows[(fields["EventId"], fields["RecordNumber"])] = (start, fields)
    return rows


def _indexer_ecs(case_dir: Path, fields: dict[str, str], family: str = rc.FAMILY) -> dict:
    """The ``ecs`` the indexer stores for one row: the same sanitiser and normalize steps as ``case_index._add``."""
    full = sanitize_field_map(fields, case_dir, roots=machine_roots(case_dir), family=family)
    return ecs_normalize.normalize(family, full, None)


def _ecs_under(emap: dict, case_dir: Path, fields: dict[str, str], family: str = rc.FAMILY) -> dict:
    with mock.patch.object(ecs_normalize, "load_ecs_map", lambda: emap):
        return _indexer_ecs(case_dir, fields, family)


def _map_before_d113() -> dict:
    """The map as it was before D113: no 4634 or 4776 block, so those documents held no account leaf."""
    old = copy.deepcopy(ecs_normalize.load_ecs_map())
    security = old["winlog_event_data"]["Security"]
    del security["4634"]
    del security["4776"]
    return old


class _Resp:
    def __init__(self, body=None):
        self._body = body or {}

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


class _FakeES:
    """Stands in for the httpx client: records each request and answers a search or a bulk call."""

    def __init__(self, sink: list, search_body: dict | None = None):
        self.sink = sink
        self.search_body = search_body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def post(self, url, json=None, content=None, headers=None):
        self.sink.append({"url": url, "json": json, "content": content})
        if content is not None:
            text = content.decode("utf-8")
            n = sum(1 for line in text.splitlines() if line.startswith('{"update"'))
            return _Resp({"items": [{"update": {"result": "updated"}} for _ in range(n)]})
        return _Resp(self.search_body)


def test_the_map_names_the_account_for_4634_and_4776():
    security = ecs_normalize.load_ecs_map()["winlog_event_data"]["Security"]
    assert security["4634"]["TargetUserName"] == "ecs.user.target.name"
    assert security["4634"]["TargetDomainName"] == "ecs.user.target.domain"
    assert security["4634"]["LogonType"] == "ecs.winlog.logon.type"
    assert security["4776"]["TargetUserName"] == "ecs.user.target.name"


def test_flatten_and_diff_name_the_leaves_a_recompute_adds_drops_or_changes():
    stored = {"user": {"target": {"name": "a"}}, "host": {"name": "h"}, "tags": ["x"], "old": {"leaf": "1"}}
    new = {
        "user": {"target": {"name": "b", "domain": "D"}},
        "host": {"name": "h"},
        "tags": ["x"],
        "winlog": {"logon": {"type": "3"}},
    }
    assert rc.flatten(stored) == {"user.target.name": "a", "host.name": "h", "tags": '["x"]', "old.leaf": "1"}
    assert rc.diff_ecs(stored, new) == {
        "lost": ["old.leaf"],
        "changed": ["user.target.name"],
        "added": ["user.target.domain", "winlog.logon.type"],
    }


def test_recompute_adds_exactly_the_account_leaves_the_change_adds(tmp_path):
    case_dir = tmp_path / "CASE-TEST"
    path = _place_extraction(case_dir)
    rows = _rows_by_event(path)
    old_map = _map_before_d113()
    wanted = {}
    for event_id, record in NEW_ROWS:
        start, fields = rows[(event_id, record)]
        wanted[start] = {
            "id": f"{event_id}-{record}",
            "index": "nexus-case-case-test",
            "fields": fields,
            "ecs": _ecs_under(old_map, case_dir, fields),
        }
    updates, problems = rc.rows_for_lines(case_dir, path, wanted)
    assert problems == []
    by_id = {u["id"]: u for u in updates}
    assert sorted(by_id) == sorted(f"{e}-{r}" for e, r in NEW_ROWS)
    for u in updates:
        assert u["diff"]["lost"] == [], u["id"]
        assert u["diff"]["changed"] == [], u["id"]
    # The account the Payload names is the account the leaf now holds.
    assert by_id["4634-3355"]["new"]["user"]["target"]["name"] == "IEUser"
    assert by_id["4776-2"]["new"]["user"]["target"]["name"] == "Administrator"
    assert by_id["4776-7"]["new"]["user"]["target"]["name"] == "samir"
    assert "user.target.name" in by_id["4634-3355"]["diff"]["added"]
    assert by_id["4776-2"]["diff"]["added"] == ["user.target.name"]


def test_a_second_pass_after_the_change_adds_nothing(tmp_path):
    case_dir = tmp_path / "CASE-TEST"
    path = _place_extraction(case_dir)
    rows = _rows_by_event(path)
    wanted = {}
    for event_id, record in NEW_ROWS:
        start, fields = rows[(event_id, record)]
        wanted[start] = {"id": f"{event_id}-{record}", "index": "i", "fields": fields,
                         "ecs": _indexer_ecs(case_dir, fields)}
    updates, problems = rc.rows_for_lines(case_dir, path, wanted)
    assert problems == []
    assert len(updates) == len(NEW_ROWS)
    assert all(u["diff"]["added"] == [] for u in updates)


def test_a_document_whose_row_identity_differs_is_refused(tmp_path):
    case_dir = tmp_path / "CASE-TEST"
    path = _place_extraction(case_dir)
    start, fields = _rows_by_event(path)[("4776", "2")]
    stale = {**fields, "EventRecordId": "1"}
    updates, problems = rc.rows_for_lines(
        case_dir, path, {start: {"id": "d", "index": "i", "fields": stale, "ecs": {}}}
    )
    assert updates == []
    assert problems == [f"line {start}: EventRecordId or RecordNumber differs from the stored document"]


def test_a_recompute_that_would_drop_or_change_a_stored_leaf_is_refused(tmp_path):
    case_dir = tmp_path / "CASE-TEST"
    path = _place_extraction(case_dir)
    start, fields = _rows_by_event(path)[("4776", "2")]
    current = _indexer_ecs(case_dir, fields)
    dropped = {**current, "extra": {"leaf": "kept"}}
    renamed = copy.deepcopy(current)
    renamed["user"]["target"]["name"] = "someone-else"
    for stored in (dropped, renamed):
        updates, problems = rc.rows_for_lines(
            case_dir, path, {start: {"id": "d", "index": "i", "fields": fields, "ecs": stored}}
        )
        assert updates == []
        assert problems == [f"line {start}: the recompute would drop or change stored leaves; refused"]


def test_a_stored_line_with_no_row_is_reported_not_guessed(tmp_path):
    case_dir = tmp_path / "CASE-TEST"
    path = _place_extraction(case_dir)
    updates, problems = rc.rows_for_lines(
        case_dir, path, {999999: {"id": "x", "index": "i", "fields": {}, "ecs": {}}}
    )
    assert updates == []
    assert problems == ["line 999999: no row starts at this line in evtx.csv"]


def test_recompute_case_writes_only_when_applied(tmp_path, monkeypatch):
    case_dir = tmp_path / "CASE-TEST"
    path = _place_extraction(case_dir)
    _place_extraction(case_dir, "csv", "eventlog.csv")
    rows = _rows_by_event(path)
    old_map = _map_before_d113()
    docs = []
    for event_id, record in NEW_ROWS:
        start, fields = rows[(event_id, record)]
        docs.append({
            "id": f"{event_id}-{record}",
            "index": "nexus-case-case-test",
            "family": "evtxecmd",
            "file": "evtxecmd/evtx.csv",
            "line": start,
            "ecs": _ecs_under(old_map, case_dir, fields),
            "fields": fields,
        })
    # The MemProcFS event log stores the same rows under its own family: the change reaches it too.
    start, fields = rows[("4776", "7")]
    docs.append({
        "id": "csv-4776-7",
        "index": "nexus-case-case-test",
        "family": "csv",
        "file": "csv/eventlog.csv",
        "line": start,
        "ecs": _ecs_under(old_map, case_dir, fields, "csv"),
        "fields": fields,
    })
    # A document whose source is not in the case: reported, never written.
    docs.append({"id": "orphan", "index": "nexus-case-case-test", "family": "evtxecmd",
                 "file": "evtxecmd/missing.csv", "line": 2, "ecs": {}, "fields": {}})
    writes: list = []
    monkeypatch.setattr(rc, "stored_documents", lambda case_id, event_ids=rc.EVENT_IDS: docs)
    monkeypatch.setattr(rc, "write_updates", lambda case_id, updates: writes.append(updates) or len(updates))

    dry = rc.recompute_case("CASE-TEST", case_dir, apply=False)
    assert writes == []
    assert dry["documents"] == 6
    assert dry["files"] == 3
    assert dry["verified"] == 5
    assert dry["changed"] == 5
    assert dry["written"] == 0
    assert any("missing.csv: no extraction file" in p for p in dry["problems"])

    applied = rc.recompute_case("CASE-TEST", case_dir, apply=True)
    assert len(writes) == 1
    assert len(writes[0]) == 5
    assert applied["written"] == 5


def test_write_updates_sends_partial_ecs_updates_in_batches(monkeypatch):
    sink: list = []
    monkeypatch.setattr(rc, "_client", lambda: _FakeES(sink))
    updates = [
        {"id": f"d{i}", "index": "nexus-case-x", "new": {"user": {"target": {"name": f"u{i}"}}}}
        for i in range(1200)
    ]
    assert rc.write_updates("CASE-X", updates) == 1200
    assert [s["url"] for s in sink] == ["/_bulk"] * 3  # 500 + 500 + 200
    first = sink[0]["content"].decode("utf-8").splitlines()
    assert json.loads(first[0]) == {"update": {"_index": "nexus-case-x", "_id": "d0"}}
    assert json.loads(first[1]) == {"doc": {"ecs": {"user": {"target": {"name": "u0"}}}}}


def test_stored_documents_asks_for_events_with_a_payload_and_an_exact_total(monkeypatch):
    sink: list = []
    hit = {
        "_id": "d1",
        "_index": "nexus-case-case-x",
        "_source": {"family": "csv", "file": "csv/a.csv", "line": 5, "ecs": {"host": {"name": "h"}},
                    "fields": {"EventRecordId": "9"}},
    }
    monkeypatch.setattr(rc, "_client", lambda: _FakeES(sink, {
        "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [hit]},
    }))
    docs = rc.stored_documents("CASE-X", ("4634",))
    assert docs == [{"id": "d1", "index": "nexus-case-case-x", "family": "csv", "file": "csv/a.csv", "line": 5,
                     "ecs": {"host": {"name": "h"}}, "fields": {"EventRecordId": "9"}}]
    assert sink[0]["url"] == "/nexus-case-case-x/_search"
    assert sink[0]["json"]["track_total_hits"] is True
    # Every family that stores the Payload is in scope, so the query names no family.
    assert sink[0]["json"]["query"]["bool"]["filter"] == [
        {"terms": {"event_id": ["4634"]}},
        {"exists": {"field": "fields.Payload"}},
    ]


def test_stored_documents_refuses_more_matches_than_one_read_returns(monkeypatch):
    monkeypatch.setattr(rc, "_client", lambda: _FakeES([], {
        "hits": {"total": {"value": rc._SEARCH_SIZE + 1, "relation": "eq"}, "hits": []},
    }))
    with pytest.raises(RuntimeError, match="reads at most"):
        rc.stored_documents("CASE-X")


def test_cli_refuses_a_missing_case_and_an_unknown_case(monkeypatch):
    from typer.testing import CliRunner

    from nexus.cli.index_cmd import app

    monkeypatch.setenv("NEXUS_ES_URL", "http://127.0.0.1:9200")
    runner = CliRunner()
    missing = runner.invoke(app, ["recompute-ecs"])
    assert missing.exit_code == 1
    assert "--case is required" in missing.output
    unknown = runner.invoke(app, ["recompute-ecs", "--case", "CASE-NOT-THERE"])
    assert unknown.exit_code == 1
    assert "Case not found" in unknown.output
