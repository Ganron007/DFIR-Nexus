"""IC-9: a seat is told why a search found nothing, and what a flood is made of.

The fresh Mode 3 run (M3-20261016T224756-da19fb, CASE-C5B04D31) had 178 zero-hit searches of 815 and 80 of more than
10,000 rows. For every one the seat saw `total`, the first rows and a cursor: `context_loop._result_summary` kept six
keys and dropped what the surface had said about the query. The queries here are that run's, verbatim from the case
audit trail (audit ids beside them); the rows are that case's, verbatim from its index
(tests/fixtures/defender_rows.json).
"""
from __future__ import annotations

import contextlib
import csv
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from nexus.langgraph import es_native
from nexus.langgraph.context_loop import _result_summary

ROWS = json.loads((Path(__file__).parent / "fixtures" / "defender_rows.json").read_text(encoding="utf-8"))

# nexus-claudebot-20261016-1969: Hayabusa writes its Channel "Defender" and its Level "crit".
DEFENDER_CRITICAL = {"bool": {"must": [{"term": {"fields.Channel": "Microsoft-Windows-Defender/Operational"}},
                                       {"term": {"fields.Level": "critical"}}]}}
# nexus-claudebot-20261016-2035
HAYABUSA_CRIT = {"bool": {"must": [{"term": {"fields.family": "hayabusa"}}, {"term": {"fields.Level": "Crit"}}]}}
# nexus-claudebot-20261016-1953: 1,130,289 rows in the case.
EVTXECMD = {"term": {"family": "evtxecmd"}}


def test_the_clauses_a_row_must_match_are_its_must_and_filter():
    assert es_native._positive_clauses(DEFENDER_CRITICAL) == DEFENDER_CRITICAL["bool"]["must"]
    # nexus-claudebot-20261016-1877: must and filter both bind; must_not and an optional should do not.
    query = {"bool": {"must": [{"terms": {"ecs.winlog.event_data.EventID": ["5140", "5145"]}}],
                      "filter": [{"term": {"ecs.source.ip": "127.0.0.1"}},
                                 {"range": {"ts": {"gte": "2023-01-23", "lte": "2023-01-26"}}}],
                      "must_not": [{"term": {"family": "hayabusa"}}],
                      "should": [{"match_phrase": {"text": "share"}}]}}
    assert es_native._positive_clauses(query) == [*query["bool"]["must"], *query["bool"]["filter"]]
    # A bool of should clauses alone needs one of them: it is one clause, as a whole.
    either = {"bool": {"should": [{"term": {"family": "pecmd"}}, {"term": {"family": "amcache"}}]}}
    assert es_native._positive_clauses(either) == [
        {"bool": {"should": either["bool"]["should"], "minimum_should_match": 1}}]


def test_the_seat_sees_what_the_surface_said_about_its_query():
    result = {
        "total": 0, "returned": 0, "has_more": False, "next_search_after": None, "hits": [],
        "normalized": ["used keyword sub-field `fields.Level.kw` for `fields.Level` (text field)"],
        "field_population_note": "fields.x is not populated by any family in this case",
        "zero_hit": {"clauses": [{"clause": "{}", "rows": 0}], "note": "x matches no row on its own."},
    }
    summary = _result_summary("es_search", result)
    for key in ("normalized", "field_population_note", "zero_hit"):
        assert summary[key] == result[key]
    assert summary["total"] == 0 and summary["hits"] == []
    flood = {"rows": 20_000, "by_family": [{"family": "evtxecmd", "rows": 20_000}], "by_event_id": [], "note": "n"}
    assert _result_summary("es_search", {"total": 20_000, "hits": [], "flood": flood})["flood"] == flood
    # Nothing is added that the surface did not say.
    assert set(_result_summary("es_search", {"total": 3, "hits": []})) == {
        "total", "returned", "has_more", "next_search_after", "window_truncated", "hits"}


def _es_url() -> str:
    env_file = Path(__file__).resolve().parents[1] / ".env"
    with contextlib.suppress(OSError):
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("NEXUS_ES_URL="):
                return line.split("=", 1)[1].strip().strip('"').strip("'").rstrip("/")
    return ""


def _es_answers(url: str) -> bool:
    with contextlib.suppress(Exception), urllib.request.urlopen(f"{url}/", timeout=2) as response:
        return response.status == 200
    return False


def _write(path: Path, rows: list[dict]) -> None:
    header = sorted({col for row in rows for col in row})
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, header)
        writer.writeheader()
        writer.writerows(rows)


@pytest.fixture
def live_case(tmp_path, monkeypatch):
    """CASE-C5B04D31's verbatim Hayabusa and EvtxECmd rows, indexed on the operator's cluster, then removed."""
    url = _es_url()
    if not url or not _es_answers(url):
        pytest.skip("no Elasticsearch in .env, or it did not answer")
    monkeypatch.setenv("NEXUS_ES_URL", url)
    from nexus.langgraph.case_index import index_case, index_name

    case = tmp_path / "CASE-TEST-IC9"
    _write(case / "extractions" / "hayabusa" / "evtx-timeline.csv",
           [r["fields"] for r in ROWS.values() if r["family"] == "hayabusa"])
    _write(case / "extractions" / "evtxecmd" / "EvtxECmd_Output.csv",
           [r["fields"] for r in ROWS.values() if r["family"] == "evtxecmd"])
    name = index_name(case.name)
    try:
        meta = index_case(case)
        assert meta.get("docs"), meta
        urllib.request.urlopen(urllib.request.Request(f"{url}/{name}/_refresh", method="POST"), timeout=15).close()
        yield case
    finally:
        with contextlib.suppress(urllib.error.URLError, OSError):
            urllib.request.urlopen(urllib.request.Request(f"{url}/{name}", method="DELETE"), timeout=15).close()


def test_a_zero_hit_search_names_the_clauses_that_match_nothing(live_case):
    result = es_native.es_search(live_case.name, DEFENDER_CRITICAL, size=10)
    assert result["total"] == 0
    clauses = result["zero_hit"]["clauses"]
    assert [c["rows"] for c in clauses] == [0, 0]
    note = result["zero_hit"]["note"]
    assert "Microsoft-Windows-Defender/Operational" in note and "critical" in note
    assert note.count("matches no row on its own") == 2
    # Counts only: each clause is the seat's own, beside numbers; no value from the rows is offered.
    counted = {"rows", "rows_in_family", "rows_ignoring_case", "rows_with_the_value_in_their_text"}
    for clause in clauses:
        assert set(clause) - {"clause"} <= counted
        assert all(isinstance(clause[k], int) for k in set(clause) - {"clause"})
    # The seat's next round carries it.
    assert _result_summary("es_search", result)["zero_hit"] == result["zero_hit"]


def test_a_value_written_in_another_case_is_counted_ignoring_case(live_case):
    result = es_native.es_search(live_case.name, HAYABUSA_CRIT, size=10)
    assert result["total"] == 0
    level = next(c for c in result["zero_hit"]["clauses"] if "fields.Level" in c["clause"])
    assert level["rows"] == 0 and level["rows_ignoring_case"] == 2
    assert "2 rows match it ignoring case" in result["zero_hit"]["note"]


def test_a_flood_says_what_its_rows_are_made_of(live_case, monkeypatch):
    # Six rows stand for the case's 1,130,289: the threshold is lowered, the query and the rows are the run's.
    monkeypatch.setattr(es_native, "FLOOD_ROWS", 3)
    result = es_native.es_search(live_case.name, EVTXECMD, size=2)
    flood = result["flood"]
    assert flood["rows"] == result["total"] == 6
    assert flood["by_family"] == [{"family": "evtxecmd", "rows": 6}]
    assert sum(b["rows"] for b in flood["by_event_id"]) == 6
    assert "not a sample" in flood["note"]
    # A later page of the same search is not composed again.
    later = es_native.es_search(live_case.name, EVTXECMD, size=2, search_after=result["next_search_after"])
    assert "flood" not in later
