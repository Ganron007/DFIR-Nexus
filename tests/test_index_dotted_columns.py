"""D271: a column whose name has dots is a field of its own, and a row Elasticsearch refuses is never counted indexed.

Sample S04's Zeek logs came back from SIFT whole, and the index took none of their conn, dns, http and files rows
(3,556 rows): `id.orig_h` became the path `fields.id` -> `orig_h`, the importers' `id` column had typed `fields.id`
as text, and Elasticsearch refused each row. The run said 130,644 docs; the index held 127,088. The Zeek lines are
S04's dns.log, verbatim (tests/fixtures/d271_zeek_dns.log); the BIND lines are S03's.
"""
from __future__ import annotations

import contextlib
import json
import shutil
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from nexus.langgraph import case_index
from nexus.langgraph.lane_gate import read_lane_gate, record_index_rejections, write_lane_gate

FIXTURE = Path(__file__).parent / "fixtures" / "d271_zeek_dns.log"
BIND = [
    "12-Jul-2016 09:45:59.115 client 10.10.10.5#42935 (google.com): query: google.com IN A +E (10.10.10.5)",
]


def test_the_fields_object_holds_column_names_not_paths():
    fields = case_index._mapping_body()["mappings"]["properties"]["fields"]
    assert fields["subobjects"] is False
    assert case_index.INDEX_SCHEMA_VERSION >= 16


def test_a_refused_row_is_counted_per_file_with_its_reason():
    class _Resp:
        status_code = 200

        @staticmethod
        def json():
            return {"errors": True, "items": [
                {"index": {"status": 201}},
                {"index": {"status": 400, "error": {"type": "document_parsing_exception",
                                                     "reason": "failed to parse field [fields.id] of type [text]"}}},
            ]}

    class _Client:
        def post(self, *_a, **_k):
            return _Resp()

    rejected: dict = {}
    docs = [{"file": "zeek/notice.log", "line": 1}, {"file": "zeek/dns.log", "line": 9}]
    assert case_index._bulk_insert(_Client(), "idx", docs, rejected=rejected) == 1
    assert rejected == {"zeek/dns.log": {"rows": 1, "reason": "failed to parse field [fields.id] of type [text]"}}


def test_a_file_with_refused_rows_is_unprocessed_until_it_indexes_whole(tmp_path):
    write_lane_gate(tmp_path, "RUN-1", [{"tool": "zeek", "purpose": "Zeek logs", "status": "OK"}])
    record_index_rejections(tmp_path, {"zeek/dns.log": {"rows": 23, "reason": "failed to parse field [fields.id]"}})
    gate = read_lane_gate(tmp_path)
    assert gate["status"] == "blocked"
    assert gate["unprocessed"] == [{"tool": "index", "purpose": "index zeek/dns.log",
                                    "reason": "23 row(s) rejected by Elasticsearch: failed to parse field [fields.id]"}]
    record_index_rejections(tmp_path, {})
    assert read_lane_gate(tmp_path)["status"] == "clear"


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


def test_zeek_rows_index_beside_an_importer_row_with_an_id(tmp_path, monkeypatch):
    url = _es_url()
    if not url or not _es_answers(url):
        pytest.skip("no Elasticsearch in .env, or it did not answer")
    monkeypatch.setenv("NEXUS_ES_URL", url)
    from nexus.langgraph.timeline_merge import ingest_into_case

    case = tmp_path / "CASE-TEST-D271"
    (case / "extractions" / "zeek").mkdir(parents=True)
    shutil.copyfile(FIXTURE, case / "extractions" / "zeek" / "dns.log")
    bind = tmp_path / "ev" / "bind.log"
    bind.parent.mkdir()
    bind.write_text("\n".join(BIND) + "\n", encoding="utf-8")
    assert ingest_into_case(bind, case)["artifacts"] == 1  # an importer row: it carries `id`
    # The importers' `id` column is typed in the mapping, as on S04's index: the path `fields.id` is taken.
    assert "id" in case_index._mapping_body()["mappings"]["properties"]["fields"]["properties"]
    name = case_index.index_name(case.name)
    try:
        meta = case_index.index_case(case)
        assert meta["errors"] == 0 and not meta.get("rejected")
        urllib.request.urlopen(urllib.request.Request(f"{url}/{name}/_refresh", method="POST"), timeout=15).close()

        def count(query: dict) -> int:
            body = json.dumps({"query": query}).encode("utf-8")
            req = urllib.request.Request(f"{url}/{name}/_count", data=body, method="POST",
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read())["count"]

        assert count({"match_all": {}}) == meta["docs"] == 4  # three Zeek rows and the BIND query
        assert count({"term": {"fields.id.orig_h.kw": "10.0.2.107"}}) == 3
    finally:
        with contextlib.suppress(urllib.error.URLError, OSError):
            urllib.request.urlopen(urllib.request.Request(f"{url}/{name}", method="DELETE"), timeout=15).close()
