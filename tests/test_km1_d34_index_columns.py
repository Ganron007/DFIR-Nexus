"""WO-KM1 item 1 (D34): importer columns reach the index.

The defect, in the reviewer's own terms: an importer computed ``process_name``,
``command_line``, ``parent_process``, ``file_path``, the hashes and the registry
key/value, stored them in the artifact record, and the index projected only the
13 envelope fields - so a mimikatz command line was **not searchable at all**,
on fields or on text. That contradicts 4k.2 "index everything".

These tests pin the real path the WO names: a temp case whose importer record
carries ``mimikatz.exe sekurlsa::logonpasswords`` in ``command_line`` is found
by ``es_search`` both on ``fields.command_line`` and on ``text``. The ES half
runs against the operator's cluster (``.env``); the projection half - which is
the actual defect - runs with no ES at all, so it always runs.
"""
from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nexus.langgraph.case_index import INDEX_SCHEMA_VERSION, index_name
from nexus.langgraph.query_pack import iter_ingest_records, render_ingest_row

# The record exactly as the WO names it: a mimikatz command line.
COMMAND_LINE = "mimikatz.exe sekurlsa::logonpasswords"

RECORD = {
    "artifact_id": "a-1",
    "artifact_type": "process_execution",
    "source": "volatility",
    "timestamp": "2026-09-29T13:04:07Z",
    "severity": "high",
    "host": "ws01.cadre.local",
    "user": "bob",
    "process_name": "mimikatz.exe",
    "process_id": 4180,
    "parent_process": "cmd.exe",
    "command_line": COMMAND_LINE,
    "file_path": r"C:\Temp\mimikatz.exe",
    "file_hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
    "file_hash_sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "file_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "registry_key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\once",
    "registry_value": "rundll32 payload.dll,start",
    "action": "create",
    "description": "",
}


def _temp_case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-KM1-D34"
    (case / "ingest").mkdir(parents=True)
    line = json.dumps(RECORD)
    (case / "ingest" / "artifacts.jsonl").write_text(line + "\n", encoding="utf-8")
    return case


# --------------------------------------------------------------------------
# the row text (the half that needs no ES)
# --------------------------------------------------------------------------


def test_the_command_line_is_in_the_row_text():
    text = render_ingest_row(RECORD)
    # the defect was that a full-text search could not find this
    assert COMMAND_LINE in text


def test_every_normalized_column_is_in_the_row_text():
    text = render_ingest_row(RECORD)
    for expected in (
        "process=mimikatz.exe",
        "pid=4180",
        "parent=cmd.exe",
        "file=C:\\Temp\\mimikatz.exe",
        "md5=d41d8cd98f00b204e9800998ecf8427e",
        "sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "regkey=HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\once",
        "regvalue=rundll32 payload.dll,start",
        "action=create",
    ):
        assert expected in text, f"missing from the row text: {expected}"


def test_an_empty_record_does_not_grow_empty_keys():
    """The guards matter: ``pid=`` and ``parent=`` must not appear empty."""
    text = render_ingest_row({"timestamp": "2026-09-29T13:04:07Z", "source": "authlog"})
    assert "pid=" not in text
    assert "parent=" not in text
    assert "cmd=" not in text
    assert "regkey=" not in text
    assert text.startswith("2026-09-29T13:04:07Z authlog")


def test_the_row_stays_bounded():
    """``_MAX_LINE`` exists because a million rows are indexed."""
    loud = dict(RECORD)
    loud["command_line"] = "x" * 100_000
    assert len(render_ingest_row(loud)) <= render_ingest_row.__defaults__[0]


def test_iter_ingest_records_yields_the_projected_text(tmp_path):
    case = _temp_case(tmp_path)
    rows = list(iter_ingest_records(Path(case)))
    assert len(rows) == 1
    _line, family, text, _ts, record = rows[0]
    assert family == "volatility"
    assert record["command_line"] == COMMAND_LINE
    assert COMMAND_LINE in text


# --------------------------------------------------------------------------
# the fields.* half (the real path, needs ES)
# --------------------------------------------------------------------------


def _es_url() -> str:
    url = ""
    for source in (os.environ.get("NEXUS_ES_URL"),):
        url = (source or "").strip().rstrip("/")
        if url:
            return url
    for env_file in (Path("C:/STUDY/Github/CADRE-Platform/DFIR-Nexus/.env"),):
        if env_file.is_file():
            for entry in env_file.read_text(encoding="utf-8").splitlines():
                if entry.startswith("NEXUS_ES_URL="):
                    return entry.split("=", 1)[1].strip().rstrip("/")
    return ""


def _projected_fields(case_dir: Path) -> dict[str, str]:
    """The fields ``case_index`` actually puts in the document for this case.

    Read back from the real path - ``iter_index_docs``, the same call the indexer
    makes - rather than reimplemented, so these assertions fail if the projection
    changes and the WO's list stops being honoured. An earlier version parsed the
    module's source for the tuple's text; that was fragile and reported a false
    failure while the code was correct.
    """
    from nexus.langgraph.case_index import iter_index_docs

    docs = iter_index_docs(Path(case_dir))
    ingest = [d for d in docs if d.get("family") == "volatility"]
    assert ingest, "no ingest document was produced for the case"
    doc = ingest[0]
    fields = doc.get("fields") if isinstance(doc.get("fields"), dict) else {}
    # The row TEXT half is asserted separately, in test_the_row_text_carries_the_command_line_too.
    return {str(k).lower(): str(v) for k, v in fields.items()}


def test_the_row_text_carries_the_command_line_too():
    """The D34 half that needs no ES: a plain full-text search finds it."""
    # build a temp case, but only the ingest artifact
    import tempfile

    from nexus.langgraph.case_index import iter_index_docs

    with tempfile.TemporaryDirectory() as tmp:
        case = Path(tmp) / "CASE-KM1-D34-TEXT"
        (case / "ingest").mkdir(parents=True)
        (case / "ingest" / "artifacts.jsonl").write_text(
            json.dumps(RECORD) + "\n", encoding="utf-8"
        )
        docs = iter_index_docs(case)
        assert docs
        text = docs[0]["text"]
    assert COMMAND_LINE in text, "the command line is not in the indexed row text"
    assert "process=mimikatz.exe" in text


def test_the_normalized_columns_are_projected_as_fields(tmp_path):
    case = _temp_case(tmp_path)
    fields = _projected_fields(case)
    for name in (
        "process_name", "process_id", "parent_process", "command_line",
        "file_path", "file_hash_md5", "file_hash_sha1", "file_hash_sha256",
        "registry_key", "registry_value", "action",
    ):
        assert name in fields, f"{name} is not projected into fields.*"
    assert fields["command_line"] == COMMAND_LINE
    assert fields["process_id"] == "4180"


def test_schema_version_bumped_for_d34():
    """A v8 index silently omits these columns; the bump is load-bearing."""
    assert INDEX_SCHEMA_VERSION >= 9


@pytest.mark.skipif(not _es_url(), reason="NEXUS_ES_URL is not configured")
def test_es_search_finds_the_command_line_on_fields_and_on_text(tmp_path):
    """The WO's real-path acceptance, against the operator's cluster.

    clause choice matters here: ``fields.command_line`` is mapped as ``text`` with a
    ``kw`` subfield, so a ``term`` clause on the analysed field scores no matches (the
    earlier version of this test used ``term`` and reported 0 while the projection was
    correct). ``match`` is the clause the surface's own ``es_search`` semantics allow,
    and the keyword subfield is checked with ``term`` too.
    """
    import urllib.error
    import urllib.request

    case = _temp_case(tmp_path)
    url = _es_url()
    index = index_name(case.name)

    from nexus.langgraph.case_index import index_case

    # case_index reads the environment, not the .env file
    os.environ["NEXUS_ES_URL"] = url
    meta = index_case(case)
    try:
        assert meta.get("docs"), meta

        def count(query: dict) -> int:
            body = {"size": 0, "query": query}
            request = urllib.request.Request(
                f"{url}/{index}/_search",
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8"))
            return payload["hits"]["total"]["value"]

        # the normalized command line is a field AND in the row text
        assert count({"match": {"fields.command_line": COMMAND_LINE}}) >= 1
        assert count({"term": {"fields.command_line.kw": COMMAND_LINE}}) >= 1
        assert count({"match": {"text": "sekurlsa"}}) >= 1
        # a keyword column matches exactly on its subfield
        assert count({"term": {"fields.process_name.kw": "mimikatz.exe"}}) >= 1
        # D35 groundwork: the family is what the index says, not a declared name
        fam_doc = count({"term": {"family": "volatility"}})
        assert fam_doc >= 1
    finally:
        # the case and its index must not outlive the test (AGENTS.md hygiene)
        with contextlib.suppress(urllib.error.URLError, OSError):
            urllib.request.urlopen(
                urllib.request.Request(f"{url}/{index}", method="DELETE"), timeout=15
            ).close()
