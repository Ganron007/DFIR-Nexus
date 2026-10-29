"""D490: the lane's importer pass rebuilds the case's ingest store, so a file another importer now reads leaves one
reading, not two.

T10 after D487: the generic CSV reader's 6,454 rows of its M365 exports stayed beside the M365 importer's 6,454 rows
of the same files, because the store only appends and dedupes by content (operator 2026-10-30: rebuild per lane run).
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from nexus.ingest import provenance
from nexus.langgraph.timeline_merge import ingest_into_case, rebuilt_ingest_store

#: Microsoft's "Download all results" header (ingest/cloud/m365.py); the values are documentation examples.
UAL = ('CreationDate,UserIds,Operations,AuditData\n'
       '2020-10-02T00:12:41.0000000Z,u@example.com,UserLoggedIn,"{""CreationTime"":""2020-10-02T00:12:41"",'
       '""Operation"":""UserLoggedIn"",""UserId"":""u@example.com"",""ClientIP"":""198.51.100.7""}"\n')


def _sources(case: Path) -> Counter:
    store = case / "ingest" / "artifacts.jsonl"
    return Counter(json.loads(line)["source"] for line in store.read_text(encoding="utf-8").splitlines() if line)


@pytest.fixture
def case_with_a_superseded_reading(tmp_path):
    case = tmp_path / "CASE-D490"
    case.mkdir()
    export = tmp_path / "audit.csv"
    export.write_text(UAL, encoding="utf-8")
    assert ingest_into_case(export, case, source="generic_csv", audit=False)["success"]
    return case, export


def test_a_rebuilt_store_holds_only_the_current_importers_reading(case_with_a_superseded_reading):
    case, export = case_with_a_superseded_reading
    with rebuilt_ingest_store(case):
        assert ingest_into_case(export, case, audit=False)["source"] == "azure"
    assert _sources(case) == Counter({"azure": 1})
    assert not list((case / "ingest").glob("*.previous"))
    chains = {chain for found in provenance.load_provenance(case).values() for chain in found}
    assert chains and all(chain[-1].endswith("M365Importer") for chain in chains), chains


def test_a_failed_pass_puts_the_old_store_and_ledger_back(case_with_a_superseded_reading):
    case, export = case_with_a_superseded_reading
    store, ledger = case / "ingest" / "artifacts.jsonl", provenance.ledger_path(case)
    before = {path: path.read_bytes() for path in (store, ledger) if path.exists()}
    with pytest.raises(RuntimeError), rebuilt_ingest_store(case):
        ingest_into_case(export, case, audit=False)
        raise RuntimeError("the pass died")
    assert {path: path.read_bytes() for path in before} == before
    assert not list((case / "ingest").glob("*.previous"))


def test_a_killed_passs_set_aside_copy_is_superseded(case_with_a_superseded_reading):
    case, export = case_with_a_superseded_reading
    leftover = case / "ingest" / "artifacts.jsonl.previous"
    leftover.write_text('{"source": "stale"}\n', encoding="utf-8")
    with rebuilt_ingest_store(case):
        ingest_into_case(export, case, audit=False)
    assert _sources(case) == Counter({"azure": 1}) and not leftover.exists()


def test_only_a_run_reading_every_registered_path_rebuilds(tmp_path, monkeypatch):
    from nexus.config import settings
    from nexus.langgraph import llm_pipeline

    case = Path(settings.cases_root) / "CASE-D490B"
    case.mkdir(parents=True)
    one, two = tmp_path / "one.csv", tmp_path / "two.csv"
    for path in (one, two):
        path.write_text("a,b\n1,2\n", encoding="utf-8")
    (case / "evidence.json").write_text(json.dumps([{"path": str(one)}, {"path": str(two)}]), encoding="utf-8")
    assert llm_pipeline._covers_registered_evidence(case.name, [str(one), str(two)])
    assert not llm_pipeline._covers_registered_evidence(case.name, [str(one)])
