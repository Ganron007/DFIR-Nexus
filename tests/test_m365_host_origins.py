"""ClientIP is a network property, not an inferred host name (D520)."""
import csv
import hashlib
import json
from pathlib import Path

from nexus.config import settings
from nexus.ingest.cloud.m365 import M365Importer
from nexus.langgraph.case_index import iter_index_doc_batches
from nexus.langgraph.pipeline_runs import create_run
from nexus.langgraph.timeline_merge import ingest_into_case

FIXTURE = Path(__file__).parent / "fixtures/d520_m365_clientip.csv"


def _source_record():
    provenance = json.loads(FIXTURE.with_name("d520_input_provenance.json").read_text(encoding="utf-8"))
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == provenance["fixture_sha256"]
    with FIXTURE.open(encoding="utf-8-sig", newline="") as source:
        (record,) = csv.DictReader(source)
    audit = json.loads(record["AuditData"])
    assert audit["ClientIP"] and not audit.get("WorkstationName")
    return record, audit


def test_a_client_address_does_not_create_a_host_name():
    original, audit = _source_record()
    (artifact,) = M365Importer().parse(FIXTURE)
    assert artifact.raw == original
    assert artifact.source_ip == audit["ClientIP"]
    assert artifact.host is None


def test_i1_preserves_client_address_without_promoting_it_to_ecs_host():
    original, audit = _source_record()
    case = Path(settings.cases_root) / "CASE-DA520001"
    case.mkdir(parents=True)
    run = create_run(case, "tools", evidence_paths=[str(FIXTURE)])
    receipt = ingest_into_case(FIXTURE, case)
    assert receipt["success"] and receipt["artifacts"] == 1
    assert receipt["importer"] == M365Importer.__name__
    (stored,) = [json.loads(line) for line in (case / "ingest/artifacts.jsonl").read_text(encoding="utf-8").splitlines()]
    assert stored["raw"] == original and stored["source_ip"] == audit["ClientIP"]
    assert stored["host"] is None
    (document,) = [row for batch in iter_index_doc_batches(case, run_id=run.run_id) for row in batch]
    assert "host" not in document
    assert "host" not in document["fields"] and "host" not in document.get("ecs", {})
    assert document["fields"]["source_ip"] == audit["ClientIP"]
    assert document["ecs"]["source"]["ip"] == audit["ClientIP"]
