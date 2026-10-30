"""D483: native image products become citable metadata without losing their backing-file integrity.

Images are read in place from the existing tiny-case tool runs; they are not redistributed as fixtures. No image
or forensic record is invented. A host without these private outputs skips the two producer-specific fixtures.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from nexus.langgraph.case_index import iter_index_doc_batches, iter_index_files
from nexus.langgraph.tool_assets import RECORD_TYPE, write_catalog

REPO = Path(__file__).resolve().parents[1]
SOURCES = {
    "bmc-tools": ("CASE-B648097E", "RUN-20261024T114926197101Z-tools-5a944aa0", "bmc-tools"),
    "thumbcache_viewer": ("CASE-218CD55A", "RUN-20261024T114842895115Z-tools-3dc12ce5", "thumbcache"),
}


@pytest.fixture(params=sorted(SOURCES))
def product(request, tmp_path, monkeypatch):
    from nexus.langgraph import pipeline_runs

    tool = request.param
    case_id, run_id, folder = SOURCES[tool]
    run = REPO / "cases" / case_id / "runs" / run_id
    source = next((run / "extractions" / folder).rglob("*.bmp"), None)
    ledger = run / "ledger" / "_tool_lane_ledger.json"
    if source is None or not ledger.is_file():
        pytest.skip("private tiny-case image products are not present; native lane replay supplies the live proof")
    job = next(row for row in json.loads(ledger.read_text(encoding="utf-8")) if row.get("tool") == tool)
    case = tmp_path / "CASE-ASSET-CATALOG"
    root = case / "runs" / "RUN-1" / "extractions"
    asset = root / folder / "tiles" / source.name
    asset.parent.mkdir(parents=True)
    shutil.copyfile(source, asset)
    monkeypatch.setattr(pipeline_runs, "resolve_tools_extractions", lambda case_dir, run_id="": root)
    from nexus.langgraph.tool_lane import _job_reuse_key

    key = _job_reuse_key(job["host"], tool, job["purpose"], job.get("evidence_sha", ""))
    return tool, case, root, asset, source, job["audit_id"], key


def test_the_real_index_walk_reads_citable_metadata_and_tracks_the_backing_file(product):
    tool, case, root, asset, source, audit_id, key = product
    catalog = write_catalog(tool, [str(asset)], root, audit_id, job_key=key)
    docs = [doc for batch in iter_index_doc_batches(case) for doc in batch]
    assert len(docs) == 1 and docs[0]["family"] == tool
    doc = docs[0]
    assert doc["fields"]["artifact_type"] == RECORD_TYPE
    assert doc["fields"]["source_audit_id"] == audit_id
    assert doc["fields"]["file_path"] == asset.relative_to(root).as_posix()
    assert int(doc["fields"]["file_size"]) == source.stat().st_size
    assert doc["ecs"]["file"]["hash"]["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert "ts" not in doc, "extraction metadata supplies no event time"
    assert {asset, catalog} <= set(iter_index_files(case)), "index verification must cover both the citation and image"
    from nexus.langgraph.case_index import _index_file_digests

    assert _index_file_digests(case)[asset.relative_to(root).as_posix()] == hashlib.sha256(source.read_bytes()).hexdigest()
    # The citation names a real, readable CSV row, rather than a physical line in a binary image.
    assert catalog.read_text(encoding="utf-8").splitlines()[doc["line"] - 1]


def test_changed_backing_image_fails_indexing_instead_of_serving_stale_metadata(product):
    tool, case, root, asset, _source, audit_id, key = product
    write_catalog(tool, [str(asset)], root, audit_id, job_key=key)
    asset.write_bytes(asset.read_bytes() + b"\x00")  # mutate only the scratch copy, never the source
    with pytest.raises(ValueError, match="changed after the tool cataloged"):
        list(iter_index_doc_batches(case))
    from nexus.langgraph.case_index import index_case

    # Refuse before touching Elasticsearch, even when only the binary input (not the catalog) changed.
    with pytest.raises(ValueError, match="changed after the tool cataloged"):
        index_case(case, incremental=True)


def test_catalog_refuses_a_file_outside_its_run(product):
    tool, _case, root, _asset, source, audit_id, key = product
    with pytest.raises(ValueError):
        write_catalog(tool, [str(source)], root, audit_id, job_key=key)
    assert not list((root / tool / "asset_catalog").glob("*.csv"))


def test_catalog_cannot_turn_empty_output_into_a_product(tmp_path):
    root = tmp_path / "extractions"
    assert write_catalog("bmc-tools", [], root, "", job_key=()) is None
    assert not root.exists(), "the helper creates no product; pytest's own case/password fixtures are elsewhere"


def test_retry_replaces_the_same_jobs_catalog_without_duplicating_images(product):
    tool, case, root, asset, _source, audit_id, key = product
    from nexus.langgraph.tool_lane import _job_reuse_key

    # Another actual invocation of this job supplies the retry's audit id; no forensic record is fabricated.
    case_id = SOURCES[tool][0]
    retry_id = None
    for ledger in (REPO / "cases" / case_id / "runs").glob("*/ledger/_tool_lane_ledger.json"):
        for row in json.loads(ledger.read_text(encoding="utf-8")):
            if (row.get("audit_id") and row["audit_id"] != audit_id
                    and _job_reuse_key(row["host"], row["tool"], row["purpose"], row.get("evidence_sha", "")) == key):
                retry_id = row["audit_id"]
                break
        if retry_id:
            break
    if retry_id is None:
        pytest.skip("a second real invocation of this private image-extraction job is not present")
    first = write_catalog(tool, [str(asset)], root, audit_id, job_key=key)
    second = write_catalog(tool, [str(asset)], root, retry_id, job_key=key)
    assert first == second
    docs = [doc for batch in iter_index_doc_batches(case) for doc in batch]
    assert len(docs) == 1
    assert docs[0]["fields"]["source_audit_id"] == retry_id


def test_thumbnail_folder_and_tool_have_one_family_meaning():
    from nexus.knowledge.family_registry import families_intersect

    assert families_intersect(["thumbcache"], ["thumbcache_viewer"])
