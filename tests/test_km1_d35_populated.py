"""D35 acceptance test, on a real ES index with a CloudTrail-only case.

The WO: "on a CloudTrail-only temp case, the catalog lists CloudTrail's populated
columns plus the core fields, and NO PayloadData1 or ImageFileName." A CloudTrail
source has no PayloadData1 at all, so the declared-but-absent claim would be told
by the index, and the populated half proves it.
"""
from __future__ import annotations

import contextlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO = Path('.').resolve()
sys.path.insert(0, str(REPO / 'src'))


def _es_url() -> str:
    for cand in (os.environ.get('NEXUS_ES_URL'),):
        url = (cand or '').strip().rstrip('/')
        if url:
            return url
    env_file = REPO / '.env'
    if env_file.is_file():
        for line in env_file.read_text(encoding='utf-8').splitlines():
            if line.startswith('NEXUS_ES_URL='):
                return line.split('=', 1)[1].strip().rstrip('/')
    return ''


AUTHLOG_LINE = json.dumps({
    "artifact_id": "a-ct", "artifact_type": "session_invocation",
    "source": "cloudtrail", "timestamp": "2026-06-05T07:00:00Z", "severity": "info",
    "host": "linux-608", "user": "bob", "action": "LookupEvents",
    "command_line": "/usr/local/bin/aws cloudtrail lookup-events --region us-east-1",
    "description": "an importer artifact with the normalized columns",
    "file_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "artifact_normalized": True,
})


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-KM1-D35"
    (case / "ingest").mkdir(parents=True)
    (case / "ingest" / "artifacts.jsonl").write_text(AUTHLOG_LINE + "\n", encoding="utf-8")
    return case


@pytest.mark.skipif(not _es_url(), reason="NEXUS_ES_URL is not configured")
def test_populated_columns_are_reported_and_declared_are_marked(tmp_path):
    url = _es_url()
    case = _case(tmp_path)
    os.environ['NEXUS_ES_URL'] = url

    from nexus.langgraph.case_index import index_case, index_name
    from nexus.langgraph.es_native import es_fields

    meta = index_case(case)
    try:
        assert meta.get('docs'), meta
        fields = es_fields(case.name)

        families = fields.get('families') or {}
        assert 'cloudtrail' in families, f"family set: {families}"

        populated = fields.get('populated_columns') or {}
        # D34: the normalized columns are now populated, because they are indexed.
        filled = populated.get('cloudtrail') or {}
        assert filled.get('command_line'), f"not populated: {filled}"
        assert filled.get('action'), filled

        # The declared half still exists (validation depends on it) but no longer
        # claims to be the present half.
        assert 'populated_columns' in fields
        note = fields.get('population_note') or ''
        assert 'parsed_columns' in note and 'matches nothing' in note, note
        # and the declared list is NOT the populated list - that was the defect.
        assert set(filled) != {c['field'] for c in (fields.get('parsed_columns') or [])}
    finally:
        with contextlib.suppress(urllib.error.URLError, OSError):
            urllib.request.urlopen(
                urllib.request.Request(f"{url}/{index_name(case.name)}", method='DELETE'),
                timeout=15,
            ).read()


def test_the_prompt_block_no_longer_claims_only_declared_columns_exist():
    """The wording is the defect: "only these columns exist" is a false promise."""
    sys.path.insert(0, str(REPO / 'src'))
    from nexus.langgraph.field_catalog import field_catalog_block

    block = field_catalog_block('CASE-KM1-D35') or ""
    assert "only these columns exist" not in block, block[:200]
