"""D286: a file saved as base64 text is identified, not extracted (2026-10-18).

Sample S06 keeps a mail attachment as ``attachment.txt``, base64 of a ZIP archive holding a script, and no importer
read it. The positive test reads S06's file where the sample is present: the attachment is a specimen and is not kept
in the repository. The negative test encodes bytes already in the fixtures (a hive's base block), whose signature is
not a file type the importer names, so it must not be taken for an attachment.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from nexus.ingest.detect import detect_format
from nexus.ingest.generic.encoded import Base64FileImporter
from nexus.ingest.schemas import ArtifactSource
from nexus.langgraph.timeline_merge import ingest_into_case

REPO = Path(__file__).resolve().parents[1]
S06_ATTACHMENT = REPO / "Evidence-files" / "_samples" / "S06" / "mail" / "attachment.txt"


@pytest.mark.skipif(not S06_ATTACHMENT.is_file(), reason="sample S06 is not on this host")
def test_a_base64_attachment_is_named_by_what_it_holds(tmp_path):
    assert detect_format(S06_ATTACHMENT) == ArtifactSource.ENCODED_FILE
    case = tmp_path / "CASE-S06"
    (case / "audit").mkdir(parents=True)
    info = ingest_into_case(S06_ATTACHMENT, case)
    assert (info["source"], info["artifacts"]) == ("encoded_file", 2)
    blob, member = [json.loads(x) for x in (case / "ingest" / "artifacts.jsonl").read_text(encoding="utf-8").splitlines()]
    assert blob["raw"]["decoded_type"] == "ZIP archive" and blob["raw"]["members"] == ["first.wsf"]
    assert len(blob["raw"]["decoded_sha256"]) == 64 and blob["raw"]["decoded_sha256"] in blob["iocs"]
    assert blob["ts_synthesized"], "the attachment itself carries no time"
    assert member["file_path"] == "first.wsf" and member["raw"]["size"] > 0 and not member["ts_synthesized"]
    assert not list(case.rglob("first.wsf")), "the member is not extracted"


def test_base64_of_a_file_with_no_known_signature_is_not_taken(tmp_path):
    hive = (Path(__file__).parent / "fixtures" / "d279_hives" / "SYSTEM_clean").read_bytes()
    encoded = tmp_path / "blob.txt"
    encoded.write_bytes(base64.b64encode(hive))
    assert not Base64FileImporter.can_handle(encoded)
    assert detect_format(encoded) != ArtifactSource.ENCODED_FILE
