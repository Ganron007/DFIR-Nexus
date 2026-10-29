"""D487: an audit log search's CSV exports reach the M365 importer by their header, and every record is read.

T10 holds Microsoft's two documented exports (module docstring of `ingest/cloud/m365.py`): `AuditLog_<dates>.csv`
("Download all results": CreationDate, UserIds, Operations, AuditData) and `UnifiedAuditLog.csv` ("Save loaded
results": Date, IP address, User, Activity, Item, Detail, More). Their names matched no rule, the importer read JSON
only, so the generic CSV reader took both and T10 selected no skill. And a record with a top-level CreationDate was
skipped as malformed: `_extract_timestamp` returned a bare datetime the caller unpacked.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus.ingest.cloud.m365 import M365Importer, audit_export_layout
from nexus.ingest.detect import detect_format
from nexus.ingest.registry import get_registry
from nexus.ingest.schemas import ArtifactSource

T10 = Path(__file__).resolve().parents[1] / "Evidence-files" / "_tiny" / "T10" / "cloud"


def test_the_documented_headers_and_nothing_else_are_audit_exports():
    assert audit_export_layout(["﻿CreationDate", "UserIds", "Operations", "AuditData"]) == "raw"
    assert audit_export_layout(["CreationDate", "UserIds", "RecordType", "AuditData"]) == "raw"
    assert audit_export_layout(["Date", "IP address", "User", "Activity", "Item", "Detail", "More"]) == "loaded"
    assert audit_export_layout(["Date", "User", "Activity", "Item"]) is None
    assert audit_export_layout(["Timestamp", "Hostname", "Message"]) is None


def test_a_record_with_a_top_level_creation_date_is_read(tmp_path):
    """The JSON path's own record shape (Search-UnifiedAuditLog output keeps CreationDate beside AuditData)."""
    audit = {"CreationTime": "2020-10-02T00:12:41", "Operation": "UserLoggedIn", "UserId": "u@example.com",
             "ClientIP": "198.51.100.7", "ResultStatus": "Succeeded"}
    path = tmp_path / "ual.json"
    path.write_text(json.dumps([{"CreationDate": "2020-10-02T00:12:41.0000000Z", "UserIds": "u@example.com",
                                 "Operations": "UserLoggedIn", "AuditData": json.dumps(audit)}]), encoding="utf-8")
    (artifact,) = list(M365Importer().parse(path))
    assert artifact.timestamp.isoformat() == "2020-10-02T00:12:41+00:00" and not artifact.ts_synthesized
    assert (artifact.user, artifact.source_ip) == ("u@example.com", "198.51.100.7")


@pytest.mark.skipif(not T10.is_dir(), reason="the tiny cases are not staged on this host")
@pytest.mark.parametrize("name,rows", [("AuditLog_2020-09-10_2020-10-04.csv", 441), ("UnifiedAuditLog.csv", 6455)])
def test_t10s_exports_reach_the_m365_importer_and_every_row_is_read(name, rows):
    path = T10 / name
    assert detect_format(path) is ArtifactSource.AZURE
    assert get_registry().resolve(ArtifactSource.AZURE, path) is M365Importer
    artifacts = list(M365Importer().parse(path))
    assert len(artifacts) == rows
    assert not any(a.ts_synthesized for a in artifacts)
    assert sum(1 for a in artifacts if a.user) == rows
