"""Unit tests for WP 10.9 artifact-recovery surfaces (RDP, thumbcache, recycle bin, deleted files)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from nexus.recovery.service import RecoveryService


@pytest.fixture
def staged_recovery_case(tmp_path: Path) -> Path:
    """Create a mock case directory with extractions across all recovery categories."""
    case_dir = tmp_path / "CASE-RECOVERY-01"
    case_dir.mkdir(parents=True)
    extractions = case_dir / "extractions"
    extractions.mkdir(parents=True)

    # 1. RDP bitmap cache tiles (bmc-tools)
    bmc_dir = extractions / "bmc-tools" / "Administrator" / "tiles"
    bmc_dir.mkdir(parents=True)
    (bmc_dir / "tile_0001.bmp").write_bytes(b"BM" + b"\x00" * 128)
    (bmc_dir / "tile_0002.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 128)

    # 2. Thumbcache entries
    thumb_dir = extractions / "thumbcache_viewer"
    thumb_dir.mkdir(parents=True)
    (thumb_dir / "thumbcache_256.db").write_bytes(b"\x00" * 512)
    (thumb_dir / "thumbcache_256_entry_01.jpg").write_bytes(b"\xff\xd8\xff" + b"\x00" * 256)

    # 3. Recycle Bin (RBCmd CSV output)
    rb_dir = extractions / "RBCmd"
    rb_dir.mkdir(parents=True)
    rb_csv = rb_dir / "20261112_RBCmd_Output.csv"
    with open(rb_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["SourceFile", "DeletedOn", "OriginalPath", "FileSize"])
        writer.writerow(["$I12345.docx", "2026-11-10 14:30:22", "C:\\Users\\Victim\\Documents\\Confidential.docx", "45020"])
        writer.writerow(["$I67890.exe", "2026-11-11 09:15:00", "C:\\Users\\Victim\\Downloads\\payload.exe", "102400"])

    # 4. Deleted files (fls output)
    fls_dir = extractions / "fls"
    fls_dir.mkdir(parents=True)
    fls_file = fls_dir / "fls_deleted.txt"
    fls_file.write_text(
        "r/r * 12894-128-3:  C:/Windows/Temp/mimikatz.exe\n"
        "d/d * 4821:  C:/Users/Victim/AppData/Local/Temp/exfil_staging\n"
        "r/r 5000:  C:/Windows/System32/calc.exe\n",
        encoding="utf-8",
    )

    # Write case metadata
    (case_dir / "case.json").write_text(
        json.dumps({"id": "CASE-RECOVERY-01", "name": "Recovery Test Case"}),
        encoding="utf-8",
    )

    return case_dir


def test_recovery_service_census_and_listing(staged_recovery_case: Path):
    service = RecoveryService(staged_recovery_case)
    summary = service.get_summary()

    assert summary.case_id == "CASE-RECOVERY-01"
    assert summary.rdp_tile_count == 2
    assert summary.thumbcache_count == 2
    assert summary.recycle_bin_count == 2
    assert summary.deleted_file_count == 2


def test_rdp_tiles_pagination(staged_recovery_case: Path):
    service = RecoveryService(staged_recovery_case)
    page1 = service.list_rdp_tiles(limit=1, offset=0)
    assert page1["total"] == 2
    assert len(page1["items"]) == 1
    assert page1["items"][0]["category"] == "rdp_bitmap"
    assert page1["items"][0]["metadata"]["user"] == "Administrator"

    page2 = service.list_rdp_tiles(limit=1, offset=1)
    assert len(page2["items"]) == 1
    assert page2["items"][0]["id"] != page1["items"][0]["id"]


def test_recycle_bin_query_and_parsing(staged_recovery_case: Path):
    service = RecoveryService(staged_recovery_case)
    res = service.list_recycle_bin(query="payload")
    assert res["total"] == 1
    assert res["items"][0]["name"] == "payload.exe"
    assert res["items"][0]["size_bytes"] == 102400
    assert "C:\\Users\\Victim\\Downloads\\payload.exe" in res["items"][0]["metadata"]["original_path"]


def test_deleted_files_parsing(staged_recovery_case: Path):
    service = RecoveryService(staged_recovery_case)
    res = service.list_deleted_files(query="mimikatz")
    assert res["total"] == 1
    assert res["items"][0]["name"] == "mimikatz.exe"
    assert res["items"][0]["metadata"]["inode"] == "12894-128-3"


def test_recovery_manifest_export(staged_recovery_case: Path):
    service = RecoveryService(staged_recovery_case)
    manifest = service.export_manifest()

    assert manifest["summary"]["rdp_tile_count"] == 2
    assert len(manifest["artifacts"]["rdp_bitmap"]) == 2
    assert len(manifest["artifacts"]["recycle_bin"]) == 2
    assert len(manifest["artifacts"]["deleted_file"]) == 2


def test_portal_recovery_api_endpoints(staged_recovery_case: Path, monkeypatch):
    from unittest.mock import patch

    from starlette.applications import Starlette

    from nexus.dashboard.app import create_dashboard

    app = Starlette(routes=create_dashboard())
    with patch("nexus.dashboard.app._get_case_dir", return_value=staged_recovery_case):
        client = TestClient(app)
        case_id = staged_recovery_case.name

        # Summary
        resp = client.get(f"/portal/api/case/{case_id}/recovery/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["rdp_tile_count"] == 2
        assert data["recycle_bin_count"] == 2

        # RDP
        resp = client.get(f"/portal/api/case/{case_id}/recovery/rdp")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

        # Thumbcache
        resp = client.get(f"/portal/api/case/{case_id}/recovery/thumbcache")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

        # Recycle bin with query
        resp = client.get(f"/portal/api/case/{case_id}/recovery/recycle-bin?query=Confidential")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

        # Deleted files
        resp = client.get(f"/portal/api/case/{case_id}/recovery/deleted-files")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

        # Export
        resp = client.get(f"/portal/api/case/{case_id}/recovery/export")
        assert resp.status_code == 200
        assert "artifacts" in resp.json()
