"""D284: an OSSEC alerts.log, and the Windows events an OSSEC agent forwards, are read (2026-10-18).

Sample S06's ``ossec-alerts.log`` is Windows Security events as the OSSEC agent forwards them, a blank line apart,
and no importer read it. The fixture is its first two events, verbatim. The block form (``** Alert``, location,
``Rule:``) follows OSSEC's OS_Log format strings; no real alerts.log with blocks was found on this host to test it on.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from nexus.ingest.detect import detect_format
from nexus.ingest.schemas import ArtifactSource
from nexus.langgraph.timeline_merge import ingest_into_case

FIXTURE = Path(__file__).parent / "fixtures" / "d284_ossec_winevtlog.log"


def test_forwarded_windows_events_are_read_event_by_event(tmp_path):
    src = tmp_path / "logs" / "ossec-alerts.log"
    src.parent.mkdir()
    shutil.copy(FIXTURE, src)
    assert detect_format(src) == ArtifactSource.OSSEC
    case = tmp_path / "CASE-S06"
    (case / "audit").mkdir(parents=True)
    info = ingest_into_case(src, case)
    assert (info["source"], info["artifacts"]) == ("ossec", 2)
    rows = [json.loads(line) for line in (case / "ingest" / "artifacts.jsonl").read_text(encoding="utf-8").splitlines()]
    first = rows[0]
    assert first["timestamp"].startswith("2016-09-14T00:56:56")
    assert first["host"] == "ecoli.pwnd.biz" and first["user"] is None, "(no user) is no user"
    assert (first["raw"]["channel"], first["raw"]["event_id"], first["raw"]["type"]) == ("Security", 4663,
                                                                                          "AUDIT_SUCCESS")
    assert first["raw"]["provider"] == "Microsoft-Windows-Security-Auditing"
    assert "regedit.exe" in first["raw"]["message"] and first["description"].startswith("Security 4663 ")
    assert rows[1]["raw"]["event_id"] == 4657
