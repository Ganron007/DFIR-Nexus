"""An audit id names one call, whichever process writes it (2026-10-14).

CASE-C5B04D31's log held 16 ids used twice: an ``es_search`` from the pipeline process and a
``record_finding`` from its stdio MCP child each got the same id, so a finding citing that id cited
two different calls. Each process kept its own counter, and the counter was resumed from the active
case's log while the row went to the case the call named.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from datetime import UTC, datetime

import pytest

from nexus.audit import AuditWriter
from nexus.config import settings


def _ids(path):
    return [json.loads(line)["audit_id"]
            for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_processes_writing_one_log_never_mint_the_same_id(tmp_path):
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    script = textwrap.dedent("""
        import sys
        from nexus.audit import AuditWriter
        writer = AuditWriter("nexus", audit_dir=sys.argv[1])
        for _ in range(25):
            assert writer.log("t", params={"x": 1})
    """)
    procs = [subprocess.Popen([sys.executable, "-c", script, str(audit_dir)],
                              env={**os.environ, "NEXUS_EXAMINER": "tester"})
             for _ in range(3)]
    assert [p.wait(timeout=120) for p in procs] == [0, 0, 0]
    ids = _ids(audit_dir / "nexus.jsonl")
    assert len(ids) == 75
    assert len(set(ids)) == 75, "two processes minted the same audit id"


@pytest.fixture()
def named_case(tmp_path, monkeypatch):
    cases_root = tmp_path / "cases"
    (cases_root / "CASE-A" / "audit").mkdir(parents=True)
    (cases_root / "CASE-B").mkdir(parents=True)
    pointer = tmp_path / "active_case"
    pointer.write_text("CASE-B", encoding="utf-8")  # another case is active
    monkeypatch.setattr(settings, "cases_root", cases_root)
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(pointer))
    monkeypatch.setenv("NEXUS_EXAMINER", "tester")
    for name in ("NEXUS_CASE_DIR", "NEXUS_AUDIT_DIR", "NEXUS_ACTIVE_CASE"):
        monkeypatch.delenv(name, raising=False)
    return cases_root / "CASE-A"


def test_the_sequence_continues_from_the_named_cases_own_log(named_case):
    today = datetime.now(UTC).strftime("%Y%m%d")
    log = named_case / "audit" / "nexus.jsonl"
    # Another process already wrote seven calls into CASE-A today.
    log.write_text("".join(json.dumps({"tool": "es_search", "audit_id": f"nexus-tester-{today}-{n:03d}"}) + "\n"
                           for n in range(1, 8)), encoding="utf-8")
    aid = AuditWriter("nexus").log("record_finding", params={"case_id": "CASE-A"})
    assert aid == f"nexus-tester-{today}-008"
    assert len(set(_ids(log))) == 8


def test_a_row_another_process_appends_is_seen_before_the_next_id(named_case):
    today = datetime.now(UTC).strftime("%Y%m%d")
    log = named_case / "audit" / "nexus.jsonl"
    writer = AuditWriter("nexus")
    first = writer.log("es_search", params={"case_id": "CASE-A"})
    # The stdio child appends its own call between two of ours.
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps({"tool": "record_finding", "audit_id": f"nexus-tester-{today}-002"}) + "\n")
    second = writer.log("es_search", params={"case_id": "CASE-A"})
    assert first == f"nexus-tester-{today}-001"
    assert second == f"nexus-tester-{today}-003"
