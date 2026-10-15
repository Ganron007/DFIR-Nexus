"""D175: a second full-run POST while one is live gets the run record, whenever it lands.

`test_api_mode1_full_run` failed in two full suite runs (2026-10-14, 2026-10-16): the second POST got
the generic busy body with no `status`. The handler read the full-run record to name its own run, the
first POST's worker wrote a new running record, and the shared busy guard read it a moment later as
another run. The window is reproduced here: a live worker, and a record that appears between reads.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch


class _LiveThread:
    def is_alive(self) -> bool:
        return True


def _case(tmp_path: Path) -> Path:
    case_dir = tmp_path / "INC-race-0001"
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("name: race\nstatus: open\nintake:\n  question: \"test?\"\n")
    (case_dir / "audit").mkdir()
    (case_dir / "extractions").mkdir()
    (case_dir / "findings.json").write_text("[]")
    return case_dir


def test_a_second_post_gets_the_running_record_while_the_first_run_writes_it(tmp_path):
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard import app as portal

    case_dir = _case(tmp_path)
    running = {"run_id": "M1-1760573000", "status": "running", "needles_total": 7, "needles_done": 2}
    reads: list[int] = []

    def record(_case_dir):
        reads.append(1)
        return None if len(reads) == 1 else dict(running)  # written between the first read and the next

    key = portal._case_key(case_dir)
    with portal._mode1_run_lock:
        portal._mode1_run_threads[key] = _LiveThread()
    try:
        with patch.object(portal, "_get_case_dir", return_value=case_dir), \
             patch.object(portal, "_mode1_run_record", side_effect=record):
            client = TestClient(Starlette(routes=portal.create_dashboard()))
            resp = client.post("/portal/api/mode1/full-run", json={})
    finally:
        with portal._mode1_run_lock:
            portal._mode1_run_threads.pop(key, None)
    assert resp.status_code == 409
    body = resp.json()
    assert body["status"] == "running" and body["run_id"] == "M1-1760573000", body
    assert body["needles_total"] == 7
