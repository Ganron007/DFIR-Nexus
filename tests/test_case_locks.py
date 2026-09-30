"""WO-14: one case lock at the persistence layer.

Real path: findings are staged through ``save_draft_finding`` (the flat
``CaseManager.record_finding`` writes ``findings.json``) and approved through
``_approve_finding`` (the portal's commit writer, HMAC ledger included), both
driven from real threads. The only stand-ins are where the ledger and
transparency logs land (``tmp_path``).
"""
from __future__ import annotations

import json
import threading

STAGERS = 20
AUDIT_ID = "mftecmd-lock-20260930-0001"


def _case(tmp_path):
    case_dir = tmp_path / "CASE-LOCK0001"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text(
        "case_id: CASE-LOCK0001\nname: lock concurrency\nstatus: open\n",
        encoding="utf-8",
    )
    (case_dir / "findings.json").write_text("[]", encoding="utf-8")
    audit = case_dir / "audit"
    audit.mkdir()
    (audit / "nexus.jsonl").write_text(
        json.dumps({
            "audit_id": AUDIT_ID, "tool": "mftecmd",
            "ts": "2026-09-30T09:00:00+00:00",
        }) + "\n",
        encoding="utf-8",
    )
    return case_dir


def _draft(i: int) -> dict:
    return {
        "title": f"concurrent finding {i}",
        "observation": f"row {i}",
        "interpretation": "staged by the WO-14 concurrency test",
        "confidence": "LOW",
        "confidence_justification": "single source; concurrency test",
        "audit_ids": [AUDIT_ID],
        "artifacts": [{"type": "parser", "audit_id": AUDIT_ID}],
    }


def test_concurrent_stage_and_approve_keep_every_update(tmp_path, monkeypatch):
    """20 writers staging + 20 approving: nothing lost, nothing half-written."""
    from nexus.case.locks import case_lock  # sanity: the module imports
    from nexus.modes.llm_desk import save_draft_finding

    assert case_lock(tmp_path / "x") is case_lock(tmp_path / "x")

    case_dir = _case(tmp_path)
    staged: list[str] = []
    errors: list[str] = []
    stage_lock = threading.Lock()

    def stager(i: int) -> None:
        try:
            result = save_draft_finding(case_dir, _draft(i))
            fid = str(result.get("finding_id") or result.get("id") or "")
            with stage_lock:
                if fid:
                    staged.append(fid)
                else:
                    errors.append(f"stage {i}: no id in {result}")
        except Exception as exc:  # noqa: BLE001
            with stage_lock:
                errors.append(f"stage {i}: {exc}")

    threads = [threading.Thread(target=stager, args=(i,)) for i in range(STAGERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert len(set(staged)) == STAGERS, staged
    entries = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    assert len(entries) == STAGERS, "a concurrent stage lost an append"

    monkeypatch.setattr("nexus.auth.VERIFICATION_DIR", tmp_path / "verification")
    monkeypatch.setattr("nexus.transparency.TRANSPARENCY_DIR", tmp_path / "transparency")

    from nexus.dashboard.app import _approve_finding

    approved: list[str] = []
    a_errors: list[str] = []

    def approver(fid: str) -> None:
        try:
            result = _approve_finding(case_dir, fid, "lock-examiner", "ab" * 32, "salt")
            with stage_lock:
                if result.get("status") == "APPROVED":
                    approved.append(fid)
                else:
                    a_errors.append(f"{fid}: {result}")
        except Exception as exc:  # noqa: BLE001
            with stage_lock:
                a_errors.append(f"{fid}: {exc}")

    threads = [threading.Thread(target=approver, args=(fid,)) for fid in staged]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not a_errors, a_errors
    assert len(set(approved)) == STAGERS
    entries = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    assert sum(1 for f in entries if f.get("status") == "APPROVED") == STAGERS, (
        "a concurrent approval lost another writer's update"
    )


def test_rebuild_timeline_write_is_atomic(tmp_path, monkeypatch):
    """The timeline write goes through a temp file + os.replace, never in place."""
    import os
    from pathlib import Path

    from nexus.langgraph.timeline_merge import rebuild_case_timeline

    case_dir = tmp_path / "CASE-LOCK0002"
    case_dir.mkdir()
    (case_dir / "timeline.json").write_text("[]", encoding="utf-8")

    replaced: list[tuple[str, str]] = []
    real_replace = os.replace

    def spy(src, dst, *args, **kwargs):
        replaced.append((str(src), str(dst)))
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", spy)
    events = rebuild_case_timeline(case_dir, hits=[])
    assert events == []
    assert any(
        Path(dst).name == "timeline.json" and str(src).endswith(".tmp")
        for src, dst in replaced
    ), f"timeline.json must be replaced from a temp file, saw {replaced[-3:]}"
    assert json.loads((case_dir / "timeline.json").read_text(encoding="utf-8")) == []
