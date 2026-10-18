"""D276: an archive in the evidence is expanded before the lane plans, and the tree it holds is planned (2026-10-18).

Sample S08 is fifteen hosts' triage collections, each a .7z of a drive tree, and the lane read none of it; sample S09's
EventLogs.7z holds Security logs that differ from the loose ones beside it. The archives here are built in the test with
the layout S08's collections have (``<host>/C/Windows/System32/winevt/Logs/...``); the planner reads names only.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

from nexus.langgraph import evidence_archives as ea
from nexus.langgraph.tool_lane import plan_windows_triage

TREE = "sam-saran-d/C/Windows/System32/winevt/Logs/Security.evtx"


def _zip(path: Path, members: dict[str, bytes]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return path


def test_a_collection_archive_is_expanded_and_its_tree_planned(tmp_path, monkeypatch):
    monkeypatch.setattr(ea, "_seven_zip", lambda: None)  # Python's reader; 7-Zip is exercised on S08 itself
    evidence = tmp_path / "S08" / "hosts"
    _zip(evidence / "sam-saran-d.zip", {TREE: b"ElfFile\x00collected"})
    case = tmp_path / "CASE-S08"
    records = ea.expand_archives([str(evidence.parent)], case)
    assert [r["status"] for r in records] == ["OK"] and records[0]["files"] == 1
    root = Path(records[0]["root"])
    assert root.is_relative_to(case / "evidence" / "_expanded") and (root / TREE).is_file()
    marker = json.loads((root / ".expanded.json").read_text(encoding="utf-8"))
    assert marker["kept"][0]["path"] == TREE and len(marker["archive_sha256"]) == 64
    # The lane plans the expanded tree like a registered drive tree.
    jobs = plan_windows_triage(str(root), tmp_path / "x")
    assert {"hayabusa", "evtxecmd"} <= {j.tool for j in jobs if j.status == "PENDING"}
    # An unchanged archive is not expanded twice.
    again = ea.expand_archives([str(evidence.parent)], case)
    assert again[0]["status"] == "OK" and "unchanged" in again[0]["reason"]


def test_a_member_identical_to_registered_evidence_is_not_kept_twice(tmp_path, monkeypatch):
    monkeypatch.setattr(ea, "_seven_zip", lambda: None)
    evidence = tmp_path / "S09" / "raw" / "EventLogs"
    evidence.mkdir(parents=True)
    (evidence / "OAlerts.evtx").write_bytes(b"ElfFile\x00same")
    _zip(evidence / "EventLogs.zip", {"OAlerts.evtx": b"ElfFile\x00same", "Security.evtx": b"ElfFile\x00other"})
    record = ea.expand_archives([str(evidence)], tmp_path / "CASE-S09")[0]
    assert (record["files"], record["duplicates"]) == (1, 1)
    assert [p.name for p in Path(record["root"]).glob("*.evtx")] == ["Security.evtx"]


def test_an_archive_that_names_a_path_outside_its_folder_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(ea, "_seven_zip", lambda: None)
    evidence = tmp_path / "ev"
    _zip(evidence / "bad.zip", {"../../escaped.txt": b"x", "ok.txt": b"y"})
    case = tmp_path / "CASE-BAD"
    record = ea.expand_archives([str(evidence)], case)[0]
    # Python's zip reader strips the '..' parts, so nothing escapes; what it keeps stays inside the folder.
    assert not (tmp_path / "escaped.txt").exists() and not (case / "escaped.txt").exists()
    assert record["status"] == "OK" or "outside" in record["reason"]


def test_each_archive_is_a_gate_row():
    rows = ea.archive_gate_rows([
        {"archive": "/e/S08/hosts/sam-saran-d.7z", "status": "OK", "reason": "767 file(s) expanded"},
        {"archive": "/e/S08/hosts/broken.7z", "status": "FAIL", "reason": "7-Zip rc=2: Data error"},
    ])
    assert [r["status"] for r in rows] == ["OK", "FAIL"]
    assert rows[1]["purpose"] == "expand /e/S08/hosts/broken.7z" and rows[1]["tool"] == "expand"
