"""D1 drafts from APPROVED findings — not N5 input."""

import json
from pathlib import Path

from nexus.detection.draft_from_findings import draft_from_approved


def test_drafts_from_approved_only(tmp_path: Path):
    (tmp_path / "findings.json").write_text(
        """[
          {"id": "F-old", "status": "DRAFT", "title": "mimikatz noise"},
          {"id": "F-new", "status": "APPROVED", "title": "Recycle PST and sdelete.exe",
           "observation": "sdelete.exe wiped backup.pst"}
        ]""",
        encoding="utf-8",
    )
    meta = draft_from_approved(tmp_path)
    dest = Path(meta["dir"])
    sigma = (dest / "draft.sigma.yml").read_text(encoding="utf-8")
    kql = (dest / "draft.kql").read_text(encoding="utf-8")
    rules = (dest / "draft.suricata.rules").read_text(encoding="utf-8")
    assert "sdelete" in sigma.lower()
    assert "sdelete" in kql.lower()
    assert "SIEM team" in (dest / "README.md").read_text(encoding="utf-8")
    assert "mimikatz" not in sigma.lower()
    assert "NEXUS-DRAFT" in rules or "INSUFFICIENT" in rules


def test_draft_respects_finding_ids(tmp_path: Path):
    (tmp_path / "findings.json").write_text(
        """[
          {"id": "F-old", "status": "APPROVED", "title": "AcroRd32.exe routine"},
          {"id": "F-new", "status": "APPROVED", "title": "sdelete.exe wiped backup.pst"}
        ]""",
        encoding="utf-8",
    )
    meta = draft_from_approved(tmp_path, finding_ids=["F-new"])
    sigma = Path(meta["dir"], "draft.sigma.yml").read_text(encoding="utf-8")
    assert "sdelete" in sigma.lower()
    assert "acrord" not in sigma.lower()
    assert meta["approved"] == 1


def test_draft_ignores_extraction_stdout_paths(tmp_path: Path):
    stdout = r"C:\Users\Ganro\.nexus\cases\INC-x\extractions\pecmd\20260813_pecmd_stdout.txt"
    payload = [{
        "id": "F-stub",
        "status": "APPROVED",
        "title": "sdelete wipe / secure-delete on host",
        "observation": f"N4 hit sdelete.exe. Also listed {stdout}",
    }]
    (tmp_path / "findings.json").write_text(json.dumps(payload), encoding="utf-8")
    meta = draft_from_approved(tmp_path)
    needles = " ".join(meta["needles"]).lower()
    assert "sdelete" in needles
    assert "_stdout.txt" not in needles
    assert ".nexus" not in needles
    assert "extractions" not in needles
