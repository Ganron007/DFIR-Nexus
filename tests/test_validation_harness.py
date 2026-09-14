"""WP 9.6 — validation harness (known-answer recall/precision)."""
from __future__ import annotations

from pathlib import Path

import yaml


def _mkcase(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-V1"
    ext = case / "extractions"
    ext.mkdir(parents=True)
    (ext / "hayabusa_alerts.csv").write_text(
        "Timestamp,Computer,Channel,EventID,Level,RuleTitle,OtherDetails\n"
        "2026-08-10 14:32:01,WS01,Sec,4688,critical,LSASS Memory Access,procdump -ma lsass.exe\n",
        encoding="utf-8",
    )
    (case / "CASE.yaml").write_text("question: was lsass dumped\n", encoding="utf-8")
    return case


def _key(**expected) -> dict:
    return {"case": "v1", "expected": expected}


def test_validation_recovers_known_answer(tmp_path):
    from nexus.validation.harness import run_validation

    rep = run_validation(_mkcase(tmp_path), _key(
        families=["hayabusa"], techniques=["T1003.001"], artifacts=["lsass"], entities=[]))
    dims = {d["dimension"]: d for d in rep["dimensions"]}
    assert "T1003.001" in dims["techniques"]["found"]
    assert dims["techniques"]["missing"] == []
    assert dims["families"]["found"] == ["hayabusa"]
    assert dims["artifacts"]["found"] == ["lsass"]
    assert rep["recall"] == 1.0
    assert rep["overall"]["missing"] == []


def test_validation_reports_missing(tmp_path):
    from nexus.validation.harness import run_validation

    rep = run_validation(_mkcase(tmp_path), _key(
        families=["hayabusa"], techniques=["T1003.001"],
        artifacts=["nonexistent-artifact-xyz"], entities=[]))
    dims = {d["dimension"]: d for d in rep["dimensions"]}
    assert "nonexistent-artifact-xyz" in dims["artifacts"]["missing"]
    assert rep["recall"] < 1.0


def test_load_answer_key_from_yaml(tmp_path):
    from nexus.validation.harness import load_answer_key, run_validation

    case = _mkcase(tmp_path)
    key_path = case / "answer_key.yaml"
    key_path.write_text(yaml.safe_dump(_key(families=["hayabusa"], techniques=["T1003.001"])),
                        encoding="utf-8")
    key = load_answer_key(key_path)
    assert key["expected"]["techniques"] == ["T1003.001"]
    rep = run_validation(case, key_path)
    assert rep["case"] == "v1"
    assert "recall" in rep and "precision" in rep and "f1" in rep
