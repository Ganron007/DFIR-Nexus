"""A1 (WP 10.3): answer keys + the findings dimension.

The point of these tests is honesty: a key that silently drops files inflates
recall, and a findings dimension that cannot attribute a finding to a mode
cannot answer GATE-H.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.validation.answer_keys import (
    AnswerKey,
    evtx_to_mitre_key,
    self_describing_key,
)
from nexus.validation.harness import (
    case_findings,
    case_mode,
    finding_mode,
    findings_dimension,
)


def _evtx_tree(root: Path) -> Path:
    key_root = root / "EVTX-to-MITRE-Attack"
    power = key_root / "TA0002-Execution" / "T1059.001-PowerShell"
    parent = key_root / "TA0002-Execution" / "T1059-PowerShell"
    cmd = key_root / "TA0003-Persistence" / "T1053.005-Scheduled Task"
    for directory in (power, parent, cmd):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{directory.name.split('-')[0]}-sample.evtx").write_bytes(
            b"EVTX\x00fixture"
        )
    (key_root / "Antivirus").mkdir(parents=True, exist_ok=True)
    (key_root / "Antivirus" / "sample.evtx").write_bytes(b"EVTX\x00unlabelled")
    loose = key_root / "EVTX_full_APT_attack_steps"
    loose.mkdir(parents=True, exist_ok=True)
    (loose / "chain.evtx").write_bytes(b"EVTX\x00loose")
    return key_root


def test_evtx_key_splits_labelled_from_unlabelled(tmp_path):
    key_root = _evtx_tree(tmp_path)
    key = evtx_to_mitre_key(key_root)

    # sub-techniques stay distinct from their parents - folding them inflates
    # recall and hides the depth an examiner asked about
    assert "T1059.001" in key.techniques()
    assert "T1059" in key.techniques()
    assert len(key.techniques()) == 3

    labelled = {e.technique for e in key.entries}
    assert labelled == {"T1059.001", "T1059", "T1053.005"}
    assert {e.tactic for e in key.entries} == {"TA0002", "TA0003"}
    assert all(len(e.sha256) == 64 for e in key.entries)

    excluded = {x.file for x in key.excluded}
    assert "Antivirus/sample.evtx" in excluded
    assert "EVTX_full_APT_attack_steps/chain.evtx" in excluded
    assert all("no technique label" in x.reason for x in key.excluded)
    # and the exclusions are reported, not dropped
    payload = key.to_dict()
    assert payload["counts"]["excluded"] == 2
    assert payload["counts"]["entries"] == 3


def test_self_describing_key_reads_prefetch_and_tasks(tmp_path):
    root = tmp_path / "evidence"
    prefetch = root / "prefetch"
    prefetch.mkdir(parents=True)
    (prefetch / "POWERSHELL.EXE-3A1B2C3D-9.pf").write_bytes(b"pf")
    (prefetch / "RUNDLL32.EXE-12.pf").write_bytes(b"pf")
    (prefetch / "Prefetch_Output.csv").write_text("Filename,Hash\n", encoding="utf-8")
    (prefetch / "notes.md").write_text("collector notes", encoding="utf-8")

    tasks = root / "tasks"
    tasks.mkdir(parents=True)
    (tasks / "scheduled.xml").write_text(
        """<?xml version="1.0" encoding="utf-8"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <RegistrationInfo><URI>\\Updater</URI></RegistrationInfo>
          <Actions><Exec><Command>C:\\Windows\\System32\\rundll32.exe</Command></Exec></Actions>
        </Task>""",
        encoding="utf-8",
    )
    (root / "SOFTWARE").write_bytes(b"regf")

    key = self_describing_key(root)
    assert {"POWERSHELL.EXE", "RUNDLL32.EXE"} <= key.entities()
    assert "task:\\Updater" in key.entities()
    assert "command:C:\\Windows\\System32\\rundll32.exe" in key.entities()
    # the hive is reported as an exclusion instead of vanishing from the numbers
    assert any("hive" in x.reason for x in key.excluded)


def _case(root: Path, *, mode: int = 3, techniques=("T1059.001",)) -> Path:
    case = root / "CASE-ACCTEST01"
    case.mkdir(parents=True, exist_ok=True)
    (case / "CASE.yaml").write_text(
        f"case_id: CASE-ACCTEST01\ninvestigation_mode: {mode}\n", encoding="utf-8"
    )
    findings = [
        {
            "id": "F1",
            "status": "APPROVED",
            "technique_ids": list(techniques),
            "entity_mentions": [{"value": "POWERSHELL.EXE"}],
        },
        {"id": "F2", "status": "DRAFT", "technique_ids": ["T9999"]},
    ]
    (case / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    return case


def test_findings_dimension_scores_staged_techniques_per_mode(tmp_path):
    case = _case(tmp_path)
    from nexus.validation.answer_keys import KeyEntry

    # a small key with two expected techniques
    key = AnswerKey(kind="fixture", root=".")
    key.entries = [
        KeyEntry(file="a.evtx", technique="T1059.001"),
        KeyEntry(file="b.evtx", technique="T1053.005"),
    ]

    scored = findings_dimension(case, key, dimension="techniques", mode=3)
    assert scored["findings_scored"] == 2  # APPROVED + DRAFT both count
    assert scored["found"] == ["T1059.001", "T9999"]
    assert scored["missed"] == ["T1053.005"]
    assert scored["extra"] == ["T9999"]
    assert scored["recall"] == 0.5
    assert scored["precision"] == 0.5
    assert scored["f1"] == 0.5
    assert scored["mode"] == 3

    # the same case scored for a mode that produced nothing
    assert findings_dimension(case, key, dimension="techniques", mode=1)["findings_scored"] == 0


def test_findings_dimension_reads_the_entity_dimension(tmp_path):
    case = _case(tmp_path)
    from nexus.validation.answer_keys import KeyEntry

    key = AnswerKey(kind="fixture", root=".")
    key.entries = [KeyEntry(file="a.pf", entity="POWERSHELL.EXE")]
    scored = findings_dimension(case, key, dimension="entities", mode="all")
    assert scored["found"] == ["POWERSHELL.EXE"]
    assert scored["recall"] == 1.0
    assert scored["precision"] == 1.0


def test_case_mode_and_finding_provenance(tmp_path):
    case = _case(tmp_path, mode=2)
    assert case_mode(case) == 2
    assert case_findings(case)[0]["id"] == "F1"

    # after B2 a finding's own provenance wins over the case's stored mode
    finding = {"provenance": {"mode": 3}}
    assert finding_mode(finding, 2) == 3
    assert finding_mode({}, 2) == 2
    assert finding_mode({}, None) is None
    assert case_mode(tmp_path / "nope") is None
    assert case_findings(tmp_path / "nope") == []


def test_techniques_are_read_from_every_field_the_product_writes():
    """A field-name mismatch must not invent a miss.

    The staging path writes `attack_ids`; `technique_ids` and `mitre_techniques`
    are the other names in use. Reading only one of them scored a correctly
    tagged finding set as recall 0 - measured on the first real K-run, where 11
    findings carried specific labels (`T1543.003`, `T1003.001`, ...) under
    `attack_ids` while the scorer looked at `technique_ids` and saw nothing.
    """
    from nexus.validation.harness import finding_techniques

    assert finding_techniques({"attack_ids": ["T1059.001"]}) == {"T1059.001"}
    assert finding_techniques({"technique_ids": ["t1053.005"]}) == {"T1053.005"}
    assert finding_techniques({"mitre_techniques": ["T1003.001"]}) == {"T1003.001"}
    # The union, deduped and upper-cased, with blanks ignored.
    assert finding_techniques({
        "attack_ids": ["T1059.001", " "],
        "technique_ids": ["T1059.001", "T1140"],
        "mitre_techniques": [],
    }) == {"T1059.001", "T1140"}
    assert finding_techniques({}) == set()