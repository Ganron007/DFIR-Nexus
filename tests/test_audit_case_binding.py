"""A call's audit row belongs to the case the call names (2026-10-11).

CASE-C5B04D31's Windows calls were written into SC1's audit log: the writer took its folder from the active-case
pointer, which named SC1 at the time, and not from the case the call named (442 rows). The rows are now written to
the named case, and a row names its case.
"""

from __future__ import annotations

import json

import pytest

from nexus.audit import AuditWriter
from nexus.config import settings


@pytest.fixture()
def cases(tmp_path, monkeypatch):
    cases_root = tmp_path / "cases"
    for name in ("CASE-A", "CASE-B"):
        (cases_root / name).mkdir(parents=True)
    pointer = tmp_path / "active_case"
    pointer.write_text("CASE-B", encoding="utf-8")  # the active case is B
    monkeypatch.setattr(settings, "cases_root", cases_root)
    monkeypatch.setattr(settings, "audit_dir", tmp_path / "process-audit")
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(pointer))
    monkeypatch.setenv("NEXUS_EXAMINER", "tester")
    monkeypatch.delenv("NEXUS_CASE_DIR", raising=False)
    monkeypatch.delenv("NEXUS_AUDIT_DIR", raising=False)
    monkeypatch.delenv("NEXUS_ACTIVE_CASE", raising=False)
    return cases_root


def _rows(path):
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_a_call_naming_case_a_is_audited_in_case_a_while_b_is_active(cases):
    writer = AuditWriter("nexus-windows")
    audit_id = writer.log("run_windows_command", params={"case_id": "CASE-A", "command": ["x"]})
    assert audit_id
    assert [row["case_id"] for row in _rows(cases / "CASE-A" / "audit" / "nexus-windows.jsonl")] == ["CASE-A"]
    assert _rows(cases / "CASE-B" / "audit" / "nexus-windows.jsonl") == []


def test_a_call_naming_no_case_keeps_the_active_case_binding(cases):
    writer = AuditWriter("nexus-windows")
    writer.log("tool_without_case", params={"x": 1})
    assert len(_rows(cases / "CASE-B" / "audit" / "nexus-windows.jsonl")) == 1
    assert _rows(cases / "CASE-A" / "audit" / "nexus-windows.jsonl") == []


def test_a_call_naming_a_missing_case_is_never_written_into_another_case(cases, tmp_path):
    writer = AuditWriter("nexus-windows")
    writer.log("run_windows_command", params={"case_id": "CASE-MISSING"})
    assert _rows(cases / "CASE-B" / "audit" / "nexus-windows.jsonl") == []
    assert _rows(cases / "CASE-A" / "audit" / "nexus-windows.jsonl") == []
    assert len(_rows(tmp_path / "process-audit" / "nexus-windows.jsonl")) == 1


def test_an_invalid_case_name_in_params_is_not_a_named_case(cases):
    writer = AuditWriter("nexus-windows")
    writer.log("run_windows_command", params={"case_id": "../CASE-A"})
    assert _rows(cases / "CASE-A" / "audit" / "nexus-windows.jsonl") == []
    assert len(_rows(cases / "CASE-B" / "audit" / "nexus-windows.jsonl")) == 1  # the no-case rule applies


def test_an_explicit_case_dir_still_binds_calls_that_name_no_case(cases, monkeypatch, tmp_path):
    bound = cases / "CASE-A"
    monkeypatch.setenv("NEXUS_CASE_DIR", str(bound))
    AuditWriter("nexus-windows").log("tool_without_case", params={"x": 1})
    assert len(_rows(bound / "audit" / "nexus-windows.jsonl")) == 1
    assert _rows(cases / "CASE-B" / "audit" / "nexus-windows.jsonl") == []
