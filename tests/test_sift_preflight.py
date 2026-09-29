"""SIFT preflight: only a SIFT-SELECTED case can be refused, and only for SIFT.

Operator policy (2026-09-29): the audited skip exists for the one situation
where processing is impossible - SIFT selected and the host unreachable.
Nothing else is ever refused or skipped; Windows evidence and unselected cases
are untouched.
"""
from __future__ import annotations

import pathlib

from nexus.case.sift_preflight import sift_preflight_message, sift_required


def _write_case(tmp_path: pathlib.Path, sift_required_value: str | None) -> pathlib.Path:
    case = tmp_path / "CASE-T"
    case.mkdir()
    lines = ["case_id: CASE-T"]
    if sift_required_value is not None:
        lines.append("intake:")
        lines.append(f"  sift_required: '{sift_required_value}'")
    (case / "CASE.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return case


def test_not_selected_is_never_probed_or_refused(tmp_path, monkeypatch):
    case = _write_case(tmp_path, None)

    def _boom():
        raise AssertionError("sift_reachable must not be called for unselected cases")

    monkeypatch.setattr("nexus.case.sift_sync.sift_reachable", _boom)
    assert sift_required(case) is False
    assert sift_preflight_message(case) == ""


def test_selected_and_unreachable_refuses_with_all_recoveries(tmp_path, monkeypatch):
    case = _write_case(tmp_path, "true")
    monkeypatch.setattr("nexus.case.sift_sync.sift_reachable", lambda: (False, "timed out"))

    assert sift_required(case) is True
    msg = sift_preflight_message(case)
    assert "SIFT analysis is required" in msg
    assert "nexus sift disable" in msg
    assert "nexus lane skip" in msg


def test_selected_and_reachable_passes(tmp_path, monkeypatch):
    case = _write_case(tmp_path, "True")
    monkeypatch.setattr("nexus.case.sift_sync.sift_reachable", lambda: (True, "ok"))
    assert sift_preflight_message(case) == ""


def test_probe_exception_reads_as_unreachable(tmp_path, monkeypatch):
    case = _write_case(tmp_path, "yes")

    def _raise():
        raise OSError("no route")

    monkeypatch.setattr("nexus.case.sift_sync.sift_reachable", _raise)
    assert "unreachable" in sift_preflight_message(case)
