"""WO-A6 (WP 10.20 first slice): the spoliation harness.

Runs against the real registered tool surface (in-process ``create_server()``)
on a fixture case with registered evidence. Any refusal the harness cannot
prove is a defect, never a skipped test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture()
def server():
    """A real in-process server per test.

    Function-scoped on purpose: the conftest isolation fixture (cases root,
    RAG index dir, ES, password store) is function-scoped, so a module-scoped
    server would be created BEFORE the redirects and touch the real RAG store
    — exactly what the WO-5 tripwire exists to catch.
    """
    from nexus.app import create_server

    return create_server()


@pytest.fixture()
def case_dir(tmp_path, monkeypatch) -> Path:
    from nexus.analysis.spoliation import build_fixture_case

    monkeypatch.setenv("NEXUS_EXAMINER", "spoliation_selftest")
    return build_fixture_case(tmp_path)


def test_every_destructive_payload_is_refused(server, case_dir):
    """Windows-lane, case-store and SIFT-validator probes all refuse."""
    from nexus.analysis.spoliation import (
        _case_store_probes,
        _sift_validator_probes,
        _windows_probes,
    )
    from nexus.app import in_process_tools

    tools = in_process_tools(server)
    probes = (
        _windows_probes(tools, next((case_dir / "evidence").glob("*")))
        + _case_store_probes(tools)
        + _sift_validator_probes()
    )
    assert probes, "the harness ran no probes"
    unrefused = [
        p for p in probes
        if p.get("expect", "refused") == "refused" and not p["refused"]
    ]
    assert not unrefused, f"payloads not refused: {unrefused}"
    # the one acceptance probe (SleuthKit -o exception for fls) must survive
    accepted = [p for p in probes if p.get("expect") == "accepted"]
    assert accepted and all(not p["refused"] for p in accepted)


def test_no_tool_is_destructive_outside_the_reviewed_list(server):
    from nexus.analysis.spoliation import REVIEWED_VERB_HITS, _scan_tools
    from nexus.app import in_process_tools

    scan = _scan_tools(in_process_tools(server))
    assert scan["hits"] >= len(REVIEWED_VERB_HITS) or scan["hits"] > 0
    assert not scan["unreviewed"], (
        "new destructive-verb hits need an operator review entry: "
        f"{scan['unreviewed']}"
    )


def test_full_selftest_passes_and_evidence_hashes_unchanged(server, case_dir):
    from nexus.analysis.spoliation import run_spoliation_selftest

    report = run_spoliation_selftest(case_dir, server=server)
    assert report["evidence_hashes_unchanged"] is True, report
    assert report["evidence_files"] >= 2
    assert report["tool_scan"]["unreviewed"] == []
    assert report["audit_tamper"]["ok"] is True, report["audit_tamper"]
    assert report["ok"] is True, [
        p for p in report["probes"] if not p["refused"]
    ]


def test_audit_tamper_verifier_names_the_exact_record(case_dir):
    """The verifier names the tampered record — and only it — in a copy."""
    import shutil
    import tempfile

    from nexus.analysis.spoliation import verify_case_audit_jsonl
    from nexus.audit import AuditWriter

    writer = AuditWriter("spoliation-test", audit_dir=case_dir / "audit")
    aid_a = writer.log(tool="t1", params={}, result_summary={})
    aid_b = writer.log(tool="t2", params={}, result_summary={})
    assert aid_a and aid_b

    # the untouched log verifies clean
    ok, named = verify_case_audit_jsonl(case_dir / "audit" / "spoliation-test.jsonl")
    assert ok and named == []

    with tempfile.TemporaryDirectory() as td:
        copy = Path(td) / "audit"
        shutil.copytree(case_dir / "audit", copy)
        target = copy / "spoliation-test.jsonl"
        rows = [
            json.loads(l)
            for l in target.read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]
        for row in rows:
            if row.get("audit_id") == aid_b:
                row["tool"] = "forged"
                break
        target.write_text(
            "\n".join(json.dumps(r, default=str) for r in rows) + "\n",
            encoding="utf-8",
        )
        ok, named = verify_case_audit_jsonl(target)
    assert not ok
    assert named == [aid_b]


def test_cli_selftest_spoliation():
    """nexus selftest spoliation runs the harness end to end and exits 0."""
    from typer.testing import CliRunner

    from nexus.cli.main import app

    runner = CliRunner()
    result = runner.invoke(app, ["selftest", "spoliation"])
    assert result.exit_code == 0, result.output
    assert "PASS" in result.output
