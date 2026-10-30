"""TA-5.4 (i), D123: Windows Suricata runs the installed rules minus the recorded disable list, and its run is a job.

The lane's local Suricata ran on T13-T16 and its eve.json rows were indexed, but the run lived in the step log only:
the gate's one `suricata` row was the SIFT host's opt-in SKIP. Suricata itself dropped sid 2065690 (`file.magic`, no
libmagic in this build), which also made `suricata -T` fail; the operator approved disabling that sid alone, through a
lane-owned rule set with a recorded disable list (2026-10-13). And fast.log, the alerts eve.json holds, was indexed too.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from nexus.langgraph import network_lane as lane

LOG_LINE = ("[1 - Suricata-Main] 2026-10-30 06:03:52 Info: detect: 1 rule files processed. 41662 rules successfully "
            "loaded, 0 rules failed, 0 rules skipped\n")
DISABLED = ('alert tcp any any -> $HOME_NET any (msg:"ET EXPLOIT 7-Zip"; flow:established,to_client; file.magic; '
            'content:"7-zip archive"; sid:2065690; rev:1;)')
KEPT = 'alert ip any any -> any any (msg:"kept"; sid:1000001; rev:1;)'


def _install(tmp_path: Path) -> Path:
    install = tmp_path / "Suricata"
    (install / "rules").mkdir(parents=True)
    (install / "suricata.exe").write_bytes(b"")
    (install / "suricata.yaml").write_text(
        f"%YAML 1.1\n---\ndefault-rule-path: {install / 'rules'}\nrule-files:\n  - a.rules\n  - b.rules\n",
        encoding="utf-8")
    (install / "rules" / "a.rules").write_text(KEPT + "\n", encoding="utf-8")
    (install / "rules" / "b.rules").write_text(DISABLED + "\n", encoding="utf-8")
    return install / "suricata.exe"


def test_the_effective_rule_set_comments_out_exactly_the_recorded_sids(tmp_path):
    binary = _install(tmp_path)
    rules = lane.suricata_effective_rules(binary)
    text = Path(rules["path"]).read_text(encoding="utf-8")
    assert rules["disabled"] == [2065690] and rules["not_in_rules"] == [] and rules["rule_files"] == 2
    assert KEPT + "\n" in text
    assert "# DFIR-Nexus disabled (operator 2026-10-13 (D123)): " + DISABLED in text
    assert lane.suricata_effective_rules(binary) == rules   # built once per installed-rules digest, then reused


def test_the_rule_load_line_is_read_from_suricatas_own_log(tmp_path):
    log = tmp_path / "suricata.log"
    log.write_text(LOG_LINE, encoding="utf-8")
    assert lane.suricata_rules_loaded(log) == (41662, 0)
    assert lane.suricata_rules_loaded(tmp_path / "absent.log") is None


def test_the_lane_runs_suricata_with_the_effective_set_and_records_the_job(tmp_path, monkeypatch):
    binary = _install(tmp_path)
    monkeypatch.setattr(lane, "resolve_local_tool", lambda name: str(binary) if name == "suricata" else None)
    seen: list[list[str]] = []

    def run(cmd, **_kwargs):
        seen.append(list(cmd))
        out = Path(cmd[cmd.index("-l") + 1])
        (out / "suricata.log").write_text(LOG_LINE, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(lane.subprocess, "run", run)
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1")
    result = lane.enrich_local_network(pcap, tmp_path / "CASE-SUR", tmp_path / "CASE-SUR" / "extractions")
    (cmd,) = [c for c in seen if c[0] == str(binary)]
    assert cmd[cmd.index("-S") + 1] == lane.suricata_effective_rules(binary)["path"]
    assert "outputs.0.fast.enabled=no" in cmd
    (row,) = [j for j in result["jobs"] if j["tool"] == "suricata"]
    assert row["status"] == "OK" and row["reason"] == "41662 rules loaded, 0 failed; disabled by decision: sid 2065690"


def test_the_gate_keeps_a_local_tool_job_through_the_index_pass(tmp_path):
    """A capture's local Suricata row is an importer-pass job, kept when the gate is re-derived (D491)."""
    import json

    from nexus.langgraph.lane_gate import (
        read_lane_gate,
        reconcile_after_index,
        record_import_results,
        write_lane_gate,
    )

    case = tmp_path / "CASE-GATESUR"
    run = case / "runs" / "RUN-20261030T000000Z-tools-sur"
    extractions = run / "extractions"
    (extractions / "suricata").mkdir(parents=True)
    (extractions / "suricata" / "eve.json").write_text("{}\n", encoding="utf-8")
    (case / "active_runs.json").write_text(json.dumps({"tools": run.name}), encoding="utf-8")
    (run / "manifest.json").write_text(json.dumps({"status": "completed"}), encoding="utf-8")
    (extractions / "_tool_lane_ledger.json").write_text("[]", encoding="utf-8")
    rows = [{"artifact": "Scheduled Tasks", "status": "PRESENT_NO_PARSER", "tools": "-", "hits": 1, "reason": ""}]
    (extractions / "_artifact_completeness.json").write_text(json.dumps(rows), encoding="utf-8")
    (case / "evidence.json").write_text("[]", encoding="utf-8")
    write_lane_gate(case, run.name, [], registered_evidence=[], completeness=rows)
    record_import_results(case, [{"tool": "suricata", "purpose": "suricata on capture.pcap (local)", "family": "suricata",
                                  "status": "OK", "reason": "41662 rules loaded, 0 failed"}])
    reconcile_after_index(case, {}, run_id=run.name)
    assert [(j["state"], j["reason"]) for j in read_lane_gate(case)["jobs"] if j["tool"] == "suricata"] == [
        ("processed", "41662 rules loaded, 0 failed")]


INSTALLED = Path(r"C:\Program Files\Suricata\suricata.exe")


@pytest.mark.skipif(not INSTALLED.is_file(), reason="Suricata is not installed on this host")
def test_the_installed_suricata_accepts_the_effective_set_its_stock_config_failed(tmp_path):
    """The real install (8.0.7, ET Open 8.0.7): `suricata -T` failed on sid 2065690; with the effective set it passes."""
    rules = lane.suricata_effective_rules(INSTALLED)
    assert 2065690 in rules["disabled"]
    proc = subprocess.run([str(INSTALLED), "-T", "-S", rules["path"], "-l", str(tmp_path)],
                          capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-400:]
