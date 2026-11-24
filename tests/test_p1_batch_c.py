"""Regression tests for P1 Batch C fixes (P1-4, P1-5, P1-8, P1-9, P1-10)."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import yaml

from nexus.collect.extra_windows import run_sysinternals
from nexus.collect.transport import ExecResult, LocalTransport, WinRmTransport
from nexus.collect.types import AuthSpec, CollectOptions, HostSpec
from nexus.detection.generator import generate_sigma_rule
from nexus.detection.indexer import DetectionIndexer
from nexus.ingest.cti_ingestion import CTIItem, CTIItemType, CTISource
from nexus.ingest.network.nfdump import NfdumpImporter
from nexus.validation.harness import _technique_needles, gather_found


def test_p1_4_sysinternals_stdout_tools_do_not_crash_without_precreated_file(tmp_path, monkeypatch):
    """Stdout-only Sysinternals tools (handle, pslist, etc.) write dest without FileNotFoundError."""
    tools = tmp_path / "tools" / "sysinternals"
    tools.mkdir(parents=True)
    for name in ("autorunsc64.exe", "handle64.exe", "pslist64.exe"):
        (tools / name).write_bytes(b"MZ")

    def fake_sysinternals_exe(name: str):
        mapping = {
            "autorunsc": tools / "autorunsc64.exe",
            "handle": tools / "handle64.exe",
            "pslist": tools / "pslist64.exe",
        }
        return mapping.get(name)

    def fake_run_local(argv: list[str], _timeout: int) -> ExecResult:
        exe_name = Path(argv[0]).name.lower()
        if "autorunsc" in exe_name:
            out_idx = argv.index("-o") + 1
            Path(argv[out_idx]).write_text("autorunsc file output\n", encoding="utf-8")
            return ExecResult(0, "banner noise", "")
        if "handle" in exe_name:
            return ExecResult(0, "handle pid=4 lsass\n", "")
        if "pslist" in exe_name:
            return ExecResult(0, "pslist pid=4 System\n", "")
        return ExecResult(1, "", "unexpected")

    monkeypatch.setattr("nexus.collect.extra_windows.sysinternals_exe", fake_sysinternals_exe)
    monkeypatch.setattr("nexus.collect.extra_windows._run_local", fake_run_local)

    pack_host = tmp_path / "pack" / "ws01"
    pack_host.mkdir(parents=True)
    spec = HostSpec(os="windows", address="localhost", hostname="ws01", transport="local")
    step = run_sysinternals(spec, LocalTransport(spec), pack_host, CollectOptions(), dry_run=False)

    assert step.status == "ok"
    assert (pack_host / "sysinternals" / "autorunsc.txt").read_text(encoding="utf-8") == "autorunsc file output\n"
    assert (pack_host / "sysinternals" / "handle.txt").read_text(encoding="utf-8") == "handle pid=4 lsass\n"
    assert (pack_host / "sysinternals" / "pslist.txt").read_text(encoding="utf-8") == "pslist pid=4 System\n"


def test_p1_5_pywinrm_uses_run_ps_for_powershell_scripts(monkeypatch):
    """_pywinrm_run runs cmdlets without leading 'powershell' via run_ps, never run_cmd."""
    monkeypatch.setenv("NEXUS_COLLECT_PASSWORD", "Secret!123")
    mock_session = MagicMock()
    mock_session.run_ps.return_value = SimpleNamespace(status_code=0, std_out=b"ORC_PID=10", std_err=b"")
    mock_session.run_cmd.side_effect = AssertionError("run_cmd must not be called for remote PS scripts")
    mock_winrm = SimpleNamespace(Session=MagicMock(return_value=mock_session))
    monkeypatch.setitem(sys.modules, "winrm", mock_winrm)

    spec = HostSpec(
        os="windows",
        address="10.0.0.10",
        hostname="ws01",
        transport="winrm",
        auth=AuthSpec(user="Administrator", password_env="NEXUS_COLLECT_PASSWORD"),
    )
    t = WinRmTransport(spec)
    res = t._pywinrm_run(
        "New-Item -ItemType Directory -Force -Path 'C:\\Temp\\orc' | Out-Null; $r = Invoke-CimMethod Win32_Process Create",
        timeout=60,
    )
    assert res.ok
    assert res.stdout == "ORC_PID=10"
    mock_session.run_ps.assert_called_once()
    mock_session.run_cmd.assert_not_called()


def test_p1_8_nfdump_timestamp_synthesized_flag_not_inverted():
    """Real timestamps produce ts_synthesized=False; missing timestamps produce ts_synthesized=True."""
    imp = NfdumpImporter()
    real_art = imp._row_to_artifact(
        {
            "ts": "2026-10-01 12:30:00",
            "sa": "10.0.0.5",
            "da": "198.51.100.10",
            "sp": "51234",
            "dp": "443",
            "pr": "TCP",
        }
    )
    assert real_art.ts_synthesized is False
    assert (
        real_art.timestamp.year == 2026
        and real_art.timestamp.hour == 12
        and real_art.timestamp.minute == 30
    )

    synth_art = imp._row_to_artifact(
        {
            "ts": "",
            "sa": "10.0.0.5",
            "da": "198.51.100.10",
            "sp": "51234",
            "dp": "443",
            "pr": "TCP",
        }
    )
    assert synth_art.ts_synthesized is True


def test_p1_9_validation_harness_technique_needles_and_nonempty_families(tmp_path, monkeypatch):
    """_technique_needles reads info['name'] and gather_found excludes empty family strings."""
    monkeypatch.setattr(
        "nexus.knowledge.loader.get_attack_techniques",
        lambda: [{"technique": "T9999", "name": "Credential Dumping"}],
    )
    needles = _technique_needles({"T9999"}, [])
    assert "T9999" in needles
    assert "Credential" in needles["T9999"]
    assert "Dumping" in needles["T9999"]

    case = tmp_path / "CASE-V2"
    ext = case / "extractions"
    ext.mkdir(parents=True)
    (ext / "hayabusa_alerts.csv").write_text(
        "Timestamp,Computer,Channel,EventID,Level,RuleTitle,OtherDetails\n"
        "2026-08-10 14:32:01,WS01,Sec,4688,critical,LSASS Memory Access,procdump -ma lsass.exe\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "nexus.validation.harness._search",
        lambda _case_dir, _needles: [
            {"family": "", "text": "lsass dump"},
            {"family": "   ", "text": "blank fam"},
            {"family": "hayabusa", "text": "procdump -ma lsass.exe"},
        ],
    )
    found = gather_found(case, {"expected": {"families": ["hayabusa"], "artifacts": ["lsass"]}})
    exp_fams, found_fams = found["families"]
    assert "" not in exp_fams and "" not in found_fams
    assert found_fams == {"hayabusa"}


def test_p1_10_sigma_hyphen_tactics_and_ored_cve_detection(tmp_path):
    """DetectionIndexer normalizes hyphenated tactics and generator emits ORed selections."""
    techniques, tactics = DetectionIndexer._extract_mitre_from_tags(
        ["attack.defense-evasion", "attack.lateral-movement", "attack.t1059.001"]
    )
    assert techniques == ["T1059.001"]
    assert tactics == ["TA0005", "TA0008"]

    item = CTIItem(
        id="cti-1",
        title="CVE-2026-1234 Edge RCE",
        description="Exploit activity from C2 IP",
        item_type=CTIItemType.VULNERABILITY,
        source=CTISource.CISA_KEV,
        cve_ids=["CVE-2026-1234"],
        affected_products=["Edge Gateway"],
        iocs=["203.0.113.50"],
        severity="high",
    )
    rule_yaml = generate_sigma_rule(item)
    parsed = yaml.safe_load(rule_yaml)
    det = parsed["detection"]
    assert det["condition"] == "1 of selection_*"
    assert "selection" not in det
    # Verify SourceIP and DestinationIP are separated (not AND-ed in the same selection block).
    sel_keys = [k for k in det if k.startswith("selection_")]
    assert len(sel_keys) == 4
    source_ip_blocks = [det[k] for k in sel_keys if "SourceIP" in det[k]]
    dest_ip_blocks = [det[k] for k in sel_keys if "DestinationIP" in det[k]]
    assert len(source_ip_blocks) == 1 and "DestinationIP" not in source_ip_blocks[0]
    assert len(dest_ip_blocks) == 1 and "SourceIP" not in dest_ip_blocks[0]
