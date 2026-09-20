"""EH-14b/EH-15 — network lane: nfdump/netflow import, SIFT job planning,
local flow projection (session guarantee), importer-lane concurrency.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_NFDUMP_CSV = (
    "ts,te,td,sa,da,sp,dp,pr,flg,fwd,stos,ipkt,ibyt,opkt,obyt,in,out,sseq,dseq\n"
    "1755000000,1755000060,60,192.168.77.55,8.8.8.8,52345,53,17,0,0,0,3,210,2,180,1,1,0,0\n"
    "1755000100,1755000130,30,10.0.0.5,10.0.0.9,49152,445,6,.AP.,0,0,12,5432,10,4100,1,1,1,1\n"
)


def _nfcapd(tmp_path: Path) -> Path:
    p = tmp_path / "nfcapd.202401010000"
    p.write_bytes(b"\x00\x00\x00\x03" + b"\x00" * 40)
    return p


def test_nfdump_csv_import_produces_netflow_artifacts(tmp_path):
    from nexus.ingest.network.nfdump import NfdumpImporter

    csv_path = tmp_path / "flows.csv"
    csv_path.write_text(_NFDUMP_CSV, encoding="utf-8")
    assert NfdumpImporter.can_handle(csv_path)
    arts = list(NfdumpImporter().parse(csv_path))
    assert len(arts) == 2
    first = arts[0].to_dict()
    assert first["artifact_type"] == "network"
    assert first["source"] == "netflow"
    assert first["source_ip"] == "192.168.77.55"
    assert first["dest_ip"] == "8.8.8.8"
    assert first["protocol"] == "udp"
    assert "pkts" in first["description"]
    second = arts[1].to_dict()
    assert second["protocol"] == "tcp"


def test_nfdump_registry_autodetect(tmp_path):
    from nexus.ingest.detect import resolve_ingest_source
    from nexus.ingest.registry import get_registry
    from nexus.ingest.schemas import ArtifactSource

    csv_path = tmp_path / "nfcapd-flows.csv"
    csv_path.write_text(_NFDUMP_CSV, encoding="utf-8")
    source, _why = resolve_ingest_source(csv_path)
    assert source == ArtifactSource.NETFLOW
    result = get_registry().import_path(csv_path, source=source)
    assert result.success, result.errors
    assert result.source == "netflow"
    assert len(result.artifacts) == 2


def test_nfdump_binary_missing_is_honest(tmp_path, monkeypatch):
    from nexus.ingest.base import ImporterError
    from nexus.ingest.network import nfdump as mod

    monkeypatch.setattr(mod, "find_nfdump", lambda: None)
    with pytest.raises(ImporterError) as exc:
        list(mod.NfdumpImporter().parse(_nfcapd(tmp_path)))
    assert "nfdump" in str(exc.value).lower()


def test_nfdump_binary_invocation(tmp_path, monkeypatch):
    from nexus.ingest.network import nfdump as mod

    monkeypatch.setattr(mod, "find_nfdump", lambda: "nfdump")
    captured: dict = {}

    def fake_run(cmd, capture_output=False, timeout=None):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout=_NFDUMP_CSV.encode(), stderr=b"")

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    arts = list(mod.NfdumpImporter().parse(_nfcapd(tmp_path)))
    assert len(arts) == 2
    assert "-r" in captured["cmd"] and captured["cmd"][captured["cmd"].index("-o") + 1] == "csv"


def test_discover_network_inputs(tmp_path):
    from nexus.langgraph.network_lane import discover_network_inputs

    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
    nf = _nfcapd(tmp_path)
    found = discover_network_inputs([str(pcap), str(nf), str(tmp_path / "notes.txt")])
    assert found["pcap"] == [str(pcap)]
    assert found["nfcapd"] == [str(nf)]


def test_plan_network_triage_default_toolset_and_honest_skip(tmp_path, monkeypatch):
    from nexus.langgraph.network_lane import plan_network_triage

    monkeypatch.delenv("NEXUS_SIFT_ZEEK", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_SURICATA", raising=False)
    root = tmp_path / "sift-evidence"
    inside = root / "captures" / "cap.pcap"
    inside.parent.mkdir(parents=True)
    inside.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
    outside = tmp_path / "local.pcap"
    outside.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)

    jobs = plan_network_triage(
        [str(inside), str(outside)], [], str(root), has_sift_mcp=True,
    )
    # SIFT default toolset: zeek/suricata are not installed there — SKIP, no FAIL.
    zeek = next(j for j in jobs if j.tool == "zeek")
    suricata = next(j for j in jobs if j.tool == "suricata")
    assert zeek.status == "SKIP" and "default toolset" in zeek.reason
    assert suricata.status == "SKIP" and "default toolset" in suricata.reason
    skips = [j for j in jobs if j.status == "SKIP"]
    assert len(skips) == 3  # outside-root + zeek + suricata
    assert any("SIFT evidence root" in j.reason for j in skips)
    assert not [j for j in jobs if j.status == "PENDING"]


def test_plan_network_triage_app_tools_are_optin(tmp_path, monkeypatch):
    from nexus.langgraph.network_lane import plan_network_triage

    monkeypatch.setenv("NEXUS_SIFT_ZEEK", "1")
    monkeypatch.setenv("NEXUS_SIFT_SURICATA", "1")
    root = tmp_path / "sift-evidence"
    inside = root / "captures" / "cap.pcap"
    inside.parent.mkdir(parents=True)
    inside.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)

    jobs = plan_network_triage([str(inside)], [], str(root), has_sift_mcp=True)
    zeek = next(j for j in jobs if j.tool == "zeek")
    assert zeek.status == "PENDING" and zeek.argv[0] == "zeek" and zeek.argv[1] == "-Cr"
    assert any(a.startswith("Log::default_logdir=") for a in zeek.argv)
    assert any(j.tool == "suricata" and j.status == "PENDING" for j in jobs)
    assert not [j for j in jobs if j.status == "SKIP"]


def test_sift_jobs_for_lane_includes_network(tmp_path, monkeypatch):
    from nexus.langgraph.tool_lane import sift_jobs_for_lane

    monkeypatch.setenv("NEXUS_SIFT_SURICATA", "1")
    root = tmp_path / "sift-root"
    root.mkdir()
    pcap = root / "cap.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
    jobs = sift_jobs_for_lane(
        str(root), has_sift_mcp=True,
        network_inputs={"pcap": [str(pcap)], "nfcapd": []},
    )
    assert any(j.tool == "suricata" and j.status == "PENDING" for j in jobs)


def test_flow_projection_writes_sessions(tmp_path, monkeypatch):
    from nexus.langgraph import network_lane as lane

    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
    stdout = (
        "frame.time_epoch,ip.src,tcp.srcport,udp.srcport,ip.dst,tcp.dstport,"
        "udp.dstport,_ws.col.Protocol,frame.len\n"
        "1755000000.1,192.168.77.55,,52345,8.8.8.8,,53,DNS,74\n"
        "1755000001.2,10.0.0.5,49152,,10.0.0.9,445,,SMB2,120\n"
    )

    monkeypatch.setattr(
        lane, "resolve_local_tool",
        lambda name: "tshark" if name == "tshark" else None,
    )

    def fake_run(cmd, capture_output=False, timeout=None, text=False):
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(lane.subprocess, "run", fake_run)
    case = tmp_path / "CASE-X"
    case.mkdir()
    out = lane.enrich_local_network(pcap, case)
    assert out["flows_rows"] == 2
    csv_path = Path(out["flows_csv"])
    assert csv_path.is_file() and csv_path.name.endswith("-flows.csv")
    body = csv_path.read_text(encoding="utf-8")
    assert "192.168.77.55" in body and "52345" in body and "protocol" in body


def test_network_tool_resolver(tmp_path, monkeypatch):
    from nexus.collect.paths import network_tool

    assert network_tool("zzz-nexus-test-tool") is None
    fake_dir = tmp_path / "tools"
    fake_dir.mkdir()
    exe = fake_dir / "zzz-nexus-test-tool"
    exe.write_text("", encoding="utf-8")
    monkeypatch.setenv("NEXUS_TOOL_PATHS", str(fake_dir))
    assert network_tool("zzz-nexus-test-tool") == exe


def test_importer_lane_concurrency_knob(monkeypatch):
    from nexus.langgraph.tool_lane import _lane_concurrency

    monkeypatch.delenv("NEXUS_TOOL_LANE_CONCURRENCY", raising=False)
    assert _lane_concurrency() == 1
    monkeypatch.setenv("NEXUS_TOOL_LANE_CONCURRENCY", "3")
    assert _lane_concurrency() == 3
    monkeypatch.setenv("NEXUS_TOOL_LANE_CONCURRENCY", "99")
    assert _lane_concurrency() == 4
