"""Phase 4k.2 — EH-11..EH-14: streaming index, exhaustive retrieval,
backend honesty, streamed PCAP, finding appendices.

These tests pin the "no silent evidence loss" contract: every row is indexed,
report paths enumerate without result caps, backend fallbacks are recorded,
and tshark output is parsed as a stream.
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest


def _case(tmp_path: Path, rows: int = 3) -> Path:
    ext = tmp_path / "extractions" / "pecmd"
    ext.mkdir(parents=True)
    lines = ["RunTime,ExecutableName"]
    lines += [f"2020-11-14 04:4{i}:43,sdelete.exe" for i in range(rows)]
    lines.append("2020-11-14 05:00:00,notepad.exe")
    (ext / "prefetch_Timeline.csv").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  playbooks: data_staging\n  question: what was staged or wiped\n",
        encoding="utf-8",
    )
    return tmp_path


# ── EH-11: streaming, uncapped index ───────────────────────────────────

def test_index_batches_stream_and_cover_every_row(tmp_path):
    from nexus.langgraph.case_index import iter_index_doc_batches, iter_index_docs

    case = _case(tmp_path, rows=4)
    batches = list(iter_index_doc_batches(case, batch_size=2))
    assert len(batches) >= 2, "must stream in multiple batches"
    streamed = [d for b in batches for d in b]
    assert len(streamed) == len(iter_index_docs(case))
    # header row is not indexed; every data row is
    assert sum(1 for d in streamed if "sdelete" in d["text"].lower()) == 4


def test_index_reads_gzip_outputs(tmp_path):
    from nexus.langgraph.case_index import iter_index_docs

    case = _case(tmp_path)
    gz_dir = tmp_path / "extractions" / "hayabusa"
    gz_dir.mkdir(parents=True)
    with gzip.open(gz_dir / "timeline.csv.gz", "wt", encoding="utf-8") as fh:
        fh.write("Time,Rule\n2020-11-14 04:49:43,sdelete usage\n")
    docs = iter_index_docs(case)
    assert any("sdelete usage" in d["text"].lower() for d in docs), (
        "gz outputs must be indexed (EH-11)"
    )


def test_index_and_scan_defaults_unlimited(monkeypatch):
    import nexus.langgraph.case_index as ci
    import nexus.langgraph.query_pack as qp

    monkeypatch.delenv("NEXUS_INDEX_MAX_DOCS", raising=False)
    monkeypatch.delenv("NEXUS_SCAN_MAX_FILE_MB", raising=False)
    monkeypatch.delenv("NEXUS_N4_MAX_FILE_MB", raising=False)
    assert ci._env_index_int("NEXUS_INDEX_MAX_DOCS", 0) == 0
    assert qp._env_mb("NEXUS_SCAN_MAX_FILE_MB", 0) == 0
    assert qp._env_mb("NEXUS_N4_MAX_FILE_MB", 0) == 0


# ── EH-12: exhaustive enumeration + exact counts ───────────────────────

def test_iter_all_hits_is_uncapped_and_exact(tmp_path, monkeypatch):
    import nexus.langgraph.query_pack as qp

    case = _case(tmp_path, rows=6)
    monkeypatch.setattr(qp, "_MAX_HITS_TOTAL", 2)
    monkeypatch.setattr(qp, "_MAX_HITS_PER_FILE", 2)

    capped, _ = qp.n4_hits(case, ["sdelete"], (None, None), backend="csv")
    assert len(capped) == 2

    everything = list(qp.iter_all_hits(case, ["sdelete"], (None, None), backend="csv"))
    assert len(everything) == 6, "exhaustive path must not apply result caps"

    count = qp.count_hits(case, ["sdelete"], (None, None), backend="csv")
    assert count["exact"] is True
    assert count["count"] == 6
    assert count["backend"] == "csv"


def test_n4_query_reports_exact_total_when_capped(tmp_path, monkeypatch):
    import nexus.langgraph.query_pack as qp

    case = _case(tmp_path, rows=5)
    monkeypatch.setattr(qp, "_MAX_HITS_TOTAL", 1)
    monkeypatch.setattr(qp, "_MAX_HITS_PER_FILE", 1)

    result = qp.n4_query(case, "sdelete", window=(None, None), backend="csv")
    assert result["count"] == 5, "capped page must still report the exact total"
    assert result["count_exact"] is True
    assert result["count_lower_bound"] is False
    assert len(result["hits"]) == 1


# ── EH-13: backend fallback is recorded, never silent ──────────────────

def test_csv_fallback_reason_recorded(tmp_path, monkeypatch):
    import nexus.langgraph.query_pack as qp

    monkeypatch.delenv("NEXUS_ES_URL", raising=False)
    case = _case(tmp_path)
    stats: dict = {}
    hits, backend = qp.n4_hits(case, ["sdelete"], (None, None), backend="auto", stats=stats)
    assert backend == "csv"
    assert hits
    assert stats["backend"] == "csv"
    assert stats["fallback_reason"], "CSV fallback must carry a reason (EH-13)"


@pytest.mark.asyncio
async def test_stage_findings_skips_after_hard_error(tmp_path):
    from nexus.langgraph.llm_pipeline import stage_findings

    out = await stage_findings({"error": "Mode 2/3 requires Elasticsearch"}, {})
    assert any("skipped" in s for s in out.get("step_log") or [])
    assert "error" not in out


@pytest.mark.asyncio
async def test_coverage_tool_lane_indexes_before_interpret(tmp_path, monkeypatch):
    """Mode 2/3 graph goes execute_tool_lane → interpret with no other indexer.

    Regression for the fresh-case "ES required: index missing" failure: the
    lane must build the N3 index itself before interpret's EH-13 gate runs.
    """
    import nexus.langgraph.llm_pipeline as pipe
    import nexus.langgraph.tool_lane as lane_mod

    indexed: list[Path] = []

    async def fake_run_tool_lane(**kwargs):
        return {"step_log": ["lane ran"]}

    monkeypatch.setattr(lane_mod, "run_tool_lane", fake_run_tool_lane)
    monkeypatch.setattr(
        pipe, "_autoindex_case", lambda case_dir: indexed.append(case_dir) or ["indexed"]
    )

    state = {
        "case_id": "CASE-T",
        "run_id": "run-1",
        "pipeline_mode": "coverage",
        "evidence_path": "",
    }
    out = await pipe.execute_tool_lane(state, {})
    assert indexed, "coverage mode must auto-index before interpret"
    assert indexed[0].name == "CASE-T"
    assert any("indexed" in s for s in out.get("step_log") or [])

    indexed.clear()
    state["pipeline_mode"] = "tools"
    await pipe.execute_tool_lane(state, {})
    assert not indexed, "tools mode indexes in emit_tool_report, not the lane"


# ── EH-14a: PCAP streams as NDJSON (no whole-file json.load) ───────────

def _ek_line(n: int, src_port: int) -> str:
    return json.dumps({
        "_index": "packets",
        "_source": {"layers": {
            "frame": {"frame.time_epoch": f"17550000{n:02d}.000"},
            "ip": {"ip.src": "10.0.0.5", "ip.dst": "8.8.8.8"},
            "udp": {"udp.srcport": str(src_port), "udp.dstport": "53"},
            "dns": {"dns.qry.name": f"host{n}.example"},
        }},
    })


def test_wireshark_parses_tshark_ek_ndjson(tmp_path, caplog):
    from nexus.ingest.network.wireshark import WiresharkImporter

    out = tmp_path / "capture.tshark.jsonl"
    out.write_text(
        _ek_line(1, 50000) + "\n"
        + "not json at all\n"
        + _ek_line(2, 50001) + "\n",
        encoding="utf-8",
    )
    arts = list(WiresharkImporter().parse(out))
    assert len(arts) == 2
    assert arts[0].source_ip == "10.0.0.5"
    assert "host2.example" in json.dumps(arts[1].raw)


def test_convert_uses_ek_streaming(tmp_path, monkeypatch):
    from nexus.ingest.network import pcap as pcap_mod

    captured: dict = {}

    class _Proc:
        returncode = 0
        stderr = b""

    def fake_run(cmd, stdout=None, stderr=None, timeout=None):
        captured["cmd"] = cmd
        if stdout is not None:
            stdout.write(b'{"_source": {"layers": {}}}\n')
        return _Proc()

    monkeypatch.setattr(pcap_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(pcap_mod, "find_tshark", lambda: "tshark")
    out = tmp_path / "out.jsonl"
    pcap_mod.convert_pcap_to_json(tmp_path / "in.pcap", out)
    cmd = captured["cmd"]
    assert "-T" in cmd and cmd[cmd.index("-T") + 1] == "ek", "must stream EK, not one giant JSON"


# ── EH-12: report appendices enumerate beyond the sampled rows ─────────

def test_finding_appendices_write_every_matching_row(tmp_path):
    from nexus.integration.dfir_report import write_finding_appendices

    case = _case(tmp_path, rows=5)
    findings = [
        {
            "id": "FND-TEST-1",
            "status": "APPROVED",
            "evidence": [{
                "family": "pecmd",
                "terms_list": ["sdelete"],
                "file": "extractions/pecmd/prefetch_Timeline.csv",
                "line": "2",
            }],
        },
        {  # DRAFT findings get no appendix
            "id": "FND-DRAFT",
            "status": "DRAFT",
            "evidence": [{"family": "pecmd", "terms_list": ["sdelete"]}],
        },
    ]
    written = write_finding_appendices(case, findings)
    assert len(written) == 1
    path = case / written[0]["path"]
    assert path.is_file()
    rows = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(rows) - 1 == 5, "appendix must contain every matched row"
