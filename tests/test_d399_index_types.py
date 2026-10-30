"""D399: a typed index column must never drop values silently.

The field registry typed each column name from a catalog's declared `es_type`, unified across families, and the
index's `ignore_malformed` left every value that did not fit out of the field index without a word. Measured on the
R1z3 indexes: T18's nfdump `sa`/`da` (IP addresses typed `double`, 32,146 rows), T22's MemProcFS hex offsets typed
`long`, EvtxECmd's `TimeCreated` (seven-digit fractions missing from the date formats), the importers' `True`/`False`
flags in `boolean` columns, RECmd's host-locale dates, and `ts_raw` holding whole lines.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml

from nexus.langgraph import lane_gate
from nexus.langgraph.case_index import unindexed_field_values
from nexus.langgraph.field_registry import field_text
from nexus.langgraph.timestamps import parse_text_time, parse_time_value

REPO = Path(__file__).resolve().parents[1]
REGISTRY = REPO / "src" / "nexus" / "data" / "schema" / "field_registry.yaml"


def _builder():
    spec = importlib.util.spec_from_file_location("bfr_d399", REPO / "scripts" / "build_field_registry.py")
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["bfr_d399"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_a_type_is_kept_only_when_every_populated_sample_fits():
    mod = _builder()
    columns = {
        "pid": {"type": "long"},
        "sa": {"type": "double"},                     # nfdump: IP addresses
        "StartAddress": {"type": "long"},            # no populated sample anywhere
        "registration_date": {"type": "date"},       # product supplement
        "ecs.source.ip": {"type": "keyword", "ecs": True},
        "Name": {"type": "text"},
    }
    samples = {"pid": [("vol", "4"), ("vol", "612")], "sa": [("nfdump", "205.203.131.117"), ("nfdump", "1.5")]}

    def accepts(kind, values):
        return [v for v in values if kind == "double" and v.count(".") > 1]

    tally = mod.prove_types(columns, samples, accepts, {"registration_date"})
    assert columns["pid"]["type"] == "long" and columns["pid"]["type_proof"]["verdict"] == "proven"
    assert columns["sa"]["type"] == "text" and columns["sa"]["declared_type"] == "double"
    assert columns["sa"]["type_proof"]["rejected"] == ["nfdump: 205.203.131.117"]
    # no populated sample: the declared type stands, marked, and the index's _ignored count would name a misfit
    assert columns["StartAddress"]["type"] == "long" and columns["StartAddress"]["type_proof"]["verdict"] == "unproven"
    assert columns["registration_date"]["type"] == "date"
    assert "type_proof" not in columns["ecs.source.ip"] and "type_proof" not in columns["Name"]
    assert tally == {"proven": 1, "contradicted": 1, "unproven": 1, "supplement": 1}


def test_new_pipeline_profiles_join_the_baseline_type_samples(tmp_path, monkeypatch):
    """D500: a changed export must reach type proof without replacing the baseline's wider population."""
    import json

    from nexus.langgraph import pipeline_runs

    spec = importlib.util.spec_from_file_location("profile_d500", REPO / "scripts/profile_field_population.py")
    profiler = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profiler)
    monkeypatch.setattr(pipeline_runs, "resolve_tools_extractions", lambda case_dir, run_id="": case_dir / "extractions")
    catalog = tmp_path / "catalog"
    catalog.mkdir()
    for family, fixture, profile_name in (
        ("chainsaw", "d474_chainsaw_t12_sigma.csv", "_population.json"),
        ("zircolite", "d474_zircolite_t12.ndjson", "_population-new-export.json"),
    ):
        case = tmp_path / family
        corpus = tmp_path / (family + "-corpus")
        corpus.mkdir()
        (corpus / "_staged.json").write_text(json.dumps({
            "families": {family: [str(REPO / "tests/fixtures" / fixture)]},
        }), encoding="utf-8")
        assert profiler._layout(corpus, case)["placed"] == 1
        measured = profiler.profile(case)
        (catalog / profile_name).write_text(json.dumps(measured), encoding="utf-8")

    builder = _builder()
    monkeypatch.setattr(builder, "SRC_DIR", catalog)
    samples = builder.load_samples()
    first = json.loads((REPO / "tests/fixtures/d474_zircolite_t12.ndjson").read_text(encoding="utf-8").splitlines()[0])
    assert ("zircolite", str(first["ProcessId"])) in samples["ProcessId"]
    assert {family for family, _value in samples["Computer"]} == {"chainsaw", "zircolite"}
    assert builder.load_population()["processid"] == {"zircolite"}


def test_the_shipped_registry_never_types_a_column_its_values_contradict():
    """The agreement test: every typed column the index maps was checked; none is typed against its real values."""
    columns = (yaml.safe_load(REGISTRY.read_text(encoding="utf-8")) or {}).get("columns") or {}
    typed = {n: c for n, c in columns.items() if c.get("type") in {"long", "double", "boolean", "date"}
             and not c.get("ecs")}
    assert typed, "the registry types nothing"
    for name, col in typed.items():
        proof = col.get("type_proof") or {}
        assert proof.get("verdict") in {"proven", "unproven", "declared by the product supplement"}, (name, col)
        if proof.get("verdict") == "proven":
            assert proof.get("samples", 0) > 0, name
        if proof.get("verdict") == "unproven":
            assert proof.get("samples") == 0, name
    contradicted = [n for n, c in columns.items() if (c.get("type_proof") or {}).get("verdict") == "contradicted"]
    assert contradicted and all(columns[n]["type"] == "text" for n in contradicted)
    # the D399 columns
    for name in ("sa", "da", "ValueData", "StartAddress", "FileOffset", "Wow64"):
        if name in columns:
            assert columns[name]["type"] == "text", (name, columns[name])


def test_flags_are_written_in_the_form_a_boolean_column_holds():
    assert field_text(True) == "true" and field_text(False) == "false"
    assert field_text(4624) == "4624" and field_text("False") == "False"


def test_ts_raw_is_the_time_as_written_not_the_line():
    line = ("0000 SEARCHPROTOCOLHOST.EXE   20658   34 SEARCHPROTOCOLHOST.EXE-0CB8CADE.pf   "
            "2020-02-22 06:03:32 UTC  2020-02-22 05:54:21 UTC")
    got = parse_text_time(line)
    assert got["raw"] == "2020-02-22 06:03:32 UTC"
    assert got["dt"].isoformat() == "2020-02-22T06:03:32+00:00" and got["tz_assumed"] is False


def test_net_invariant_dates_keep_their_offset():
    got = parse_time_value("09/27/2020 14:33:42 +00:00")
    assert got["dt"].isoformat() == "2020-09-27T14:33:42+00:00" and got["tz_assumed"] is False
    shifted = parse_time_value("09/27/2020 14:33:42 +05:30")
    assert shifted["dt"].isoformat() == "2020-09-27T09:03:42+00:00"
    assert parse_time_value("09/27/2020 14:33:42")["tz_assumed"] is True
    # the host-locale form stays untimed rather than read month-first
    assert parse_time_value("02-11-2020 01:13:23 AM +00:00") is None


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class _Client:
    def post(self, path, json=None):
        return _Resp({"aggregations": {"ignored": {"buckets": [
            {"key": "fields.sa", "doc_count": 32146}, {"key": "fields.Payload.kw", "doc_count": 7}]}}})

    def get(self, path):
        return _Resp({"nexus-case-x": {"mappings": {
            "fields.sa": {"full_name": "fields.sa", "mapping": {"sa": {"type": "double"}}},
            "fields.Payload.kw": {"full_name": "fields.Payload.kw", "mapping": {"kw": {"type": "keyword"}}}}}})


def test_unindexed_values_are_counted_per_field_with_the_field_type():
    assert unindexed_field_values(_Client(), "nexus-case-x") == {
        "fields.sa": {"docs": 32146, "type": "double"}, "fields.Payload.kw": {"docs": 7, "type": "keyword"}}


def test_the_gate_shows_unindexed_values_even_when_reconcile_returns_early(tmp_path):
    case = tmp_path / "CASE-X"
    (case / "analysis").mkdir(parents=True)
    lane_gate._atomic_write(lane_gate.gate_path(case), {"schema": 1, "run_id": "RUN-1", "status": "clear"})
    lane_gate.reconcile_after_index(case, {}, run_id="RUN-1", unindexed_field_values={
        "fields.sa": {"docs": 32146, "type": "double"}, "fields.Payload.kw": {"docs": 7, "type": "keyword"}})
    gate = lane_gate.read_lane_gate(case)
    assert gate["status"] == "clear", "a warning never blocks"
    first, second = gate["index_warnings"]
    assert (first["field"], first["docs"]) == ("fields.sa", 32146) and "(double) cannot hold" in first["reason"]
    assert second["field"] == "fields.Payload.kw" and "8,191 characters" in second["reason"]


def test_d402_nfdump_flows_end_at_the_summary_line(tmp_path):
    from nexus.ingest.network.nfdump import parse_nfdump_csv
    from nexus.langgraph.case_index import _index_header, _open_text_auto, iter_indexable_rows

    # the shape of a real nfdump -o csv file (T18): flows, then Summary, its header and its values
    header = "ts,te,td,sa,da,sp,dp,pr,flg,fwd,stos,ipkt,ibyt"
    flow = "2013-08-29 16:43:46,2013-08-29 16:43:46,0.000,172.16.62.42,172.16.62.1,8321,53,UDP,........,0,0,1,74"
    path = tmp_path / "20261023T145008_nfdump_out.csv"
    path.write_text("\n".join([header, flow, flow, "Summary", "flows,bytes,packets,avg_bps,avg_pps,avg_bpp",
                               "2,148,2,0,0,74", ""]), encoding="utf-8")
    with _open_text_auto(path) as fh:
        rows = list(iter_indexable_rows(path, fh, _index_header(path)))
    assert [r[2].get("sa") for r in rows[:2]] == ["172.16.62.42", "172.16.62.42"]
    assert len(rows) == 3 and rows[2][2]["flows"] == "2" and rows[2][2]["ts_none"] == "true"
    assert "sa" not in rows[2][2]
    assert len(parse_nfdump_csv(path.read_text(encoding="utf-8"))) == 2


def test_d403_every_keyword_sub_field_holds_the_one_limit():
    from nexus.langgraph.case_index import _mapping_body
    from nexus.langgraph.field_registry import KEYWORD_IGNORE_ABOVE, es_property

    assert KEYWORD_IGNORE_ABOVE * 4 <= 32766, "a term must stay under Lucene's byte limit"
    assert es_property({"type": "text"})["fields"]["kw"]["ignore_above"] == KEYWORD_IGNORE_ABOVE
    body = _mapping_body()
    limits = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == "keyword" and "ignore_above" in node:
                limits.append(node["ignore_above"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(body["mappings"])
    assert limits and set(limits) <= {KEYWORD_IGNORE_ABOVE, 64}, sorted(set(limits))  # 64: ts_raw, a time token


def test_windows_tools_run_under_the_invariant_culture(tmp_path, monkeypatch):
    from mcp.server.fastmcp import FastMCP

    import nexus.tools.windows as win
    from nexus.audit import AuditWriter

    captured: dict = {}

    class _Result:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def _fake_run(parts, **kwargs):
        captured.update(kwargs)
        return _Result()

    monkeypatch.setattr(win.subprocess, "run", _fake_run)
    server = FastMCP("d399")
    win.register_tools(server, AuditWriter("t", audit_dir=tmp_path / "audit"))
    result = server._tool_manager._tools["run_windows_command"].fn(
        command=["recmd", "--help"], purpose="D399 culture", save_output=False)
    assert result.get("success") is True, result
    assert (captured.get("env") or {}).get("DOTNET_SYSTEM_GLOBALIZATION_INVARIANT") == "1"
    assert captured.get("stdin") is subprocess.DEVNULL
