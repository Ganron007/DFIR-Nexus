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
    assert columns["StartAddress"]["type"] == "text" and columns["StartAddress"]["type_proof"]["verdict"] == "unproven"
    assert columns["registration_date"]["type"] == "date"
    assert "type_proof" not in columns["ecs.source.ip"] and "type_proof" not in columns["Name"]
    assert tally == {"proven": 1, "contradicted": 1, "unproven": 1, "supplement": 1}


def test_the_shipped_registry_types_only_proven_columns():
    """The agreement test: every typed column the index maps was proven on populated values (or is the product's)."""
    columns = (yaml.safe_load(REGISTRY.read_text(encoding="utf-8")) or {}).get("columns") or {}
    typed = {n: c for n, c in columns.items() if c.get("type") in {"long", "double", "boolean", "date"}
             and not c.get("ecs")}
    assert typed, "the registry types nothing"
    for name, col in typed.items():
        proof = col.get("type_proof") or {}
        assert proof.get("verdict") in {"proven", "declared by the product supplement"}, (name, col)
        if proof.get("verdict") == "proven":
            assert proof.get("samples", 0) > 0, name
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
            {"key": "fields.sa", "doc_count": 32146}, {"key": "ts_raw", "doc_count": 7}]}}})


def test_unindexed_values_are_counted_per_field():
    assert unindexed_field_values(_Client(), "nexus-case-x") == {"fields.sa": 32146, "ts_raw": 7}


def test_the_gate_shows_unindexed_values_even_when_reconcile_returns_early(tmp_path):
    case = tmp_path / "CASE-X"
    (case / "analysis").mkdir(parents=True)
    lane_gate._atomic_write(lane_gate.gate_path(case), {"schema": 1, "run_id": "RUN-1", "status": "clear"})
    lane_gate.reconcile_after_index(case, {}, run_id="RUN-1", unindexed_field_values={"fields.sa": 32146})
    gate = lane_gate.read_lane_gate(case)
    assert gate["status"] == "clear", "a warning never blocks"
    assert gate["index_warnings"][0]["field"] == "fields.sa" and gate["index_warnings"][0]["docs"] == 32146


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
