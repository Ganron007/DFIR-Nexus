"""R09 and R13: the index proves source identity on real bytes, and verify follows the run.

Both tests use a local Elasticsearch and real EvtxECmd output lines (verbatim
leading rows of the operator's ES-Mapping outputs). They are skipped when
Elasticsearch or that output set is absent, so the default suite stays hermetic.
Each test deletes its own throwaway index.
"""
from __future__ import annotations

import contextlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ES = os.environ.get("NEXUS_TEST_ES_URL", "http://localhost:9200").rstrip("/")
REAL = Path(__file__).resolve().parents[1] / "Evidence-files" / "ES-Mapping" / "outputs" / "evtxecmd"
SMALL = REAL / "20260921194149_EvtxECmd_Output.csv"
BIG = REAL / "20260921195250_EvtxECmd_Output.csv"


def _es_up() -> bool:
    try:
        with urllib.request.urlopen(ES, timeout=3) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False


pytestmark = pytest.mark.skipif(
    not (_es_up() and SMALL.is_file() and BIG.is_file()),
    reason="needs a local Elasticsearch and the operator's real EvtxECmd outputs",
)


def _head_lines(src: Path, n: int) -> str:
    with open(src, encoding="utf-8-sig", errors="replace") as fh:
        return "".join(next(fh) for _ in range(n))


@pytest.fixture
def es_env(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    monkeypatch.setenv("NEXUS_ES_URL", ES)
    yield tmp_path
    for index in ("nexus-case-case-r09test", "nexus-case-case-r13test"):
        req = urllib.request.Request(f"{ES}/{index}", method="DELETE")
        with contextlib.suppress(urllib.error.URLError, OSError):
            urllib.request.urlopen(req, timeout=20).read()


def test_r09_changed_bytes_with_a_preserved_mtime_are_reindexed(es_env, monkeypatch):
    from nexus.langgraph.case_index import index_case

    case = es_env / "cases" / "CASE-R09TEST"
    target = case / "extractions" / "evtxecmd" / "real.csv"
    target.parent.mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: CASE-R09TEST\n", encoding="utf-8")
    target.write_text(_head_lines(SMALL, 300), encoding="utf-8")
    mtime = target.stat().st_mtime
    index_case(case, incremental=False)

    # Different real bytes under the same name, with the original mtime restored.
    target.write_text(_head_lines(BIG, 200), encoding="utf-8")
    os.utime(target, (mtime, mtime))
    index_case(case, incremental=True)

    meta = json.loads((case / "analysis" / "es_index.json").read_text(encoding="utf-8"))
    assert any(rel.endswith("real.csv") for rel in meta.get("files_reindexed") or [])


def test_r13_verify_checks_the_run_the_index_was_built_from(es_env, monkeypatch):
    from typer.testing import CliRunner

    from nexus.cli.index_cmd import app
    from nexus.langgraph.case_index import index_case

    case = es_env / "cases" / "CASE-R13TEST"
    run = case / "runs" / "RUN-R13-COMPLETED"
    (run / "extractions" / "evtxecmd").mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: CASE-R13TEST\n", encoding="utf-8")
    (run / "extractions" / "evtxecmd" / "real.csv").write_text(_head_lines(SMALL, 200), encoding="utf-8")
    (run / "manifest.json").write_text(json.dumps({
        "run_id": "RUN-R13-COMPLETED", "mode": "tools", "status": "completed",
        "parent_run_id": "", "previous_active_run_id": "",
    }), encoding="utf-8")
    (case / "active_runs.json").write_text(json.dumps({"tools": "RUN-R13-COMPLETED"}), encoding="utf-8")
    index_case(case, incremental=False)

    result = CliRunner().invoke(app, ["verify", "--case", "CASE-R13TEST"])
    assert result.exit_code == 0, result.output
    assert "MISSING" not in result.output
