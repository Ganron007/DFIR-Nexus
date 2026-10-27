"""D409: review the retained failures as well as the true run record."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "review_run", Path(__file__).resolve().parents[1] / "devtools/runbook/review_run.py",
)
review_run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(review_run)


def _run(tmp_path, monkeypatch, mode, run_id, status):
    monkeypatch.setattr(review_run, "ROOT", tmp_path)
    model_env = tmp_path / "operator.env"
    model_env.write_text("NEXUS_LLM_MODEL=agnes-3.0-flash\n", encoding="utf-8")
    monkeypatch.setattr(review_run, "MODEL_ENV", model_env, raising=False)
    case = tmp_path / "CASE-REVIEW"
    (case / ".trace").mkdir(parents=True)
    (case / "audit").mkdir()
    record = {"run_id": run_id, "status": status,
              "model": {"model": "agnes-3.0-flash"}, "candidates": [{}, {}, {}, {}]}
    if mode == "1":
        target = case / "runs" / run_id / "manifest.json"
        record["error"] = "awaiting approval at await_approval (3 DRAFT finding(s) staged)"
        (case / "analysis").mkdir()
        (case / "analysis/interpretation.md").write_text("DRAFT interpretation")
    else:
        target = case / "analysis" / f"mode{mode}_runs" / f"{run_id}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(record))
    return case


def test_review_reads_manifest_status_instead_of_the_cli_completed_line(tmp_path, monkeypatch, capsys):
    run_id = "RUN-20261026T080810259289Z-interpret-a28092ac"
    case = _run(tmp_path, monkeypatch, "1", run_id, "interrupted")
    (case / ".trace/run-T19-R1z3b-mode1.log").write_text(
        f"2026-10-26T08:07:38Z\nrun_id={run_id} status=completed mode=interpret\n"
        "MODE1_EXIT=0\n2026-10-26T08:17:19Z\n")
    report = review_run.review("T19-R1z3b", case.name, "1")
    output = capsys.readouterr().out
    assert "status=interrupted" in output
    assert "awaiting approval at await_approval" in output
    assert report["status"] == "interrupted"
    assert report["issues"] == []
    assert review_run.main([f"T19-R1z3b:{case.name}:1"]) == 0


def test_review_includes_pre_audit_failures_and_deduplicates_audited_results(tmp_path, monkeypatch, capsys):
    run_id = "M2-20261026T082224-803b0d"
    case = _run(tmp_path, monkeypatch, "2", run_id, "completed")
    # Verbatim error lines retained in the real T19 Mode 2 log.
    lines = [
        "2026-10-26T08:22:12Z",
        "2026-10-26T08:37:43  tool.result  correlation-wo-3c442c99d1f8  es_aggregate  es_aggregate: unsupported argument(s) size; allowed: aggs, query",
        "2026-10-26T10:24:34  tool.result  verifier-wo-b84a8598e10d  es_search  es_search: unsupported argument(s) filter; allowed: query, search_after, size, sort",
        "2026-10-26T10:34:36  tool.result  verifier-wo-d9c00c24ca5b  es_aggregate  audit=nexus-claudebot-20261026-313  es_aggregate failed: ESQueryError: aggregation on metadata field `_id` is not allowed",
        f"run_id={run_id} status=completed stop=completed orders=14/14 candidates=4",
        "MODE2_EXIT=0", "2026-10-26T10:41:00Z",
    ]
    (case / ".trace/run-T19-R1z3b-mode2.log").write_text("\n".join(lines))
    audit = {"ts": "2026-10-26T10:34:36+00:00", "tool": "es_aggregate",
             "audit_id": "nexus-claudebot-20261026-313",
             "result_summary": {"error": "ESQueryError: aggregation on metadata field `_id` is not allowed"}}
    (case / "audit/nexus.jsonl").write_text(json.dumps(audit) + "\n")
    report = review_run.review("T19-R1z3b", case.name, "2")
    assert report["tool_errors"] == 3
    assert report["unaudited_tool_errors"] == 2
    assert report["issues"]
    output = capsys.readouterr().out
    assert "unsupported argument(s) filter" in output
    assert "unsupported argument(s) size" in output
    assert review_run.main([f"T19-R1z3b:{case.name}:2"]) == 1


def test_cannot_match_value_error_is_not_an_unknown_field_hint(tmp_path, monkeypatch):
    run_id = "M2-20261026T082224-803b0d"
    case = _run(tmp_path, monkeypatch, "2", run_id, "completed")
    (case / ".trace/run-T19-R1z3b-mode2.log").write_text(
        f"2026-10-26T08:22:12Z\nrun_id={run_id} status=completed\nMODE2_EXIT=0\n2026-10-26T10:41:00Z\n")
    errors = ["query references fields that cannot match: missing (unknown_field)",
              "query references fields that cannot match: ts (value '2021-13-01' cannot be a date)"]
    (case / "audit/nexus.jsonl").write_text("\n".join(json.dumps({
        "ts": "2026-10-26T09:00:00+00:00", "audit_id": str(index),
        "tool": "es_search", "result_summary": {"error": error},
    }) for index, error in enumerate(errors)))
    report = review_run.review("T19-R1z3b", case.name, "2")
    assert report["unknown_field_hints"] == 1
    assert report["tool_errors"] == 1


def test_review_cannot_pass_missing_terminal_stamp_or_missing_record(tmp_path, monkeypatch):
    monkeypatch.setattr(review_run, "ROOT", tmp_path)
    case = tmp_path / "CASE-REVIEW"
    (case / ".trace").mkdir(parents=True)
    (case / ".trace/run-T19-R1z3b-mode2.log").write_text(
        "2026-10-26T08:22:12Z\nMODE2_EXIT=0\n")
    report = review_run.review("T19-R1z3b", case.name, "2")
    assert report["issues"]
    assert not report["run_id"]


def test_error_word_in_a_task_description_is_data_not_a_logger_failure(tmp_path, monkeypatch):
    run_id = "M2-20261026T082224-803b0d"
    case = _run(tmp_path, monkeypatch, "2", run_id, "completed")
    (case / ".trace/run-T19-R1z3b-mode2.log").write_text(
        "2026-10-26T08:22:12Z\n"
        "2026-10-26T09:00:00  work_order.started  evidence-wo-1  Examine the ERROR field in retrieved rows\n"
        f"run_id={run_id} status=completed\nMODE2_EXIT=0\n2026-10-26T10:41:00Z\n")
    assert review_run.review("T19-R1z3b", case.name, "2")["issues"] == []


def test_replay_only_skips_unknown_fields_and_replays_value_failures(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "replay_refused", Path(__file__).resolve().parents[1] / "devtools/runbook/replay_refused.py",
    )
    replay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(replay)
    monkeypatch.setattr(replay, "ROOT", tmp_path)
    case = tmp_path / "CASE-REVIEW"
    (case / "audit").mkdir(parents=True)
    entries = [
        {"ts": "2026-10-26T09:00:00Z", "audit_id": "unknown-1", "tool": "es_search",
         "params": {"query": {"term": {"missing": "x"}}},
         "result_summary": {"error": "query references fields that cannot match: missing (unknown_field)"}},
        {"ts": "2026-10-26T09:00:01Z", "audit_id": "bad-value-1", "tool": "es_search",
         "params": {"query": {"range": {"ts": {"gte": "2021-13-01"}}}},
         "result_summary": {"error": "query references fields that cannot match: ts (value '2021-13-01' cannot be a date)"}},
    ]
    (case / "audit/nexus.jsonl").write_text("\n".join(json.dumps(entry) for entry in entries))
    executed = []

    def execute(case_id, entry):
        assert case_id == case.name
        executed.append(entry)
        return {}

    monkeypatch.setattr(replay, "replay_call", execute)
    replay.main("2026-10-26T08:00:00", [case.name])
    assert executed == [entries[1]], "a bad value must not disappear as an unknown-field hint"


def test_review_reads_the_bare_mode3_run_id_from_the_real_cli_format(tmp_path, monkeypatch):
    run_id = "M3-20261026T063632-bfb75c"
    case = _run(tmp_path, monkeypatch, "3", run_id, "completed")
    record_path = case / "analysis/mode3_runs" / f"{run_id}.json"
    record = json.loads(record_path.read_text())
    record["stop_reason"] = "settled"
    record["candidates"] = [{} for _ in range(8)]
    record_path.write_text(json.dumps(record))
    (case / ".trace/run-T18-R1z3b-mode3.log").write_text(
        "2026-10-26T06:36:19Z\n"
        "M3-20261026T063632-bfb75c  completed  stop=settled  candidates=8\n"
        "MODE3_EXIT=0\n2026-10-26T07:21:08Z\n")
    report = review_run.review("T18-R1z3b", case.name, "3")
    assert report["run_id"] == run_id
    assert report["status"] == "completed"
    assert report["stop_reason"] == "settled"
    assert report["candidates"] == 8
    assert report["issues"] == []


def test_replay_does_not_report_an_error_result_as_runs_now(tmp_path, monkeypatch, capsys):
    spec = importlib.util.spec_from_file_location(
        "replay_refused", Path(__file__).resolve().parents[1] / "devtools/runbook/replay_refused.py",
    )
    replay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(replay)
    monkeypatch.setattr(replay, "ROOT", tmp_path)
    case = tmp_path / "CASE-REVIEW"
    (case / "audit").mkdir(parents=True)
    error = "query references fields that cannot match: ts (value '2021-13-01' cannot be a date)"
    (case / "audit/nexus.jsonl").write_text(json.dumps({
        "ts": "2026-10-26T09:00:00Z", "audit_id": "bad-value-1", "tool": "es_search",
        "params": {"query": {"range": {"ts": {"gte": "2021-13-01"}}}},
        "result_summary": {"error": error},
    }))
    monkeypatch.setattr(replay, "replay_call", lambda *_: {"error": error, "degraded": True})
    replay.main("2026-10-26T08:00:00", [case.name])
    output = capsys.readouterr().out
    assert "now:  STILL:" in output
    assert "RUNS NOW" not in output


def test_review_uses_dotenv_model_instead_of_process_environment(tmp_path, monkeypatch):
    run_id = "M2-20261026T082224-803b0d"
    case = _run(tmp_path, monkeypatch, "2", run_id, "completed")
    review_run.MODEL_ENV.write_text('export NEXUS_LLM_MODEL="operator-selected-model"\n', encoding="utf-8")
    monkeypatch.setenv("NEXUS_LLM_MODEL", "different-process-model")
    record_path = case / "analysis/mode2_runs" / f"{run_id}.json"
    record = json.loads(record_path.read_text())
    record["model"]["model"] = "operator-selected-model"
    record_path.write_text(json.dumps(record))
    (case / ".trace/run-T22-R1z3b-mode2.log").write_text(
        f"2026-10-26T08:22:12Z\nrun_id={run_id} status=completed\nMODE2_EXIT=0\n2026-10-26T10:41:00Z\n")
    before = review_run.MODEL_ENV.read_bytes()
    report = review_run.review("T22-R1z3b", case.name, "2")
    assert report["issues"] == []
    assert report["expected_model"] == "operator-selected-model"
    assert review_run.MODEL_ENV.read_bytes() == before
    import os
    assert os.environ["NEXUS_LLM_MODEL"] == "different-process-model"


def test_review_rejects_actual_model_when_operator_env_expects_another(tmp_path, monkeypatch):
    run_id = "M2-20261026T082224-803b0d"
    case = _run(tmp_path, monkeypatch, "2", run_id, "completed")
    review_run.MODEL_ENV.write_text("NEXUS_LLM_MODEL=operator-selected-model\n", encoding="utf-8")
    (case / ".trace/run-T22-R1z3b-mode2.log").write_text(
        f"2026-10-26T08:22:12Z\nrun_id={run_id} status=completed\nMODE2_EXIT=0\n2026-10-26T10:41:00Z\n")
    report = review_run.review("T22-R1z3b", case.name, "2")
    assert any("wrong or missing model" in issue for issue in report["issues"])
    assert report["expected_model"] == "operator-selected-model"


def test_review_fails_closed_without_configured_operator_model(tmp_path, monkeypatch):
    run_id = "M2-20261026T082224-803b0d"
    case = _run(tmp_path, monkeypatch, "2", run_id, "completed")
    review_run.MODEL_ENV.write_text("UNRELATED=value\n", encoding="utf-8")
    (case / ".trace/run-T22-R1z3b-mode2.log").write_text(
        f"2026-10-26T08:22:12Z\nrun_id={run_id} status=completed\nMODE2_EXIT=0\n2026-10-26T10:41:00Z\n")
    report = review_run.review("T22-R1z3b", case.name, "2")
    assert any("NEXUS_LLM_MODEL" in issue for issue in report["issues"])
