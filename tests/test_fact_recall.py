"""IC-11 (Part 9): the fact-recall scorer reads what a run states, never the rows it cites or what it denies."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

SCORER = Path(__file__).resolve().parents[1] / "devtools" / "eval" / "fact_recall.py"
spec = importlib.util.spec_from_file_location("fact_recall", SCORER)
fact_recall = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
spec.loader.exec_module(fact_recall)  # type: ignore[union-attr]

KEY = {"facts": [
    {"id": "A", "require": [["svc.exe"], ["task", "schtask"]]},
    {"id": "B", "require": [["alice"], ["4648", "explicit credential"]]},
    {"id": "C", "require": [["timestomp", "si<fn"]]},
    {"id": "D", "require": [["winrm"]]},
]}


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-RECALL"
    (case / "analysis" / "mode3_runs").mkdir(parents=True)
    record = {
        "run_id": "M3-r",
        "candidates": [{"title": "svc.exe runs from a scheduled task", "observation": "the task runs svc.exe",
                        # a term inside a cited row is evidence the finding points at, not what it states
                        "evidence": [{"text": "alice 4648 explicit credential timestomp"}]}],
        "narrative": "Explicit credentials (4648) were used by alice.",
        "case": {"timeline": [], "attack_chain": [], "entities": [], "open_questions": []},
        "settled_claims": [{"title": "host - absence: no winrm session", "claim_kind": "absence",
                            "value": "no winrm session"}],
        "board": [],
    }
    (case / "analysis" / "mode3_runs" / "M3-r.json").write_text(json.dumps(record), encoding="utf-8")
    return case


def test_each_fact_is_placed_by_what_the_run_states(tmp_path):
    result = fact_recall.score(_case(tmp_path), KEY, "M3-r")
    tiers = {fact: found["tier"] for fact, found in result["facts"].items()}
    assert tiers["A"] == "finding"
    assert tiers["B"] == "narrative"
    assert tiers["C"] == "missing", "a term in a cited row is not a stated fact"
    assert tiers["D"] == "missing", "an absence claim that names the fact denies it"
    assert result["counts"] == {"finding": 1, "narrative": 1, "board": 0, "missing": 2}
