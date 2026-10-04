"""WO-K7 + WO-K8 — absence honesty and per-layer ablation.

K7's test: a run with one source disabled says so in the run record, the report
and the API. K8's test: each toggle actually removes its layer, asserted on the
run record.

Both matter because a disabled layer and a layer that found nothing look
identical in a "no findings" result.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from nexus.analysis.absence import absence_statement, record, source_activity
from nexus.analysis.layers import (
    ENV_KNOWLEDGE_DISABLE,
    ENV_LEADS_DISABLE,
    KNOWLEDGE_LAYERS,
    LEAD_SOURCES,
    disabled_names,
    knowledge_enabled,
    layer_status,
    leads_enabled,
    unknown_toggles,
)

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _clean_toggles(monkeypatch):
    """No test inherits another's toggles."""
    monkeypatch.delenv(ENV_LEADS_DISABLE, raising=False)
    monkeypatch.delenv(ENV_KNOWLEDGE_DISABLE, raising=False)


# ---------------------------------------------------------------------------
# K8: each toggle removes its layer
# ---------------------------------------------------------------------------

def test_the_toggle_names_match_the_work_order():
    assert set(LEAD_SOURCES) == {"needles", "rules", "baselines", "anomaly", "analytics"}
    assert set(KNOWLEDGE_LAYERS) == {"skills", "playbooks", "kb", "rag", "registries"}


@pytest.mark.parametrize("source", LEAD_SOURCES)
def test_each_lead_toggle_removes_its_layer(monkeypatch, source):
    """Asserted per layer, so one broken switch cannot hide behind the others."""
    assert leads_enabled(source) is True
    monkeypatch.setenv(ENV_LEADS_DISABLE, source)
    assert leads_enabled(source) is False, f"{source} was not disabled"
    status = layer_status()
    assert status["leads"][source]["enabled"] is False
    assert status["leads"][source]["reason"]
    # Every other layer is untouched.
    for other in LEAD_SOURCES:
        if other != source:
            assert leads_enabled(other) is True, f"{source} also disabled {other}"


@pytest.mark.parametrize("layer", KNOWLEDGE_LAYERS)
def test_each_knowledge_toggle_removes_its_layer(monkeypatch, layer):
    assert knowledge_enabled(layer) is True
    monkeypatch.setenv(ENV_KNOWLEDGE_DISABLE, layer)
    assert knowledge_enabled(layer) is False
    assert layer_status()["knowledge"][layer]["enabled"] is False


def test_the_run_record_reports_disabled_layers(monkeypatch):
    """The work order's ablation test: the record says what was off."""
    monkeypatch.setenv(ENV_LEADS_DISABLE, "rules,analytics")
    monkeypatch.setenv(ENV_KNOWLEDGE_DISABLE, "rag")
    status = layer_status()
    assert status["leads"]["rules"]["enabled"] is False
    assert status["leads"]["analytics"]["enabled"] is False
    assert status["knowledge"]["rag"]["enabled"] is False
    assert status["leads"]["needles"]["enabled"] is True
    assert sorted(disabled_names()) == ["analytics", "rag", "rules"]


def test_an_alias_does_not_silently_disable_nothing(monkeypatch):
    """`rule_engines` must mean `rules`; a typo must not look like a live layer."""
    monkeypatch.setenv(ENV_LEADS_DISABLE, "rule_engines,hayabusa")
    assert leads_enabled("rules") is False


def test_an_unknown_toggle_name_is_reported_not_swallowed(monkeypatch):
    monkeypatch.setenv(ENV_LEADS_DISABLE, "rules,nope_layer")
    assert unknown_toggles()["leads"] == ["nope_layer"]
    # And it does not disable anything real.
    assert leads_enabled("analytics") is True


# ---------------------------------------------------------------------------
# K7: the statement
# ---------------------------------------------------------------------------

def _leads(kinds_and_engines=None):
    out = []
    for kind in kinds_and_engines or []:
        out.append({"kind": kind, "subject": kind, "family": "hayabusa", "detail": "d",
                    "rows": [], "audit_ids": [], "score": 0.5,
                    "extra": {"engine": "hayabusa"} if kind == "rule_engine" else {}})
    return out


def test_the_statement_replaces_no_findings(tmp_path: Path):
    statement = absence_statement(tmp_path, families=["hayabusa", "pecmd"],
                                  leads=_leads(["rarity"]))
    assert statement["statement"]
    assert "not observed by" in statement["statement"]
    assert statement["instead_of_no_findings"] == statement["statement"]
    assert statement["not_examined"] == []


def test_a_disabled_source_is_named_and_not_counted_as_having_run(tmp_path: Path,
                                                                 monkeypatch):
    """K7's test: a run with one source disabled says so."""
    monkeypatch.setenv(ENV_LEADS_DISABLE, "rules")
    statement = absence_statement(tmp_path, families=["hayabusa"], leads=_leads([]))
    assert "rule engines" in statement["disabled"]
    assert "rule engines" not in statement["ran"]
    assert "layers disabled for this run" in statement["statement"]
    # And the per-source table says why.
    assert statement["sources"]["rules"]["enabled"] is False
    assert statement["sources"]["rules"]["ran"] is False
    assert statement["sources"]["rules"]["reason"], "a disabled source must say why"


def test_an_unexamined_family_is_named(tmp_path: Path):
    statement = absence_statement(tmp_path, families=["hayabusa", "pecmd"], leads=[])
    assert statement["examined_by"], "the sources that can read these families must be listed"
    assert "statement" in statement


def test_a_source_that_produced_nothing_is_distinguished_from_a_disabled_one(
    tmp_path: Path, monkeypatch
):
    """The whole point: 'ran and found nothing' != 'never ran'."""
    silent = absence_statement(tmp_path, families=["hayabusa"], leads=[])
    assert "no output from" in silent["statement"] or silent["never_ran"]

    monkeypatch.setenv(ENV_LEADS_DISABLE, "rules")
    disabled = absence_statement(tmp_path, families=["hayabusa"], leads=[])
    assert "disabled for this run" in disabled["statement"]
    assert "no output from" not in disabled["statement"] or "rule engines" not in (
        disabled["statement"].split("no output from")[1].split(";")[0]
    )


def test_source_activity_counts_contributions(tmp_path: Path):
    activity = source_activity(tmp_path, leads=_leads(["rarity", "rarity", "rule_engine"]),
                               families=["hayabusa"])
    assert activity["anomaly"]["count"] == 2
    assert activity["rules"]["ran"] is True
    assert set(activity) >= set(LEAD_SOURCES)


def test_record_is_small_enough_for_a_run_record(tmp_path: Path):
    block = record(tmp_path, ["hayabusa", "pecmd"], leads=[])
    assert set(block) == {"statement", "ran", "never_ran", "disabled", "not_examined",
                          "examined_by"}
    assert "coverage" not in block, "the per-family table belongs in the briefing, not the record"


def test_the_statement_never_claims_nothing_happened_when_nothing_is_known(tmp_path: Path):
    """An empty case must still produce a sentence, not an empty string."""
    statement = absence_statement(tmp_path)
    assert statement["statement"]
    assert len(statement["statement"]) > 10


# ---------------------------------------------------------------------------
# K7's three surfaces
# ---------------------------------------------------------------------------

def test_the_api_exposes_the_statement():
    """The work order requires it in the API; assert the route is registered."""
    text = (REPO / "src" / "nexus" / "dashboard" / "app.py").read_text(encoding="utf-8")
    assert "/portal/api/case/absence" in text
    assert re.search(r"api_case_absence", text), "the handler is missing"
    assert "absence_statement" in text


def test_the_briefing_carries_the_statement():
    """The report and the UI read the briefing, so it must be in there."""
    text = (REPO / "src" / "nexus" / "langgraph" / "briefing.py").read_text(encoding="utf-8")
    assert "absence_statement" in text
    assert 'out["absence"]' in text


def test_the_run_record_carries_the_statement(tmp_path: Path, monkeypatch):
    """A run record must be able to say what was disabled."""
    import nexus.analysis.absence as absence

    assert callable(absence.record)
    monkeypatch.setenv(ENV_LEADS_DISABLE, "needles")
    block = absence.record(tmp_path, ["hayabusa"], leads=[])
    assert block["disabled"], "the record must name the disabled layers"
    assert "disabled for this run" in block["statement"]


def test_the_pipeline_run_manifest_carries_the_layers(tmp_path: Path, monkeypatch):
    """The WO says a toggle must be asserted ON THE RUN RECORD.

    Asserted through the real writer, so this fails if the wiring stops recording
    it - not merely if `layer_status()` returns the wrong thing.
    """
    from nexus.langgraph.pipeline_runs import create_run, finalize_run, load_manifest

    monkeypatch.setenv(ENV_LEADS_DISABLE, "rules")
    case = tmp_path / "CASE-RUNRECORD"
    case.mkdir()
    run = create_run(case, "tools", [])
    manifest = load_manifest(run.path)

    assert "layers" in manifest, "the run record does not carry the layer state"
    assert manifest["layers"]["leads"]["rules"]["enabled"] is False
    assert manifest["layers"]["leads"]["rules"]["reason"]
    assert manifest["layers"]["leads"]["needles"]["enabled"] is True

    finalize_run(run, "completed")
    finalized = load_manifest(run.path)
    assert "absence" in finalized, "the finished run must say what it could observe"
    assert finalized["absence"]["disabled"], finalized["absence"]


def test_a_run_with_no_toggles_records_every_layer_enabled(tmp_path: Path):
    from nexus.langgraph.pipeline_runs import create_run, load_manifest

    case = tmp_path / "CASE-RUNCLEAN"
    case.mkdir()
    manifest = load_manifest(create_run(case, "tools", []).path)
    assert manifest["layers"]["leads"]["rules"]["enabled"] is True
    assert manifest["layers"]["knowledge"]["rag"]["enabled"] is True
    assert manifest["layers"]["unknown_toggles"] == {"leads": [], "knowledge": []}


# ---------------------------------------------------------------------------
# K8: --ablate
# ---------------------------------------------------------------------------

def _eval_run_module():
    import importlib.util
    import sys as _sys

    spec = importlib.util.spec_from_file_location("eval_run_ablate", REPO / "scripts" / "eval_run.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    _sys.modules["eval_run_ablate"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_ablate_covers_every_layer_and_a_subset_works():
    er = _eval_run_module()
    every = er.ablations_to_run("", True)
    assert set(every) == set(LEAD_SOURCES) | set(KNOWLEDGE_LAYERS)
    assert er.ablations_to_run("rules,rag", False) == ["rules", "rag"]
    assert er.ablations_to_run("", False) == []


def test_ablate_refuses_an_unknown_layer():
    """A typo must fail the command, not silently ablate nothing."""
    er = _eval_run_module()
    with pytest.raises(SystemExit) as exc:
        er.ablations_to_run("rule_enginess", False)
    assert "unknown layer" in str(exc.value)


def test_the_ablation_table_reports_a_delta_per_layer():
    """A layer's removal must be visible as a recall/precision/FP delta."""
    er = _eval_run_module()

    def case(recall, precision, fp):
        return {
            "dimensions": {"techniques": {"recall": recall, "precision": precision}},
            "false_positive": {"benign_only": fp},
        }

    runs = [
        {"label": "baseline", "cases": [case(0.667, 0.30, 0), case(0.5, 0.25, 1)]},
        {"label": "ablate:rules", "cases": [case(0.0, 0.0, 0), case(0.0, 0.0, 0)]},
        {"label": "ablate:analytics", "cases": [case(0.667, 0.30, 0), case(0.5, 0.25, 1)]},
    ]
    table = er._ablation_table(runs, "baseline")
    assert "Ablation (WO-K8)" in table
    assert "| rules |" in table
    assert "| analytics |" in table
    # Disabling rules must show a recall drop; disabling analytics must not.
    rules_row = [line for line in table.splitlines() if line.startswith("| rules |")][0]
    analytics_row = [line for line in table.splitlines() if line.startswith("| analytics |")][0]
    assert "-0.583" in rules_row or "-0.584" in rules_row, rules_row
    assert "+0.000" in analytics_row, analytics_row
    # And the operator decides the cuts, so the table must say so.
    assert "operator decides the cuts" in table


def test_the_ablation_table_lists_layers_that_were_not_run():
    er = _eval_run_module()
    runs = [{"label": "baseline", "cases": [{
        "dimensions": {"techniques": {"recall": 0.5, "precision": 0.5}},
        "false_positive": {"benign_only": 0}}]}]
    table = er._ablation_table(runs, "baseline")
    assert "_(not run)_" in table
    assert "| needles |" in table


def test_the_ablation_table_needs_a_baseline():
    """No baseline means no delta to compute, so no table."""
    er = _eval_run_module()
    assert er._ablation_table([], "baseline") == ""
    # A baseline with nothing ablated still gets a table - it says nothing ran.
    only_baseline = [{"label": "baseline", "cases": []}]
    table = er._ablation_table(only_baseline, "baseline")
    assert "Ablation (WO-K8)" in table
    assert "_(not run)_" in table
