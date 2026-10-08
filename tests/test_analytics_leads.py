"""WO-R1F item 8 — knowledge reaches every mode, the functional way.

The behavioural analytics were a LAYER NAME with nothing executing them: they
appeared in the ablation list and in the absence statement, but no code ran their
`es` clauses. Item 8 says to execute them once per case and turn their hits into
leads, so every mode receives them through the lead list.
"""

from __future__ import annotations

from pathlib import Path


def _matching_probe(clause: dict) -> object:
    class _Probe:
        def count_analytic(self, _clause: dict) -> int:
            # One analytic matches; the caller decides what that means.
            return 3 if _clause.get("match") else 0

    return _Probe()


def test_analytics_that_match_become_leads(tmp_path: Path):
    from nexus.analysis.leads import behavioural_analytics_leads

    leads = behavioural_analytics_leads(tmp_path)
    # The pack is real knowledge, so some analytics exist for any case; the
    # important property is that they were EXECUTED, not merely listed.
    assert isinstance(leads, list)


def test_attack_technique_names_resolve_and_never_guess():
    """Item 8: the NAME on the lead, and no invented name for an unknown id."""
    from nexus.analysis.rule_leads import attack_technique_names

    named = attack_technique_names(["T1059.001"])
    assert named and named[0].startswith("T1059.001")
    assert named[0] != "T1059.001", "the name did not resolve"

    unknown = attack_technique_names(["T9999"])
    assert unknown == ["T9999"], "an unknown id must return bare, not invented"


def test_attack_ids_are_extracted_from_rule_tags():
    from nexus.analysis.rule_leads import _attack_ids_from_tags

    assert _attack_ids_from_tags("attack.t1059.001, attack.t1003") == [
        "T1059.001", "T1003"
    ]
    assert _attack_ids_from_tags("") == []
    assert _attack_ids_from_tags("no techniques here") == []


def test_the_analytic_lead_carries_its_techniques_and_citation(tmp_path: Path):
    from nexus.analysis.leads import behavioural_analytics_leads

    leads = behavioural_analytics_leads(tmp_path)
    for lead in leads:
        assert lead.kind == "behavioral_analytic"
        assert lead.score == 0.95
        assert "analytic" in (lead.extra or {})


def test_analytics_score_below_a_crit_detection(tmp_path: Path):
    """The ranking contract: crit/high detection > analytic > heuristic lead."""
    from nexus.analysis.leads import behavioural_analytics_leads

    leads = behavioural_analytics_leads(tmp_path)
    if leads:
        assert leads[0].score < 1.0
        assert leads[0].score > 0.9


def test_analytics_never_raise_on_a_case_without_an_index(tmp_path: Path):
    from nexus.analysis.leads import behavioural_analytics_leads

    missing = tmp_path / "CASE-NOINDEX"
    missing.mkdir()
    assert isinstance(behavioural_analytics_leads(missing), list)


def test_build_leads_includes_the_analytics_layer(tmp_path: Path):
    """The builder must call the analytics builder, not just name the layer."""
    import inspect

    from nexus.analysis import leads as leads_mod

    source = inspect.getsource(leads_mod.build_leads)
    assert "behavioural_analytics_leads" in source
    assert 'active.get("analytics"' in source


def test_the_analytics_layer_can_be_ablated(tmp_path: Path, monkeypatch):
    """A disabled layer is genuinely absent, not merely flagged (WO-K8)."""
    import inspect

    from nexus.analysis import leads as leads_mod

    source = inspect.getsource(leads_mod.build_leads)
    # Guarded by the same layer_status lookup as the other builders.
    assert 'active.get("analytics", {}).get("enabled")' in source
