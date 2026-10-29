"""One actual producer must not become two selection signals through aliases."""
import pytest

from nexus.knowledge.skills import _score_skill, get_skills, retrieve_skills, skills_for


def test_shared_source_and_importer_are_one_signal_for_the_real_skill():
    skill = next(item for item in get_skills() if item.get("skill") == "cloud_identity_forensics")
    families = {"azure", "m365"}
    single = [{"azure", "m365"}]
    distinct = [{"azure", "m365"}, {"azure"}]
    assert _score_skill(skill, families, set(), set(), single)[0] == 1
    assert _score_skill(skill, families, set(), set(), distinct)[0] == 2


def test_both_skill_surfaces_use_the_same_grouped_ranking():
    group = [{"azure", "m365"}]
    plain = skills_for({"azure"}, family_groups=group, limit=50)
    cited = retrieve_skills({"azure"}, family_groups=group, limit=50)
    assert [s["skill"] for s in plain] == [s["skill"] for s in cited]
    result = next(s for s in cited if s["skill"] == "cloud_identity_forensics")
    assert result["score"] == 1


def test_an_unobserved_requested_source_does_not_become_a_group():
    assert not skills_for({"azure"}, family_groups=[], limit=50)


def test_aliases_of_one_producer_are_one_signal():
    from nexus.knowledge.skills import _distinct_family_matches

    assert _distinct_family_matches({"mftecmd", "mftecmd-usn"}, {"mftecmd", "mftecmd-usn"}) == 1


def test_memory_capability_does_not_merge_distinct_producers():
    """MemProcFS and Volatility both yield memory evidence and stay two producers. `volatility` is not a second
    producer: its importer reads Volatility 3 output (`ingest/df/volatility.py`), the tool the lane runs as `vol`, so
    it is one of that producer's spellings and one selection signal."""
    from nexus.knowledge.family_registry import families_intersect
    from nexus.knowledge.skills import _distinct_family_matches

    assert not families_intersect({"memprocfs"}, {"vol"})
    assert families_intersect({"memprocfs"}, {"kind:memory"})
    assert families_intersect({"volatility"}, {"vol"}) and families_intersect({"volatility"}, {"kind:memory"})
    assert _distinct_family_matches({"vol", "volatility"}, {"vol", "volatility"}) == 1


def test_mode2_planner_uses_measured_importer_groups(tmp_path, monkeypatch):
    from nexus.analysis import work_orders
    from nexus.knowledge.family_registry import get_family_registry
    from nexus.langgraph import backbone
    from nexus.modes.multi_role import plan_work_orders

    importer = "nexus.ingest.cloud.m365.M365Importer"
    names = sorted(get_family_registry().evidence_group("azure", [importer]))
    measured = {"family_rows": {"azure": 1}, "evidence_groups": [
        {"source": "azure", "importers": [importer], "families": names, "rows": 1},
    ]}
    monkeypatch.setattr(backbone, "backbone_call", lambda *args, **kwargs: measured)
    monkeypatch.setattr(work_orders, "orders_from_leads", lambda *args, **kwargs: [])

    class Sink:
        def emit(self, event):
            pass

    orders = plan_work_orders(tmp_path, "", run_id="M2-group", sink=Sink())
    refs = next(order.skill_refs for order in orders if order.role == "correlation")
    cloud = next(ref for ref in refs if ref["skill"] == "cloud_identity_forensics")
    assert cloud["score"] == 1


def test_mode2_planner_does_not_hide_failed_group_measurement(tmp_path, monkeypatch):
    from nexus.langgraph import backbone
    from nexus.modes.multi_role import plan_work_orders

    monkeypatch.setattr(backbone, "backbone_call", lambda *args, **kwargs: {"error": "incomplete groups"})
    with pytest.raises(RuntimeError, match="incomplete groups"):
        plan_work_orders(tmp_path, "", run_id="M2-group", sink=None)


def test_compiled_specific_importer_query_does_not_match_its_shared_source():
    from devtools.knowledge.step_search import compile_source
    from nexus.knowledge.query_validation import extract_es_fields, validate_stored_query
    from nexus.langgraph.es_native import validate_query

    query = compile_source({"families": ["m365"]})
    validate_query(query)
    assert "importer_leaf" in extract_es_fields(query)
    assert validate_stored_query(query, declared_families=["m365"], citation="test") == []
    clauses = query["bool"]["filter"][0]["bool"]["should"]
    assert {"terms": {"family": ["m365"]}} in clauses
    assert {"terms": {"importer_leaf": ["nexus.ingest.cloud.m365.M365Importer"]}} in clauses
    assert all("azure" not in str(clause) for clause in clauses)


def test_mode3_reports_unavailable_group_measurement_even_with_requested_families(tmp_path, monkeypatch):
    from nexus.langgraph import backbone
    from nexus.modes.multi_agent import run_mode3

    case = tmp_path / "CASE-GROUPS"
    case.mkdir()
    monkeypatch.setattr(backbone, "backbone_call", lambda *args, **kwargs: {"error": "incomplete groups"})
    result = run_mode3(case, "", model=object(), families=[("azure", 1)], es_ok=True)
    assert result["status"] == "failed"
    assert result["stop_reason"] == "evidence_group_unavailable"
    assert "incomplete groups" in result["error"]
