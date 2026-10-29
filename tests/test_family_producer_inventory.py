"""Source inventory retains producer evidence and separates candidates from facts."""
from devtools.runbook.family_producers import inventory
from nexus.ingest.registry import get_registry
from nexus.knowledge.family_registry import FamilyRegistry
from nexus.langgraph.lane_gate import STAGED_FAMILY


def test_registered_and_staged_families_have_their_source_evidence():
    evidence = inventory()["candidate_evidence"]
    for source in get_registry().all_sources():
        assert evidence[source.value]["registered_importer_source"]
    for name in STAGED_FAMILY.values():
        assert evidence[name]["staged_family"]


def test_direct_output_paths_and_hints_are_identified_as_candidates():
    evidence = inventory()["candidate_evidence"]
    assert any(ref.startswith("tool_lane.py:") for ref in evidence["mplog"]["direct_path_projection"])
    assert any(ref.startswith("tool_lane.py:") for ref in evidence["wmi_parser"]["direct_path_projection"])
    assert any(ref.startswith("network_lane.py:") for ref in evidence["network"]["direct_path_projection"])
    assert any(ref.startswith("network_lane.py:") for ref in evidence["nfdump"]["literal_job_tool"])
    assert "classifier_hint" in evidence["vol"]
    assert "_staged" not in evidence
    assert "_tool_lane_ledger.json" not in evidence


def test_literal_lane_output_projections_resolve_in_registry():
    """Check the actual classifier against every literal lane output folder."""
    observed = inventory()
    assert not observed["dynamic_out_dirs"], observed["dynamic_out_dirs"]
    projected = set(observed["folder_family_projection"].values())
    projected.update(observed["stdout_family_projection"].values())
    assert not projected - FamilyRegistry.load()._aliases.keys()
