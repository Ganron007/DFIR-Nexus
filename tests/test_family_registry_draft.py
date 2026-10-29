"""Check source-backed draft vocabulary without treating it as complete coverage."""
from nexus.ingest.registry import get_registry
from nexus.knowledge.family_registry import FamilyRegistry
from nexus.langgraph.lane_gate import STAGED_FAMILY


def test_source_backed_event_and_memory_kinds_stay_directional():
    registry = FamilyRegistry.load()
    assert registry.intersect({"memprocfs"}, {"evtx"}) == {"evtx"}
    assert registry.intersect({"evtxecmd"}, {"evtx"}) == {"evtx"}
    assert registry.intersect({"vol"}, {"memory"}) == {"memory"}
    assert not registry.intersect({"evtxecmd"}, {"memory"})


def test_known_importer_spelling_is_attached_to_its_source():
    registry = FamilyRegistry.load()
    assert registry.intersect({"zeek"}, {"ingest-zeek"}) == {"ingest-zeek"}
    assert registry.intersect({"ingest-zeek"}, {"zeek"}) == {"zeek"}


def test_registered_importer_and_staged_producers_have_registry_entries():
    """The producers registered by the product must each resolve in the inventory."""
    registry = FamilyRegistry.load()
    producers = {source.value for source in get_registry().all_sources()} | set(STAGED_FAMILY.values())
    assert not producers - registry._aliases.keys()


def test_shared_sources_are_disambiguated_by_actual_importer_class():
    registry = FamilyRegistry.load()
    email = "nexus.ingest.generic.email_import.EmailImporter"
    jsonl = "nexus.ingest.generic.jsonl.JSONLImporter"
    m365 = "nexus.ingest.cloud.m365.M365Importer"
    sysdig = "nexus.ingest.network.sysdig.SysdigImporter"
    assert registry.importer_families([email]) == {"email"}
    assert registry.importer_families([jsonl]) == {"generic_jsonl"}
    assert registry.importer_families([m365, sysdig]) == {"m365", "sysdig"}
    assert not registry.importer_families(["nexus.ingest.cloud.azure.AzureImporter"])
