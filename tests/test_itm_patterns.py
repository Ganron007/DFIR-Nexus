"""ITM Mode 3 pattern chains — load, id validation, value-anchored matching."""

from __future__ import annotations


def _ent(etype: str, value: str, families: list[str]) -> dict:
    return {
        "value": value,
        "hits": [{"family": f, "file": "x.csv", "line": 1} for f in families],
        "families": families,
    }


def test_itm_library_loads_with_valid_ids():
    from nexus.langgraph.itm import itm_index
    from nexus.langgraph.pattern_agent import PatternAgent

    agent = PatternAgent()
    itm_patterns = [p for p in agent._patterns if p.get("itm")]
    assert len(itm_patterns) >= 8, [p.get("name") for p in itm_patterns]
    index = itm_index()
    for pattern in itm_patterns:
        assert pattern.get("required_values"), pattern.get("name")
        for ref in pattern["itm"]:
            section = ref.split("/", 1)[1]
            assert section in index, (pattern.get("name"), ref)
        for mitre in pattern.get("mitre") or []:
            assert mitre.startswith("T"), (pattern.get("name"), mitre)


def test_shadow_deletion_matches_only_with_value_anchor():
    from nexus.langgraph.pattern_agent import PatternAgent

    agent = PatternAgent()
    entities = {
        "process_name": [
            _ent("process_name", "VSSADMIN.EXE", ["evtxecmd", "hayabusa"]),
        ],
        "domain_user": [
            _ent("domain_user", "SRL\\fredr", ["evtxecmd", "prefetch"]),
        ],
    }
    found = [m["name"] for m in agent.detect_patterns(entities, None)["patterns"]]
    assert "itm_anti_forensics_shadow_deletion" in found

    # Same shape, different tool -> no match (the value anchor gates it).
    entities2 = {
        "process_name": [
            _ent("process_name", "notepad.exe", ["evtxecmd", "hayabusa"]),
        ],
        "domain_user": [
            _ent("domain_user", "SRL\\fredr", ["evtxecmd", "prefetch"]),
        ],
    }
    found2 = [m["name"] for m in agent.detect_patterns(entities2, None)["patterns"]]
    assert "itm_anti_forensics_shadow_deletion" not in found2


def test_rdp_and_web_exfil_patterns_match():
    from nexus.langgraph.pattern_agent import PatternAgent

    agent = PatternAgent()

    rdp = {
        "process_name": [_ent("process_name", "mstsc.exe", ["evtxecmd", "hayabusa"])],
        "domain_user": [_ent("domain_user", "SRL\\fredr", ["evtxecmd", "hayabusa"])],
    }
    names = [m["name"] for m in agent.detect_patterns(rdp, None)["patterns"]]
    assert "itm_rdp_remote_access" in names

    exfil = {
        "domain": [_ent("domain", "mega.nz", ["browser", "srumecmd"])],
        "url": [_ent("url", "https://mega.nz/folder/abc", ["browser", "srumecmd"])],
    }
    names2 = [m["name"] for m in agent.detect_patterns(exfil, None)["patterns"]]
    assert "itm_exfil_web_service" in names2


def test_pattern_matches_carry_itm_and_evidence():
    from nexus.langgraph.pattern_agent import PatternAgent

    agent = PatternAgent()
    entities = {
        "process_name": [_ent("process_name", "sc.exe", ["evtxecmd", "recmd"])],
        "windows_path": [
            _ent("windows_path", "C:\\Users\\fredr\\svc.exe", ["evtxecmd", "recmd"]),
        ],
    }
    matches = agent.detect_patterns(entities, None)["patterns"]
    persistence = [m for m in matches if m["name"] == "itm_persistence_service_task"]
    assert persistence
    match = persistence[0]
    assert match["itm"] == ["AR3/PR046"]
    assert match["evidence"]
    assert "ITM:" in match["narrative"]


def test_unknown_itm_and_mitre_ids_are_dropped(tmp_path):
    import yaml

    from nexus.langgraph.pattern_agent import PatternAgent

    path = tmp_path / "patterns.yaml"
    path.write_text(yaml.safe_dump({
        "patterns": [{
            "name": "bogus",
            "itm": ["PR999", "AR3/PR026"],
            "mitre": ["T9999", "T1021.001"],
            "required_entities": ["process_name"],
            "families": [],
            "min_entities": 1,
            "confidence_base": 0.5,
        }],
    }), encoding="utf-8")
    agent = PatternAgent(patterns_path=path)
    pattern = agent._patterns[0]
    assert pattern["itm"] == ["AR3/PR026"]   # unknown PR999 dropped
    assert pattern["mitre"] == ["T1021.001"]  # unknown T9999 dropped
