"""External-threat value-anchored patterns + ATT&CK detection grounding."""

from __future__ import annotations


def _ent(etype: str, value: str, families: list[str]) -> dict:
    return {
        "value": value,
        "hits": [{"family": f, "file": "x.csv", "line": 1} for f in families],
        "families": families,
    }


def test_external_library_loads_with_anchors_and_ids():
    from nexus.langgraph.pattern_agent import PatternAgent

    agent = PatternAgent()
    external = [p for p in agent._patterns if str(p.get("name", "")).startswith("ext_")]
    assert len(external) >= 10, len(external)
    for pattern in external:
        assert pattern.get("required_values"), pattern.get("name")
        assert pattern.get("mitre"), pattern.get("name")
        assert pattern.get("evidence"), pattern.get("name")


def test_psexec_lateral_movement_matches():
    from nexus.langgraph.pattern_agent import PatternAgent

    agent = PatternAgent()
    entities = {
        "process_name": [_ent("process_name", "PsExec.exe", ["evtxecmd", "recmd"])],
        "service_name": [_ent("service_name", "PSEXESVC", ["evtxecmd", "recmd"])],
    }
    names = [m["name"] for m in agent.detect_patterns(entities, None)["patterns"]]
    assert "ext_lateral_smb_psexec" in names


def test_rmm_uac_and_temp_execution_patterns():
    from nexus.langgraph.pattern_agent import PatternAgent

    agent = PatternAgent()

    rmm = {"process_name": [_ent("process_name", "TeamViewer.exe", ["prefetch", "amcache"])]}
    assert "ext_remote_management_tool" in [
        m["name"] for m in agent.detect_patterns(rmm, None)["patterns"]
    ]

    uac = {"process_name": [_ent("process_name", "fodhelper.exe", ["evtxecmd", "recmd"])]}
    assert "ext_uac_bypass_autoelevate" in [
        m["name"] for m in agent.detect_patterns(uac, None)["patterns"]
    ]

    temp = {
        "process_name": [_ent("process_name", "a.exe", ["evtxecmd", "prefetch"])],
        "windows_path": [
            _ent("windows_path", "C:\\Users\\fredr\\AppData\\Local\\Temp\\a.exe",
                 ["evtxecmd", "prefetch"]),
        ],
    }
    assert "ext_exec_from_temp" in [
        m["name"] for m in agent.detect_patterns(temp, None)["patterns"]
    ]

    # A benign tool matches none of the anchored external patterns.
    benign = {"process_name": [_ent("process_name", "notepad.exe", ["evtxecmd", "hayabusa"])]}
    ext_names = {
        m["name"] for m in agent.detect_patterns(benign, None)["patterns"]
        if str(m["name"]).startswith("ext_")
    }
    assert ext_names == set(), ext_names


def test_attack_detection_guidance_reaches_prompts():
    from nexus.knowledge.attack_needles import attack_context_for, attack_detections_for

    detections = attack_detections_for(["T1021.001"], cap=1)
    assert detections, "no detection strategy for T1021.001 in the deep registry"
    found = detections[0]
    assert found["strategy"].startswith("DET")
    assert found["text"]

    block = attack_context_for([{
        "technique": "T1021.001",
        "name": "Remote Desktop Protocol",
        "needles": ["mstsc.exe"],
        "caveats": ["legitimate admin use is common"],
    }])
    assert "T1021.001" in block
    assert "detection (" in block
    assert "caveat:" in block
