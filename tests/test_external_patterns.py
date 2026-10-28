"""External-threat value-anchored patterns + ATT&CK detection grounding."""

from __future__ import annotations


def _library(name: str) -> list[dict]:
    from pathlib import Path

    import yaml

    path = Path(__file__).resolve().parents[1] / "src" / "nexus" / "data" / "knowledge" / name
    return list((yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("patterns") or [])


def test_external_library_loads_with_anchors_and_ids():
    from nexus.knowledge.loader import get_attack_registry

    techniques = {str(t.get("id") or "").upper() for t in get_attack_registry().get("techniques") or []}
    external = [p for p in _library("attack_patterns_external.yaml") if str(p.get("name", "")).startswith("ext_")]
    assert len(external) >= 10, len(external)
    for pattern in external:
        assert pattern.get("required_values"), pattern.get("name")
        assert pattern.get("mitre"), pattern.get("name")
        assert pattern.get("evidence"), pattern.get("name")
        assert all(str(t).upper() in techniques for t in pattern["mitre"]), pattern.get("name")


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
