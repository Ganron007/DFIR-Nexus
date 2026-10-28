"""ITM Mode 3 pattern chains — load, id validation, value-anchored matching."""

from __future__ import annotations


def test_itm_library_loads_with_valid_ids():
    from pathlib import Path

    import yaml

    from nexus.langgraph.itm import itm_index

    path = Path(__file__).resolve().parents[1] / "src" / "nexus" / "data" / "knowledge" / "attack_patterns_itm.yaml"
    patterns = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("patterns") or []
    itm_patterns = [p for p in patterns if p.get("itm")]
    assert len(itm_patterns) >= 8, [p.get("name") for p in itm_patterns]
    index = itm_index()
    for pattern in itm_patterns:
        assert pattern.get("required_values"), pattern.get("name")
        for ref in pattern["itm"]:
            section = ref.split("/", 1)[1]
            assert section in index, (pattern.get("name"), ref)
        for mitre in pattern.get("mitre") or []:
            assert mitre.startswith("T"), (pattern.get("name"), mitre)
