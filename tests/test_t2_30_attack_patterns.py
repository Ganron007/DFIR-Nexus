"""Tests for Attack Pattern Matching Engine (T2-30 / WP 13.8)."""

from nexus.analysis.attack_patterns import AttackPatternMatcher


def test_attack_pattern_matcher_loads_knowledge():
    """Matcher must successfully parse knowledge library files."""
    matcher = AttackPatternMatcher()
    assert len(matcher.patterns) > 10
    pattern_names = [p.name for p in matcher.patterns]
    assert "persistence_registry_run_key" in pattern_names
    assert "persistence_scheduled_task" in pattern_names


def test_match_persistence_registry_run_key():
    """Events with windows_path and process_name in registry family trigger persistence pattern."""
    matcher = AttackPatternMatcher()
    events = [
        {
            "id": "EV-01",
            "family": "registry",
            "timestamp": "2026-05-10T10:00:00Z",
            "entities": {
                "windows_path": ["C:\\Windows\\System32\\evil.exe"],
                "process_name": ["reg.exe"],
            },
            "message": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run entry added",
        },
        {
            "id": "EV-02",
            "family": "evtx",
            "timestamp": "2026-05-10T10:02:00Z",
            "entities": {
                "process_name": ["evil.exe"],
                "domain_user": ["CORP\\victim"],
            },
            "message": "Process evil.exe spawned from registry run key",
        },
    ]

    matches = matcher.match_events(events)
    assert matches, "Expected at least one matched pattern"
    run_key_match = next((m for m in matches if m.pattern_name == "persistence_registry_run_key"), None)
    assert run_key_match is not None
    assert "T1547.001" in run_key_match.mitre_techniques or "T1060" in run_key_match.mitre_techniques
    assert "windows_path" in run_key_match.matched_entities
    assert "process_name" in run_key_match.matched_entities
    assert run_key_match.confidence >= 0.7


def test_missing_required_entities_does_not_match():
    """Events without all required entities must not trigger the pattern."""
    matcher = AttackPatternMatcher()
    # Missing windows_path for persistence_registry_run_key
    events = [
        {
            "id": "EV-03",
            "family": "registry",
            "timestamp": "2026-05-10T10:00:00Z",
            "entities": {
                "process_name": ["reg.exe"],
            },
            "message": "Registry queried",
        }
    ]
    matches = matcher.match_events(events)
    run_key_match = next((m for m in matches if m.pattern_name == "persistence_registry_run_key"), None)
    assert run_key_match is None
