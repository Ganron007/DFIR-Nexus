"""TA-5.1: evidence kinds must reach steps without conflating unrelated producers."""
from pathlib import Path

import yaml

from nexus.analysis.skill_steps import methodology_only
from nexus.knowledge.skills import families_intersect


def test_memory_event_logs_satisfy_the_stored_service_install_step():
    """The real compiled step must accept the memory events its own query reads."""
    path = (Path(__file__).resolve().parents[1] / "src/nexus/data/knowledge/skills/lateral_movement.yaml")
    skill = yaml.safe_load(path.read_text(encoding="utf-8"))
    step = next(step for step in skill["steps"] if any(
        "4697" in [str(code) for code in event.get("codes", [])]
        for event in (step.get("search") or {}).get("events", [])
    ))
    assert not methodology_only({"requires": step["requires"]}, case_families=["memprocfs"])


def test_event_log_only_evidence_does_not_imply_memory_evidence():
    """Overlapping event capability must not turn an event parser into a memory image."""
    assert not families_intersect({"evtxecmd"}, {"memory"})
    assert methodology_only({"requires": {"families": ["memory"]}}, case_families=["evtxecmd"])


def test_event_log_kind_matches_both_native_and_memory_producers():
    assert families_intersect({"evtxecmd"}, {"evtx"})
    assert families_intersect({"memprocfs"}, {"evtx"})


def test_detection_labels_do_not_turn_event_logs_into_other_artifacts():
    """Hayabusa detection types describe events, not a registry hive or browser profile."""
    assert not families_intersect({"hayabusa"}, {"registry", "browser", "powershell"})
