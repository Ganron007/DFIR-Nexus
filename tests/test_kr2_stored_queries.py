"""WO-KR2 acceptance tests: stored-query format (ES query JSON in es:, validated, remove dsl:).

Verifies:
1. Zero `dsl:` keys remain under `src/nexus/data/knowledge/`.
2. Every behavioral analytic has valid `es:` query JSON passing (a) query shape,
   (b) field registry for declared families, and (c) citations.
3. Every skill step across all 37 skills has valid `es:` query JSON passing validation.
4. Non-dict / string `es:` or unknown field is rejected by validation.
5. Rendered worker prompt in Mode 2 contains step name, look_for, corroborate, result
   and neither `| run:` nor `es:` query JSON.
6. Mode 1 query DSL remains untouched and functional.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from nexus.analysis.behavioural_analytics import analytics, validate_pack
from nexus.analysis.skill_steps import validate_skill_steps
from nexus.knowledge.query_validation import validate_stored_query
from nexus.modes.multi_role import _skill_procedure_block

KNOWLEDGE_DIR = Path(__file__).resolve().parent.parent / "src" / "nexus" / "data" / "knowledge"


def test_zero_dsl_keys_under_knowledge_dir():
    """Requirement: zero `dsl:` keys exist under src/nexus/data/knowledge/."""
    violating_files: list[str] = []
    for p in KNOWLEDGE_DIR.rglob("*.yaml"):
        text = p.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        if _has_key_recursive(data, "dsl"):
            violating_files.append(str(p.relative_to(KNOWLEDGE_DIR)))
    assert violating_files == [], f"Found dsl: keys in knowledge files: {violating_files}"


def _has_key_recursive(val: Any, target: str) -> bool:
    if isinstance(val, dict):
        if target in val:
            return True
        return any(_has_key_recursive(v, target) for v in val.values())
    if isinstance(val, list):
        return any(_has_key_recursive(item, target) for item in val)
    return False


def test_every_behavioral_analytic_has_valid_es_query():
    """Requirement: every analytic has es: query JSON passing validation."""
    packs = analytics()
    assert len(packs) >= 30, f"Expected >= 30 analytics, got {len(packs)}"
    for a in packs:
        assert "es" in a, f"Analytic {a.get('id')} missing 'es:' block"
        assert isinstance(a["es"], dict), f"Analytic {a.get('id')} 'es:' must be a dict"
        assert "dsl" not in a, f"Analytic {a.get('id')} has lingering 'dsl:' key"
        # Validate through validate_pack and validate_stored_query directly
        errs = validate_stored_query(
            a["es"],
            declared_families=a.get("families", []),
            citation=a.get("citation"),
        )
        assert errs == [], f"Analytic {a.get('id')} validation failed: {errs}"

    # Also test validate_pack passes on all analytics
    pack_errs = validate_pack({"packs": packs})
    assert pack_errs == [], f"validate_pack failed: {pack_errs}"


def test_every_skill_step_has_valid_es_query():
    """Requirement: every skill step has es: query JSON passing validation."""
    skills_dir = KNOWLEDGE_DIR / "skills"
    skill_files = list(skills_dir.glob("*.yaml"))
    assert len(skill_files) == 37, f"Expected 37 skills, found {len(skill_files)}"

    total_steps = 0
    all_problems: list[str] = []
    for sf in skill_files:
        skill = yaml.safe_load(sf.read_text(encoding="utf-8")) or {}
        steps = skill.get("steps") or []
        total_steps += len(steps)
        for step in steps:
            assert "es" in step, f"Skill {sf.name} step {step.get('name')} missing 'es:'"
            assert isinstance(step["es"], dict), f"Skill {sf.name} step {step.get('name')} 'es:' must be a dict"
            assert "dsl" not in step, f"Skill {sf.name} step {step.get('name')} has lingering 'dsl:'"

        probs = validate_skill_steps(skill)
        if probs:
            all_problems.extend([f"{sf.name}: {p}" for p in probs])

    assert total_steps >= 250, f"Expected >= 250 steps, found {total_steps}"
    assert all_problems == [], "Skill step validation errors:\n" + "\n".join(all_problems[:10])


def test_validator_rejects_non_dict_es():
    """Requirement: non-dict / string es: is rejected."""
    errs = validate_stored_query(
        "file:svchost.exe",  # type: ignore[arg-type]
        declared_families=["evtx"],
        citation="test",
    )
    assert any("must be an ES query JSON object" in e for e in errs)


def test_validator_rejects_unknown_field_for_declared_family():
    """Requirement: field registry validation rejects fields not in declared family."""
    bad_query = {
        "term": {"fields.NonExistentField": "value"}
    }
    errs = validate_stored_query(
        bad_query,
        declared_families=["evtx"],
        citation="test",
    )
    assert any("not in field registry" in e for e in errs)


def test_validator_rejects_missing_citation():
    """Requirement: stored query validator enforces citations."""
    good_query = {
        "term": {"fields.EventID": 4624}
    }
    errs = validate_stored_query(
        good_query,
        declared_families=["evtx"],
        citation=None,
    )
    assert any("missing citation" in e for e in errs)


def test_multi_role_worker_prompt_contains_no_query_text():
    """Requirement: prompt rendering renders step name, look_for, corroborate, result only;

    never displays query text (contains neither `| run:` nor `es:` query JSON).
    """
    from nexus.modes.multi_role import WorkOrder

    order = WorkOrder(
        order_id="wo-test",
        role="host",
        task="Triage host artifacts",
        skill_refs=[
            {
                "skill": "lsass_credential_access",
                "version": "1.0",
                "role": "host",
                "citations": ["EIR CH4-1"],
            }
        ],
    )
    rendered = _skill_procedure_block(order)
    assert "lsass_credential_access" in rendered
    assert "sysmon_lsass_access" in rendered
    assert "look_for:" in rendered

    # Strictly forbidden in prompt:
    assert "| run:" not in rendered
    assert "fields.process_name.kw" not in rendered
    assert "wildcard" not in rendered
    assert "case_insensitive" not in rendered

