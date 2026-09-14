"""WP 9.5 — runtime skill retrieval + agent provenance tests."""
from __future__ import annotations

import json
from pathlib import Path

from nexus.knowledge.loader import get_skills
from nexus.knowledge.skills import (
    retrieve_skills,
    skill_provenance,
    skill_version,
    skills_for,
)


def test_retrieve_skills_returns_ranked_metadata():
    entries = retrieve_skills(families={"evtx", "hayabusa"}, keywords={"lsass"},
                              techniques={"T1003.001"})
    assert entries, "expected a ranked skill"
    top = entries[0]
    for key in ("skill", "title", "version", "score", "why", "citations", "mitre"):
        assert key in top, key
    assert top["skill"] == "lsass_credential_access"
    assert top["why"], "expected match reasons"
    assert any("T1003.001" in w for w in top["why"]) or any(
        "keyword" in w or "family" in w for w in top["why"])
    assert isinstance(top["citations"], list)
    # ranked descending
    scores = [e["score"] for e in entries]
    assert scores == sorted(scores, reverse=True)


def test_skill_version_stable_and_content_sensitive():
    skill = next(s for s in get_skills() if s.get("skill") == "persistence")
    v1 = skill_version(skill)
    assert v1 == skill_version(skill), "version must be stable"
    assert len(v1) == 12

    mutated = json.loads(json.dumps(skill))
    mutated["steps"][-1]["look_for"] = str(mutated["steps"][-1].get("look_for", "")) + " CHANGED"
    assert skill_version(mutated) != v1, "content change must bump the version"

    # cosmetic-only change (extra non-semantic key) does not bump
    cosmetic = json.loads(json.dumps(skill))
    cosmetic["_note"] = "cosmetic"
    assert skill_version(cosmetic) == v1


def test_skill_provenance_shape():
    skill = next(s for s in get_skills() if s.get("skill") == "memory_process_analysis")
    prov = skill_provenance(skill)
    assert prov["skill"] == "memory_process_analysis"
    assert prov["version"]
    assert isinstance(prov["citations"], list)

    # machine-readable `source:` entries surface as citations (SK-1 schema)
    synthetic = {
        "skill": "demo",
        "title": "Demo",
        "trigger": {"keywords": ["x"]},
        "steps": [{"query": "foo"}],
        "source": [{"chunk_id": "d_abc123:c0001", "rel_path": "x.md", "lines": "1-2"}],
    }
    assert skill_provenance(synthetic)["citations"] == ["d_abc123:c0001"]


def test_skills_for_backward_compat():
    out = skills_for(families={"evtx"}, keywords={"lsass"})
    assert out and isinstance(out[0], dict)
    assert "skill" in out[0] and "score" not in out[0]  # plain skill dicts, unchanged


def _mkcase(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-T1"
    ext = case / "extractions"
    ext.mkdir(parents=True)
    (ext / "hayabusa_alerts.csv").write_text(
        "Timestamp,Computer,Channel,EventID,Level,RuleTitle,OtherDetails\n"
        "2026-08-10 14:32:01,WS01,Sec,4688,critical,LSASS Memory Access,powershell.exe\n",
        encoding="utf-8",
    )
    (case / "CASE.yaml").write_text("question: was lsass dumped\n", encoding="utf-8")
    return case


def test_agent_run_records_skill_provenance(tmp_path):
    from nexus.langgraph.orchestrator import run_orchestrator

    result = run_orchestrator(_mkcase(tmp_path))
    runs = result["agent_runs"]
    assert runs
    prov_runs = [r for r in runs if r.get("skill_provenance")]
    assert prov_runs, "expected at least one agent to report skill provenance"
    prov = prov_runs[0]["skill_provenance"][0]
    assert prov["skill"] and prov["version"]
    step_recs = [sr for r in runs for sr in (r.get("skill_results") or [])]
    assert step_recs, "expected skill step results"
    sr = step_recs[0]
    assert sr.get("skill_version"), "step result must carry the skill version"
    assert "skill_citations" in sr
