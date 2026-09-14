"""WP 9.2 — skill distillation pipeline tests (deterministic path)."""
from __future__ import annotations

import os
from pathlib import Path

import yaml


def _draft() -> dict:
    src = {"chunk_id": "d_abcdef:c0001", "rel_path": "KB/x.md", "lines": "1-10"}
    return {
        "skill": "demo_topic",
        "title": "Demo topic — skill draft",
        "description": "draft",
        "trigger": {"families": ["evtx"], "keywords": ["demo"], "techniques": ["T1014"]},
        "steps": [
            {"name": "s1", "query": "rundll32 OR regsvr32",
             "look_for": "LOLBin execution", "pivot": "CommandLine",
             "corroborate": "", "source": src},
            # exact duplicate — must be deduped
            {"name": "s1dup", "query": "rundll32 OR regsvr32",
             "look_for": "LOLBin execution", "pivot": "CommandLine",
             "corroborate": "", "source": src},
        ],
        "mitre": ["T1014"],
        "confidence_rules": {"high": "", "medium": "", "low": ""},
        "caveats": ["draft"],
        "negative": "",
        "source": [src],
    }


def test_distill_from_yaml_refines_and_gates(tmp_path):
    from nexus.knowledge.distill import distill

    draft_path = tmp_path / "in.yaml"
    draft_path.write_text(yaml.safe_dump(_draft()), encoding="utf-8")

    report = distill(from_yaml=draft_path, out_dir=tmp_path / "out")
    assert report["gate"] == [], report["gate"]
    assert report["steps"] == 1, "duplicate step should be deduped"
    assert report["citations"] == 1
    assert report["refined_by"] == "deterministic"

    out = yaml.safe_load(Path(report["written"]).read_text(encoding="utf-8"))
    # DET dictionary caveat folded in for T1014 (kernel/rootkit)
    assert any("kernel" in c.lower() or "signer" in c.lower() for c in out["caveats"])
    assert any(str(v).strip() for v in out["confidence_rules"].values())
    assert out["negative"].strip()


def test_gate_flags_missing_query_and_bad_citation():
    from nexus.knowledge.distill import gate

    bad = {
        "skill": "bad",
        "trigger": {"keywords": ["x"]},
        "steps": [{"name": "s", "query": ""}],
        "source": [{"chunk_id": "not-a-chunk"}],
    }
    problems = gate(bad)
    assert any("missing 'query'" in p for p in problems)
    assert any("malformed citation" in p for p in problems)


def test_distill_requires_input():
    from nexus.knowledge.distill import distill

    try:
        distill()
    except ValueError as exc:
        assert "folder" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")


def test_refine_llm_without_model_is_none():
    from nexus.knowledge.distill import refine_llm

    assert refine_llm(_draft(), None) is None


def test_install_writes_to_skills_dir(tmp_path, monkeypatch):
    import nexus.knowledge.distill as distill_mod

    monkeypatch.setattr(distill_mod, "_SKILLS_DIR", tmp_path / "skills")
    draft_path = tmp_path / "in.yaml"
    draft_path.write_text(yaml.safe_dump(_draft()), encoding="utf-8")

    rep = distill_mod.distill(from_yaml=draft_path, name="demo_installed",
                              out_dir=tmp_path / "out", install=True)
    assert rep["installed"] is True
    assert (tmp_path / "skills" / "demo_installed.yaml").is_file()

    # second install without force → blocked, draft kept in the review dir
    rep2 = distill_mod.distill(from_yaml=draft_path, name="demo_installed",
                               out_dir=tmp_path / "out", install=True)
    assert rep2["installed"] is False
    assert any("already exists" in p for p in rep2["gate"])


def test_distill_end_to_end_via_kb(tmp_path):
    """Full acquire→refine→gate→emit loop against the real KB.

    Slow (runs kb export); opt in with NEXUS_DISTILL_KB=1 and a present KB.
    """
    kb = Path(os.environ.get("NEXUS_KB_PY", r"G:\doc_extract\kb\kb.py"))
    if os.environ.get("NEXUS_DISTILL_KB") != "1" or not kb.is_file():
        import pytest

        pytest.skip("set NEXUS_DISTILL_KB=1 with the KB present to run the live loop")

    from nexus.knowledge.distill import distill

    report = distill(folder="DFIR-Report", name="dfir_report_distilled",
                     out_dir=tmp_path, kb_py=str(kb))
    assert report["steps"] > 0
    assert report["gate"] == [], report["gate"]
    assert Path(report["written"]).is_file()
