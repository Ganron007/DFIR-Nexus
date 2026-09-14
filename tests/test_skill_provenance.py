"""WP 9.1 — skill provenance + citation-schema tests.

Every shipped skill must carry provenance: either a ``# kb:`` comment
(human-readable, the 4j format) or a machine-readable ``source:`` list.
Operator machines additionally resolve those citations with
``python G:\\doc_extract\\kb\\kb.py verify-cites <skill.yaml>`` (not run in
CI — the KB lives outside the repo).
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

import nexus
from nexus.knowledge.loader import skill_sources, validate_skill

SKILLS_DIR = Path(nexus.__file__).parent / "data" / "knowledge" / "skills"
_CITE_RE = re.compile(r"\bd_[0-9a-f]{4,}:[cu]?[0-9a-f]{1,12}\b")


def _skill_files() -> list[Path]:
    return sorted(SKILLS_DIR.glob("*.yaml"))


def test_skills_dir_present():
    files = _skill_files()
    assert len(files) >= 30, f"expected the skill corpus, found {len(files)}"


def test_every_skill_has_provenance():
    """Every skill file cites its KB source (comment or `source:` field)."""
    missing = []
    for f in _skill_files():
        text = f.read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
        if "# kb:" in text or (data.get("source") or []):
            continue
        missing.append(f.name)
    assert not missing, f"skills without provenance: {missing}"


def test_every_skill_validates_and_cites_a_chunk():
    """Schema-valid, and any chunk citation is well-formed."""
    for f in _skill_files():
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        assert validate_skill(data) == [], f"{f.name}: {validate_skill(data)}"
        # comment-style citations in the raw file are chunk ids
        for cid in _CITE_RE.findall(f.read_text(encoding="utf-8")):
            assert cid.startswith("d_"), f"{f.name}: malformed citation {cid}"


def test_source_field_schema():
    """`source:` entries normalise and validate; bad shapes are rejected."""
    good = {
        "skill": "demo",
        "trigger": {"keywords": ["x"]},
        "steps": [{"query": "foo"}],
        "source": [
            {"chunk_id": "d_abc123:c0001", "rel_path": "SANS/x.md", "lines": "1-10"},
            "d_def456:c0002",
        ],
    }
    assert validate_skill(good) == []
    norm = skill_sources(good)
    assert [s["chunk_id"] for s in norm] == ["d_abc123:c0001", "d_def456:c0002"]

    bad = {
        "skill": "demo",
        "trigger": {"keywords": ["x"]},
        "steps": [{"query": "foo"}],
        "source": [{"rel_path": "SANS/x.md"}],
    }
    assert any("chunk_id" in p for p in validate_skill(bad))
