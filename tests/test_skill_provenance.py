"""WP 9.1 — skill provenance, corpus-free (operator decision 2026-10-12).

Skills are authored in this repo and carry no pointer into the external research corpus.
The schema still accepts a ``source:`` list for a future machine-readable source; the
shipped skills have none.
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


def test_no_skill_points_into_the_external_corpus():
    """No shipped skill cites a chunk, a corpus file or a `# kb:` note.

    The corpus is not a source for any mode, so a skill's provenance is its own content
    (``version`` is a content hash of the procedure).
    """
    pointers = []
    for f in _skill_files():
        text = f.read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
        if "source" in data or "# kb:" in text or "chunk_id" in text or "rel_path" in text:
            pointers.append(f.name)
    assert not pointers, f"skills that still point into the corpus: {pointers}"


def test_every_skill_validates_and_names_no_corpus_chunk():
    """Schema-valid, and no chunk id survives in the raw file."""
    for f in _skill_files():
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        assert validate_skill(data) == [], f"{f.name}: {validate_skill(data)}"
        leftovers = _CITE_RE.findall(f.read_text(encoding="utf-8"))
        assert not leftovers, f"{f.name}: corpus chunk ids {leftovers}"


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
