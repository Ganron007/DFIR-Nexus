"""WO-R1F items 3-6 — mode lineage, duplicate staging, the context audit, intake.

Item 5 (D39) is here because it is the defect SC1 hit: `_prune_contexts` deleted
every context past the newest 60, so the audit of what the model was given
disappeared and the cause was invisible. The rule is "compress; never delete".
"""

from __future__ import annotations

import gzip
from pathlib import Path


def test_prune_contexts_compresses_instead_of_deleting(tmp_path: Path):
    """D39: 65 contexts in must still be 65 (60 plain + 5 gzipped) after a prune."""
    from nexus.langgraph import prompt_budget as pb

    for i in range(65):
        (tmp_path / f"2026010{i:02d}T000000-turn-{i}.md").write_text(
            f"context {i}", encoding="utf-8"
        )
    before = len(list(tmp_path.glob("*.md")))

    pb._prune_contexts(tmp_path)

    plain = list(tmp_path.glob("*.md"))
    gz = list(tmp_path.glob("*.md.gz"))
    assert len(plain) + len(gz) == before, "contexts were LOST, not compressed"
    assert len(gz) == 5, gz
    assert len(plain) == 60
    # And the content is still readable.
    with gzip.open(sorted(gz)[0], "rt", encoding="utf-8") as fh:
        assert fh.read().startswith("context ")


def test_prune_contexts_is_idempotent(tmp_path: Path):
    from nexus.langgraph import prompt_budget as pb

    for i in range(65):
        (tmp_path / f"f-{i:03d}.md").write_text("x", encoding="utf-8")
    pb._prune_contexts(tmp_path)
    first = sorted(p.name for p in tmp_path.iterdir())
    pb._prune_contexts(tmp_path)
    assert sorted(p.name for p in tmp_path.iterdir()) == first
