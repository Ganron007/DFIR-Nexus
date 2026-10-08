"""WO-R1F items 3-6 — mode lineage, duplicate staging, the context audit, intake.

Item 5 (D39) is here because it is the defect SC1 hit: `_prune_contexts` deleted
every context past the newest 60, so the audit of what the model was given
disappeared and the cause was invisible. The rule is "compress; never delete".
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path


def test_parse_claims_accepts_the_known_alternates():
    """WO-R1F item 7: a seat answered `{"notes": [...]}` on SC1 and lost it."""
    from nexus.modes.multi_agent import _parse_claims

    for key in ("claims", "notes", "findings", "observations"):
        payload = json.dumps({key: [{"entity_value": "cmd.exe",
                                     "claim_kind": "presence"}]})
        claims = _parse_claims(payload)
        assert len(claims) == 1, f"{key} was not accepted"


def test_has_claims_key_distinguishes_prose_from_a_wrong_key():
    from nexus.modes.multi_agent import _has_claims_key

    assert _has_claims_key('{"notes": []}') is True
    assert _has_claims_key('{"claims": []}') is True
    assert _has_claims_key("I found nothing conclusive on this host.") is False
    assert _has_claims_key("") is False


def test_a_parser_inventory_claim_is_coverage_not_a_finding():
    """Item 7: "tool X parsed N records" describes the parser, not the evidence."""
    from nexus.modes.multi_agent import _claim_is_coverage_only

    assert _claim_is_coverage_only(
        {"entity_value": "mftecmd", "value": "parsed 794,313 records"}
    ) is True
    assert _claim_is_coverage_only(
        {"entity_value": "hayabusa", "value": "parsed 89872 rows"}
    ) is True
    # A behavioural claim keeps its place on the board.
    assert _claim_is_coverage_only(
        {"entity_value": "cmd.exe", "value": "executed net use H: \\\\172.16.6.12"}
    ) is False
    assert _claim_is_coverage_only(
        {"entity_value": "CobaltStrike", "value": "Defender flagged it severe"}
    ) is False


def test_parse_claims_ignores_a_reply_with_no_json():
    from nexus.modes.multi_agent import _parse_claims

    assert _parse_claims("no json here") == []
    assert _parse_claims("") == []
    assert _parse_claims('{"claims": "not a list"}') == []


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
