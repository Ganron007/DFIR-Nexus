"""The tripwire's failure must say what was touched (register D21).

The guard protects three different things: case/credential state under
`~/.nexus`, the LLM key in `.env`, and an IDE-agent file under `~/.claude`. A
bare path list made all three read the same, so an agent-driven run that only
touched its own IDE file looked like a credential incident.

The classifier matches the path **as the snapshot records it** — absolute, so a
`~/.nexus` fragment would never match (that bug was caught here).
"""
from __future__ import annotations

from conftest import _tripwire_hint

CLAUDE = r"~ modified C:\Users\x\.claude\settings.json"
STORE = r"+ created  C:\Users\x\.nexus\passwords\gate-bot.json"
ENV = r"~ modified C:\proj\.env"


def test_the_hint_names_the_ide_file_as_a_likely_false_positive():
    hint = _tripwire_hint([CLAUDE])
    assert "  - IDE-agent file:" in hint
    assert "false positive" in hint
    # It must not report a case/credential incident for an IDE file.
    assert "  - case/credential store:" not in hint


def test_the_hint_calls_a_password_store_write_a_real_incident():
    """The store path is absolute, so the match must not require a `~`."""
    hint = _tripwire_hint([STORE])
    assert "  - case/credential store:" in hint
    assert "real incident" in hint


def test_the_hint_flags_the_llm_key_separately():
    hint = _tripwire_hint([ENV])
    assert "  - LLM key" in hint
    assert "  - case/credential store:" not in hint


def test_the_hint_always_advises_checking_the_mtime():
    """The actionable step for any of these is comparing the mtime."""
    for line in (CLAUDE, STORE, ENV):
        assert "mtime" in _tripwire_hint([line])
