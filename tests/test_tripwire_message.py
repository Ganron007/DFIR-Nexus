"""The tripwire's failure must say what was touched, and protect the right set.

The guard protects two things: case/credential state under `~/.nexus` and the
LLM key in `.env`. A bare path list made both read the same, so a real incident
in the store looked like routine config churn (register D21).

The classifier matches the path **as the snapshot records it** — absolute, so a
`~/.nexus` fragment would never match (that bug was caught here).

Register D21, operator decision 2026-10-03: the protected set was narrowed to
that D25–D27 rationale. `~/.claude/settings.json` was dropped because no test
and no `src/` file writes it and the agent's own session rewrites it mid-run,
which manufactured a false error in agent-driven runs. A re-add is a deliberate
act, and `test_the_ide_agent_file_is_no_longer_protected` says so.
"""
from __future__ import annotations

from pathlib import Path

from conftest import _protected_snapshot, _tripwire_hint

STORE = r"+ created  C:\Users\x\.nexus\passwords\gate-bot.json"
ENV = r"~ modified C:\proj\.env"


def test_the_hint_names_the_case_store_as_a_real_incident():
    """The store path is absolute, so the match must not require a `~`."""
    hint = _tripwire_hint([STORE])
    assert "  - case/credential store:" in hint
    assert "real incident" in hint
    assert "  - LLM key" not in hint


def test_the_hint_flags_the_llm_key_separately():
    hint = _tripwire_hint([ENV])
    assert "  - LLM key" in hint
    assert "  - case/credential store:" not in hint


def test_the_hint_always_advises_checking_the_mtime():
    """The actionable step for any of these is comparing the mtime."""
    for line in (STORE, ENV):
        assert "mtime" in _tripwire_hint([line])


def test_the_ide_agent_file_is_no_longer_protected():
    """Register D21, operator decision 2026-10-03: narrow to the D25-D27 rationale.

    No test and no `src/` file writes ~/.claude/settings.json, and the agent's
    own session rewrites it mid-run, so guarding it produced a false error in
    agent-driven runs. Verified here so a re-add is a deliberate act.
    """
    snapshot = _protected_snapshot()
    assert not [p for p in snapshot if ".claude" in p], snapshot.keys()
    # The real ones are still covered.
    assert any(".nexus" in p for p in snapshot) or not Path.home().joinpath(".nexus").is_dir()
