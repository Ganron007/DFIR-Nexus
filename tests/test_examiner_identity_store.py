"""The password store must key on the same identity the audit chain uses.

Found by the debug-mode gate run: the examiner was configured as ``gate_bot``,
the audit chain canonically records ``gate-bot``, and the password store keyed
on the raw string. So the entry was written to ``gate_bot.json`` and read from
``gate-bot.json``, and every approval failed with 403 "No password configured"
- an examiner who had correctly set a password could never approve anything,
with an error that named the wrong problem.

The human-approval boundary is the one path where "it works on my machine"
costs an examiner their case, so the canonicalisation is pinned here for every
name shape that slugifies differently from itself.
"""
from __future__ import annotations

import json

import pytest

from nexus.audit import normalize_examiner, resolve_examiner
from nexus.auth import _load_password_entry, _password_file, _save_password_entry

# Names whose slug differs from the raw string, plus names that do not.
NAMES = [
    "gate_bot",
    "gate-bot",
    "Jane Doe",
    "j.doe",
    "jane.doe@corp",
    "A" * 40,
    "plain",
    "already-slugged",
    "UPPER_Case",
]


def test_store_file_is_keyed_on_the_canonical_slug():
    for name in NAMES:
        assert _password_file(name).stem == normalize_examiner(name), name


def test_every_name_shape_resolves_its_own_entry(tmp_path, monkeypatch):
    """Each name must be able to read back what it wrote.

    Names that share a slug are the same examiner (see the next test), so only
    the readability is asserted here; the distinct-value case is asserted there.
    """
    monkeypatch.setattr("nexus.auth._PASSWORDS_DIR", tmp_path)
    for name in NAMES:
        _save_password_entry(name, {"hash": f"h-{name}", "salt": f"s-{name}",
                                    "iterations": 600_000})
    for name in NAMES:
        entry = _load_password_entry(name)
        assert entry is not None, f"{name} could not read back its own entry"
        assert entry["hash"].startswith("h-")


def test_a_name_reads_back_exactly_what_it_wrote(tmp_path, monkeypatch):
    """Round-trip identity, isolated from slug-sharing names."""
    monkeypatch.setattr("nexus.auth._PASSWORDS_DIR", tmp_path)
    for name in ("plain", "Jane Doe", "j.doe", "already-slugged"):
        _save_password_entry(name, {"hash": f"h-{name}", "salt": "s", "iterations": 1})
        assert _load_password_entry(name)["hash"] == f"h-{name}"


def test_names_sharing_a_slug_share_one_entry(tmp_path, monkeypatch):
    """gate_bot and gate-bot are the same examiner, not two."""
    monkeypatch.setattr("nexus.auth._PASSWORDS_DIR", tmp_path)
    _save_password_entry("gate_bot", {"hash": "h1", "salt": "s1", "iterations": 1})
    _save_password_entry("gate-bot", {"hash": "h2", "salt": "s2", "iterations": 1})
    assert _load_password_entry("gate_bot")["hash"] == "h2"
    assert _load_password_entry("gate-bot")["hash"] == "h2"


def test_a_store_written_under_the_old_name_is_still_found(tmp_path, monkeypatch):
    """An examiner who set a password before the fix must not lose approval."""
    monkeypatch.setattr("nexus.auth._PASSWORDS_DIR", tmp_path)
    (tmp_path / "gate_bot.json").write_text(
        json.dumps({"hash": "legacy", "salt": "s", "iterations": 1}), encoding="utf-8"
    )
    # The canonical lookup is what resolve_examiner() produces.
    entry = _load_password_entry(normalize_examiner("gate_bot"))
    assert entry is not None and entry["hash"] == "legacy"


def test_a_misnamed_store_is_adopted_to_the_canonical_name(tmp_path, monkeypatch):
    monkeypatch.setattr("nexus.auth._PASSWORDS_DIR", tmp_path)
    (tmp_path / "Jane Doe.json").write_text(
        json.dumps({"hash": "legacy", "salt": "s", "iterations": 1}), encoding="utf-8"
    )
    assert _load_password_entry("jane-doe")["hash"] == "legacy"
    assert (tmp_path / "jane-doe.json").is_file()
    assert not (tmp_path / "Jane Doe.json").exists()


def test_adoption_does_not_clobber_an_existing_canonical_entry(tmp_path, monkeypatch):
    monkeypatch.setattr("nexus.auth._PASSWORDS_DIR", tmp_path)
    (tmp_path / "jane-doe.json").write_text(
        json.dumps({"hash": "canonical", "salt": "s", "iterations": 1}), encoding="utf-8")
    (tmp_path / "Jane Doe.json").write_text(
        json.dumps({"hash": "legacy", "salt": "s", "iterations": 1}), encoding="utf-8")
    # The canonical file wins; the stale one is left alone, not merged.
    assert _load_password_entry("jane-doe")["hash"] == "canonical"
    assert (tmp_path / "Jane Doe.json").is_file()


def test_unrelated_entries_are_never_adopted(tmp_path, monkeypatch):
    monkeypatch.setattr("nexus.auth._PASSWORDS_DIR", tmp_path)
    (tmp_path / "other.json").write_text(
        json.dumps({"hash": "x", "salt": "s", "iterations": 1}), encoding="utf-8")
    assert _load_password_entry("gate-bot") is None
    assert (tmp_path / "other.json").is_file()


def test_empty_and_punctuation_names_resolve_to_unknown():
    assert normalize_examiner("") == "unknown"
    assert normalize_examiner("!!!") == "unknown"
    assert normalize_examiner(None) == "unknown"


def test_normalize_matches_resolve_examiner(monkeypatch):
    """The store key and the audit identity must be the same string."""
    for raw in ("gate_bot", "Jane Doe", "plain"):
        monkeypatch.setenv("NEXUS_EXAMINER", raw)
        assert resolve_examiner() == normalize_examiner(raw)


@pytest.mark.parametrize("name", NAMES)
def test_commit_route_finds_the_entry_for_any_name(tmp_path, monkeypatch, name):
    """The portal's own loader must agree - it is a different module path."""
    monkeypatch.setattr("nexus.auth._PASSWORDS_DIR", tmp_path)
    _save_password_entry(name, {"hash": "h", "salt": "s", "iterations": 1})
    monkeypatch.setattr(
        "nexus.auth._load_password_entry",
        _load_password_entry,
        raising=True,
    )
    from nexus.dashboard.app import _load_password_entry as portal_load

    assert portal_load(name) is not None
