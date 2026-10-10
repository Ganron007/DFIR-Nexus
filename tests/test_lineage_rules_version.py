"""The rule set a finding depends on is recorded in its tool's lineage (WO-TA item 8).

Hayabusa's rules are a git checkout. Its commit is read from the checkout's files, not by running git.
"""
from pathlib import Path

from nexus.tools.lineage import rules_lineage


def _checkout(root: Path, head: str, ref: str = "", ref_value: str = "") -> None:
    git = root / "hayabusa" / "rules" / ".git"
    git.mkdir(parents=True)
    (git / "HEAD").write_text(head + "\n", encoding="utf-8")
    if ref:
        target = git / ref
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(ref_value + "\n", encoding="utf-8")


def test_hayabusa_rules_version_is_the_commit_HEAD_resolves_to(tmp_path: Path):
    _checkout(tmp_path, "ref: refs/heads/main", "refs/heads/main", "9f3ab1c2d4e5f60718293a4b5c6d7e8f90a1b2c3")

    assert rules_lineage("hayabusa", tmp_path) == {"rules_version": "git:9f3ab1c2d4e5f60718293a4b5c6d7e8f90a1b2c3"}


def test_a_detached_head_is_read_directly(tmp_path: Path):
    _checkout(tmp_path, "1111222233334444555566667777888899990000")

    assert rules_lineage("hayabusa", tmp_path) == {"rules_version": "git:1111222233334444555566667777888899990000"}


def test_a_tool_without_a_rule_set_adds_nothing(tmp_path: Path):
    assert rules_lineage("mftecmd", tmp_path) == {}


def test_a_missing_rules_checkout_is_recorded_as_unknown(tmp_path: Path):
    assert rules_lineage("hayabusa", tmp_path) == {"rules_version": ""}
