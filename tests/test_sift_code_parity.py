"""``nexus sift setup`` must not start the SIFT MCP on code the host does not hold (D108).

The SSH layer is faked; ``setup`` itself runs. ``fixtures/sift_src_stale_20261012.sha256`` is the host's real
``sha256sum`` listing from the day it was found 120 files behind this tree.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nexus.cli import sift_cmd
from nexus.cli.sift_cmd import app, code_manifest, compare_manifests, parse_sha256sum

FIXTURE = Path(__file__).parent / "fixtures" / "sift_src_stale_20261012.sha256"
SRC = Path(sift_cmd.__file__).resolve().parents[2]
runner = CliRunner()


def _listing(manifest: dict[str, str]) -> str:
    return "".join(f"{digest}  {path}\n" for path, digest in sorted(manifest.items()))


def test_parse_reads_the_real_pre_sync_listing():
    host = parse_sha256sum(FIXTURE.read_text(encoding="utf-8"))
    assert len(host) == 636
    assert all(path.startswith("nexus/") for path in host)


def test_compare_names_changed_local_only_and_host_only():
    local = {"nexus/a.py": "1" * 64, "nexus/b.py": "2" * 64, "nexus/new.py": "3" * 64}
    host = {"nexus/a.py": "1" * 64, "nexus/b.py": "9" * 64, "nexus/old.py": "4" * 64}
    assert compare_manifests(local, host) == {
        "changed": ["nexus/b.py"], "local_only": ["nexus/new.py"], "host_only": ["nexus/old.py"],
    }


def test_code_manifest_is_relative_and_skips_pycache(tmp_path):
    (tmp_path / "nexus" / "cli").mkdir(parents=True)
    (tmp_path / "nexus" / "cli" / "x.py").write_text("x", encoding="utf-8")
    (tmp_path / "nexus" / "__pycache__").mkdir()
    (tmp_path / "nexus" / "__pycache__" / "x.pyc").write_bytes(b"c")
    assert list(code_manifest(tmp_path)) == ["nexus/cli/x.py"]


class FakeHost:
    """Answers the SSH commands ``setup`` sends. ``listing`` is what the host's ``sha256sum`` prints."""

    def __init__(self, listing: str):
        self.listing = listing
        self.pushed = False
        self.started = False

    def run(self, cmd, **kwargs):
        if "input" in kwargs:  # the code push: a tar stream on stdin
            self.pushed = True
            return subprocess.CompletedProcess(cmd, 0, stdout=b"SYNC-OK\n", stderr=b"")
        remote = cmd[-1]
        if "sha256sum" in remote:
            out = self.listing
        elif remote.startswith("hostname"):
            out = "siftworkstation\n6.8.0\n"
        elif "setsid nohup" in remote:
            self.started = True
            out = "MCP-UP\n"
        elif "MCP-UP" in remote:  # the listener probe: a server is up on 4508
            out = "MCP-UP\n"
        else:
            out = "OK-vol\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")


@pytest.fixture
def ssh_key(tmp_path, monkeypatch):
    key = tmp_path / "cadre-sift-key"
    key.write_text("placeholder: the fake host never reads it", encoding="utf-8")
    monkeypatch.setenv("NEXUS_SIFT_SSH_KEY", str(key))
    return key


def _stale_listing() -> str:
    stale = dict(code_manifest(SRC))
    stale[sorted(stale)[0]] = "0" * 64  # one file on the host differs from this tree
    return _listing(stale)


def test_setup_refuses_to_start_on_stale_code(ssh_key, monkeypatch):
    host = FakeHost(_stale_listing())
    monkeypatch.setattr(subprocess, "run", host.run)
    result = runner.invoke(app, ["setup"])
    assert result.exit_code == 1, result.output
    assert "host differs from this tree: 1 changed" in result.output
    assert "not started on stale code" in result.output
    assert not host.pushed and not host.started


def test_setup_sync_code_replaces_the_host_tree_and_restarts_the_server(ssh_key, monkeypatch):
    host = FakeHost(_stale_listing())
    monkeypatch.setattr(subprocess, "run", host.run)
    result = runner.invoke(app, ["setup", "--sync-code"])
    assert result.exit_code == 0, result.output
    assert host.pushed
    # A running server keeps the code it imported at start: the new code needs a restart (D108).
    assert host.started
    assert "restarting so the new code" in result.output


def test_setup_leaves_a_running_server_alone_when_the_host_matches(ssh_key, monkeypatch):
    host = FakeHost(_listing(code_manifest(SRC)))
    monkeypatch.setattr(subprocess, "run", host.run)
    result = runner.invoke(app, ["setup"])
    assert result.exit_code == 0, result.output
    assert f"host matches this tree ({len(code_manifest(SRC))} files)" in result.output
    assert not host.pushed and not host.started
