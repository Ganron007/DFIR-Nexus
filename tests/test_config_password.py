"""HMAC examiner password setup (env + --replace)."""

from pathlib import Path

from nexus.auth import has_password, setup_password, verify_password
from nexus.cli.config_cmd import _run_set


def test_replace_uses_env_password(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("nexus.auth._PASSWORDS_DIR", tmp_path)
    setup_password("e2e_host", "old-lab-secret")
    assert has_password("e2e_host")
    assert verify_password("e2e_host", "old-lab-secret")
    monkeypatch.setenv("NEXUS_APPROVAL_PASSWORD", "dfirnexus")
    monkeypatch.setattr("nexus.config.settings.examiner", "e2e_host")
    _run_set("", setup_password=True, replace=True)
    assert verify_password("e2e_host", "dfirnexus")
    assert not verify_password("e2e_host", "old-lab-secret")
    assert (tmp_path / "e2e_host.json").is_file()
