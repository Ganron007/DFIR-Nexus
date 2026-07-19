"""Tests for nexus.utils.constants — env validation helpers."""

from __future__ import annotations

import pytest

from nexus.utils.constants import (
    ENV_AUDIT_SECRET,
    ENV_PORTAL_PASSWORD,
    MissingProductionEnvError,
    cases_db_path,
    check_required_env,
    detection_index_path,
    is_loopback_bind,
    push_tokens_path,
    warn_loopback_env,
)


def test_is_loopback_bind_loopback() -> None:
    assert is_loopback_bind("127.0.0.1", port=8000) is True
    assert is_loopback_bind("localhost") is True
    assert is_loopback_bind("::1") is True


def test_is_loopback_bind_non_loopback() -> None:
    assert is_loopback_bind("0.0.0.0", port=8000) is False
    assert is_loopback_bind("192.168.77.10", port=8000) is False


def test_check_required_env_loopback_returns_missing() -> None:
    missing = check_required_env(host="127.0.0.1", port=8000)
    assert ENV_AUDIT_SECRET in missing
    assert ENV_PORTAL_PASSWORD in missing


def test_check_required_env_loopback_no_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_AUDIT_SECRET, "x")
    monkeypatch.setenv(ENV_PORTAL_PASSWORD, "y")
    assert check_required_env(host="127.0.0.1") == []


def test_check_required_env_non_loopback_raises() -> None:
    with pytest.raises(MissingProductionEnvError) as exc_info:
        check_required_env(host="0.0.0.0", port=8000)
    assert ENV_AUDIT_SECRET in exc_info.value.missing


def test_check_required_env_non_loopback_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_AUDIT_SECRET, "x")
    monkeypatch.setenv(ENV_PORTAL_PASSWORD, "y")
    assert check_required_env(host="0.0.0.0") == []


def test_warn_loopback_env() -> None:
    missing = warn_loopback_env()
    assert isinstance(missing, list)
    assert ENV_AUDIT_SECRET in missing


def test_cases_db_path_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_CASES_DB", raising=False)
    assert cases_db_path().name == "cases.db"
    assert cases_db_path().parent.name == "data"


def test_cases_db_path_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_CASES_DB", "C:/temp/cases.db")
    assert cases_db_path().name == "cases.db"


def test_push_tokens_path_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_PUSH_TOKENS", raising=False)
    assert push_tokens_path().name == "push_tokens.json"


def test_detection_index_path_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_DETECTION_INDEX", raising=False)
    assert detection_index_path().name == "detection"
