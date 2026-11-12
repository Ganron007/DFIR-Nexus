"""Tests for Stage E / TE-2: Elasticsearch Authentication (D145).

Verifies:
1. Basic authentication via URL credentials (http://user:pass@host:9200).
2. Basic authentication via environment variables (NEXUS_ES_USER + NEXUS_ES_PASSWORD).
3. API key authentication via environment variable (NEXUS_ES_API_KEY).
4. Bearer token authentication via environment variable (NEXUS_ES_BEARER_TOKEN).
5. Unauthenticated fallback preservation for local sandbox clusters.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

import pytest

from nexus.langgraph.case_index import _client, _es_auth_and_headers, es_available


def test_es_auth_and_headers_resolution(monkeypatch: pytest.MonkeyPatch):
    """Verifies D145 authentication credential extraction."""
    # 1. URL credentials
    parsed_with_userinfo = urlparse("http://elastic:secretPass@127.0.0.1:9200")
    auth, headers = _es_auth_and_headers(parsed_with_userinfo)
    assert auth == ("elastic", "secretPass")
    assert headers == {}

    # 2. Env basic auth
    parsed_clean = urlparse("http://127.0.0.1:9200")
    monkeypatch.setenv("NEXUS_ES_USER", "secops-analyst")
    monkeypatch.setenv("NEXUS_ES_PASSWORD", "SecOps!Pass2026")
    auth, headers = _es_auth_and_headers(parsed_clean)
    assert auth == ("secops-analyst", "SecOps!Pass2026")
    assert headers == {}

    # 3. Env API key
    monkeypatch.delenv("NEXUS_ES_USER", raising=False)
    monkeypatch.delenv("NEXUS_ES_PASSWORD", raising=False)
    monkeypatch.setenv("NEXUS_ES_API_KEY", "VnVhQ2ZHY0JDZ1h4TF...")
    auth, headers = _es_auth_and_headers(parsed_clean)
    assert auth is None
    assert headers.get("Authorization") == "ApiKey VnVhQ2ZHY0JDZ1h4TF..."

    # 4. Env Bearer token
    monkeypatch.delenv("NEXUS_ES_API_KEY", raising=False)
    monkeypatch.setenv("NEXUS_ES_BEARER_TOKEN", "bearer-token-123")
    auth, headers = _es_auth_and_headers(parsed_clean)
    assert auth is None
    assert headers.get("Authorization") == "Bearer bearer-token-123"

    # 5. Clean / unauthenticated
    monkeypatch.delenv("NEXUS_ES_BEARER_TOKEN", raising=False)
    auth, headers = _es_auth_and_headers(parsed_clean)
    assert auth is None
    assert headers == {}


def test_es_client_passes_auth(monkeypatch: pytest.MonkeyPatch):
    """Verifies that _client() supplies auth and headers to httpx.Client."""
    monkeypatch.setenv("NEXUS_ES_URL", "http://127.0.0.1:9200")
    monkeypatch.setenv("NEXUS_ES_USER", "es-user")
    monkeypatch.setenv("NEXUS_ES_PASSWORD", "es-pass")

    with patch("httpx.Client") as mock_httpx:
        mock_instance = MagicMock()
        mock_instance.is_closed = False
        mock_httpx.return_value = mock_instance

        client = _client()
        assert client is not None

        # Confirm httpx.Client was initialized with auth credentials
        mock_httpx.assert_called()
        call_kwargs = mock_httpx.call_args.kwargs
        assert call_kwargs.get("auth") == ("es-user", "es-pass")


def test_es_available_passes_auth(monkeypatch: pytest.MonkeyPatch):
    """Verifies that es_available probe passes authentication credentials."""
    monkeypatch.setenv("NEXUS_ES_URL", "http://127.0.0.1:9200")
    monkeypatch.setenv("NEXUS_ES_API_KEY", "TestApiKey999")

    # Clear cached probe result
    import nexus.langgraph.case_index as ci
    ci._es_probe_cache = None

    with patch("httpx.Client") as mock_httpx:
        mock_instance = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"version": {"number": "8.17.4"}}
        mock_instance.get.return_value = mock_resp
        mock_instance.__enter__.return_value = mock_instance
        mock_instance.__exit__.return_value = False
        mock_httpx.return_value = mock_instance

        available = es_available()
        assert available is True

        call_kwargs = mock_httpx.call_args.kwargs
        assert call_kwargs.get("headers", {}).get("Authorization") == "ApiKey TestApiKey999"
