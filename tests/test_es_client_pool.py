"""D219: one pooled Elasticsearch client per URL, and a dropped connection on a read is sent once more.

Every call used to open its own client, a new TCP connection per request; a stored-query test failed with
`httpcore.ReadError [WinError 10054]` on es_search's HEAD in a full run and in one of three isolated runs.
"""
from __future__ import annotations

import httpx
import pytest

from nexus.langgraph import case_index


@pytest.fixture(autouse=True)
def _fresh_pool(monkeypatch):
    monkeypatch.setattr(case_index, "_SHARED_CLIENTS", {})
    yield
    for client in case_index._SHARED_CLIENTS.values():
        client.close()


def test_the_client_is_pooled_per_url_and_outlives_a_with_block(monkeypatch):
    monkeypatch.setenv("NEXUS_ES_URL", "http://127.0.0.1:9")
    with case_index._client() as first:
        pass
    with case_index._client() as second:
        assert second is first
        assert not second.is_closed, "leaving a with block must not close the pooled client"
    monkeypatch.setenv("NEXUS_ES_URL", "http://127.0.0.2:9")
    with case_index._client() as other:
        assert other is not first


def test_a_caller_using_the_client_directly_cannot_close_the_pool(monkeypatch):
    monkeypatch.setenv("NEXUS_ES_URL", "http://127.0.0.1:9")
    direct = case_index._client()
    assert direct.base_url == httpx.URL("http://127.0.0.1:9")
    direct.close()
    with case_index._client() as again:
        assert not again.is_closed


class _DropsOnce(httpx.BaseTransport):
    def __init__(self):
        self.calls = 0

    def handle_request(self, request):
        self.calls += 1
        if self.calls == 1:
            raise httpx.ReadError("[WinError 10054] An existing connection was forcibly closed")
        return httpx.Response(200, json={"ok": True})


@pytest.mark.parametrize("method, path", [("HEAD", "/nexus-case-x"), ("POST", "/nexus-case-x/_search"),
                                          ("POST", "/nexus-case-x/_count"), ("GET", "/nexus-case-x/_mapping")])
def test_a_read_whose_connection_dropped_is_sent_once_more(method, path):
    inner = _DropsOnce()
    with httpx.Client(base_url="http://es", transport=case_index._reset_retry_transport(inner)) as client:
        assert client.request(method, path, json={} if method == "POST" else None).status_code == 200
    assert inner.calls == 2


@pytest.mark.parametrize("method, path", [("POST", "/_bulk"), ("DELETE", "/nexus-case-x"),
                                          ("PUT", "/nexus-case-x"), ("POST", "/nexus-case-x/_delete_by_query")])
def test_a_write_is_never_sent_twice(method, path):
    inner = _DropsOnce()
    transport = case_index._reset_retry_transport(inner)
    with httpx.Client(base_url="http://es", transport=transport) as client, pytest.raises(httpx.ReadError):
        client.request(method, path, content=b"{}")
    assert inner.calls == 1
