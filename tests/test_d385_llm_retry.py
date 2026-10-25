"""D385: one transient provider error must not end a mode run.

R1z3, T05 Mode 1 (2026-10-25 13:24): the first model call got HTTP 500 "Failed to reach upstream, please retry later"
from agnes and the run failed; T05 Mode 2 started two minutes later with no error. `_construct_model` set no retry
policy, so the client kept the SDK default of 2 retries (about 1.5 s of backoff). The router had its own 3-try loop
for rate limits, a second definition of the policy that no caller used (rule 16). One policy now:
`nexus.llm.providers.llm_max_retries()` (NEXUS_LLM_MAX_RETRIES) on every client the factory builds; the SDK retries
408/409/429/5xx and connection errors with exponential backoff and honours Retry-After, and fails at once on any other
4xx.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from tests.test_llm_timeout import _model

#: The provider's own text from the failed T05 Mode 1 call.
_UPSTREAM_500 = {"error": {"message": "Failed to reach upstream, please retry later", "type": "server_error"}}
_COMPLETION = {
    "id": "chatcmpl-1", "object": "chat.completion", "created": 0, "model": "agnes-3.0-flash",
    "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}


def test_the_documented_default_is_the_one_default(monkeypatch):
    from nexus.llm.providers import DEFAULT_LLM_MAX_RETRIES, llm_max_retries

    monkeypatch.delenv("NEXUS_LLM_MAX_RETRIES", raising=False)
    assert llm_max_retries() == DEFAULT_LLM_MAX_RETRIES == 10
    monkeypatch.setenv("NEXUS_LLM_MAX_RETRIES", "4")
    assert llm_max_retries() == 4
    monkeypatch.setenv("NEXUS_LLM_MAX_RETRIES", "-3")
    assert llm_max_retries() == 0
    monkeypatch.setenv("NEXUS_LLM_MAX_RETRIES", "many")
    assert llm_max_retries() == DEFAULT_LLM_MAX_RETRIES


@pytest.mark.parametrize("env", [
    {"NEXUS_LLM_MODEL": "agnes-3.0-flash", "NEXUS_LLM_BASE_URL": "http://127.0.0.1:9/v1", "NEXUS_LLM_API_KEY": "k"},
    {"NEXUS_MODEL": "openai/gpt-4o", "OPENAI_API_KEY": "k"},
])
def test_an_openai_client_has_the_retry_policy(monkeypatch, env):
    model = _model(monkeypatch, NEXUS_LLM_MAX_RETRIES="7", **env)
    assert model.max_retries == 7


@pytest.mark.parametrize("env", [
    {"NEXUS_LLM_MODEL": "claude-sonnet-5-5", "NEXUS_LLM_PROVIDER": "anthropic", "NEXUS_LLM_API_KEY": "k"},
    {"NEXUS_MODEL": "claude-sonnet-5-5", "ANTHROPIC_API_KEY": "k"},
])
def test_an_anthropic_client_has_the_retry_policy(monkeypatch, env):
    pytest.importorskip("langchain_anthropic")
    model = _model(monkeypatch, NEXUS_LLM_MAX_RETRIES="7", **env)
    assert model.max_retries == 7


def test_the_router_keeps_no_retry_loop_of_its_own():
    from nexus.llm.router import LLMRouter

    assert not hasattr(LLMRouter, "chat_with_retry")


class _Upstream(BaseHTTPRequestHandler):
    """Answers like the provider did: HTTP 500 for the first `fail` calls, then a completion."""

    fail = 2
    calls = 0

    def do_POST(self):  # noqa: N802 - the http.server hook name
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        type(self).calls += 1
        status, body = (500, _UPSTREAM_500) if type(self).calls <= type(self).fail else (200, _COMPLETION)
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture()
def upstream():
    _Upstream.calls = 0
    server = HTTPServer(("127.0.0.1", 0), _Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def _agnes(monkeypatch, upstream, **env):
    url = f"http://127.0.0.1:{upstream.server_address[1]}/v1"
    return _model(monkeypatch, NEXUS_LLM_MODEL="agnes-3.0-flash", NEXUS_LLM_BASE_URL=url, NEXUS_LLM_API_KEY="k", **env)


def test_the_real_client_rides_out_the_upstream_500(monkeypatch, upstream):
    _Upstream.fail = 2
    model = _agnes(monkeypatch, upstream)
    assert model.invoke("hello").content == "ok"
    assert _Upstream.calls == 3


def test_a_provider_that_stays_down_still_fails_after_the_budget(monkeypatch, upstream):
    import openai

    _Upstream.fail = 99
    model = _agnes(monkeypatch, upstream, NEXUS_LLM_MAX_RETRIES="1")
    with pytest.raises(openai.InternalServerError, match="Failed to reach upstream"):
        model.invoke("hello")
    assert _Upstream.calls == 2
