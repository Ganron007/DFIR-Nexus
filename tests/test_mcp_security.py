"""MCP Host allowlist / DNS-rebinding helpers."""

from nexus.mcp_security import build_allowed_hosts, build_allowed_origins


def test_loopback_hosts_always_present():
    hosts = build_allowed_hosts("127.0.0.1")
    assert "127.0.0.1:*" in hosts
    assert "localhost:*" in hosts


def test_explicit_bind_host_added():
    hosts = build_allowed_hosts("192.168.77.135")
    assert "192.168.77.135:*" in hosts
    assert "192.168.77.135" in hosts


def test_env_extra_hosts(monkeypatch):
    monkeypatch.setenv("NEXUS_MCP_ALLOWED_HOSTS", "10.0.0.5,lab.local")
    hosts = build_allowed_hosts("127.0.0.1")
    assert any(h.startswith("10.0.0.5") for h in hosts)
    assert any("lab.local" in h for h in hosts)


def test_origins_include_lab_ip():
    hosts = ["127.0.0.1:*", "192.168.77.135:*"]
    origins = build_allowed_origins(hosts)
    assert "http://192.168.77.135:*" in origins
