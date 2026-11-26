"""Regression tests for Group A pre-v1 hardening items."""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest


class _FakeServer:
    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self):
        def _deco(fn):
            self.tools[fn.__name__] = fn
            return fn

        return _deco


class _FakeKnownGood:
    def lookup_service(self, _name: str):
        return []

    def lookup_task(self, _key: str):
        return []

    def lookup_autorun(self, _key_path: str, _value_name=None):
        return []


class _FakeContext:
    def get_expected_process(self, _name: str):
        return None

    def get_protected_process_names(self):
        return []

    def check_lolbin(self, _filename: str):
        return None

    def check_suspicious_filename(self, _filename: str):
        return None

    def check_vulnerable_driver(self, _norm: str, _algo: str):
        return None

    def check_hijackable_dll(self, _dll: str):
        return []

    def check_windows_pipe(self, _pipe: str):
        return None

    def check_suspicious_pipe(self, _pipe: str):
        return None


def test_config_rejects_malformed_and_out_of_range_ints(tmp_path, monkeypatch):
    from nexus.config import Settings

    fake_home = tmp_path / "home"
    (fake_home / ".nexus").mkdir(parents=True)
    (fake_home / ".nexus" / "config.yaml").write_text(
        "command_timeout: not-an-int\ngateway_port: false\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: fake_home))

    cfg = Settings()
    cfg.load_config_file()
    assert cfg.command_timeout == 600
    assert cfg.gateway_port == 4508

    monkeypatch.setenv("NEXUS_COMMAND_TIMEOUT", "abc")
    monkeypatch.setenv("NEXUS_GATEWAY_PORT", "99999")
    cfg.update_from_env()
    assert cfg.command_timeout == 600
    assert cfg.gateway_port == 4508

    monkeypatch.setenv("NEXUS_COMMAND_TIMEOUT", "120")
    monkeypatch.setenv("NEXUS_GATEWAY_PORT", "4510")
    cfg.update_from_env()
    assert cfg.command_timeout == 120
    assert cfg.gateway_port == 4510


@pytest.mark.parametrize("bad_case_id", ["", "   ", "../escape", "a/b", "a\\b", "CASE\x001"])
def test_transparency_rejects_invalid_case_ids(tmp_path, monkeypatch, bad_case_id):
    from nexus import transparency

    monkeypatch.setattr(transparency, "TRANSPARENCY_DIR", tmp_path / "transparency")
    assert transparency.transparency_append(bad_case_id, {"finding_id": "F-1"}) is None
    res = transparency.transparency_verify(bad_case_id)
    assert res["valid"] is False
    assert "error" in res


def test_transparency_concurrent_appends_preserve_chain(tmp_path, monkeypatch):
    from nexus import transparency

    monkeypatch.setattr(transparency, "TRANSPARENCY_DIR", tmp_path / "transparency")
    case_id = "CASE-CONCURRENT"
    results: list[dict | None] = []
    lock = threading.Lock()

    def _worker(i: int) -> None:
        env = transparency.transparency_append(case_id, {"finding_id": f"F-{i:03d}"})
        with lock:
            results.append(env)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(r is not None for r in results)
    status = transparency.transparency_verify(case_id)
    assert status == {"valid": True, "entries": 16}


def test_triage_tools_return_recorded_audit_id(tmp_path, monkeypatch):
    from nexus.audit import AuditWriter
    from nexus.triage import server as triage_server

    audit_dir = tmp_path / "audit"
    writer = AuditWriter("triage", audit_dir=audit_dir)
    mcp = _FakeServer()

    reg_dir = tmp_path / "triage_db"
    reg_dir.mkdir()
    (reg_dir / "known_good_registry.db").write_bytes(b"")

    fake_reg = SimpleNamespace(lookup_value=lambda *a: [], lookup_key=lambda *a: [])
    monkeypatch.setattr(triage_server, "_get_db_path", lambda: reg_dir)
    monkeypatch.setattr(
        triage_server,
        "_open_dbs",
        lambda read_only=True: (_FakeKnownGood(), _FakeContext()),
    )
    monkeypatch.setattr(triage_server, "_open_registry_db", lambda read_only=True: fake_reg)
    monkeypatch.setattr(triage_server, "download_databases", lambda *_a, **_kw: True)

    triage_server.register_tools(mcp, writer)

    calls = [
        ("check_process_tree", {"process_name": "evil.exe", "parent_name": "explorer.exe"}),
        ("check_service", {"service_name": "CustomSvc"}),
        ("check_scheduled_task", {"task_path": "\\Custom\\Task"}),
        ("check_autorun", {"key_path": "SOFTWARE\\Vendor\\Run"}),
        ("check_registry", {"key_path": "SOFTWARE\\Vendor\\Key"}),
        ("check_hash", {"hash_value": "a" * 64}),
        ("analyze_filename_triage", {"filename": "report.pdf"}),
        ("check_lolbin", {"filename": "notalolbin.exe"}),
        ("check_hijackable_dll", {"dll_name": "missing.dll"}),
        ("check_pipe", {"pipe_name": "\\\\.\\pipe\\custom"}),
        ("triage_download", {"tag": "latest"}),
    ]

    returned_ids: list[str] = []
    for name, kwargs in calls:
        out = mcp.tools[name](**kwargs)
        assert isinstance(out, dict), name
        audit_id = out.get("audit_id")
        assert isinstance(audit_id, str) and audit_id, f"{name} omitted audit_id: {out}"
        returned_ids.append(audit_id)

    log_rows = [
        json.loads(line)["audit_id"]
        for line in (audit_dir / "triage.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert set(returned_ids) <= set(log_rows)
