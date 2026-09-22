"""Case cleanup must not leave orphan ES indexes behind."""

from __future__ import annotations

import json


class _Resp:
    def __init__(self, code: int = 200, payload: dict | None = None):
        self.status_code = code
        self._payload = payload or {}
        self.text = json.dumps(self._payload)

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, code: int = 200):
        self.code = code
        self.calls: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def delete(self, path):
        self.calls.append(path)
        return _Resp(self.code)


def test_delete_index_success(monkeypatch):
    from nexus.langgraph import case_index

    fake = _FakeClient(200)
    monkeypatch.setattr(case_index, "_client", lambda: fake)
    monkeypatch.setattr(case_index, "es_url", lambda: "http://localhost:9200")

    res = case_index.delete_index("CASE-ABC12345")

    assert res["deleted"] is True
    assert res["index"] == "nexus-case-case-abc12345"
    assert fake.calls == ["/nexus-case-case-abc12345"]


def test_delete_index_absent_and_unset(monkeypatch):
    from nexus.langgraph import case_index

    monkeypatch.setattr(case_index, "es_url", lambda: "")
    res = case_index.delete_index("CASE-X")
    assert res["deleted"] is False
    assert "NEXUS_ES_URL" in res["reason"]

    monkeypatch.setattr(case_index, "es_url", lambda: "http://localhost:9200")
    monkeypatch.setattr(case_index, "_client", lambda: _FakeClient(404))
    res = case_index.delete_index("CASE-X")
    assert res["deleted"] is False
    assert res["reason"] == "index absent"


def test_delete_index_never_raises_on_es_failure(monkeypatch):
    from nexus.langgraph import case_index

    def _boom():
        raise RuntimeError("ES down")

    monkeypatch.setattr(case_index, "es_url", lambda: "http://localhost:9200")
    monkeypatch.setattr(case_index, "_client", _boom)
    res = case_index.delete_index("CASE-Y")
    assert res["deleted"] is False
    assert "RuntimeError" in res["reason"]


def test_clean_cases_removes_only_unkept_indexes(monkeypatch):
    from nexus.cli import case_cmd
    from nexus.config import settings
    from nexus.langgraph import case_index

    root = settings.cases_root  # conftest redirects this to a tmp dir
    for cid in ("CASE-AAAA0001", "CASE-BBBB0002"):
        (root / cid).mkdir(parents=True, exist_ok=True)
    called: list[str] = []
    monkeypatch.setattr(
        case_index, "delete_index",
        lambda cid: called.append(cid) or {"deleted": True},
    )
    monkeypatch.setattr(case_index, "es_url", lambda: "http://localhost:9200")

    case_cmd.clean_cases(yes=True, keep="CASE-BBBB0002")

    assert called == ["CASE-AAAA0001"]
    assert not (root / "CASE-AAAA0001").exists()
    assert (root / "CASE-BBBB0002").exists()


def test_clean_cases_skips_indexes_when_es_unset(monkeypatch):
    from nexus.cli import case_cmd
    from nexus.config import settings
    from nexus.langgraph import case_index

    root = settings.cases_root
    (root / "CASE-CCCC0003").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(case_index, "es_url", lambda: "")

    case_cmd.clean_cases(yes=True, keep="")
    assert not (root / "CASE-CCCC0003").exists()
