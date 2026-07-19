"""Tests for the HMAC audit chain (P1.5)."""

from __future__ import annotations

import pytest

from nexus.case import (
    AuditAction,
    AuditChain,
    get_audit_secret,
)


class TestAuditChain:
    def test_genesis_hash(self) -> None:
        chain = AuditChain("CASE-1")
        entries = chain.entries()
        assert len(entries) == 0

    def test_append_creates_entry(self) -> None:
        chain = AuditChain("CASE-1")
        entry = chain.append(
            AuditAction.CASE_CREATED,
            actor="analyst",
            payload={"name": "Test"},
        )
        assert entry.action == AuditAction.CASE_CREATED
        assert entry.actor == "analyst"
        assert entry.prev_hash == "0" * 64
        assert len(entry.hash) == 64
        assert len(entry.signature) == 64

    def test_chain_links(self) -> None:
        chain = AuditChain("CASE-1")
        e1 = chain.append(AuditAction.CASE_CREATED, "a", {})
        e2 = chain.append(AuditAction.FINDING_RECORDED, "b", {"x": 1})
        e3 = chain.append(AuditAction.CASE_CLOSED, "c", {})
        assert e2.prev_hash == e1.hash
        assert e3.prev_hash == e2.hash

    def test_verify_valid_chain(self) -> None:
        chain = AuditChain("CASE-1")
        chain.append(AuditAction.CASE_CREATED, "a", {})
        chain.append(AuditAction.FINDING_RECORDED, "b", {"x": 1})
        chain.append(AuditAction.CASE_CLOSED, "c", {})
        ok, errors = chain.verify()
        assert ok
        assert errors == []

    def test_verify_detects_tampered_payload(self) -> None:
        chain = AuditChain("CASE-1")
        chain.append(AuditAction.CASE_CREATED, "a", {"value": "original"})
        chain.append(AuditAction.FINDING_RECORDED, "b", {"x": 1})
        # Tamper with the first entry's payload
        chain._entries[0].payload["value"] = "tampered"
        ok, errors = chain.verify()
        assert not ok
        assert len(errors) > 0

    def test_verify_detects_broken_link(self) -> None:
        chain = AuditChain("CASE-1")
        chain.append(AuditAction.CASE_CREATED, "a", {})
        chain.append(AuditAction.FINDING_RECORDED, "b", {"x": 1})
        # Break the chain: change prev_hash on entry 1
        chain._entries[1].prev_hash = "f" * 64
        ok, errors = chain.verify()
        assert not ok
        assert any("prev_hash mismatch" in e for e in errors)

    def test_to_list(self) -> None:
        chain = AuditChain("CASE-1")
        chain.append(AuditAction.CASE_CREATED, "a", {"x": 1})
        chain.append(AuditAction.FINDING_RECORDED, "b", {})
        lst = chain.to_list()
        assert len(lst) == 2
        assert all(isinstance(d, dict) for d in lst)

    def test_from_entries(self) -> None:
        chain = AuditChain("CASE-1")
        chain.append(AuditAction.CASE_CREATED, "a", {})
        chain.append(AuditAction.FINDING_RECORDED, "b", {})
        rebuilt = AuditChain.from_entries("CASE-1", chain.entries())
        ok, errors = rebuilt.verify()
        assert ok
        assert errors == []

    def test_different_keys_produce_different_hashes(self) -> None:
        chain1 = AuditChain("CASE-1", secret_key=b"secret-one")
        chain2 = AuditChain("CASE-1", secret_key=b"secret-two")
        e1 = chain1.append(AuditAction.CASE_CREATED, "a", {})
        e2 = chain2.append(AuditAction.CASE_CREATED, "a", {})
        assert e1.hash != e2.hash

    def test_from_entries_requires_same_key(self) -> None:
        chain = AuditChain("CASE-1", secret_key=b"secret-one")
        chain.append(AuditAction.CASE_CREATED, "a", {})
        rebuilt = AuditChain.from_entries(
            "CASE-1", chain.entries(), secret_key=b"different-key"
        )
        ok, errors = rebuilt.verify()
        assert not ok
        assert len(errors) > 0


class TestGetAuditSecret:
    def test_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEXUS_AUDIT_SECRET", "production-secret")
        assert get_audit_secret() == b"production-secret"

    def test_dev_fallback(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        monkeypatch.delenv("NEXUS_AUDIT_SECRET", raising=False)
        monkeypatch.setattr("nexus.case.secrets._PERSISTED_SECRET_PATH", tmp_path / "audit_secret")
        secret = get_audit_secret()
        assert isinstance(secret, bytes)
        assert len(secret) == 64
        assert get_audit_secret() == secret
