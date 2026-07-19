"""Smoke tests for ported push ingest module.

Run as a script: python tests/test_push.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from nexus.push.auth import PushTokenStore
from nexus.push.payload import normalize_push_payload
from nexus.push.pipeline import PushPipeline

passed = 0
failed = 0


def check(label, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS: {label}" + (f" — {detail}" if detail else ""))
    else:
        failed += 1
        print(f"  FAIL: {label}" + (f" — {detail}" if detail else ""))


def run_tests():
    # ---------------------------------------------------------------------------
    # Push auth
    # ---------------------------------------------------------------------------

    with tempfile.TemporaryDirectory() as tmp:
        store_path = Path(tmp) / "tokens.json"
        store = PushTokenStore(store_path)

        store.set_global_token("global-secret")
        check("global token verifies", store.verify("global-secret"))
        check("global token rejects bad", not store.verify("bad-secret"))

        token = store.generate_case_token("CASE-001", label="test-label")
        check("case token verifies", store.verify(token, case_id="CASE-001"))
        check("case token rejects wrong case", not store.verify(token, case_id="CASE-002"))
        check("case token hint present", len(store.list_case_tokens("CASE-001")) == 1)

        revoked = store.revoke_case_tokens("CASE-001")
        check("revoke returns count", revoked == 1)
        check("revoked token no longer verifies", not store.verify(token, case_id="CASE-001"))

    # ---------------------------------------------------------------------------
    # Push payload normalization
    # ---------------------------------------------------------------------------

    batch = normalize_push_payload([{"title": "a", "url": "http://x"}, {"name": "b"}])
    check("batch kind", batch.get("kind") == "capture_batch")
    check("batch captures", len(batch.get("captures", [])) == 2)

    capture = normalize_push_payload({"kind": "capture", "title": "t", "body": "data"})
    check("capture kind", capture.get("kind") == "capture")
    check("capture title", capture["capture"]["title"] == "t")

    generic = normalize_push_payload({"kind": "foo", "foo": "bar"})
    check("generic kind", generic.get("kind") == "foo")

    not_json: Any = "not json"
    garbage = normalize_push_payload(not_json)
    check("garbage kind", garbage.get("kind") == "unknown")

    # ---------------------------------------------------------------------------
    # Push pipeline with mock manager
    # ---------------------------------------------------------------------------

    class MockManager:
        def __init__(self):
            self.cases = {"CASE-001": SimpleNamespace(id="CASE-001")}
            self.evidence = []
            self.findings = []

        def get_case(self, case_id: str):
            return self.cases.get(case_id)

        def add_evidence(self, case_id: str, **kwargs):
            self.evidence.append({"case_id": case_id, **kwargs})

        def add_finding(self, case_id: str, **kwargs):
            self.findings.append({"case_id": case_id, **kwargs})
            return SimpleNamespace(id="FIND-001")

    mgr = MockManager()
    pipeline = PushPipeline(mgr)
    result = pipeline.process("CASE-001", {"kind": "capture", "title": "x", "body": "y"})
    check("pipeline success", result.get("success") is True)
    check("pipeline registered", result.get("registered") == 1)

    result = pipeline.process("CASE-002", {"kind": "capture"})
    check("pipeline missing case fails", result.get("success") is False)

    result = pipeline.process(
        "CASE-001",
        {"kind": "capture", "title": "mimikatz dump", "body": "lsass"},
    )
    check("pipeline finding raised", result.get("finding_id") is not None)

    # ---------------------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------------------

    print(f"\nResults: {passed} passed, {failed} failed")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
