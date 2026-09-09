"""Tests for WP 2.8 — FD-006/007 hard enforcement in validate_finding."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nexus.discipline import validate_finding


class TestFD006Enforcement:
    """FD-006: single evidence family with MEDIUM/HIGH confidence must be REJECTED."""

    def test_single_family_medium_rejected(self):
        """Single-family MEDIUM must fail validation (not just warn)."""
        finding = {
            "title": "LSASS access",
            "observation": "Process accessed lsass.exe",
            "interpretation": "Credential dumping attempt",
            "confidence": "MEDIUM",
            "confidence_justification": "Sysmon Event 10 observed",
            "type": "finding",
            "audit_ids": ["a1", "a2"],
            "evidence": [{"source": "prefetch/x"}],
        }
        result = validate_finding(finding)
        assert not result["valid"], f"Expected rejection, got: {result}"
        assert any("FD-006" in e for e in result["errors"]), \
            f"Expected FD-006 error, got: {result['errors']}"

    def test_single_family_high_rejected(self):
        """Single-family HIGH must fail validation."""
        finding = {
            "title": "LSASS access",
            "observation": "Process accessed lsass.exe",
            "interpretation": "Credential dumping",
            "confidence": "HIGH",
            "confidence_justification": "Multiple indicators",
            "type": "finding",
            "audit_ids": ["a1", "a2", "a3"],
            "evidence": [{"source": "evtx/x"}],
        }
        result = validate_finding(finding)
        assert not result["valid"]
        assert any("FD-006" in e for e in result["errors"])

    def test_single_family_low_accepted(self):
        """Single-family LOW must still pass (no corroboration needed)."""
        finding = {
            "title": "Suspicious prefetch",
            "observation": "mimikatz.exe in prefetch",
            "interpretation": "Possible credential tool",
            "confidence": "LOW",
            "confidence_justification": "Single source, needs corroboration",
            "type": "finding",
            "audit_ids": ["a1"],
            "evidence": [{"source": "prefetch/x"}],
        }
        result = validate_finding(finding)
        assert result["valid"], f"LOW single-family should pass, got: {result}"

    def test_multi_family_high_accepted(self):
        """Multi-family HIGH with sufficient audit_ids must pass."""
        finding = {
            "title": "Credential dumping",
            "observation": "mimikatz in prefetch + LSASS access in Sysmon",
            "interpretation": "Credential dumping confirmed",
            "confidence": "HIGH",
            "confidence_justification": "Two independent sources",
            "type": "finding",
            "audit_ids": ["a1", "a2", "a3"],
            "evidence": [
                {"source": "prefetch/x"},
                {"source": "evtx/y"},
            ],
        }
        result = validate_finding(finding)
        assert result["valid"], f"Multi-family HIGH should pass, got: {result}"


class TestFD007Enforcement:
    """FD-007: MEDIUM/HIGH confidence with < 2 audit_ids must be REJECTED."""

    def test_high_single_audit_id_rejected(self):
        """HIGH with only 1 audit_id must fail."""
        finding = {
            "title": "Test",
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "HIGH",
            "confidence_justification": "justified",
            "type": "finding",
            "audit_ids": ["a1"],
            "evidence": [
                {"source": "prefetch/x"},
                {"source": "evtx/y"},
            ],
        }
        result = validate_finding(finding)
        assert not result["valid"]
        assert any("FD-007" in e for e in result["errors"])

    def test_medium_single_audit_id_rejected(self):
        """MEDIUM with only 1 audit_id must fail."""
        finding = {
            "title": "Test",
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "MEDIUM",
            "confidence_justification": "justified",
            "type": "finding",
            "audit_ids": ["a1"],
            "evidence": [
                {"source": "prefetch/x"},
                {"source": "evtx/y"},
            ],
        }
        result = validate_finding(finding)
        assert not result["valid"]
        assert any("FD-007" in e for e in result["errors"])

    def test_high_two_audit_ids_accepted(self):
        """HIGH with 2+ audit_ids and multi-family must pass."""
        finding = {
            "title": "Test",
            "observation": "obs",
            "interpretation": "interp",
            "confidence": "HIGH",
            "confidence_justification": "justified",
            "type": "finding",
            "audit_ids": ["a1", "a2"],
            "evidence": [
                {"source": "prefetch/x"},
                {"source": "evtx/y"},
            ],
        }
        result = validate_finding(finding)
        assert result["valid"], f"Should pass, got: {result}"
