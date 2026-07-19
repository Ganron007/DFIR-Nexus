"""Tests for the detection module.

Exercises schemas, indexing, search, and coverage without requiring an
LLM or external network.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nexus.detection import (
    DetectionIndexer,
    DetectionRule,
    DetectionSearcher,
    DetectionSource,
    MITRECoverage,
    RuleFormat,
    RuleSeverity,
)

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


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------

rule = DetectionRule(
    id="test-001",
    title="Test Rule",
    description="A test detection rule.",
    format=RuleFormat.SIGMA,
    source=DetectionSource.NEXUS_CUSTOM,
    severity=RuleSeverity.HIGH,
    technique_ids=["T1003.001"],
    tactic_ids=["TA0006"],
    tags=["attack.t1003.001", "attack.credential_access"],
    source_path="rules/test.yml",
)

check("DetectionRule creation", rule.id == "test-001" and rule.title == "Test Rule")

d = rule.to_dict()
check("to_dict has id", d.get("id") == "test-001")
check("to_dict format value", d.get("format") == "sigma")
check("to_dict source value", d.get("source") == "nexus_custom")
check("to_dict technique_ids", "T1003.001" in d.get("technique_ids", []))


# ---------------------------------------------------------------------------
# Indexer + Searcher tests
# ---------------------------------------------------------------------------

sample_sigma = """
title: Suspicious PowerShell Download
id: 12345678-1234-1234-1234-123456789abc
status: experimental
description: Detects suspicious PowerShell download commands.
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Invoke-WebRequest'
      - 'bitsadmin'
  condition: selection
falsepositives:
  - Unknown
tags:
  - attack.execution
  - attack.t1059.001
level: high
"""

sample_sigma_2 = """
title: LSASS Memory Dump
id: 87654321-4321-4321-4321-cba987654321
status: experimental
description: Detects LSASS memory access.
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage: 'lsass.exe'
  condition: selection
falsepositives:
  - Unknown
tags:
  - attack.credential_access
  - attack.t1003.001
level: critical
"""

with tempfile.TemporaryDirectory() as tmp:
    sigma_root = Path(tmp) / "sigma"
    sigma_root.mkdir()
    (sigma_root / "rule1.yml").write_text(sample_sigma, encoding="utf-8")
    (sigma_root / "rule2.yml").write_text(sample_sigma_2, encoding="utf-8")

    index_dest = Path(tmp) / "index"
    indexer = DetectionIndexer(index_dest)
    count = indexer.index_sigma_directory(sigma_root)
    check("index_sigma_directory count", count == 2, f"indexed {count} rules")

    # Manifest should be written
    check("manifest exists", (index_dest / "manifest.json").exists())

    searcher = DetectionSearcher(index_dest)
    check("searcher count", searcher.count() == 2, f"count={searcher.count()}")

    # Search by technique
    results = searcher.search(technique_id="T1003.001")
    check("search by technique T1003.001", len(results) == 1, f"found {len(results)}")

    # Search by query
    results = searcher.search(query="powershell")
    check("search by query 'powershell'", len(results) == 1, f"found {len(results)}")

    # Search by severity
    results = searcher.search(severity=RuleSeverity.CRITICAL)
    check("search by severity CRITICAL", len(results) == 1, f"found {len(results)}")

    # Stats
    stats = searcher.stats()
    check("stats total", stats.get("total") == 2)
    check("stats by_format has sigma", stats.get("by_format", {}).get("sigma") == 2)
    check("stats by_severity has high", stats.get("by_severity", {}).get("high") == 1)
    check("stats by_severity has critical", stats.get("by_severity", {}).get("critical") == 1)

    # ---------------------------------------------------------------------------
    # Coverage tests
    # ---------------------------------------------------------------------------
    coverage = MITRECoverage(searcher)

    cov = coverage.coverage_for_technique("T1003.001")
    check("coverage_for_technique total", cov.get("total_rules") == 1)
    check("coverage_for_technique id", cov.get("technique_id") == "T1003.001")

    matrix = coverage.coverage_matrix(["T1003.001", "T1059.001"])
    check("coverage_matrix keys", set(matrix.keys()) == {"T1003.001", "T1059.001"})
    check("coverage_matrix T1003.001 critical", matrix.get("T1003.001", {}).get("critical") == 1)

    gaps = coverage.gap_analysis(["T1003.001", "T9999.999"])
    check("gap_analysis finds T9999.999", any(g["technique_id"] == "T9999.999" for g in gaps))


# ---------------------------------------------------------------------------
# Sigma translation optional dependency handling
# ---------------------------------------------------------------------------

try:
    from nexus.detection import sigma_repo
    # pysigma is not required for basic tests; the function should raise
    # ImportError gracefully if the dependency is missing.
    try:
        sigma_repo.sigma_translate(sample_sigma, target="kql")
        check("sigma_translate available", True, "pysigma installed")
    except ImportError as exc:
        check("sigma_translate missing dependency handled", "dfir-nexus[detection]" in str(exc))
except Exception as exc:
    check("sigma_repo import", False, str(exc))


print()
print(f"=== {passed} PASSED, {failed} FAILED (out of {passed + failed}) ===")
sys.exit(0 if failed == 0 else 1)
