"""Smoke test for the standalone ingest layer."""

from __future__ import annotations

import csv
import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nexus.ingest import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Severity,
    get_registry,
)
from nexus.ingest.artifact_store import ArtifactStore
from nexus.ingest.schemas import TimelineEntry

passed = 0
failed = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS: {label}" + (f" - {detail}" if detail else ""))
    else:
        failed += 1
        print(f"  FAIL: {label}" + (f" - {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------

timestamp = datetime(2026, 1, 15, 14, 32, 0, tzinfo=UTC)
artifact = Artifact(
    id=Artifact.new_id(),
    artifact_type=ArtifactType.NETWORK,
    source=ArtifactSource.SURICATA,
    timestamp=timestamp,
    severity=Severity.HIGH,
    source_ip="192.168.1.10",
    dest_ip="10.0.0.5",
    description="Test network artifact",
    technique_ids=["T1041"],
)

check("Artifact creation", artifact.id is not None and artifact.timestamp == timestamp)
check("Artifact to_dict", artifact.to_dict()["severity"] == "high")
check("Artifact to_json", isinstance(artifact.to_json(), str))

d = artifact.to_dict()
restored = Artifact.from_dict(d)
check("Artifact round-trip", restored.id == artifact.id and restored.severity == Severity.HIGH)

check("Severity.normalize high", Severity.normalize("HIGH") == Severity.HIGH)
check("Severity.normalize int", Severity.normalize(2) == Severity.HIGH)

timeline = TimelineEntry(
    timestamp=timestamp,
    artifact_id=artifact.id,
    artifact_type=ArtifactType.NETWORK,
    description="Timeline event",
    severity=Severity.MEDIUM,
)
check("TimelineEntry to_dict", timeline.to_dict()["artifact_type"] == "network")

# ---------------------------------------------------------------------------
# ArtifactStore tests
# ---------------------------------------------------------------------------

store = ArtifactStore(max_count=10, max_bytes=1024 * 1024)
store.put(artifact)
check("store put", len(store) == 1)

retrieved = store.get(artifact.id)
check("store get", retrieved is not None and retrieved.id == artifact.id)

store.clear()
check("store clear", len(store) == 0)

stats = store.stats()
check("store stats", stats["count"] == 0 and stats["max_count"] == 10)

# ---------------------------------------------------------------------------
# Generic importers (JSONL + CSV)
# ---------------------------------------------------------------------------

tmpdir = Path(tempfile.mkdtemp(prefix="nexus_ingest_"))
jsonl_path = tmpdir / "events.jsonl"
jsonl_path.write_text(
    json.dumps({"timestamp": "2026-01-15T14:32:00Z", "host": "host1", "message": "event1"}) + "\n"
    + json.dumps({"timestamp": 1705329120000, "host": "host2", "message": "event2"}) + "\n",
    encoding="utf-8",
)

csv_path = tmpdir / "events.csv"
with csv_path.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["timestamp", "host", "message"])
    writer.writeheader()
    writer.writerow({"timestamp": "2026-01-15T14:33:00Z", "host": "host3", "message": "event3"})

registry = get_registry()
jsonl_result = registry.import_path(jsonl_path)
check("JSONL import", jsonl_result.success and len(jsonl_result.artifacts) == 2)

csv_result = registry.import_path(csv_path)
check("CSV import", csv_result.success and len(csv_result.artifacts) == 1)

check("Registry sources", ArtifactSource.GENERIC_JSONL in registry.all_sources())

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

for p in tmpdir.iterdir():
    p.unlink()
tmpdir.rmdir()

print()
print(f"=== {passed} PASSED, {failed} FAILED (out of {passed + failed}) ===")

if failed > 0:
    sys.exit(1)
