from __future__ import annotations

from pathlib import Path

from nexus.ingest.cloud.azure import AzureImporter


# This two-row excerpt is verbatim from Tiny T20's staged Azure activity export:
# lab-2.1_source_evidence/insights-activity-logs.json, lines 2475-2476.
def test_azure_importer_reads_real_json_lines_export_excerpt():
    path = Path(__file__).parent / "fixtures" / "d349_azure_activity_jsonl.jsonl"
    importer = AzureImporter()
    assert importer.can_handle(path)
    artifacts = list(importer.parse(path))

    assert [artifact.description for artifact in artifacts] == [
        "Azure Microsoft.Resourcehealth/healthevent/Updated/action (Succeeded)",
        "Azure Microsoft.Advisor/recommendations/available/action (Succeeded)",
    ]
    # Literal source clocks in the unchanged two-row captured export. Keep the
    # compatibility datetime but retain its additional 100-ns digit in storage.
    assert [artifact.to_dict()["timestamp"] for artifact in artifacts] == [
        "2023-03-28T00:35:52.121452900Z",
        "2023-03-28T05:00:22.475768100Z",
    ]
    from nexus.ingest.schemas import Artifact

    for artifact in artifacts:
        assert Artifact.from_dict(artifact.to_dict()).to_dict() == artifact.to_dict()
        assert artifact.ts_synthesized is False
        assert artifact.ts_tz_assumed is False
