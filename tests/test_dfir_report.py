"""DFIR Report-style narrative renderer."""

from nexus.integration.dfir_report import build_dfir_markdown
from nexus.langgraph.agents.evidence import cite_block, finding
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity
from datetime import UTC, datetime


def _art(**kw):
    defaults = dict(
        id=Artifact.new_id(),
        source=ArtifactSource.ZEEK,
        artifact_type=ArtifactType.NETWORK,
        severity=Severity.HIGH,
        timestamp=datetime.now(UTC),
        host="WS01",
        source_ip="192.168.77.62",
        dest_ip="192.168.77.10",
        dest_port=445,
        description="SMB conn",
        technique_ids=["T1021.002"],
    )
    defaults.update(kw)
    return Artifact(**defaults)


def test_cite_block_includes_ips():
    text = cite_block([_art()])
    assert "192.168.77.10" in text
    assert "WS01" in text


def test_finding_helper_has_description_body():
    f = finding("SMB lateral", [_art()], severity="high", lead="Lateral SMB observed.")
    assert "Lateral SMB" in f["description"]
    assert "192.168.77.10" in f["description"]
    assert "T1021.002" in f["technique_ids"]


def test_dfir_markdown_sections():
    md = build_dfir_markdown(
        case_id="CASE-TEST",
        case_name="Test Case",
        findings=[{
            "id": "F1",
            "title": "Network activity to 192.168.77.10",
            "status": "APPROVED",
            "severity": "high",
            "observation": "SMB traffic cited",
            "mitre_ids": ["T1021.002"],
            "approved_by": "e2e_host",
        }],
        evidence=[{
            "name": "conn.log",
            "path": "/tmp/conn.log",
            "host": "WS01",
            "dest_ip": "192.168.77.10",
            "source_ip": "192.168.77.62",
        }],
        timeline=[{"timestamp": "2026-08-12T00:00:00Z", "host": "WS01", "description": "SMB", "source": "zeek"}],
        sift_notes=["tshark -r conn.pcap -q -z io,phs → OK"],
        rag_notes=["RAG grounded: 4/4 queries"],
        examiner="e2e_host",
    )
    for section in (
        "## Key Takeaways",
        "## Case Summary",
        "## Findings (Evidence-Backed)",
        "## Network",
        "## SIFT Linux Tooling",
        "## Timeline",
        "## Indicators",
        "## Detections",
        "## MITRE ATT&CK",
        "## Evidence Registry",
    ):
        assert section in md
    assert "192.168.77.10" in md
    assert "tshark" in md
    assert "`T1021.002`" in md
    assert "RAG grounded" in md


def test_rag_notes_are_human_readable():
    md = build_dfir_markdown(
        case_id="CASE-RAG",
        case_name="RAG",
        findings=[],
        evidence=[],
        rag_notes=[
            "RAG ready model=BAAI/bge-base-en-v1.5 records=22268",
            "[{'rank': 1, 'score': 0.73, 'source': 'SANS_FOR508', 'title': 'Prefetch PECmd'}]",
        ],
    )
    assert "RAG ready model=BAAI/bge-base-en-v1.5 records=22268" in md
    assert "Prefetch PECmd" in md
    assert "[{'rank'" not in md
