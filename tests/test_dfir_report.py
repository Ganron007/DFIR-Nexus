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


def test_dfir_markdown_filters_to_this_run_finding_ids():
    md = build_dfir_markdown(
        case_id="CASE-FILTER",
        case_name="Filter",
        findings=[
            {
                "id": "F-old",
                "title": "Routine Acrobat from CSV heads",
                "status": "APPROVED",
                "severity": "high",
                "observation": "AcroRd32.exe",
            },
            {
                "id": "F-new",
                "title": "Recycle Bin contains deleted PST and SDelete",
                "status": "APPROVED",
                "severity": "high",
                "observation": "sdelete.exe and backup.pst",
            },
        ],
        evidence=[],
        finding_ids=["F-new"],
    )
    assert "SDelete" in md
    assert "Acrobat" not in md


def test_split_questions_strips_trailing_comma():
    from nexus.integration.dfir_report import _split_questions

    qs = _split_questions("What supports insider staging, data staging,? and what supports external compromise?")
    assert qs
    assert not any(",?" in q or q.endswith(",?") for q in qs)
    assert all(q.endswith("?") for q in qs)
    assert any("staging" in q.lower() for q in qs)
    assert any(q.lower().startswith("what ") for q in qs)


def test_timeline_keeps_i1_when_n4_is_truncated():
    n4 = [
        {"timestamp": f"2020-11-14T13:{i:02d}:00Z", "host": "WS01",
         "description": f"n4 hit {i}", "source": "n4"}
        for i in range(90)
    ]
    n4.append({
        "timestamp": "2020-11-14T13:42:00Z",
        "host": "linux01",
        "description": "conn 192.168.77.62 -> 192.168.77.10:445",
        "source": "i1:zeek",
    })
    md = build_dfir_markdown(
        case_id="CASE-I1",
        case_name="I1",
        findings=[],
        evidence=[],
        timeline=n4,
    )
    assert "### Import/ingest (I1)" in md
    assert "i1:zeek" in md
    assert "192.168.77.10" in md


def test_qa_spine_answers_or_insufficient():
    from nexus.integration.dfir_report import build_qa_spine

    rows = build_qa_spine(
        ["What supports insider staging?", "What supports external compromise?"],
        [{
            "id": "F-1",
            "title": "Recycle Bin contains deleted PST and SDelete",
            "observation": "sdelete.exe and backup.pst",
            "status": "APPROVED",
        }, {
            "id": "F-014",
            "title": "No host artifacts in the query pack support external compromise",
            "observation": "Query pack does not support C2 or malware on this host",
            "status": "APPROVED",
        }],
    )
    assert "sdelete" in rows[0]["answer"].lower() or "pst" in rows[0]["answer"].lower()
    assert "INSUFFICIENT" in rows[1]["answer"]
    assert "F-014" in rows[1]["cite"]


def test_qa_spine_ignores_dual_lens_c2_prose():
    from nexus.integration.dfir_report import build_qa_spine

    rows = build_qa_spine(
        ["What supports external compromise?"],
        [{
            "id": "F-009",
            "title": "fredr accessed PST stores",
            "observation": "backup.pst opened",
            "interpretation": "Under the external-compromise lens, no malicious process or C2 is associated.",
            "status": "APPROVED",
        }],
    )
    assert "INSUFFICIENT" in rows[0]["answer"]


def test_qa_spine_refute_beaconing_is_not_external_support():
    from nexus.integration.dfir_report import build_qa_spine

    rows = build_qa_spine(
        ["What supports or refutes external compromise?"],
        [{
            "id": "F-016",
            "title": "PowerShell history records direct SDelete volume wipes",
            "observation": "sdelete64.exe -nobanner -z -c D:",
            "interpretation": (
                "It strengthens the insider-misuse lens; externally it could "
                "reflect cleanup by an operator, but no malware or C2 beaconing "
                "is present in the provided hits."
            ),
        }],
    )
    assert "INSUFFICIENT" in rows[0]["answer"]
    assert "Supported" not in rows[0]["answer"]
    assert "beacon" not in rows[0]["answer"].lower()


def test_qa_spine_sdelete_row_still_supports_insider():
    from nexus.integration.dfir_report import build_qa_spine

    findings = [{
        "id": "F-016",
        "title": "PowerShell history records direct SDelete volume wipes",
        "observation": "sdelete64.exe -nobanner -z -c D:",
        "interpretation": (
            "It strengthens the insider-misuse lens, but no malware or C2 "
            "beaconing is present in the provided hits."
        ),
    }]
    rows = build_qa_spine(
        [
            "What host activity supports or refutes insider misuse / data staging?",
            "What supports or refutes external compromise?",
        ],
        findings,
    )
    assert "Supported" in rows[0]["answer"] and "sdelete" in rows[0]["answer"]
    assert "INSUFFICIENT" in rows[1]["answer"]


def test_finding_evidence_renders_as_table_not_prose_wall():
    wall = (
        "Host artifacts show repeated Google Drive File Stream and OneDrive "
        "activity on 2020-11-14: amcache records googledrivefs3229.sys first "
        "seen 2020-08-17 and drive binaries entry 2020-11-15 09:05:16; "
        "appcompat shows GoogleDriveFSSetup.exe on 2020-11-08 and "
        "googledrivesync.exe on 2020-11-03 and 2020-10-15; pecmd shows 8 "
        "GOOGLEDRIVEFS.EXE prefetch runs on 2020-11-14 between 03:56:46 and "
        "14:10:59; jlecmd/lecmd show numerous Quick Access and recent LNK "
        "targets under G:\\My Drive\\STARK-RESEARCH-LABS FOLDER and "
        "G:\\My Drive\\Key; Outlook backup.pst resides in "
        "C:\\Users\\fredr\\OneDrive\\Documents\\Outlook Files."
    )
    md = build_dfir_markdown(
        case_id="CASE-TABLE",
        case_name="Table",
        findings=[{
            "id": "F-022",
            "title": "Google Drive File Stream staging",
            "status": "APPROVED",
            "severity": "high",
            "observation": wall,
            "interpretation": "Authorized cloud sync used for staging.",
        }],
        evidence=[],
    )
    assert "**Evidence**" in md
    assert "| Time (UTC) | Source | Artifact / path | What it shows |" in md
    assert "pecmd" in md
    assert "2020-11-15 09:05:16" in md
    assert r"G:\My Drive" in md
    assert "GOOGLEDRIVEFS.EXE" in md
    assert "Authorized cloud sync used for staging." in md
    assert wall not in md


def test_n4_usb_dump_becomes_table_and_drops_garbage():
    obs = (
        "N4 query-pack hits (113 rows, families: amcache, pecmd, recmd):\n"
        "amcache\\amcache_DevicePnps.csv:194 terms=usbstor: "
        "usbstor/disk&ven_toshiba&prod_external_usb_3.0&rev_0/20130904004110f&0,"
        "2020-11-16 02:29:46,TOSHIBA External USB 3.0 USB Device,diskdrive\n"
        "amcache\\amcache_DevicePnps.csv:207 terms=usbstor: "
        "swd/wpdbusenum/_??_usbstor#disk,2020-11-06 09:37:28,,\ufffd,{eec5ad98}\n"
    )
    md = build_dfir_markdown(
        case_id="CASE-USB",
        case_name="USB",
        findings=[{
            "id": "F-028",
            "title": "USB / USBSTOR activity",
            "status": "APPROVED",
            "severity": "high",
            "observation": obs,
            "interpretation": "Removable media was attached.",
        }],
        evidence=[],
    )
    assert "TOSHIBA External USB 3.0" in md
    assert "2020-11-16 02:29:46" in md
    assert "\ufffd" not in md
    assert "amcache\\amcache_DevicePnps.csv:194 terms=usbstor:" not in md


def test_structured_evidence_wins_over_observation():
    md = build_dfir_markdown(
        case_id="CASE-EV",
        case_name="EV",
        findings=[{
            "id": "F-1",
            "title": "SDelete",
            "status": "APPROVED",
            "severity": "high",
            "observation": "ignore this wall",
            "evidence": [{
                "time": "2020-11-14 13:42:33",
                "source": "amcache",
                "artifact": r"C:\Users\fredr\Downloads\SDelete\sdelete.exe",
                "detail": "first executed",
            }],
            "interpretation": "Anti-forensics.",
        }],
        evidence=[],
    )
    assert "2020-11-14 13:42:33" in md
    assert "amcache" in md
    assert "sdelete.exe" in md
    assert "ignore this wall" not in md

