"""N4 query pack — hits not CSV heads."""

from __future__ import annotations

from pathlib import Path

from nexus.langgraph.query_pack import (
    build_query_pack_markdown,
    collect_query_terms,
    n4_finding_candidates,
    parse_intake_window,
    parse_window,
    scan_extractions,
)


def test_parse_window_single_day():
    start, end = parse_window("examiner window 2020-11-14")
    assert start is not None and end is not None
    assert start.date().isoformat() == "2020-11-14"
    assert end.date().isoformat() == "2020-11-14"


def test_parse_window_unparseable():
    start, end = parse_window("examiner-supplied; evidence timestamps win")
    assert start is None and end is None


def test_parse_intake_window_ignores_question_incident_date():
    start, end = parse_intake_window({
        "window": "2022-08-31 2023-01-29",
        "question": (
            "Incident formally called 2023-01-24 after anti-malware alerts. "
            "What attacker activity is evidenced on disk/memory/security/admin?"
        ),
    })
    assert start is not None and end is not None
    assert start.date().isoformat() == "2022-08-31"
    assert end.date().isoformat() == "2023-01-29"


def test_question_collection_prose_is_not_query_terms():
    terms = [t.lower() for t in collect_query_terms({
        "playbooks": "external_compromise",
        "question": (
            "F-Response disk/memory collected. Scope security admin activity "
            "on this pack. Velociraptor and Kansa hunts. What attacker "
            "activity is evidenced?"
        ),
        "subjects": "rsydow-a, tdungan",
    })]
    for noise in (
        "disk", "memory", "security", "admin", "pack", "scope",
        "velociraptor", "kansa", "attacker", "evidenced", "hunts",
        "f-response",
    ):
        assert noise not in terms
    assert "rsydow-a" in terms
    assert "tdungan" in terms
    assert "wevtutil" in terms


def test_host_hunt_playbooks_include_log_tamper_terms():
    from nexus.langgraph.case_intake import extra_playbook_names
    from nexus.langgraph.query_pack import collect_playbook_query_terms

    names = extra_playbook_names({
        "question": "What attacker activity is evidenced on this host?",
        "playbooks": "external_compromise",
    })
    assert "log_tampering" in names
    terms = [t.lower() for t in collect_playbook_query_terms({
        "question": "What attacker activity is evidenced on this host?",
        "playbooks": "external_compromise",
    })]
    assert "wevtutil" in terms
    assert "1102" in terms
    assert "dataoverwrite" in terms


def test_data_staging_terms_include_wipe_and_cloud():
    terms = [t.lower() for t in collect_query_terms({"playbooks": "data_staging"})]
    assert "sdelete" in terms
    assert any("pst" in t for t in terms)
    assert any("drive" in t for t in terms)


def test_query_pack_prefers_sdelete_over_acrobat_head(tmp_path: Path):
    ext = tmp_path / "extractions" / "pecmd"
    ext.mkdir(parents=True)
    csv = ext / "prefetch_Timeline.csv"
    csv.write_text(
        "RunTime,ExecutableName\n"
        "2020-11-14 04:49:43,ACRORD32.EXE\n"
        "2020-11-14 13:42:11,sdelete.exe\n"
        "2020-11-14 13:43:00,SDELETE.EXE\n",
        encoding="utf-8",
    )
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  playbooks: data_staging\n",
        encoding="utf-8",
    )
    md = build_query_pack_markdown(tmp_path, ledger=[])
    assert "sdelete" in md.lower()
    assert "ACRORD32" not in md
    assert "## N2 extras" in md


def test_window_filters_out_of_range_rows(tmp_path: Path):
    ext = tmp_path / "extractions" / "rbcmd"
    ext.mkdir(parents=True)
    (ext / "recycle.csv").write_text(
        "path,when\n"
        "sdelete.exe,2020-10-01 00:00:00\n"
        "sdelete.exe,2020-11-14 13:41:24\n",
        encoding="utf-8",
    )
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  playbooks: data_staging\n  window: 2020-11-14\n",
        encoding="utf-8",
    )
    start, end = parse_window("2020-11-14")
    hits = scan_extractions(tmp_path, ["sdelete"], (start, end))
    texts = " ".join(h["text"] for h in hits)
    assert "2020-11-14" in texts
    assert "2020-10-01" not in texts


def test_notes_are_not_query_terms():
    terms = [t.lower() for t in collect_query_terms({
        "playbooks": "data_staging",
        "notes": "Use MFTECmd bodyfile + TSK mactime; do not run plaso.",
        "question": "what was staged",
    })]
    assert "sdelete" in terms
    assert "plaso" not in terms
    assert "mactime" not in terms
    assert "mftecmd" not in terms


def test_playbook_hits_survive_earlier_noise(tmp_path: Path):
    ext = tmp_path / "extractions" / "pecmd"
    ext.mkdir(parents=True)
    rows = ["RunTime,ExecutableName"]
    rows.extend(f"2020-11-14 04:00:{i:02d},OneDrive.exe" for i in range(50))
    rows.append("2020-11-14 13:42:11,sdelete.exe")
    (ext / "prefetch_Timeline.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  playbooks: data_staging\n",
        encoding="utf-8",
    )
    md = build_query_pack_markdown(tmp_path, ledger=[])
    assert "sdelete" in md.lower()


def test_strong_terms_outrank_usbstor_flood(tmp_path: Path):
    recmd = tmp_path / "extractions" / "recmd"
    recmd.mkdir(parents=True)
    usb_rows = ["ts,path"]
    usb_rows.extend(
        f"2020-11-10 12:00:{i:02d},USBSTOR\\Disk&Ven_Generic_{i}" for i in range(80)
    )
    (recmd / "DeviceClasses__SYSTEM.csv").write_text(
        "\n".join(usb_rows) + "\n", encoding="utf-8"
    )
    (recmd / "UserAssist__NTUSER.DAT.csv").write_text(
        "name,path\n"
        "sdelete,C:\\Users\\x\\Downloads\\sdelete.exe\n"
        "docs,G:\\My Drive\\SRL-EMAIL-EXPORT.pst\n",
        encoding="utf-8",
    )
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  playbooks: usb_activity,data_staging\n",
        encoding="utf-8",
    )
    md = build_query_pack_markdown(tmp_path, ledger=[])
    hits = md.split("## Hits", 1)[-1].lower()
    assert "sdelete" in hits
    assert "srl-email-export.pst" in hits
    assert hits.index("sdelete") < hits.index("usbstor")
    ext = tmp_path / "extractions" / "pecmd"
    ext.mkdir(parents=True)
    rows = ["RunTime,ExecutableName"]
    rows.extend(f"2020-11-14 04:00:{i:02d},OneDrive.exe" for i in range(50))
    rows.append("2020-11-14 13:42:11,sdelete.exe")
    (ext / "prefetch_Timeline.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  playbooks: data_staging\n",
        encoding="utf-8",
    )
    md = build_query_pack_markdown(tmp_path, ledger=[])
    assert "sdelete" in md.lower()


def test_skips_tool_meta_logs(tmp_path: Path):
    ext = tmp_path / "extractions" / "recmd"
    ext.mkdir(parents=True)
    (ext / "20260813T064159_recmd_meta.json").write_text(
        '{"cmd": "sdelete.exe"}\n', encoding="utf-8"
    )
    (ext / "user.csv").write_text(
        "name,path\nkeep,C:\\sdelete.exe\n", encoding="utf-8"
    )
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  playbooks: data_staging\n", encoding="utf-8"
    )
    md = build_query_pack_markdown(tmp_path, ledger=[])
    assert "sdelete" in md.lower()
    assert "_meta.json" not in md


def test_write_snippets_also_writes_query_pack(tmp_path: Path):
    from nexus.langgraph.snippets import write_snippets

    ext = tmp_path / "extractions"
    ext.mkdir()
    (ext / "note.csv").write_text("a,b\nsdelete.exe,x\n", encoding="utf-8")
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  playbooks: data_staging\n", encoding="utf-8"
    )
    write_snippets(tmp_path, [])
    assert (tmp_path / "analysis" / "snippets.md").is_file()
    qp = (tmp_path / "analysis" / "query_pack.md").read_text(encoding="utf-8")
    assert "sdelete" in qp.lower()


def test_n4_finding_candidates_quote_sdelete_not_acrobat(tmp_path: Path):
    ext = tmp_path / "extractions" / "pecmd"
    ext.mkdir(parents=True)
    (ext / "prefetch_Timeline.csv").write_text(
        "RunTime,ExecutableName\n"
        "2020-11-14 04:49:43,ACRORD32.EXE\n"
        "2020-11-14 13:42:11,sdelete.exe\n",
        encoding="utf-8",
    )
    recmd = tmp_path / "extractions" / "recmd"
    recmd.mkdir(parents=True)
    (recmd / "UserAssist__NTUSER.DAT.csv").write_text(
        "name,path\n"
        "docs,G:\\My Drive\\SRL-EMAIL-EXPORT.pst\n",
        encoding="utf-8",
    )
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  playbooks: data_staging\n  host: rocba\n",
        encoding="utf-8",
    )
    ledger = [
        {
            "status": "OK",
            "tool": "windows/pecmd",
            "audit_id": "win-e-20260101-001",
            "purpose": "prefetch",
        },
        {
            "status": "OK",
            "tool": "windows/recmd",
            "audit_id": "win-e-20260101-002",
            "purpose": "registry",
        },
    ]
    cands = n4_finding_candidates(tmp_path, ledger=ledger)
    assert cands
    blob = " ".join(f"{c['title']} {c['observation']}" for c in cands).lower()
    assert "sdelete" in blob
    assert "completed ok" not in blob
    assert "acrord32" not in blob
    assert "pst" in blob
    assert any(c.get("audit_ids") for c in cands)


def test_n4_finding_candidates_empty_without_hits(tmp_path: Path):
    (tmp_path / "extractions" / "pecmd").mkdir(parents=True)
    (tmp_path / "extractions" / "pecmd" / "prefetch_Timeline.csv").write_text(
        "RunTime,ExecutableName\n2020-11-14 04:49:43,ACRORD32.EXE\n",
        encoding="utf-8",
    )
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  playbooks: data_staging\n",
        encoding="utf-8",
    )
    assert n4_finding_candidates(tmp_path, ledger=[]) == []


def test_query_extra_needles_and_ingest_root(tmp_path: Path):
    from nexus.langgraph.query_pack import run_ad_hoc_query

    ext = tmp_path / "extractions" / "pecmd"
    ext.mkdir(parents=True)
    (ext / "prefetch_Timeline.csv").write_text(
        "RunTime,ExecutableName\n2020-11-14 13:00:00,notepad.exe\n",
        encoding="utf-8",
    )
    ingest = tmp_path / "ingest"
    ingest.mkdir()
    (ingest / "conn.log").write_text(
        "ts,id.orig_h\n2020-11-14 13:01:00,192.168.77.62\n",
        encoding="utf-8",
    )
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  playbooks: data_staging\n  query_extra: notepad.exe\n",
        encoding="utf-8",
    )
    md = build_query_pack_markdown(tmp_path, ledger=[])
    assert "notepad.exe" in md.lower()
    result = run_ad_hoc_query(
        tmp_path, extra_needles=["192.168.77.62"], persist=True, limit=20
    )
    assert result["count"] >= 1
    texts = " ".join(h["text"] for h in result["hits"])
    assert "192.168.77.62" in texts
    yaml_text = (tmp_path / "CASE.yaml").read_text(encoding="utf-8")
    assert "192.168.77.62" in yaml_text


def test_bmc_tools_file_cap(tmp_path: Path):
    from nexus.langgraph.query_pack import iter_extraction_files

    bmc = tmp_path / "extractions" / "bmc-tools"
    bmc.mkdir(parents=True)
    for i in range(200):
        (bmc / f"tile{i}.txt").write_text("rdp cache tile\n", encoding="utf-8")
    files = iter_extraction_files(tmp_path)
    bmc_n = sum(1 for _p, _r, fam in files if fam == "bmc-tools")
    assert bmc_n <= 120
    assert bmc_n > 0


def test_n4_scans_hayabusa_named_file(tmp_path: Path):
    hay = tmp_path / "extractions" / "hayabusa"
    hay.mkdir(parents=True)
    pecmd = tmp_path / "extractions" / "pecmd"
    pecmd.mkdir()
    rows = ["RunTime,ExecutableName"]
    rows.extend(f"2023-01-23 07:00:{i:02d},rundll32.exe" for i in range(50))
    (pecmd / "prefetch_Timeline.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    hay_rows = ["Timestamp,Rule,Computer"]
    hay_rows.extend(
        f"2023-01-23 06:{i // 60:02d}:{i % 60:02d},MSI Install,rd01.shieldbase.com"
        for i in range(220)
    )
    hay_rows.append("2023-01-23 07:19:16,EventID 1102 wevtutil cl Security,rd01")
    (hay / "evtx-timeline.csv").write_text("\n".join(hay_rows) + "\n", encoding="utf-8")
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  playbooks: external_compromise\n"
        "  question: What attacker activity is evidenced on RD01?\n"
        "  host: rd01.shieldbase.com\n"
        "  window: 2023-01-01 2023-01-29\n",
        encoding="utf-8",
    )
    md = build_query_pack_markdown(tmp_path, ledger=[])
    hits = md.split("## Hits", 1)[-1].lower()
    assert "wevtutil" in hits
    assert "hayabusa" in md.lower()
    assert hits.index("wevtutil") < hits.index("rundll32")
    cands = n4_finding_candidates(tmp_path, ledger=[])
    blob = " ".join(f"{c['title']} {c['observation']}" for c in cands).lower()
    assert "wevtutil" in blob or "1102" in blob


def test_numeric_needles_are_not_substrings():
    from nexus.langgraph.query_pack import needle_in_text

    assert needle_in_text("eventid 1102 wevtutil cl security", "1102")
    assert needle_in_text(",1102,microsoft-windows-eventlog", "1102")
    assert not needle_in_text("id f1102060-264a-4b13", "1102")
    assert not needle_in_text("000010110217e1e0deadbeef", "1102")
    assert not needle_in_text('value="704501"', "7045")
    assert not needle_in_text("46cc1149ff39", "1149")
    assert needle_in_text("c:\\windows\\system32\\sdelete.exe", "sdelete")


def test_n4_skips_artifacts_jsonl_and_hash_1102(tmp_path: Path):
    ext = tmp_path / "extractions" / "amcache"
    ext.mkdir(parents=True)
    (ext / "binaries.csv").write_text(
        "path,hash\n"
        "c:/windows/system32/drivers/errdev.sys,000010110217e1e0deadbeef\n",
        encoding="utf-8",
    )
    hay = tmp_path / "extractions" / "hayabusa"
    hay.mkdir()
    (hay / "evtx-timeline.csv").write_text(
        "Timestamp,Rule\n"
        "2023-01-23 07:19:16,EventID 1102 wevtutil cl Security\n",
        encoding="utf-8",
    )
    ingest = tmp_path / "ingest"
    ingest.mkdir()
    (ingest / "artifacts.jsonl").write_text(
        '{"id":"f1102060-264a","source":"generic_jsonl",'
        '"timestamp":"2026-08-15T08:21:25Z","description":"sdelete mentioned"}\n',
        encoding="utf-8",
    )
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  playbooks: external_compromise,data_staging\n"
        "  window: 2023-01-01 2023-01-29\n",
        encoding="utf-8",
    )
    start, end = parse_window("2023-01-01 2023-01-29")
    hits = scan_extractions(tmp_path, ["1102", "wevtutil", "sdelete"], (start, end))
    files = " ".join(h["file"] for h in hits).lower()
    texts = " ".join(h["text"] for h in hits).lower()
    assert "artifacts.jsonl" not in files
    assert "errdev" not in texts
    assert "eventid 1102" in texts or "wevtutil" in texts
    cands = n4_finding_candidates(tmp_path, ledger=[])
    blob = " ".join(f"{c['title']} {c['observation']}" for c in cands).lower()
    assert "sdelete" not in blob
    assert "wevtutil" in blob or "1102" in blob
