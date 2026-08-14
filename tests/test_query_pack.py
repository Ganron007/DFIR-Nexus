"""N4 query pack — hits not CSV heads."""

from __future__ import annotations

from pathlib import Path

from nexus.langgraph.query_pack import (
    build_query_pack_markdown,
    collect_query_terms,
    n4_finding_candidates,
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
