"""plaso importer: psort detailed CSV + l2tcsv support."""

from __future__ import annotations

L2TCSV = (
    "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra\n"
    "09/27/2020,14:43:18,UTC,M..B,EVT,WinEVTX,Content Modification Time,-,SRL-FORGE,"
    "TerminalServices event,desc text,2,Microsoft-Windows-TerminalServices%4Operational.evtx,-,-,winevtx,eventid=34\n"
    "09/27/2020,14:44:18,UTC,.A..,FILE,NTFS,Access Time,fredr,SRL-FORGE,file accessed,desc 2,2,secret.docx,-,-,ntfs,-"
)

DETAILED = (
    "datetime,timestamp_desc,source,source_long,message,parser,display_name\n"
    "2020-09-27 14:43:18,Content Modification Time,EVT,WinEVTX,event message,winevtx,OS:test.evtx\n"
)


def test_l2tcsv_can_handle_and_parse(tmp_path):
    from nexus.ingest.df.plaso import PlasoImporter

    f = tmp_path / "plaso.csv"
    f.write_text(L2TCSV, encoding="utf-8")
    assert PlasoImporter.can_handle(f)
    arts = list(PlasoImporter().parse(f))
    assert len(arts) == 2
    a = arts[0].to_dict()
    assert a["source"] == "plaso"
    assert a["timestamp"].startswith("2020-09-27T14:43:18")
    assert a["ts_synthesized"] is False
    assert a["host"] == "SRL-FORGE"
    assert a["description"].startswith("EVT: ")
    b = arts[1].to_dict()
    assert b["user"] == "fredr"


def test_detailed_csv_still_parses(tmp_path):
    from nexus.ingest.df.plaso import PlasoImporter

    f = tmp_path / "detailed.csv"
    f.write_text(DETAILED, encoding="utf-8")
    assert PlasoImporter.can_handle(f)
    arts = list(PlasoImporter().parse(f))
    assert len(arts) == 1
    assert arts[0].to_dict()["timestamp"].startswith("2020-09-27T14:43:18")


def test_other_csv_rejected(tmp_path):
    from nexus.ingest.df.plaso import PlasoImporter

    f = tmp_path / "other.csv"
    f.write_text("alpha,beta\n1,2\n", encoding="utf-8")
    assert PlasoImporter.can_handle(f) is False
