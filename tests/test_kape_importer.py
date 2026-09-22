"""KAPE importer: collection-log markers (CopyLog/SkipLog) + tree walk."""

from __future__ import annotations


def test_kape_copy_log_marker_and_parse(tmp_path):
    from nexus.ingest.df.kape import KAPEImporter

    log = tmp_path / "2020-11-22T162001_CopyLog.csv"
    log.write_text(
        "CopiedTimestamp,SourceFile,DestinationFile,FileSize,SourceFileSha1,DeferredCopy,"
        "CreatedOnUtc,ModifiedOnUtc,LastAccessedOnUtc,CopyDuration\n"
        "2020-11-22 16:20:18.4651672,e:\\Users\\fredr\\AppData\\Roaming\\Microsoft\\Teams\\desktop-config.json,"
        "C:\\Temp\\Rocba-Triage\\e\\Users\\fredr\\AppData\\Roaming\\Microsoft\\Teams\\desktop-config.json,"
        "1691,0DBAED3E794CA6F098CDAB060614C667588B6E6E,False,2020-10-30 19:51:51.4700885,"
        "2020-11-16 02:29:37.9932257,2020-11-16 02:29:37.9932257,00:00:00.0079782\n",
        encoding="utf-8",
    )
    assert KAPEImporter.can_handle(tmp_path)
    arts = list(KAPEImporter().parse(tmp_path))
    assert len(arts) == 1
    a = arts[0].to_dict()
    assert a["source"] == "kape"
    assert a["artifact_type"] == "file"
    assert a["timestamp"].startswith("2020-11-22T16:20:18.465167")
    assert a["ts_synthesized"] is False
    assert a["file_path"] == r"e:\Users\fredr\AppData\Roaming\Microsoft\Teams\desktop-config.json"
    assert a["file_hash_sha1"] == "0DBAED3E794CA6F098CDAB060614C667588B6E6E"
    assert a["description"].startswith("KAPE collected")
    assert a["raw"]["sha1"] == a["file_hash_sha1"]
    assert a["raw"]["source"] == "kape_copy_log"


def test_kape_skip_log_marker_and_parse(tmp_path):
    from nexus.ingest.df.kape import KAPEImporter

    (tmp_path / "2020-11-22T162001_SkipLog.csv").write_text(
        "SourceFile,SourceFileSha1,Reason\n"
        "e:\\Users\\fredr\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 1\\Cookies-journal,"
        "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709,Deduped\n",
        encoding="utf-8",
    )
    assert KAPEImporter.can_handle(tmp_path)
    arts = list(KAPEImporter().parse(tmp_path))
    assert len(arts) == 1
    a = arts[0].to_dict()
    assert a["description"].startswith("KAPE skipped")
    assert a["raw"]["reason"] == "Deduped"
    assert a["ts_synthesized"] is True
    assert "kape.skipped" in a["tags"]


def test_kape_plain_dir_not_handled(tmp_path):
    from nexus.ingest.df.kape import KAPEImporter

    (tmp_path / "notes.txt").write_text("hi", encoding="utf-8")
    assert KAPEImporter.can_handle(tmp_path) is False
