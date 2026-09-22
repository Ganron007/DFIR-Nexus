"""amcache importer: AmcacheParser CSV only (raw hive is N-lane)."""

from __future__ import annotations

CSV = (
    "FullPath,Name,SHA1,FileSize,FileVersionString\n"
    "C:\\Users\\fredr\\Downloads\\evil.exe,evil.exe,"
    "da39a3ee5e6b4b0d3255bfef95601890afd80709,1234,1.0\n"
)


def test_csv_can_handle_and_parse(tmp_path):
    from nexus.ingest.df.amcache import AmCacheImporter

    p = tmp_path / "Amcache_ProgramEntries.csv"
    p.write_text(CSV, encoding="utf-8")
    assert AmCacheImporter.can_handle(p)
    arts = [a.to_dict() for a in AmCacheImporter().parse(p)]
    assert len(arts) == 1
    a = arts[0]
    assert a["source"] == "amcache"
    assert "evil.exe" in a["description"]
    assert a["severity"] == "high"  # \downloads\ path
    assert a["file_hash_sha1"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def test_raw_hive_refused_with_hint(tmp_path):
    from nexus.ingest.detect import lane_routing_hint
    from nexus.ingest.df.amcache import AmCacheImporter

    p = tmp_path / "Amcache.hve"
    p.write_bytes(b"regf\x00\x00\x00\x00" + b"\x00" * 64)
    assert AmCacheImporter.can_handle(p) is False
    assert "AmcacheParser" in (lane_routing_hint(p) or "")

    reg = tmp_path / "SYSTEM"
    reg.write_bytes(b"regf\x00\x00\x00\x00" + b"\x00" * 64)
    assert "RECmd" in (lane_routing_hint(reg) or "")
