"""Raw disk/memory containers must never enter the importer lane (D51).

G7, 2026-09-29: the pipeline routed the 20 GiB dmz-www raw disk and the 3 GiB
Windows memory dump into the ingest lane; `detect_format` then burned CPU for
minutes with no output. The importer lane refuses raw containers up front by
suffix or bounded magic sniff; the SIFT/imager lanes own them.
"""
from __future__ import annotations

from nexus.ingest.detect import detect_format, is_raw_container


def test_suffix_containers_are_refused(tmp_path):
    for name in ("disk.img", "mem.raw", "chunk.dd", "base.vmdk", "dump.mem", "caps.lime"):
        f = tmp_path / name
        f.write_bytes(b"\x00" * 16)
        assert is_raw_container(f) is True, name
        assert detect_format(f) is None, name


def test_magic_only_containers_are_refused(tmp_path):
    vhd = tmp_path / "base.bin"
    vhd.write_bytes(b"conectix" + b"\x00" * 100)
    assert is_raw_container(vhd) is True

    qcow = tmp_path / "disk.dat"
    qcow.write_bytes(b"QFI\xfb" + b"\x00" * 100)
    assert is_raw_container(qcow) is True


def test_text_logs_are_not_containers(tmp_path):
    log = tmp_path / "conn.log"
    log.write_text("#fields\tts\tuid\n", encoding="utf-8")
    assert is_raw_container(log) is False
    assert detect_format(log) is not None
