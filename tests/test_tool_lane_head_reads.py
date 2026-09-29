"""Head sniffers must read a bounded prefix, never the whole evidence file.

Exposed live on 2026-09-29 (G7 SIFT run): the planner sniffed
``dmz-www-disk.img`` (20 GiB) with ``read_bytes()[:limit]`` — the server sat at
25 GB RSS and ~95% CPU before any job started. These tests pin the bounded
reader so the same shape cannot come back.
"""
from __future__ import annotations

from nexus.langgraph import tool_lane


def test_head_sniffers_never_call_read_bytes(tmp_path, monkeypatch):
    f = tmp_path / "disk.img"
    f.write_bytes(b"\x00" * 4096)

    def _boom(self, *args, **kwargs):  # noqa: ANN001 - monkeypatched Path method
        raise AssertionError("evidence heads must be read with _read_head(), not read_bytes()")

    monkeypatch.setattr(type(f), "read_bytes", _boom)

    # Every sniffer must work without touching read_bytes().
    assert tool_lane._decode_head(f) is not None
    assert isinstance(tool_lane._is_all_zero(f), bool)
    assert isinstance(tool_lane._has_utf16_text(f), bool)
    assert isinstance(tool_lane._is_mostly_text(f), bool)


def test_read_head_reads_only_the_prefix(tmp_path):
    f = tmp_path / "big.bin"
    with open(f, "wb") as fh:
        fh.write(b"\xAA" * 10)
        fh.write(b"\x00" * (5 * 1024 * 1024))

    head = tool_lane._read_head(f, 4096)

    assert head == b"\xAA" * 10 + b"\x00" * (4096 - 10)


def test_is_all_zero_gates_a_large_all_zero_artifact(tmp_path):
    f = tmp_path / "zeros.img"
    with open(f, "wb") as fh:
        fh.truncate(64 * 1024 * 1024)  # sparse 64 MiB of zeros

    assert tool_lane._is_all_zero(f) is True

    with open(f, "r+b") as fh:
        fh.seek(1024)
        fh.write(b"\x01")

    assert tool_lane._is_all_zero(f) is False
