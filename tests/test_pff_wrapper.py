"""D281: the mail wrapper reads every item of a store, by its MAPI properties (2026-10-18).

Two of sample S09's three OSTs wrote nothing: their first address-book item (IPM.AbchPerson) is a plain pypff item
without the message attributes, and reading it as a message ended the walk. Most of S09's mail has an HTML body only
and some a compressed-RTF body only, so the body column was empty for nearly all of it, and the rows carried no
sender address, recipients, headers or attachment names. The store test runs on S09's own OST where the sample is
present; the RTF test uses the example in [MS-OXRTFCP] 3.1.1, which decompresses to the 43 bytes its header declares.
"""
from __future__ import annotations

import csv
import importlib.util
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
WRAPPER = REPO / "tools" / "windows" / "extra" / "pff" / "run-pff-ost.py"
S09_STORE = REPO / "Evidence-files" / "_samples" / "S09" / "raw" / "Email" / "fred.rocba@outlook.com.ost"


def _wrapper():
    spec = importlib.util.spec_from_file_location("run_pff_ost", WRAPPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_compressed_rtf_body_is_decompressed_and_read_as_text():
    w = _wrapper()
    example = (b"-\x00\x00\x00+\x00\x00\x00LZFu\xf1\xc5\xc7\xa7\x03\x00\n\x00rcpg125B2\n\xf3 hel\t\x00 bw\x05\xb0ld}"
               b"\n\x80\x0f\xa0")
    rtf = w._rtf_decompress(example)
    assert rtf == b"{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n" and len(rtf) == 0x2B
    assert w._rtf_text(rtf) == "hello world"
    assert w._rtf_text(b"{\\rtf1{\\fonttbl{\\f0 Arial;}}{\\*\\htmltag <p>}Hi\\par there\\'e9}") == "Hi\nthereé"


def test_a_store_body_falls_back_from_plain_to_html_to_rtf():
    w = _wrapper()
    assert w._body({"body": "plain", w._HTML_BODY: b"<p>html</p>"}) == "plain"
    assert w._body({w._HTML_BODY: b"<html><style>p{}</style><p>Dear <b>Fred</b></p></html>"}) == "Dear Fred"
    assert w._body({w._RTF_BODY: b"not a compressed body"}) == ""


@pytest.mark.skipif(not S09_STORE.is_file(), reason="sample S09 is not on this host")
def test_every_item_of_a_real_store_is_read(tmp_path):
    pytest.importorskip("pypff")
    out = tmp_path / "mail.csv"
    proc = subprocess.run([sys.executable, str(WRAPPER), str(S09_STORE), str(out)], capture_output=True, text=True,
                          timeout=600)
    assert proc.returncode == 0, proc.stderr[-500:]
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    classes = Counter(r["message_class"] for r in rows)
    assert len(rows) == 343 and classes["IPM.Note"] == 327 and classes["IPM.AbchPerson"] == 6
    assert all(r["timestamp"].endswith("+00:00") for r in rows)
    mail = [r for r in rows if r["message_class"] == "IPM.Note"]
    # Received mail names its sender; four items with no transport headers and no sender are unsent drafts.
    assert all(r["sender_email"] for r in mail if r["transport_headers"])
    assert sum(1 for r in mail if r["body_preview"]) >= 320
    assert any(r["attachments"].endswith(" bytes)") for r in mail)
