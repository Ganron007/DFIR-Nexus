"""EH-5 — evidence-table row filter must never drop legitimate script text."""


def test_cjk_rows_are_not_garbage():
    from nexus.integration.evidence_table import _GARBAGE

    assert _GARBAGE.search("正常关机 event") is None
    assert _GARBAGE.search("İstanbul") is None
    assert _GARBAGE.search("ok \ufffd broken") is not None

def test_n4_loc_parses_windows_paths():
    """EH-8: `C:\\dir\\a.csv:12 terms=x: body` must parse the file/line from
    the RIGHT — the old `[^:]+` file group choked on the drive colon."""
    from nexus.integration.evidence_table import _N4_LINE

    m = _N4_LINE.match(r"C:\evidence\hayabusa\timeline.csv:12 terms=sdelete: 2026 row")
    assert m is not None
    assert m.group("file") == r"C:\evidence\hayabusa\timeline.csv"
    assert m.group("line") == "12"
    assert m.group("terms") == "sdelete"
    assert "2026 row" in m.group("body")

    # terms containing ':' still parse (non-greedy up to ': body')
    m2 = _N4_LINE.match("a/b.csv:3 terms=host:DC01: some body")
    assert m2 is not None
    assert m2.group("file") == "a/b.csv"
    assert m2.group("line") == "3"
