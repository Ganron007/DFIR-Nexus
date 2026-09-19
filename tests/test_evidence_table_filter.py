"""EH-5 — evidence-table row filter must never drop legitimate script text."""


def test_cjk_rows_are_not_garbage():
    from nexus.integration.evidence_table import _GARBAGE

    assert _GARBAGE.search("正常关机 event") is None
    assert _GARBAGE.search("İstanbul") is None
    assert _GARBAGE.search("ok \ufffd broken") is not None
