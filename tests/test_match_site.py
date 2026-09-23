"""Mode 1 match-site awareness — keyword hits know what they landed on.

Live case evidence (2026-09-23, H-Triage): the playbook keyword ``325`` (an
ESENT event id) matched 156 rows through EventId cells and timestamps, and
``cipher`` matched inside ``CipherData`` XML identifiers. Mode 1 stays keyword
search, but a hit may only count when the keyword lands in evidence *content*
at a token boundary; id/label columns become field facts, never signal.
"""

from __future__ import annotations

from pathlib import Path


def test_column_classes():
    from nexus.langgraph.match_site import column_class

    assert column_class("evtxecmd", "EventId") == "numeric"
    assert column_class("evtxecmd", "TimeCreated") == "timestamp"
    assert column_class("evtxecmd", "Provider") == "structure"
    assert column_class("evtxecmd", "Payload") == "content"
    assert column_class("evtxecmd", "SourceFile") == "provenance"
    assert column_class("hayabusa", "RuleTitle") == "content"
    assert column_class("evtxecmd", "FancyNewTextColumn") == "content"


def test_numeric_event_id_is_a_fact_not_signal():
    from nexus.langgraph.match_site import classify_matched_terms

    out = classify_matched_terms(
        "evtxecmd",
        {"EventId": "325", "Provider": "ESENT", "Payload": "database started"},
        "row text",
        ["325"],
    )
    assert out["signal"] == []
    assert out["facts"] == ["325"]
    assert out["sites"][0]["field"] == "EventId"
    assert out["sites"][0]["kind"] == "value"


def test_numeric_in_timestamp_is_not_counted():
    from nexus.langgraph.match_site import classify_matched_terms

    out = classify_matched_terms(
        "evtxecmd",
        {"TimeCreated": "2020-11-14T13:25:46.325Z", "Payload": "started"},
        "row text",
        ["325"],
    )
    assert out["signal"] == [] and out["facts"] == [] and out["weak"] == []


def test_numeric_in_content_text_is_weak_only():
    from nexus.langgraph.match_site import classify_matched_terms

    out = classify_matched_terms(
        "evtxecmd", {"Payload": "listening on port 325 now"}, "row text", ["325"]
    )
    assert out["signal"] == [] and out["facts"] == [] and out["weak"] == ["325"]


def test_embedded_word_is_not_a_hit():
    from nexus.langgraph.match_site import classify_matched_terms

    out = classify_matched_terms(
        "evtxecmd",
        {"Payload": "<CipherData>abc</CipherData>"},
        "row text",
        ["cipher"],
    )
    assert out["signal"] == []
    assert "cipher" in out["weak"]


def test_tool_prefix_hits_and_label_facts():
    from nexus.langgraph.match_site import classify_matched_terms

    sig = classify_matched_terms(
        "evtxecmd",
        {"Payload": r"C:\Tools\sdelete64.exe -accepteula"},
        "row text",
        ["sdelete"],
    )
    assert sig["signal"] == ["sdelete"]

    label = classify_matched_terms(
        "evtxecmd",
        {"Provider": "Microsoft-Windows-Winlogon", "Payload": "started"},
        "row text",
        ["winlogon"],
    )
    assert label["signal"] == []
    assert label["facts"] == ["winlogon"]


def _case_with_rows(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-MATCH"
    (case / "extractions" / "evtxecmd").mkdir(parents=True)
    (case / "extractions" / "evtxecmd" / "out.csv").write_text(
        "TimeCreated,EventId,Level,Provider,Payload,SourceFile\n"
        '2020-11-14T13:25:46.325Z,325,Information,ESENT,'
        '"Application log started",C:\\evidence\\evtx\\Application.evtx\n'
        '2020-11-14T03:56:46Z,4688,Information,Microsoft-Windows-Winlogon,'
        '"cipher /w C:\\Users\\x\\secret.docx",C:\\evidence\\evtx\\System.evtx\n'
        '2020-11-14T03:56:47Z,4688,Information,Microsoft-Windows-PowerShell,'
        '"<CipherData>abc</CipherData>",C:\\evidence\\evtx\\System.evtx\n'
        '2020-11-14T03:56:48Z,4688,Information,Microsoft-Windows-PowerShell,'
        '"C:\\Tools\\sdelete64.exe -accepteula",C:\\evidence\\evtx\\System.evtx\n'
        '2020-11-14T03:56:49Z,4688,Information,Microsoft-Windows-Winlogon,'
        '"winlogon started",C:\\evidence\\evtx\\System.evtx\n',
        encoding="utf-8",
    )
    return case


def test_scan_classifies_matches(tmp_path):
    from nexus.langgraph.query_pack import parse_window, scan_extractions

    case = _case_with_rows(tmp_path)
    start, end = parse_window("")
    hits = scan_extractions(
        case, ["325", "cipher", "sdelete", "winlogon"], (start, end)
    )
    by_line = {h["line"]: h for h in hits}

    # Line 2: EventId=325 (+ ".325" in the timestamp) -> field fact, not signal.
    assert "2" in by_line, sorted(by_line)
    assert by_line["2"]["terms_list"] == []
    assert by_line["2"]["fact_terms"] == ["325"]
    assert by_line["2"]["fact_sites"][0]["field"] == "EventId"

    # Line 3: "cipher /w" on the payload -> real signal hit.
    assert by_line["3"]["terms_list"] == ["cipher"]

    # Line 4: "cipher" embedded in <CipherData> -> no hit row at all.
    assert "4" not in by_line

    # Line 5: "sdelete" inside sdelete64.exe -> signal (tool prefix).
    assert by_line["5"]["terms_list"] == ["sdelete"]

    # Line 6: winlogon in the payload is signal; the Provider label fact for
    # the same term is dropped once it counts as signal.
    assert by_line["6"]["terms_list"] == ["winlogon"]
    assert not by_line["6"].get("fact_terms")


def test_numbers_never_stage_from_facts(tmp_path):
    """The signal map must not turn EventId cells into suspicious signal."""
    from nexus.langgraph.query_pack import parse_window, scan_extractions

    case = _case_with_rows(tmp_path)
    start, end = parse_window("")
    hits = scan_extractions(case, ["325"], (start, end))
    assert hits, "the fact row should still be returned as a hit (fact-only)"
    for h in hits:
        assert h["terms_list"] == [], h
        assert h.get("fact_terms") == ["325"], h
