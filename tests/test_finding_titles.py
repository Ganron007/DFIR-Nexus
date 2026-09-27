"""Finding titles must read as English, not as machine identifiers.

Every title below is a real one from the debug-mode run. "Signal: sdelete - 1
hit(s) across evtxecmd" and "evtxecmd: presence" are search keys and dispute
keys; an examiner scanning the Key Takeaways learns nothing from either, and the
report reads as an inventory rather than a set of conclusions. Mode 2 already
met the standard ("Host identity: WIN-7LFOBBPCFKB is inferred to be SRL-FORGE"),
which is what these have to match.
"""
from __future__ import annotations

from nexus.analysis.report_grade import _is_machine_title
from nexus.analysis.titles import claim_title, needle_title, row_descriptor

SDDELETE_ROW = {
    "detail": "MapDescription: Restore point created successfully",
    "fields": {
        "EventId": "8194", "Provider": "System Restore",
        "MapDescription": "Restore point created successfully",
        "Data": 'C:\\WINDOWS\\system32\\systempropertiesprotection.exe , sdelete',
    },
}
POWERSHELL_ROW = {
    "detail": "HostApplication: powershell.exe -EncodedCommand ...",
    "fields": {
        "EventId": "4104", "Provider": "Microsoft-Windows-PowerShell",
        "RuleTitle": "Potentially Malicious PwSh",
    },
}


def test_descriptor_is_the_rows_own_words():
    d = row_descriptor(SDDELETE_ROW)
    assert "Restore point created successfully" in d
    assert "8194" in d, "the event id is what a responder searches on"


def test_a_needle_that_the_row_does_not_describe_says_so():
    """The D7 case: sdelete matched a System Restore event that merely lists it.

    The title must not read as though the row evidences the needle, or the
    examiner approves on the strength of an incidental substring match.
    """
    t = needle_title("sdelete", [SDDELETE_ROW], ["evtxecmd"])
    assert "Restore point created successfully" in t
    assert "sdelete" in t
    assert "appears in" in t, "an incidental match must be labelled as one"
    assert _is_machine_title(t) is False


def test_a_needle_the_row_actually_describes_reads_directly():
    """When the row's own descriptor names the needle, no hedge is needed."""
    t = needle_title("restore point", [SDDELETE_ROW], ["evtxecmd"])
    assert "which describe" not in t, t
    assert "Restore point created successfully" in t


def test_titles_are_never_a_bare_needle():
    for needle, rows, fams in (
        ("sdelete", [SDDELETE_ROW], ["evtxecmd"]),
        ("scriptblock", [POWERSHELL_ROW], ["hayabusa"]),
        ("pid_", [{"text": "zzzzzzzz"}], ["hayabusa"]),
    ):
        t = needle_title(needle, rows, fams)
        assert _is_machine_title(t) is False, f"{needle}: {t!r} reads as a machine key"
        assert len(t) > len(needle) + 8, t


def test_a_row_with_nothing_sayable_still_gets_a_title():
    t = needle_title("pid_", [{"text": "x"}], ["hayabusa"])
    assert "pid_" in t and len(t) > 10
    assert _is_machine_title(t) is False


def test_a_one_character_fragment_is_not_a_descriptor():
    assert row_descriptor({"text": "x"}) == ""


def test_claim_title_is_english_not_a_dispute_key():
    t = claim_title("evtxecmd", "presence")
    assert t != "evtxecmd: presence"
    assert ":" not in t
    assert "evtxecmd" in t
    assert _is_machine_title(t) is False


def test_claim_title_uses_the_claim_value_when_there_is_one():
    t = claim_title("lsass.exe", "presence", "S-1-5-18 logged on at 18:31:42")
    assert "S-1-5-18 logged on at 18:31:42" in t


def test_claim_title_falls_back_to_the_justification():
    t = claim_title("powershell.exe", "execution",
                    justification="PwSh engine start carrying -EncodedCommand")
    assert "EncodedCommand" in t


def test_claim_title_ignores_a_useless_value():
    t = claim_title("evtxecmd", "presence", value="true",
                    justification="Event rows exist for this family")
    assert "true" not in t.lower().replace("Event rows exist for this family", "")
    assert "Event rows exist" in t


def test_titles_stay_bounded():
    long_row = {"fields": {"MapDescription": "word " * 400}}
    t = needle_title("needle", [long_row], ["family"])
    assert len(t) < 200, len(t)


def test_the_three_modes_all_clear_the_machine_title_bar():
    """Regression on the exact set the run produced."""
    m1 = [needle_title(n, [SDDELETE_ROW], ["evtxecmd"])
          for n in ("sdelete", "pid_", "vid_", "usbstor", "onedrive", "usb",
                    "rdp", "scriptblock", "winlogon", "my drive")]
    m3 = [claim_title(e, "presence") for e in
          ("evtxecmd", "hayabusa", "chainsaw", "4625", "8194")]
    m2 = ["Host identity: WIN-7LFOBBPCFKB is inferred to be SRL-FORGE",
          "No reliable process-execution ledger exists; absence is a coverage gap"]
    for label, titles in (("m1", m1), ("m2", m2), ("m3", m3)):
        for t in titles:
            assert not _is_machine_title(t), f"{label}: {t!r} reads as a machine key"
