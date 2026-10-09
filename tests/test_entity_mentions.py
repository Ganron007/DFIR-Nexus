"""Entity mentions must resolve to the rows, or be flagged.

The asymmetry with Modes 2 and 3 is structural, not a prompt problem. Both agent
runtimes put every candidate through ``accept_claim`` (FD-001..007) and a
verifier node before anything is staged. Mode 1 goes needle -> scribe -> DRAFT
with nothing in between, so an LLM-written interpretation can name a process the
rows never mention. On the first real case one finding's interpretation named
``msmpeng.exe`` (Defender) while all eleven of its evidence rows were ``PwSh
Engine Started`` - PowerShell only.

The remedy follows the rule 10.4 already sets for timestamps: **flag, never
reject and never rewrite.** A mention that does not resolve may be a negative
one ("this is not msmpeng.exe"), and rejecting a correct finding over a phrase
would be worse than flagging it.

WO-R2F item 7 (D47) replaced the earlier in-place rewrite: the function used to
substitute ``[entity: unsupported by the cited rows]`` into
``title``/``observation``/``interpretation`` (``integrity.py:366-374``), which
overwrote the model's words and nested markers when one pass replaced a
substring of an earlier pass's marker. The finding's text now stays
byte-identical; every unsupported mention is reported in ``unsupported`` and
``notes``, and ``enforce_submission_integrity`` hands the notes to the finding's
``integrity_notes`` for the examiner to read beside the untouched text.
"""
from __future__ import annotations

import json

from nexus.analysis.integrity import (
    enforce_submission_integrity,
    sanitize_entity_mentions,
)

ROWS = [{
    "time": "2020-11-02T18:38:46",
    "source": "hayabusa/evtx-timeline.csv",
    "artifact": "hayabusa/evtx-timeline.csv",
    "detail": "RuleTitle: Potentially Malicious PwSh - powershell.exe -EncodedCommand",
    "loc": "hayabusa/evtx-timeline.csv:41",
    "fields": {"EventId": "4104", "Provider": "Microsoft-Windows-PowerShell"},
}]


def _finding(**extra):
    f = {
        "id": "F1", "title": "suspicious script block", "status": "DRAFT",
        "artifacts": [{"audit_id": "nx-audit-0001"}],
        "evidence": [dict(ROWS[0])],
    }
    f.update(extra)
    return f


def test_the_real_msmpeng_case_is_flagged_never_rewritten():
    """D47: the mention is recorded, the finding's words are not touched."""
    f = _finding(
        interpretation=("The script block launched powershell.exe while msmpeng.exe "
                        "was not running, so the payload was unobstructed."),
    )
    before = f["interpretation"]
    out = sanitize_entity_mentions(f)
    assert out["checked"] is True
    assert [u["entity"] for u in out["unsupported"]] == ["msmpeng.exe"]
    # The narrative is byte-identical - no marker, no rewrite, no nesting.
    assert f["interpretation"] == before
    assert "unsupported by the cited rows" not in f["interpretation"]
    assert f["interpretation"].count("msmpeng.exe") == 1
    # ... and the mention is recorded with the field it came from.
    assert out["notes"] == [
        "entity mention unsupported by the cited rows: interpretation named "
        "msmpeng.exe (process)"
    ]


def test_a_supported_entity_is_left_alone():
    f = _finding(interpretation="powershell.exe ran an encoded command from temp.")
    out = sanitize_entity_mentions(f)
    assert out["unsupported"] == []
    assert out["notes"] == []


def test_a_negative_mention_is_flagged_not_rejected():
    """'this is not X' is legitimate prose; the examiner decides, not the linter."""
    f = _finding(interpretation="This is not msmpeng.exe, so no AV event is claimed.")
    before = f["interpretation"]
    out = sanitize_entity_mentions(f)
    assert [u["entity"] for u in out["unsupported"]] == ["msmpeng.exe"]
    # The sentence survives whole, marker-free, so the examiner keeps the
    # context and judges the mention from the integrity note instead.
    assert f["interpretation"] == before == (
        "This is not msmpeng.exe, so no AV event is claimed."
    )
    assert out["notes"]


def test_a_live_resolver_can_vouch_for_an_entity():
    f = _finding(interpretation="msmpeng.exe was disabled by the operator.")
    assert sanitize_entity_mentions(f, resolver=lambda e: 5)["unsupported"] == []


def test_no_evidence_rows_is_unknown_not_clean():
    f = {"id": "F2", "title": "x happened", "interpretation": "nothing.exe ran"}
    out = sanitize_entity_mentions(f)
    assert out["checked"] is False
    assert out["unsupported"] == []


def test_staging_warns_without_rejecting():
    """A fabricated citation still rejects. An unresolved mention must not."""
    case = None
    f = _finding(interpretation="msmpeng.exe was bypassed during the run.")
    res = enforce_submission_integrity(
        f, case, known_ids={"nx-audit-0001"},
    )
    assert res["ok"] is True, res["errors"]
    assert any("entity mention unsupported by the cited rows" in w
               for w in res["warnings"]), res["warnings"]
    # The note reaches the caller so the finding record can carry it.
    assert res["integrity_notes"]
    assert "msmpeng.exe" in res["integrity_notes"][0]


def test_staging_still_rejects_a_fabricated_citation():
    f = _finding(artifacts=[{"audit_id": "nx-does-not-exist"}])
    res = enforce_submission_integrity(f, None, known_ids={"nx-audit-0001"})
    assert res["ok"] is False
    assert any("citation integrity" in e for e in res["errors"])


def test_a_clean_finding_produces_no_entity_warning():
    f = _finding(interpretation="powershell.exe ran an encoded command from temp.")
    res = enforce_submission_integrity(f, None, known_ids={"nx-audit-0001"})
    assert not any("entity" in w for w in res["warnings"]), res["warnings"]


def test_the_result_is_serialisable_for_the_finding_record():
    f = _finding(interpretation="lsass.exe and msmpeng.exe both appear.")
    res = enforce_submission_integrity(f, None, known_ids={"nx-audit-0001"})
    json.dumps(res["entities"])  # must not raise


def test_bare_needles_are_not_treated_as_entities():
    """A needle is a search term, not a claim about the host."""
    f = _finding(title="Signal: sdelete - 1 hit(s) across evtxecmd")
    out = sanitize_entity_mentions(f)
    assert out["unsupported"] == []


# ── D47 entity extraction ────────────────────────────────────────────────


def test_a_windows_path_with_spaces_is_one_entity():
    """D47: `C:\\Program Files\\Asset Management\\tool.exe` is one entity.

    The old pattern stopped at the first space and produced `c:\\program`,
    which never matched the row's full path and flagged a phantom.
    """
    from nexus.analysis.cross_mode import _entities

    out = _entities(r"ran from C:\Program Files\Asset Management\tool.exe on ws01")
    assert ("file", r"c:\program files\asset management\tool.exe") in out
    assert not any(v == r"c:\program" for _t, v in out)


def test_a_path_does_not_swallow_the_sentence_after_it():
    """A path ends at its final component; the prose after it is not a path."""
    from nexus.analysis.cross_mode import _entities

    out = _entities(r"C:\Windows\Temp\x.exe while msmpeng.exe was not running")
    assert ("file", r"c:\windows\temp\x.exe") in out
    assert not any("while" in v for _t, v in out)


def test_an_fqdn_matches_its_short_name_in_the_rows():
    """D47: `ws01.cadre.local` matches rows that say `ws01`."""
    from nexus.analysis.cross_mode import _entity_in_blob

    assert _entity_in_blob("ws01.cadre.local", "host=ws01 level=high")
    assert _entity_in_blob("ws01", "host=ws01.cadre.local level=high")
    # A genuinely absent host still fails - the equivalence is not a bypass.
    assert not _entity_in_blob("ws02.cadre.local", "host=ws01 level=high")
    assert not _entity_in_blob("dc01", "host=ws01 level=high")


def test_lab_internal_tlds_are_hosts():
    """`.cadre.local` / `.corp.local` are domains, not bare filenames."""
    from nexus.analysis.cross_mode import _entities

    out = _entities("the host ws01.cadre.local ran lsass.exe")
    assert ("domain", "ws01.cadre.local") in out
