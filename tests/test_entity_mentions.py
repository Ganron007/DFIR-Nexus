"""Entity mentions must resolve to the rows, or be marked.

The asymmetry with Modes 2 and 3 is structural, not a prompt problem. Both agent
runtimes put every candidate through ``accept_claim`` (FD-001..007) and a
verifier node before anything is staged. Mode 1 goes needle -> scribe -> DRAFT
with nothing in between, so an LLM-written interpretation can name a process the
rows never mention. On the first real case one finding's interpretation named
``msmpeng.exe`` (Defender) while all eleven of its evidence rows were ``PwSh
Engine Started`` - PowerShell only.

The remedy follows the rule 10.4 already sets for timestamps: **nullify and flag,
never reject.** A mention that does not resolve may be a negative one ("this is
not msmpeng.exe"), and rejecting a correct finding over a phrase would be worse
than flagging it. So the unsupported mention is marked in place, recorded, and
the examiner sees both.
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


def test_the_real_msmpeng_case_is_flagged_and_marked():
    f = _finding(
        interpretation=("The script block launched powershell.exe while msmpeng.exe "
                        "was not running, so the payload was unobstructed."),
    )
    out = sanitize_entity_mentions(f)
    assert out["checked"] is True
    assert [u["entity"] for u in out["unsupported"]] == ["msmpeng.exe"]
    assert "msmpeng.exe" in f["interpretation"]
    assert "unsupported by the cited rows" in f["interpretation"]


def test_a_supported_entity_is_left_alone():
    f = _finding(interpretation="powershell.exe ran an encoded command from temp.")
    out = sanitize_entity_mentions(f)
    assert out["unsupported"] == []
    assert "unsupported by the cited rows" not in f["interpretation"]


def test_a_negative_mention_is_marked_not_rejected():
    """'this is not X' is legitimate prose; the examiner decides, not the linter."""
    f = _finding(interpretation="This is not msmpeng.exe, so no AV event is claimed.")
    out = sanitize_entity_mentions(f)
    assert [u["entity"] for u in out["unsupported"]] == ["msmpeng.exe"]
    text = f["interpretation"]
    # The marker replaces the entity in place rather than dropping the sentence,
    # so the examiner keeps the context and sees which word is unsupported.
    assert "so no AV event is claimed" in text
    assert text.startswith("This is not")
    assert "unsupported by the cited rows" in text


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
    assert any("entity mention nullified" in w for w in res["warnings"]), res["warnings"]


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
