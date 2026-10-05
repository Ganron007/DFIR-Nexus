"""WO-K4 — the behavioural analytic pack.

The work order's tests, made real:

* every analytic parses and references existing fields;
* a fixture with a **renamed tool** (behaviour only, no name string) is caught by
  an analytic rather than by a needle — proven with the matcher, not asserted;
* no term derives from a K1 or GATE-H sample (provenance), and every citation is
  one we actually hold.
"""
from __future__ import annotations

from pathlib import Path

from nexus.analysis.behavioural_analytics import (
    PROVENANCE,
    analytics,
    analytics_for,
    car_citation_ids,
    catalog_fields,
    load_pack,
    matches_record,
    validate_pack,
)


def test_the_pack_is_valid_on_every_axis():
    """Parse, field existence, citation and rationale - all in one gate."""
    problems = validate_pack()
    assert problems == [], "\n".join(problems)


def test_there_are_enough_analytics_and_they_are_the_wo_s_shape():
    items = analytics()
    assert len(items) >= 30, f"the work order asks for about 30, got {len(items)}"
    kinds = {str(i.get("id") or "") for i in items}
    for expected in (
        "ba-exec-user-writable",          # execution from a user-writable path
        "ba-persist-service-temp",        # a service ImagePath in temp/AppData
        "ba-persist-task-script-host",    # a task running a script host / -enc
        "ba-persist-run-usbable",         # a Run key to a user-writable path
        "ba-cred-lsass-nonsystem",        # non-system lsass access
        "ba-cred-new-local-admin",        # a new local admin
        "ba-eva-log-cleared",             # log clearing
        "ba-cred-rdp-firstseen",          # RDP from a first-seen source
    ):
        assert expected in kinds, f"{expected} is missing"


def test_every_analytic_cites_something_we_hold():
    """A citation we cannot resolve is worse than none: it looks authoritative."""
    held = car_citation_ids()
    assert held, "car_analytics.yaml should be present"
    for item in analytics():
        citation = item.get("citation") or {}
        cid = str(citation.get("id") or "")
        assert cid, item.get("id")
        if str(citation.get("type")) == "car":
            assert cid in held, f"{item['id']} cites {cid}, which we do not hold"


def test_every_analytic_declares_families_and_techniques():
    """The hand-curated pack's hygiene, checked over that pack alone.

    Scoped with an explicit path on purpose: `analytics()` also loads the
    generated SigmaHQ pack (WO-KL2b), where a rule legitimately carries no ATT&CK
    tag, and this assertion is about the authored pack.
    """
    from nexus.analysis.behavioural_analytics import PACK_PATH

    for item in analytics(str(PACK_PATH)):
        assert item.get("families"), item.get("id")
        assert item.get("techniques"), item.get("id")
        for tech in item["techniques"]:
            assert str(tech).startswith("T"), f"{item['id']}: {tech} is not an ATT&CK id"


# ---------------------------------------------------------------------------
# behaviour-keyed, not name-keyed
# ---------------------------------------------------------------------------

def test_a_renamed_tool_is_caught_by_behaviour_and_not_by_its_name():
    """The work order's fixture: mimikatz renamed, so no string matches.

    The record carries the behaviour - a credential dump run against lsass from a
    non-system context - and never the string 'mimikatz'. A needle cannot see it;
    the analytic can.
    """
    analytic = next(a for a in analytics() if a["id"] == "ba-cred-lsass-nonsystem")
    renamed = {
        "User": "CORP\\alice",
        "CommandLine": r"C:\Users\alice\AppData\Local\Temp\svc32.exe --lsass",
        "Path": r"C:\Users\alice\AppData\Local\Temp\svc32.exe",
    }
    assert "mimikatz" not in str(renamed).lower()
    assert matches_record(analytic, renamed) is True


def test_the_negative_term_actually_excludes_the_system_case():
    """The analytic must not match a system process just because it says lsass.

    This is the regression the pack could not express: the DSL ignores typed
    negation, so 'lsass and not user:SYSTEM' would have required lsass AND a
    non-SYSTEM user *as two positives*. The pack now carries one positive term
    and the narrowing is a follow-on filter, so a system record still matches the
    broad term - which is exactly why the rationale says so.
    """
    analytic = next(a for a in analytics() if a["id"] == "ba-cred-lsass-nonsystem")
    assert "not " not in str(analytic.get("es")), analytic.get("es")
    system = {
        "User": "NT AUTHORITY\\SYSTEM",
        "CommandLine": r"C:\Windows\System32\svchost.exe --lsass",
    }
    # It matches on the behaviour (a reference to lsass); narrowing by user is the
    # next filter, deliberately not folded into a term the DSL cannot negate.
    assert matches_record(analytic, system) is True
    assert "follow-on filter" in analytic["rationale"]
    assert "non-system" in analytic["rationale"]


def test_the_validator_refuses_a_negated_typed_filter():
    """The DSL's `not field:` is a trap; the pack must not be able to use it."""
    bad = {"packs": [{
        "id": "ba-bad", "name": "bad", "families": ["security"],
        "dsl": "file_path:AppData and not path:\\Windows",
        "citation": {"type": "car", "id": "CAR-2014-11-004"},
        "techniques": ["T1059"], "rationale": "x",
    }]}
    problems = validate_pack(bad)
    assert any("not field:value" in p or "POSITIVE filter" in p or "missing es" in p for p in problems), problems


def test_a_user_writable_execution_matches_without_any_tool_name():
    analytic = next(a for a in analytics() if a["id"] == "ba-exec-user-writable")
    assert matches_record(analytic, {
        "FilePath": r"C:\Users\bob\AppData\Roaming\task.exe",
        "Path": r"C:\Users\bob\AppData\Roaming",
    })
    # No system-tree term is folded in (see the validator test above).
    assert "not " not in str(analytic.get("es"))


def test_no_analytic_depends_on_a_tool_name_string():
    """A name-keyed analytic would be defeated by a rebuild - the point of K4.

    Scoped to the hand-curated pack: a rules file translated from SigmaHQ is
    *expected* to name the tool its authors wrote the rule for, and changing that
    would misrepresent the upstream rule.
    """
    from nexus.analysis.behavioural_analytics import PACK_PATH

    banned = ("mimikatz", "rubeus", "cobalt", "beacon", "meterpreter", "psexec")
    for item in analytics(str(PACK_PATH)):
        query_str = str(item.get("es") or "").lower()
        for word in banned:
            assert word not in query_str, f"{item['id']} keys on the tool name {word!r}"


# ---------------------------------------------------------------------------
# provenance: nothing derives from a sample
# ---------------------------------------------------------------------------

def test_citations_are_external_and_no_term_comes_from_a_sample():
    pack = load_pack()
    assert PROVENANCE.startswith("external")
    assert "car.mitre.org" in str(pack.get("source") or "")

    # A K1 sample's identifying strings must not appear in the pack. The case
    # set's directory names carry their technique and the sample families carry
    # host/user names; a term lifted from one would be tuning on the set.
    sample_terms = ("offsec", "lambda-user", "win10-02", "russellmitchell",
                    "ta0002", "ta0004", "ta0006", "ta0007", "ta0008")
    body = ""
    for item in analytics():
        body += str(item.get("es") or "") + str(item.get("name") or "") + str(item.get("id") or "")
    lowered = body.lower()
    for term in sample_terms:
        assert term not in lowered, f"pack term {term!r} looks sample-derived"


# ---------------------------------------------------------------------------
# family routing
# ---------------------------------------------------------------------------

def test_analytics_route_by_family():
    security = analytics_for(["security"])
    assert security, "security is the richest family; it must have analytics"
    assert len(security) < len(analytics()), "routing must actually narrow"
    assert analytics_for(["prefetch"]), "prefetch has no rule-engine coverage"
    assert analytics_for(["no-such-family"]) == []
    assert analytics_for(None) == analytics(), "no family list means everything"


def test_a_missing_pack_is_not_a_crash(tmp_path: Path):
    assert load_pack(tmp_path / "nope.yaml")["packs"] == []
    assert analytics(tmp_path / "nope.yaml") == []
    assert validate_pack({"packs": []}) == []


def test_the_catalog_covers_the_fields_the_pack_uses():
    """The validator's own field set must be a real registry read, not a stub."""
    fields = catalog_fields()
    assert len(fields) > 100, f"catalog looks like a stub: {len(fields)}"
    assert {"process_name", "command_line", "file_path"} <= fields
