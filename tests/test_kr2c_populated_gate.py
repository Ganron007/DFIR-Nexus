"""WO-KR2c 0b: a column is a valid target for a family only if it is populated there.

The reviewer's root cause, measured on `536f4c9`: 113 of 253 skill steps and 805 of
966 Sigma analytics target an importer slot (`command_line`, `process_name`,
`file_path`, `registry_key`, `parent_process`), and **none of those is filled for
EVTX rows** - yet `expand_families` expands `evtxecmd` into `ingest-hayabusa` /
`ingest-kape`, whose shared 32-column schema makes the slots "exist".

`families` is what the catalog **declares**. `populated_in` (WO-KM1 item 3) is what
real documents **filled**. These tests pin the difference and the gate, and record
where the gate is silent - because an unsampled column is not an invalid one.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from nexus.knowledge.query_validation import (  # noqa: E402
    load_field_registry,
    validate_stored_query,
)

CMD_LINE = {
    "wildcard": {
        "fields.command_line.kw": {"value": "*mimikatz*", "case_insensitive": True},
    },
}


def _registry() -> dict:
    return load_field_registry()


def test_declared_families_alone_are_not_the_gate():
    """The reviewer's measurement, restated against the measured profile.

    This is why `families` alone cannot be the gate: a declared family list is wide
    enough to cover the whole ingest schema. `command_line` declares ~30 `ingest-*`
    families, so a query naming it validates for almost any case - and then matches
    nothing, which is the silent zero KR2c exists to stop.

    The original version of this test asserted `populated_in` was EMPTY. That was true
    of the profile as it then stood, which had staged no importer rows at all - so it
    asserted the ABSENCE of a corpus, not the property it meant to. With the importer
    lane staged (KR2c item 4) the profile now measures 13 families that genuinely fill
    `command_line`, which is exactly why the gate is `populated_in` and not `families`:
    the two answer different questions, and only one of them is measured.
    """
    cols = _registry()
    info = cols.get("command_line") or {}
    declared = {str(f).lower() for f in (info.get("families") or [])}
    assert declared, "command_line declares no families"
    # `evtxecmd` reaches command_line only through the importer expansion.
    assert any(f.startswith("ingest-") for f in declared), sorted(declared)[:4]
    populated = {str(f).lower() for f in (info.get("populated_in") or [])}
    # The declared set is wide; the measured set is narrow. THAT gap is the finding:
    # a query naming `command_line` validates for a family the profile never filled.
    # Compare on the same spelling - `families` uses the registry's `ingest-*` form
    # and `populated_in` the runtime's own name, so normalise through the alias table.
    from nexus.knowledge.skills import family_names

    populated_wide = {spelling for f in populated for spelling in family_names(f)}
    # Of the declared families, which does the profile actually vouch for?
    declared_populated = {d for d in declared
                          if family_names(d) & populated_wide}
    assert declared_populated, (
        "no declared family is vouched for by the profile - is the importer lane "
        "staged in the population profile?")
    assert declared_populated < declared, (
        "the profile vouches for every declared family, so `populated_in` adds nothing "
        f"over `families` and the gate cannot tell a measured column from a declared "
        f"one: vouched={sorted(declared_populated)}")
    # and the EVTX-analyser lanes the Sigma pack declares are NOT among them.
    evtx_lanes = {"evtxecmd", "hayabusa", "chainsaw", "zircolite", "deepbluecli"}
    assert not (populated & evtx_lanes), (
        "an EVTX-analyser lane fills command_line, which contradicts the reviewer's "
        "measurement - re-check the population profile")


def test_the_default_gate_still_accepts_a_declared_query():
    """Opt-in on purpose: an unsampled column is unsampled, not invalid.

    The population corpus is a subset of the world, so turning the populated check
    on by default would reject valid queries for families nobody has staged. The
    gate is explicit so the caller says what it knows.
    """
    errs = validate_stored_query(CMD_LINE, declared_families=["evtxecmd"],
                                citation=["sigma-1"], registry_columns=_registry())
    assert errs == [], errs[:3]


def test_the_populated_gate_rejects_a_column_filled_only_for_other_families():
    cols = _registry()
    info = cols.get("dest_ip") or {}
    populated = {str(f).lower() for f in (info.get("populated_in") or [])}
    if not populated:
        return  # no profile data for this column at all; nothing to assert
    other = "authlog"
    assert other in _families_of("dest_ip") or f"ingest-{other}" in _families_of(
        "dest_ip"), "authlog should declare dest_ip"
    assert other not in populated, f"{other} should not fill dest_ip"
    query = {"term": {"fields.dest_ip": "1.2.3.4"}}
    errs = validate_stored_query(query, declared_families=[other], citation=["sigma-1"],
                                registry_columns=cols, require_populated=True)
    assert any("population profile" in e for e in errs), errs


def test_the_gate_accepts_a_query_on_a_family_that_does_fill_the_column():
    cols = _registry()
    info = cols.get("dest_ip") or {}
    populated = sorted(str(f).lower() for f in (info.get("populated_in") or []))
    if not populated:
        return
    query = {"term": {"fields.dest_ip": "1.2.3.4"}}
    errs = validate_stored_query(query, declared_families=populated[:1],
                                citation=["sigma-1"], registry_columns=cols,
                                require_populated=True)
    assert errs == [], errs[:3]


def test_a_column_the_profile_never_sampled_is_unsampled_not_invalid():
    """The honest limit, recorded rather than papered over.

    `command_line` has no `populated_in` because no staged corpus fills it - which is
    a fact about the corpus, not about the column. The gate says nothing.
    """
    cols = _registry()
    info = cols.get("command_line") or {}
    if info.get("populated_in"):
        return  # the corpus has since grown; the next assertion covers it
    errs = validate_stored_query(CMD_LINE, declared_families=["evtxecmd"],
                                citation=["sigma-1"], registry_columns=cols,
                                require_populated=True)
    assert errs == [], errs[:3]


def _families_of(column: str) -> set[str]:
    info = (_registry().get(column) or {})
    return {str(f).lower() for f in (info.get("families") or [])}
