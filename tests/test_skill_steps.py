"""WO-K6 — skills at examiner grade.

The work order's four tests, made real:

* every `dsl:` step parses against the registry;
* `verify-cites` fails a skill with zero citations;
* a run records the result of each step;
* a skill whose families are missing is shown as methodology-only.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from nexus.analysis.behavioural_analytics import catalog_fields
from nexus.analysis.skill_steps import (
    LANE_SIFT,
    LANE_WINDOWS,
    authority_conflicts,
    authority_table,
    citation_grade,
    declared_requires,
    derive_requires,
    dsl_for_step,
    methodology_only,
    run_skill_steps,
    step_records,
    validate_skill_dsl,
    verify_citations,
)

SKILLS_DIR = Path(__file__).resolve().parent.parent / "src" / "nexus" / "data" / "knowledge" / "skills"


def _skills() -> list[dict]:
    out = []
    for path in sorted(SKILLS_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if isinstance(data, dict):
            out.append(data)
    return out


@pytest.fixture(scope="module")
def skills() -> list[dict]:
    loaded = _skills()
    assert loaded, f"no skills found under {SKILLS_DIR}"
    return loaded


# ---------------------------------------------------------------------------
# every step has a typed query that parses
# ---------------------------------------------------------------------------

def test_every_skill_step_has_a_typed_query(skills):
    """The work order's first test, over the whole catalog.

    Measured before this landed: 0 of 252 steps carried a `dsl:`. Now every one
    resolves - an authored dsl, a pivot-derived field filter, or a bare term -
    and every one parses against the registry.
    """
    fields = catalog_fields()
    total = 0
    problems: list[str] = []
    for skill in skills:
        records = step_records(skill, fields)
        total += len(records)
        for record in records:
            if not record["has_dsl"]:
                problems.append(f"{skill.get('skill')}/{record['name']}: no typed query")
        problems += [f"{skill.get('skill')}: {p}" for p in validate_skill_dsl(skill, fields)]
    assert total >= 250, f"only {total} steps found - the catalog did not load"
    assert problems == [], "\n".join(problems[:12])


def test_a_pivot_resolves_to_a_real_column_or_is_reported():
    """A pivot naming a real column produces `column:value`; one that does not
    must still yield a usable query rather than a silent empty string."""
    exact = dsl_for_step({"pivot": "KeyPath", "query": "Run svchost"}, {"KeyPath"})
    assert exact.startswith("KeyPath:"), exact

    # An unknown pivot still yields a bare term - the step stays executable.
    bare = dsl_for_step({"pivot": "NoSuchField", "query": "localtime"}, {"KeyPath"})
    assert bare and ":" not in bare, bare

    # A column name containing a space cannot be emitted as `field:value`: the
    # DSL would read the field after the space, so it falls back to a bare term.
    spaced = dsl_for_step({"pivot": "SourceAddress", "query": "10.0.0.9"},
                          {"Source Address"})
    assert " " not in spaced.split(":")[0], spaced


def test_an_authored_dsl_wins_over_derivation():
    step = {"pivot": "CommandLine", "query": "mimikatz", "dsl": "command_line:lsass"}
    assert dsl_for_step(step, {"command_line"}) == "command_line:lsass"


def test_a_step_with_no_query_yields_nothing_rather_than_a_match_all():
    assert dsl_for_step({"pivot": "KeyPath", "query": ""}, {"KeyPath"}) == ""


# ---------------------------------------------------------------------------
# requires / methodology only
# ---------------------------------------------------------------------------

def test_no_skill_currently_declares_requires(skills):
    """The gap the work order names: 0 of 37 declared `requires`.

    Recorded so the derived form is understood as a fix for a real absence, not
    as a redundant recomputation of something the data already carried.
    """
    declaring = [s for s in skills if isinstance(s.get("requires"), dict)]
    assert declaring == [], (
        "a skill now declares requires - the report should say so, and "
        "declared_requires will prefer it over the derived form"
    )


def test_derived_requires_come_from_the_trigger_and_the_pivots():
    skill = {
        "skill": "x",
        "trigger": {"families": ["evtx", "sysmon"]},
        "steps": [{"name": "a", "pivot": "SourceImage", "query": "lsass"}],
    }
    requires = derive_requires(skill)
    assert requires["families"] == ["evtx", "sysmon"]
    assert LANE_WINDOWS in requires["lanes"]
    assert LANE_SIFT not in requires["lanes"]


def test_a_memory_skill_requires_the_sift_lane():
    skill = {
        "skill": "mem",
        "trigger": {"families": ["vol"]},
        "steps": [{"name": "a", "pivot": "EPROCESS", "query": "malfind"}],
    }
    requires = derive_requires(skill)
    assert LANE_SIFT in requires["lanes"], requires


def test_a_skill_whose_families_are_missing_is_methodology_only(skills):
    """The work order's fourth test."""
    lsass = next(s for s in skills if s.get("skill") == "lsass_credential_access")
    assert methodology_only(lsass, case_families=["evtx", "syscall"]) is False
    assert methodology_only(lsass, case_families=["plaso"]) is True


def test_unknown_case_evidence_does_not_silently_drop_every_skill(skills):
    """`None` means unknown, and unknown is not missing."""
    for skill in skills:
        assert methodology_only(skill, case_families=None, case_lanes=None) is False


def test_a_declared_requires_is_preferred_over_the_derived_form():
    skill = {"skill": "x", "trigger": {"families": ["evtx"]},
             "requires": {"families": ["vol"], "lanes": ["sift"]},
             "steps": []}
    assert declared_requires(skill) == {"families": ["vol"], "lanes": ["sift"]}
    assert methodology_only(skill, case_families=["evtx"]) is True
    assert methodology_only(skill, case_families=["vol"], case_lanes=["sift"]) is False


# ---------------------------------------------------------------------------
# a run records the result of each step
# ---------------------------------------------------------------------------

def test_a_run_records_hit_none_and_not_applicable():
    """The work order's third test: each step's result is recorded."""
    skill = {
        "skill": "s", "trigger": {"families": ["evtx"]},
        "steps": [
            {"name": "has_hits", "pivot": "CommandLine", "query": "mimikatz"},
            {"name": "no_hits", "pivot": "CommandLine", "query": "nosuchtoken"},
            {"name": "no_query", "pivot": "CommandLine", "query": ""},
        ],
    }

    def searcher(dsl, _limit):
        return {"count": 3 if "mimikatz" in dsl else 0}

    out = run_skill_steps(skill, es_search=searcher, available={"command_line"},
                          case_families=["evtx"])
    assert out["methodology_only"] is False
    by_name = {step["name"]: step for step in out["steps"]}
    assert by_name["has_hits"]["result"] == "hit"
    assert by_name["has_hits"]["hits"] == 3
    assert by_name["no_hits"]["result"] == "none"
    assert "matched no rows" in by_name["no_hits"]["reason"]
    assert by_name["no_query"]["result"] == "not_applicable"
    assert out["summary"]["hit"] == 1
    assert out["summary"]["none"] == 1
    assert out["summary"]["not_applicable"] == 1


def test_without_a_searcher_every_step_is_not_applicable_never_none():
    """A step that could not run must never be recorded as having found nothing."""
    skill = {"skill": "s", "trigger": {"families": ["evtx"]},
             "steps": [{"name": "a", "pivot": "CommandLine", "query": "lsass"}]}
    out = run_skill_steps(skill, es_search=None, available={"command_line"},
                          case_families=["evtx"])
    assert [step["result"] for step in out["steps"]] == ["not_applicable"]
    assert "no searcher" in out["steps"][0]["reason"]
    assert out["summary"]["none"] == 0


def test_a_failing_step_does_not_lose_the_others():
    skill = {"skill": "s", "trigger": {"families": ["evtx"]},
             "steps": [{"name": "boom", "pivot": "CommandLine", "query": "a"},
                       {"name": "ok", "pivot": "CommandLine", "query": "b"}]}

    def searcher(dsl, _limit):
        # Match the VALUE, not the field name - "command_line" itself contains
        # an "a", which made both steps raise and the test pass for the wrong
        # reason before this was fixed.
        if dsl.endswith(":aaa"):
            raise RuntimeError("index exploded")
        return {"count": 1}

    skill["steps"] = [{"name": "boom", "pivot": "CommandLine", "query": "aaa"},
                      {"name": "ok", "pivot": "CommandLine", "query": "bbb"}]
    out = run_skill_steps(skill, es_search=searcher, available={"command_line"},
                          case_families=["evtx"])
    by_name = {step["name"]: step for step in out["steps"]}
    assert by_name["boom"]["result"] == "not_applicable"
    assert "index exploded" in by_name["boom"]["reason"]
    assert by_name["ok"]["result"] == "hit"


def test_a_methodology_only_skill_records_why_for_every_step(skills):
    lsass = next(s for s in skills if s.get("skill") == "lsass_credential_access")
    out = run_skill_steps(lsass, es_search=lambda *a: {"count": 9},
                          available=catalog_fields(), case_families=["plaso"])
    assert out["methodology_only"] is True
    assert out["steps"]
    for step in out["steps"]:
        assert step["result"] == "not_applicable"
        assert "methodology only" in step["reason"]


# ---------------------------------------------------------------------------
# citations
# ---------------------------------------------------------------------------

def test_verify_cites_fails_a_skill_with_zero_citations(skills):
    """The work order's second test."""
    report = verify_citations([{"skill": "no-cites"}])
    assert report["ok"] is False
    assert report["failing"] == [{"skill": "no-cites", "grade": "none"}]


def test_verify_cites_fails_a_document_only_citation():
    """A document name points at a book, not the passage the step relies on."""
    assert citation_grade({"source": ["EIR CH4-1 (Windows credential theft)"]}) == "document"
    report = verify_citations([{"skill": "doc-only", "source": ["EIR CH4-1"]}])
    assert report["ok"] is False
    assert report["failing"][0]["grade"] == "document"


def test_verify_cites_accepts_a_chunk_citation():
    ok = {"skill": "cited", "source": [{"chunk_id": "d_291d23d46cc2:c0047",
                                        "rel_path": "x.md", "lines": "4122-4220"}]}
    assert citation_grade(ok) == "chunk"
    assert verify_citations([ok])["ok"] is True


def test_the_current_catalog_reports_its_citation_grade(skills):
    """Recorded, not asserted green: the upgrade to chunk-level is data work.

    The mechanism (grade + fail behaviour) is what this WO lands; the test states
    the present grade so a later change to it is visible rather than silent.
    """
    report = verify_citations(skills)
    assert sum(report["by_grade"].values()) == len(skills)
    if not report["ok"]:
        assert all(row["grade"] in ("document", "none") for row in report["failing"])


# ---------------------------------------------------------------------------
# the authority table
# ---------------------------------------------------------------------------

def test_the_authority_table_names_one_owner_per_topic():
    """One owner per topic - a dict cannot hold two owners for one key.

    A single skill owning several topics is fine (registry analysis covers
    shellbags); two *different* owners for one topic is the drift this prevents.
    """
    table = authority_table()
    assert table, "the authority table is empty"
    for topic, owner in table.items():
        assert str(topic).strip(), f"empty topic with owner {owner!r}"
        assert str(owner).strip(), f"empty owner for topic {topic!r}"
    # Topics are unique by construction; the regression to guard is a skill id
    # that looks like a topic, or an accidental case-duplicate.
    lowered = [t.strip().lower() for t in table]
    assert len(lowered) == len(set(lowered)), "two topics differ only by case"


def test_authority_conflicts_are_reported_not_silent(skills):
    conflicts = authority_conflicts(skills)
    # Not required to be empty (a skill may cover an unnamed topic), but it must
    # be a report rather than an exception, and it must name the real gap.
    assert isinstance(conflicts, list)
    assert any("authority row" in c or "id used by" in c for c in conflicts) or conflicts == []
