"""IC-6 / IC-7 (Part 9): the stored skill-step and analytic queries, rebuilt by meaning and proved on real rows.

Measured on CASE-C5B04D31 before the rebuild: 79 literal phrases (free terms glued into one wildcard string),
32 floods, 36 zero-hit queries among 248 steps; 24 of 36 analytics matched nothing and 3 flooded. Each search
is now authored as data (`search:`: the log it reads, cited from pinned sources, and the fields and values it
matches), compiled by `devtools/knowledge/compile_skills.py`, and proved by
`devtools/knowledge/prove_step_controls.py` on the control corpus: public EVTX parsed by the lane's EvtxECmd,
the ES-Mapping tool outputs, and real course logs through the real importers (`build_control_corpus.py`).

These tests read the committed record (`step-controls.json`); they need no Elasticsearch.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
DEVTOOLS = REPO / "devtools" / "knowledge"
SKILLS = REPO / "src" / "nexus" / "data" / "knowledge" / "skills"
ANALYTICS = REPO / "src" / "nexus" / "data" / "knowledge" / "needles" / "behavioral_analytics.yaml"
RECORD = DEVTOOLS / "step-controls.json"
sys.path.insert(0, str(DEVTOOLS))

#: Stored queries the control corpus holds no real row for, each with the reason. The set must equal what
#: the prover measured, so a query that loses its control fails here instead of passing unnoticed.
NO_CONTROL: dict[str, str] = json.loads((DEVTOOLS / "step-controls-absent.json").read_text(encoding="utf-8"))


def _steps() -> list[tuple[str, dict]]:
    out = []
    for path in sorted(SKILLS.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        out.extend((f"skill:{doc.get('skill')}/{s.get('name')}", s) for s in doc.get("steps") or [] if isinstance(s, dict))
    return out


def _analytics() -> list[tuple[str, dict]]:
    doc = yaml.safe_load(ANALYTICS.read_text(encoding="utf-8")) or {}
    return [(f"analytic:{a.get('id')}", a) for a in doc.get("packs") or [] if isinstance(a, dict)]


def _values(node: object, out: list[str]) -> list[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "value" and isinstance(value, str):
                out.append(value)
            else:
                _values(value, out)
    elif isinstance(node, list):
        for value in node:
            _values(value, out)
    return out


def test_every_search_is_compiled_from_its_authored_form_with_no_problem():
    from compile_skills import run, run_analytics

    skills, analytics = run(check=True), run_analytics(check=True)
    for stats in (skills, analytics):
        assert stats["problems"] == [], stats["problems"][:5]
        assert stats["drift"] == [], stats["drift"][:5]
        assert stats["uncompiled"] == [], stats["uncompiled"][:5]
    assert skills["steps"] == skills["search"] + skills["aggregate"] + skills["procedure"]


def test_a_glued_phrase_is_refused_by_the_checker():
    """The KR2b defect, as data: `*procdump nanodump mimikatz sekurlsa*` is four terms in one value."""
    from step_search import check_step

    glued = {"search": {"families": ["pecmd"], "any": [
        {"field": "ecs.process.command_line", "contains": ["procdump nanodump mimikatz sekurlsa"]}]}}
    problems, _ = check_step(glued)
    assert any("glued phrase" in p for p in problems)
    split = {"search": {"families": ["pecmd"], "any": [
        {"field": "ecs.process.command_line", "contains": ["procdump", "nanodump", "mimikatz", "sekurlsa"]}]}}
    assert check_step(split)[0] == []


def test_an_event_must_come_from_a_pinned_source():
    from step_search import check_step

    uncited = {"search": {"basis": ["attack:DET0363"], "events": [
        {"channel": "Security", "codes": ["4769"]}]}}
    assert any("not named by a cited ATT&CK analytic" in p for p in check_step(uncited)[0])
    cited = {"search": {"basis": ["attack:DET0157"], "events": [{"channel": "Security", "codes": ["4769"]}]}}
    assert check_step(cited)[0] == []


def test_no_stored_value_carries_mode1_syntax():
    """KR2b's defect: Mode 1 `field:value` text (`file:prefetch`) inside a value. A value that holds colons
    because the data does (Hindsight's `chrome:history:file_downloaded`) is not Mode 1 syntax."""
    literal = re.compile(r"^\*?(family|host|user|event|file|ts|time|timestamp|date|after|before):")
    for ident, item in _steps() + _analytics():
        for value in _values(item.get("es") or {}, []):
            assert not literal.match(value), (ident, value)


def test_a_procedure_step_says_why_and_holds_no_query():
    for ident, step in _steps():
        if step.get("kind") == "procedure":
            assert str(step.get("procedure_reason") or "").strip(), ident
            assert "es" not in step and "search" not in step, ident


def test_every_stored_query_is_proved_on_a_real_row_or_named_absent():
    record = json.loads(RECORD.read_text(encoding="utf-8"))
    items = record["items"]
    from prove_step_controls import query_hash

    absent: set[str] = set()
    for ident, item in _steps() + _analytics():
        if not isinstance(item.get("es"), dict):
            continue
        entry = items.get(ident)
        assert entry, f"{ident}: never proved (run devtools/knowledge/prove_step_controls.py)"
        assert entry["query_sha"] == query_hash(item["es"], item.get("es_aggs")), f"{ident}: changed since proved"
        assert not entry.get("control_error"), (ident, entry.get("control_error"))
        assert not entry.get("normalized"), (ident, entry.get("normalized"))
        if entry.get("control_total", 0) < 1:
            absent.add(ident)
        else:
            row = entry.get("control_row") or {}
            assert row.get("file") and row.get("file_sha256"), f"{ident}: the control row names no source file"
    assert absent == set(NO_CONTROL), {"newly absent": sorted(absent - set(NO_CONTROL)),
                                       "now proved": sorted(set(NO_CONTROL) - absent)}
    for ident, reason in NO_CONTROL.items():
        assert len(reason) > 20, ident


def test_no_search_floods_the_measured_case():
    record = json.loads(RECORD.read_text(encoding="utf-8"))
    for ident, entry in record["items"].items():
        assert not entry.get("case_error"), (ident, entry.get("case_error"))
        if entry.get("kind") == "search":
            assert entry.get("case_total", 0) <= record["flood"], (ident, entry.get("case_total"))


def test_the_timestomp_analytic_reads_si_fn_on_executables_not_every_file():
    """IC-7: the old analytic matched 101,681 rows on CASE-C5B04D31; SI<FN alone is True for 243,589 of the
    602,367 MFT rows of the control corpus (copied and extracted files). It now needs SI<FN with whole-second
    $SI times on an executable outside the servicing stores; the USN journal's BasicInfoChange on an executable
    is its own analytic."""
    by_id = dict(_analytics())
    si = by_id["analytic:ba-eva-timestomp"]
    fields = {c["field"] for c in si["search"]["all"]}
    assert {"fields.SI<FN", "fields.uSecZeros", "ecs.file.extension"} <= fields
    assert "analytic:ba-eva-timestomp-usn" in by_id
    record = json.loads(RECORD.read_text(encoding="utf-8"))["items"]
    for ident in ("analytic:ba-eva-timestomp", "analytic:ba-eva-timestomp-usn"):
        assert 0 < record[ident]["case_total"] < 5_000, (ident, record[ident]["case_total"])


def test_no_skill_or_analytic_cites_a_revoked_technique():
    from nexus.knowledge.attack_method import current_technique

    for path in sorted(SKILLS.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for tid in ((doc.get("trigger") or {}).get("techniques") or []) + (doc.get("mitre") or []):
            assert current_technique(tid) == str(tid).upper(), (path.name, tid)
    for ident, item in _analytics():
        for tid in item.get("techniques") or []:
            assert current_technique(tid) == str(tid).upper(), (ident, tid)


@pytest.fixture()
def lsass_order():
    from nexus.modes.multi_role import WorkOrder

    return WorkOrder(order_id="wo-ic6", role="host", task="credential access",
                     skill_refs=[{"skill": "lsass_credential_access", "version": "x", "role": "host"}])


def test_the_seat_reads_which_logs_a_step_needs_and_gets_no_prose_for_a_log_the_case_lacks(
        lsass_order, monkeypatch, tmp_path):
    """Run 4 read "Sysmon EventID 10 (ProcessAccess) on lsass.exe" in 23 calls on a case with no Sysmon log,
    then claimed Sysmon events. With the case named, a step whose log the case does not hold is shown as
    such, without its look_for; the query itself is never shown (WO-KR2)."""
    from nexus.analysis import skill_steps
    from nexus.modes.multi_role import _skill_procedure_block

    def rows(case_id: str, source_json: str) -> int:
        assert case_id == "CASE-IC6TEST"
        return 0 if "Sysmon" in source_json else 12

    monkeypatch.setattr(skill_steps, "_source_rows", rows)
    block = _skill_procedure_block(lsass_order, tmp_path / "CASE-IC6TEST")
    sysmon = next(line for line in block.splitlines() if "* sysmon_lsass_access" in line)
    assert "reads Sysmon 10: this case holds none of it" in sysmon
    assert "look_for" not in sysmon and "GrantedAccess" not in sysmon
    security = next(line for line in block.splitlines() if "* sec_lsass_handle" in line)
    assert "reads Security 4656, 4663 (this case holds it)" in security and "look_for:" in security
    assert "procedure (an order of method" in block  # memory_side_confirmation
    for forbidden in ("wildcard", "case_insensitive", "ecs.winlog", "| run:"):
        assert forbidden not in block
