"""D244 / D245: the case's tasks and services against the triage baseline, and the memory scanner's verdicts, as leads.

On CASE-C5B04D31 no mode weighed ``\\SRL Update Service`` -> ``C:\\Windows\\System32\\STUN.exe`` (a task outside the
baseline running a file no Windows build ships, as SYSTEM, at boot), and none read MemProcFS's YARA matches of
Cobalt Strike in STUN.exe, explorer.exe, msedge.exe and lsass.exe: neither was a lead. The rows below are that
case's indexed documents, copied verbatim (``tests/fixtures/persistence_rows.json``). The baseline is a stand-in
for the 5.9 GB ``known_good.db``: it holds what that database answered for these values on 2026-10-16.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.analysis.baseline_leads import (
    entries_from_documents,
    memory_verdict_leads_from,
    persistence_leads_from,
    rows_from_documents,
)
from nexus.analysis.leads import build_leads
from nexus.triage.analysis import normalize_path

FIXTURE = Path(__file__).parent / "fixtures" / "persistence_rows.json"


def _docs(*names: str) -> list[dict]:
    docs = json.loads(FIXTURE.read_text(encoding="utf-8"))["docs"]
    return [row for name in (names or docs) for row in docs[name]]


class Baseline:
    """What known_good.db answered for these values (2026-10-16): LPRemove and lpremove.exe are Windows'."""

    def __init__(self, tasks=("\\microsoft\\windows\\mui\\lpremove",), files=("\\windows\\system32\\lpremove.exe",)):
        self.tasks = set(tasks)
        self.files = set(files)

    def lookup_task(self, path):
        return [{"task": path}] if path.lower() in self.tasks else []

    def lookup_service(self, name):
        return []

    def path_exists(self, path):
        return normalize_path(path) in self.files

    def filename_exists(self, name):
        return any(f.rsplit("\\", 1)[-1] == name.lower() for f in self.files)


def _by_name(entries):
    return {e.name: e for e in entries}


def test_every_source_names_the_task_and_what_it_runs():
    entries = _by_name(entries_from_documents(_docs()))
    stun = entries["\\SRL Update Service"]
    # Its run (129, with the program), its registration (106, without), the task XML and the memory task list.
    assert stun.count == 4 and list(stun.executables) == ["\\windows\\system32\\stun.exe"]
    assert list(entries["\\SRL User Maintenance"].executables) == ["\\windows\\system32\\srlupdate.exe"]
    assert list(entries["\\Microsoft\\Windows\\MUI\\LPRemove"].executables) == ["\\windows\\system32\\lpremove.exe"]
    assert list(entries["F-Response Subject Service"].executables) == ["\\windows\\subject_srv.exe"]
    assert entries["F-Response Subject Service"].kind == "service"
    assert list(entries["Amazon Elastic Network Adapter Driver"].executables) == [
        "\\windows\\system32\\drivers\\ena.sys"]


def test_an_unknown_program_in_the_windows_directory_is_crit_and_windows_own_task_raises_nothing():
    leads = {lead.subject: lead for lead in persistence_leads_from(entries_from_documents(_docs()), Baseline())}
    assert "%windir%\\system32\\lpremove.exe" not in {s.lower() for s in leads}
    stun = leads["C:\\Windows\\System32\\STUN.exe"]
    assert stun.kind == "baseline" and stun.score == 1.0 and stun.extra["crit_high"] is True
    assert "task \\SRL Update Service (not in the Windows baseline)" in stun.detail
    assert stun.extra["entries"] == [{"kind": "task", "name": "\\SRL Update Service", "in_baseline": False}]
    assert leads["C:\\Windows\\System32\\SRLUpdate.exe"].extra["crit_high"] is True
    assert leads["C:\\windows\\subject_srv.exe"].extra["crit_high"] is True
    # A kernel driver there is routine for hardware and vendor packages: high, not crit.
    driver = leads["\\SystemRoot\\System32\\drivers\\ena.sys"]
    assert driver.score == 0.9 and driver.extra["crit_high"] is False
    # The lead can be read again: its query names the rows as the index holds them.
    assert {"term": {"ecs.winlog.event_data.Path": "C:\\Windows\\System32\\STUN.exe"}} in (
        stun.extra["query"]["bool"]["should"])


def test_a_windows_task_whose_program_is_not_windows_own_is_still_a_lead():
    """A built-in task pointed at another program: the task is known, the program is not."""
    baseline = Baseline(tasks=("\\srl update service",), files=())
    leads = {lead.subject: lead for lead in
             persistence_leads_from(entries_from_documents(_docs("task_run_stun")), baseline)}
    stun = leads["C:\\Windows\\System32\\STUN.exe"]
    assert stun.extra["crit_high"] is True
    assert stun.extra["entries"] == [{"kind": "task", "name": "\\SRL Update Service", "in_baseline": True}]


def test_a_yara_match_naming_a_threat_is_a_crit_detection_and_other_verdicts_are_neutral():
    leads = memory_verdict_leads_from(_docs("yara_stun"), _docs("findevil_stun_yara", "findevil_msedge_thread"))
    by_subject = {lead.subject: lead for lead in leads}
    stun = by_subject["STUN.exe (pid 1912)"]
    assert stun.kind == "rule_engine" and stun.extra["crit_high"] is True and stun.score == 1.0
    assert stun.extra["threats"] == ["Windows.Trojan.CobaltStrike"] and len(stun.extra["rules"]) == 3
    assert len(stun.rows) == 3
    # The FindEvil table's own YR_ row is the YARA report's match: not a second lead.
    assert [lead.subject for lead in leads if "YR_" in lead.subject] == []
    thread = by_subject["THREAD msedge.exe"]
    assert thread.extra["crit_high"] is False and thread.score == 0.5 and thread.extra["count"] == 2


class _Probe:
    """The index and baseline as these documents give them; the other lead builders find nothing."""

    def __init__(self):
        self.baseline = Baseline()

    def aggregate(self, **_kw):
        return {"top": [], "buckets": [], "audit_id": ""}

    def observed_calls(self, *_a, **_kw):
        return []

    def process_check(self, **_kw):
        return {}

    def count_analytic(self, _clause):
        return 0

    def persistence_rows(self):
        return rows_from_documents(_docs())

    def memory_hits(self):
        return _docs("yara_stun"), _docs("findevil_stun_yara", "findevil_msedge_thread")


def test_build_leads_puts_crit_baseline_leads_before_lesser_detections(tmp_path):
    case = tmp_path / "CASE-BASELINE"
    (case / "analysis").mkdir(parents=True)
    leads = build_leads(case, probe=_Probe(), known_fields=set())
    order = [(lead.kind, lead.subject, bool((lead.extra or {}).get("crit_high"))) for lead in leads]
    crit = [o for o in order if o[2]]
    assert order[:len(crit)] == crit, order  # every crit/high lead first
    assert order[0] == ("rule_engine", "STUN.exe (pid 1912)", True)  # detections first among them
    assert ("baseline", "C:\\Windows\\System32\\STUN.exe", True) in crit
    assert order.index(("rule_engine", "THREAD msedge.exe", False)) > order.index(
        ("baseline", "C:\\windows\\subject_srv.exe", True))
