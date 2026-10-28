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


def test_an_unknown_program_is_a_review_item_and_windows_own_task_raises_nothing():
    """Part 12 FM-5: absent from the baseline is data reduction, not suspicion (FD-004)."""
    leads = {lead.subject: lead for lead in persistence_leads_from(entries_from_documents(_docs()), Baseline())}
    assert "%windir%\\system32\\lpremove.exe" not in {s.lower() for s in leads}
    stun = leads["C:\\Windows\\System32\\STUN.exe"]
    assert stun.kind == "baseline" and stun.score == 0.5 and stun.extra["crit_high"] is False
    assert "a review item" in stun.detail
    assert "task \\SRL Update Service (not in the Windows baseline)" in stun.detail
    assert stun.extra["entries"] == [{"kind": "task", "name": "\\SRL Update Service", "in_baseline": False}]
    assert leads["C:\\Windows\\System32\\SRLUpdate.exe"].extra["crit_high"] is False
    assert leads["C:\\windows\\subject_srv.exe"].extra["crit_high"] is False
    driver = leads["\\SystemRoot\\System32\\drivers\\ena.sys"]
    assert driver.score == 0.45 and driver.extra["crit_high"] is False
    # IC-5: a task is ATT&CK's Scheduled Task, a service its Windows Service (by ATT&CK's own names).
    assert stun.extra["attack_ids"] == ["T1053.005"]
    assert leads["C:\\windows\\subject_srv.exe"].extra["attack_ids"] == ["T1543.003"]
    # The lead can be read again: its query names the rows as the index holds them.
    assert {"term": {"ecs.winlog.event_data.Path": "C:\\Windows\\System32\\STUN.exe"}} in (
        stun.extra["query"]["bool"]["should"])


def test_a_windows_task_whose_program_is_not_windows_own_is_still_a_lead():
    """A built-in task pointed at another program: the task is known, the program is not."""
    baseline = Baseline(tasks=("\\srl update service",), files=())
    leads = {lead.subject: lead for lead in
             persistence_leads_from(entries_from_documents(_docs("task_run_stun")), baseline)}
    stun = leads["C:\\Windows\\System32\\STUN.exe"]
    assert stun.extra["crit_high"] is False
    assert stun.extra["entries"] == [{"kind": "task", "name": "\\SRL Update Service", "in_baseline": True}]


class Context:
    """What the triage context's expected_processes holds for a name: its valid paths (SANS / MemProcFS)."""

    def __init__(self, expected):
        self.expected = expected

    def get_expected_process(self, name):
        paths = self.expected.get(name.lower())
        return {"process_name_lower": name.lower(), "valid_paths": paths} if paths else None


def test_a_well_known_process_name_at_another_path_is_masquerading():
    """T1036.005: a well-known Windows process name at a path none of its valid paths names is crit/high."""
    elsewhere = Context({"stun.exe": ["\\windows\\syswow64\\stun.exe"]})
    leads = {lead.subject: lead for lead in
             persistence_leads_from(entries_from_documents(_docs("task_run_stun")), Baseline(), elsewhere)}
    stun = leads["C:\\Windows\\System32\\STUN.exe"]
    assert stun.extra["crit_high"] is True and stun.extra["masquerade"] is True and stun.score == 1.0
    assert "masquerading, T1036.005" in stun.detail
    # At one of its valid paths (wildcards allowed) the name is not a masquerade.
    here = Context({"stun.exe": ["\\windows\\sys*\\stun.exe"]})
    leads = {lead.subject: lead for lead in
             persistence_leads_from(entries_from_documents(_docs("task_run_stun")), Baseline(), here)}
    assert leads["C:\\Windows\\System32\\STUN.exe"].extra["masquerade"] is False


def test_a_yara_match_naming_a_threat_is_a_crit_detection_and_other_verdicts_are_neutral():
    leads = memory_verdict_leads_from(_docs("yara_stun"), _docs("findevil_stun_yara", "findevil_msedge_thread"))
    by_subject = {lead.subject: lead for lead in leads}
    stun = by_subject["STUN.exe (pid 1912)"]
    assert stun.kind == "rule_engine" and stun.extra["crit_high"] is True and stun.score == 1.0
    assert stun.extra["threats"] == ["Windows.Trojan.CobaltStrike"] and len(stun.extra["rules"]) == 3
    assert len(stun.rows) == 3
    # The FindEvil table's own YR_ row is the YARA report's match: not a second lead.
    assert [lead.subject for lead in leads if "YR_" in lead.subject] == []
    # Part 12 FM-6: MemProcFS rates THREAD false positives HIGH (pinned FS_FindEvil), so it is context.
    thread = by_subject["THREAD msedge.exe"]
    assert thread.kind == "context" and thread.extra["fp_rating"] == "HIGH"
    assert thread.extra["crit_high"] is False and thread.score == 0.2 and thread.extra["count"] == 2


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


def test_a_detection_naming_a_known_tool_carries_its_attack_software():
    """IC-5: the YARA lead's Threat_name and a Defender threat rendered in an engine's row map to ATT&CK's
    software entry, whose techniques are the hunt list the seats get. Kekeo is not in ATT&CK: nothing."""
    from nexus.analysis.leads import Lead, _with_software

    yara = memory_verdict_leads_from(_docs("yara_stun"), [])[0]
    assert _with_software(yara).extra["software"] == [{"id": "S0154", "name": "Cobalt Strike"}]
    defender = Lead(kind="rule_engine", subject="Antivirus - Exploitation Framework Signature", family="hayabusa",
                    detail="Hayabusa crit detection", score=1.0,
                    rows=({"details": "Threat: Behavior:Win32/CobaltStrike.E!sms ¦ Severity: Severe"},))
    assert [s["id"] for s in _with_software(defender).extra["software"]] == ["S0154"]
    kekeo = Lead(kind="rule_engine", subject="Defender Alert (Severe)", family="hayabusa", detail="", score=1.0,
                 rows=({"details": "Threat: VirTool:Win32/Kekeo.B ¦ Severity: Severe"},))
    assert "software" not in (_with_software(kekeo).extra or {})


def test_build_leads_puts_crit_baseline_leads_before_lesser_detections(tmp_path):
    case = tmp_path / "CASE-BASELINE"
    (case / "analysis").mkdir(parents=True)
    leads = build_leads(case, probe=_Probe(), known_fields=set())
    order = [(lead.kind, lead.subject, bool((lead.extra or {}).get("crit_high"))) for lead in leads]
    crit = [o for o in order if o[2]]
    assert order[:len(crit)] == crit, order  # every crit/high lead first
    assert order[0] == ("rule_engine", "STUN.exe (pid 1912)", True)  # detections first among them
    # FM-5: STUN.exe is crit/high because the YARA verdict names the same program, not because it is unknown.
    stun = next(lead for lead in leads if lead.subject == "C:\\Windows\\System32\\STUN.exe")
    assert stun.extra["crit_high"] is True and stun.extra["corroborated_by"] == ["STUN.exe (pid 1912)"]
    assert ("baseline", "C:\\windows\\subject_srv.exe", False) in order
    # FM-6: the THREAD verdict on msedge.exe, a process no other lead is about, is context and ranks last.
    assert order[-1] == ("context", "THREAD msedge.exe", False)


def test_the_examiners_responder_tools_label_their_programs(tmp_path):
    case = tmp_path / "CASE-RESPONDER"
    (case / "analysis").mkdir(parents=True)
    (case / "CASE.yaml").write_text("intake:\n  responder_tools: F-Response, KAPE\n", encoding="utf-8")
    leads = build_leads(case, probe=_Probe(), known_fields=set())
    subject = next(lead for lead in leads if lead.subject == "C:\\windows\\subject_srv.exe")
    assert subject.extra["responder_tool"] == "F-Response" and subject.extra["crit_high"] is False
    assert "the examiner names F-Response among the responders' tools" in subject.detail


def test_findevil_ratings_are_the_pinned_wiki_pages():
    """The ratings are the importer's reading of the pinned page; regenerating changes nothing."""
    import subprocess
    import sys as _sys

    from nexus.analysis.baseline_leads import findevil_rating

    check = subprocess.run([_sys.executable, "devtools/knowledge/import_memprocfs_findevil.py", "--check"],
                           cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True)
    assert check.returncode == 0, check.stdout + check.stderr
    assert findevil_rating("PE_PATCHED") == "HIGH" and findevil_rating("pe_nolink") == "HIGH"
    assert findevil_rating("HIGH_ENTROPY") == "MEDIUM" and findevil_rating("YR_TROJAN") == "MEDIUM"
    assert findevil_rating("PE_INJECT") == "LOW" and findevil_rating("NOT_A_TYPE") == ""


def test_t22_an_object_memory_yara_match_names_its_object_not_a_process():
    """D461: T22's vulnerable-driver match is object memory (a kernel driver, no PID, no process). Grouped by
    process it became the lead "? (pid ?)", which no Mode 1 note could name. It names the MemoryTag object."""
    t22 = json.loads((FIXTURE.parent / "t22_yara_matches.json").read_text(encoding="utf-8"))["docs"]
    leads = memory_verdict_leads_from(t22["yara_t22_mnemosyne_object"] + t22["yara_t22_mcshield_process"], [])
    by_subject = {lead.subject: lead for lead in leads}
    assert set(by_subject) == {"FILE:[\Windows\Mnemosyne.sys]", "mcshield.exe (pid 3836)"}
    driver = by_subject["FILE:[\Windows\Mnemosyne.sys]"]
    assert driver.detail.startswith("MemProcFS YARA: 1 rule(s) matched object memory FILE:[\Windows\Mnemosyne.sys]")
    assert "?" not in driver.detail and driver.extra["object"] == "FILE:[\Windows\Mnemosyne.sys]"
    assert driver.extra["process"] == "" and driver.extra["level"] == "severity 50"
    mcshield = by_subject["mcshield.exe (pid 3836)"]
    assert "the memory of mcshield.exe (pid 3836" in mcshield.detail and mcshield.extra["object"] == ""
