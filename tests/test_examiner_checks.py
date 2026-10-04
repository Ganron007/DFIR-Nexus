"""WO-K2 — the examiner toolkit in the agent loop.

The work order names three tests:

* each tool is callable from the loop **and audited**;
* a role without a tool is **refused**;
* an UNKNOWN verdict alone never stages a DRAFT.

Plus the two things that decide whether the feature is real: the tools are
validated in the loop's own argument table, and the loop surface and the MCP
surface cannot drift into two different baseline checks.
"""
from __future__ import annotations

import pytest

from nexus.analysis import examiner_checks as ec
from nexus.langgraph.backbone import (
    _CONTEXT_TOOL_NAMES,
    MODE2_TOOL_ALLOWLIST,
    backbone_call,
)
from nexus.langgraph.context_loop import _REQUIRED_ARGS, _TOOL_ARGS, _validate_args
from nexus.modes.multi_role import ROLES


class RecordingAudit:
    """Stands in for AuditWriter; records what was logged."""

    def __init__(self):
        self.entries: list[dict] = []

    def log(self, **kwargs):
        self.entries.append(kwargs)
        return f"nexus-test-{len(self.entries):04d}"


# ---------------------------------------------------------------------------
# callable from the loop, and audited
# ---------------------------------------------------------------------------

def test_every_examiner_tool_is_callable_from_the_loop():
    """Each of the ten must actually run through `backbone_call`."""
    calls = {
        "check_file": {"path": r"C:\Windows\System32\cmd.exe"},
        "check_process_tree": {"process_name": "lsass.exe", "parent_name": "services.exe"},
        "check_service": {"service_name": "Spooler"},
        "check_hash": {"hash_value": "d41d8cd98f00b204e9800998ecf8427e"},
        "check_autorun": {"key_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"},
        "check_registry": {"key_path": r"SOFTWARE\Microsoft\Windows NT"},
        "analyze_filename_triage": {"filename": "invoice.pdf.exe"},
        "check_lolbin": {"filename": "certutil.exe"},
        "check_hijackable_dll": {"dll_name": "version.dll"},
        "deobfuscate_command": {"command": "powershell -enc SQBFAFgA"},
        "check_driver": {"driver_name": "gdrv.sys"},
        "check_lots_domain": {"domain": "discordapp.com"},
        "check_loobin": {"binary_name": "osascript"},
    }
    assert set(calls) == set(ec.EXAMINER_CHECK_TOOLS)
    for name, kwargs in calls.items():
        result = backbone_call(name, **kwargs)
        assert isinstance(result, dict), name
        assert "error" not in result or result.get("verdict"), f"{name}: {result}"


def test_each_loop_call_is_audited():
    """A check without provenance is not usable as evidence (FD-001)."""
    audit = RecordingAudit()
    for name, kwargs in (
        ("check_lolbin", {"filename": "certutil.exe"}),
        ("check_file", {"path": r"C:\Windows\System32\cmd.exe"}),
        ("deobfuscate_command", {"command": "powershell -enc SQBFAFgA"}),
    ):
        backbone_call(name, audit=audit, **kwargs)
    assert len(audit.entries) == 3, audit.entries
    assert {e["tool"] for e in audit.entries} == {
        "check_lolbin", "check_file", "deobfuscate_command"
    }


def test_results_never_read_as_suspicious_without_evidence():
    """UNKNOWN must carry its constraint, so no caller can read it as a verdict.

    Measured on a path that is not in the baseline: UNKNOWN, with the FD-004
    constraint attached - not SUSPICIOUS.
    """
    result = backbone_call("check_file", path=r"C:\Program Files\SomeVendor\app.exe")
    assert result["verdict"] == "UNKNOWN"
    assert "NOT suspicious" in result["interpretation_constraint"]
    for name in ec.EXAMINER_CHECK_TOOLS:
        assert name in _TOOL_ARGS, f"{name} is not validated by the loop"


# ---------------------------------------------------------------------------
# validation lives in the loop's own tables
# ---------------------------------------------------------------------------

def test_arguments_are_validated_in_the_same_tables_as_other_tools():
    ok, error = _validate_args("check_file", {"path": r"C:\Windows\System32\cmd.exe"})
    assert error == "" and ok["path"].endswith("cmd.exe")

    _, error = _validate_args("check_file", {"nope": 1})
    assert "unsupported argument" in error

    _, error = _validate_args("check_process_tree", {"process_name": "lsass.exe"})
    assert "missing required argument" in error and "parent_name" in error

    _, error = _validate_args("check_lolbin", {"filename": 42})
    assert "must be a string" in error


def test_every_required_argument_table_entry_is_reachable():
    """A required arg that is not in _TOOL_ARGS could never be supplied."""
    for name, required in _REQUIRED_ARGS.items():
        if name not in _TOOL_ARGS:
            continue
        for arg in required:
            assert arg in _TOOL_ARGS[name], f"{name}: required {arg} is not accepted"


# ---------------------------------------------------------------------------
# a role without a tool is refused
# ---------------------------------------------------------------------------

def test_a_tool_outside_the_allowlist_is_refused():
    with pytest.raises(PermissionError):
        backbone_call("nmap_scan", target="10.0.0.1")
    with pytest.raises(PermissionError):
        backbone_call("run_command", command="whoami")


def test_the_evidence_and_correlation_roles_carry_the_examiner_toolkit():
    for role in ("evidence", "correlation"):
        tools = set(ROLES[role].tools)
        assert {"check_file", "check_lolbin"} <= tools, role
        unreachable = tools - set(MODE2_TOOL_ALLOWLIST) - set(_CONTEXT_TOOL_NAMES)
        assert not unreachable, f"{role} names tools the loop cannot run: {unreachable}"


def test_mode1_loop_exposes_the_toolkit():
    for name in ec.EXAMINER_CHECK_TOOLS:
        assert name in _CONTEXT_TOOL_NAMES, name


# ---------------------------------------------------------------------------
# no drift between the two surfaces
# ---------------------------------------------------------------------------

class _StubKnownGood:
    """A minimal known_good DB with cmd.exe present and nothing else."""

    def path_exists(self, path):
        return path.lower().endswith(r"system32\cmd.exe")

    def filename_exists(self, filename):
        return filename.lower() == "cmd.exe"

    def is_directory_known_for_file(self, filename, directory):
        return True

    def lookup_hash(self, _h):
        return []


class _StubContext:
    def check_suspicious_filename(self, _f):
        return None

    def get_protected_process_names(self):
        return []

    def check_lolbin(self, filename):
        if filename.lower() == "certutil.exe":
            return {"name": "certutil.exe", "description": "certificate utility",
                    "functions": [], "expected_paths": [], "mitre_techniques": [],
                    "detection": ""}
        return None

    def check_protected_process(self, _f):
        return None


def test_the_prompt_advertises_every_examiner_check():
    """K2: an agent can only call what the prompt tells it exists.

    Measured 2026-10-04: the checks were wired, allowlisted and role-scoped, but
    ABSENT from `tool_contracts_block` - and **zero** of the ten appeared in any
    case audit across the whole store. A tool the model is never told about is
    never used, which made K2 inert however correct its plumbing was.
    """
    from nexus.langgraph.backbone import tool_contracts_block

    for include_external in (True, False):
        block = tool_contracts_block(2, include_external=include_external)
        missing = sorted(t for t in ec.EXAMINER_CHECK_TOOLS if t not in block)
        assert missing == [], f"not advertised (include_external={include_external}): {missing}"
    block = tool_contracts_block(2)
    # FD-004 must travel with them, or the model escalates an UNKNOWN.
    assert "UNKNOWN means" in block and "NOT suspicious" in block


def test_every_advertised_tool_is_actually_callable():
    """No prompt-only tools: a name in the contract that is not in the allowlist
    would fail at call time, which the model reads as the tool being broken."""
    import re

    from nexus.langgraph.backbone import tool_contracts_block

    advertised = set(re.findall(r"^- (\w+)\(", tool_contracts_block(2), re.M))
    assert advertised, "the contract block advertises nothing"
    unavailable = sorted(advertised - set(MODE2_TOOL_ALLOWLIST))
    assert unavailable == [], f"advertised but not callable: {unavailable}"
    # And the checks specifically are among them.
    assert set(ec.EXAMINER_CHECK_TOOLS) <= advertised


def test_the_director_attaches_skill_refs_to_its_orders(monkeypatch):
    """The K5 -> K6 chain: an order with no refs records no steps.

    Measured 2026-10-04: `_record_skill_steps` returns [] when an order carries no
    `skill_refs`, so if the director stopped attaching them K6 would go silent
    without failing anything - the same shape as the K2 defect, one link earlier.
    Asserted through `plan_work_orders` with retrieval stubbed, so it fails if the
    wiring drops the refs rather than if retrieval returns none.
    """
    from pathlib import Path

    import nexus.modes.multi_role as mr

    ref = {"skill": "windows_event_log_analysis", "version": "1",
           "citations": ["d_x:c1"], "role": "evidence"}
    monkeypatch.setattr(mr, "_retrieve_skill_refs", lambda *a, **k: [dict(ref)])

    class _Sink:
        def emit(self, *_a, **_k):
            return None

    orders = mr.plan_work_orders(Path("."), "q", run_id="r", sink=_Sink(), max_orders=2)
    assert orders, "the director produced no orders"
    for order in orders:
        assert order.skill_refs, f"{order.role} order carries no skill_refs"


def test_the_two_surfaces_share_one_implementation(monkeypatch):
    """The loop must not become a second, drifted baseline check.

    Both the MCP tool and the loop decide through
    `triage.analysis.calculate_file_verdict`. This asserts the loop really calls
    it rather than re-implementing a verdict - so a fix in one place moves both.
    """
    from nexus.triage import analysis as ta

    seen: list[str] = []
    real = ta.calculate_file_verdict

    def _spy(**kwargs):
        seen.append("called")
        return real(**kwargs)

    import nexus.analysis.examiner_checks as module

    monkeypatch.setattr(module, "calculate_file_verdict", _spy)
    result = module.check_file(
        _StubKnownGood(), _StubContext(), path=r"C:\Windows\System32\cmd.exe",
    )
    assert seen, "the loop did not go through the shared verdict function"
    assert result["verdict"] not in ("", None)
    assert "interpretation_constraint" in result


def test_a_lolbin_is_reported_but_not_called_malicious(monkeypatch):
    """`EXPECTED_LOLBIN` is the sanctioned reading: legitimate, abusable."""
    import nexus.analysis.examiner_checks as module

    result = module.check_lolbin(_StubContext(), filename="certutil.exe")
    assert result["found"] is True
    assert result["verdict"] == "EXPECTED_LOLBIN"
    assert "not by itself malicious" in result["interpretation_constraint"]


def test_an_absent_baseline_is_unknown_not_suspicious():
    """No triage DB must read as UNKNOWN with the reason, never as a verdict."""
    import nexus.analysis.examiner_checks as module

    result = module.check_file(None, None, path=r"C:\Windows\System32\cmd.exe")
    assert result["verdict"] == "UNKNOWN"
    assert "NOT suspicious" in result["interpretation_constraint"]
    assert "not found" in result["message"].lower()


def test_an_unknown_verdict_alone_never_stages_a_draft():
    """The work order's journey test, asserted structurally.

    A DRAFT needs a title and at least one technique id (and an audit_id, FD-001).
    No examiner check may emit those from an UNKNOWN: it returns a verdict and a
    constraint, never a finding-shaped payload. So an UNKNOWN alone cannot become
    a staged finding, whatever a caller does with it.
    """
    finding_keys = {"title", "technique_ids", "observation", "interpretation"}
    unknown_calls = {
        "check_file": {"path": r"C:\Program Files\Vendor\app.exe"},
        "check_process_tree": {"process_name": "app.exe", "parent_name": "explorer.exe"},
        "check_service": {"service_name": "SomeVendorService"},
        "check_hash": {"hash_value": "d41d8cd98f00b204e9800998ecf8427e"},
        "check_autorun": {"key_path": r"SOFTWARE\Vendor\Run"},
        "check_registry": {"key_path": r"SOFTWARE\Vendor"},
        "analyze_filename_triage": {"filename": "ordinary.txt"},
        "check_lolbin": {"filename": "notalolbin.exe"},
        "check_hijackable_dll": {"dll_name": "notahijackable.dll"},
    }
    for name, kwargs in unknown_calls.items():
        result = backbone_call(name, **kwargs)
        assert isinstance(result, dict), name
        leaked = finding_keys & set(result)
        assert not leaked, f"{name} returned finding-shaped keys {leaked}"
        verdict = str(result.get("verdict") or "").upper()
        if verdict == "UNKNOWN":
            assert "NOT suspicious" in str(result.get("interpretation_constraint")), (
                f"{name} returned UNKNOWN without the FD-004 constraint"
            )
        # A tool that says "not found" must not read as malicious either.
        assert verdict not in ("SUSPICIOUS", "MALICIOUS"), f"{name}: {verdict}"


def test_an_examiner_check_result_cannot_be_staged_without_an_audit_id():
    """A check's result is evidence only with the audit id the loop attaches.

    This is the other half of the journey: the tool returns a verdict, the loop
    audits the call, and the finding cites that audit id. Without the audit the
    finding is refused (FD-001).
    """
    from nexus.discipline import validate_finding

    report = validate_finding({
        "title": "lsass access by an unsigned binary",
        "technique_ids": ["T1003.001"],
        "observation": "Sysmon 10 on lsass.exe from a temp path",
        "interpretation": "credential dumping",
        "confidence": "MEDIUM",
        "confidence_justification": "unsigned SourceImage + dump artifact",
        "audit_ids": [],
    })
    assert report.get("valid") is False, report
    errors = " ".join(str(e) for e in (report.get("errors") or []))
    assert "audit" in errors.lower(), report

    # And the same finding WITH enough corroboration is accepted, so the test is
    # not passing merely because something else is missing. FD-007 requires two
    # independent audit_ids to escalate above LOW, so this is LOW with one.
    ok = validate_finding({
        "title": "lsass access by an unsigned binary",
        "technique_ids": ["T1003.001"],
        "observation": "Sysmon 10 on lsass.exe from a temp path",
        "interpretation": "credential dumping",
        "confidence": "LOW",
        "confidence_justification": "single sysmon source, unconfirmed",
        "audit_ids": ["nexus-gate-bot-20261004-001"],
    })
    assert ok.get("valid") is True, ok
    """Adding a check without an allowlist entry, or the reverse, is a bug."""
    assert set(ec.EXAMINER_CHECK_TOOLS) <= set(MODE2_TOOL_ALLOWLIST)
    assert ec.is_examiner_check("check_lolbin")
    assert not ec.is_examiner_check("es_search")
    assert not ec.is_examiner_check("")


def test_mode2_records_steps_not_applicable_rather_than_false_none():
    """K6: a Mode 2/3 worker must never report a Mode 1 DSL step as `none`.

    Backbone 4k.5.5: "the Mode 2/3 agent surface is ES-only. The typed DSL lives in
    the MCP tools for Mode 1 / deterministic paths - never here." An earlier version
    handed the step's `dsl:` to `es_search`, which takes ES query JSON; the searcher
    swallowed the `ESQueryError` and returned 0, so **every step was recorded
    `none`** - nine false "ran, found nothing" on a nine-step skill.

    Asserted through the real `_record_skill_steps`, so it fails on the wiring.
    """
    from pathlib import Path

    from nexus.modes.multi_role import WorkOrder, _record_skill_steps

    order = WorkOrder(
        order_id="wo-k6", role="evidence", task="t", skill_refs=[
            {"skill": "windows_event_log_analysis", "version": "1"},
        ],
    )
    records = _record_skill_steps(order, Path("."))
    assert records, "no skill record was produced"
    for record in records:
        summary = record.get("summary") or {}
        assert summary.get("none", 0) == 0, (
            f"steps recorded as `none` in a Mode 2/3 run: {summary}")
        assert summary.get("not_applicable", 0) > 0, summary
        for step in record.get("steps") or []:
            assert step["result"] == "not_applicable"
            # The reason must name the separation, not just "no searcher".
            assert "Mode 1 DSL" in step["reason"], step["reason"]
            assert "Elasticsearch directly" in step["reason"], step["reason"]


def test_the_skill_step_searcher_contract_is_the_surface_language():
    """`run_skill_steps` takes a searcher in the SURFACE's own query form.

    Documented, because the bug was passing a Mode 1 DSL string to an ES-native
    searcher. The docstring must keep saying so.
    """
    from nexus.analysis.skill_steps import run_skill_steps

    doc = run_skill_steps.__doc__ or ""
    assert "ES query JSON" in doc
    assert "Mode 1" in doc and "Mode 2/3" in doc
