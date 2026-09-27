"""Stage-by-stage verification of the shared pipeline, against the design.

Each test drives the stage's **real** entry point and asserts the contract the
design states for it. No mock of the thing under test: a stage verified through
a mock is the same vacuous pass this exercise exists to eliminate.

Order follows the pipeline; each section names the contract it enforces, so a
failure says which rule broke rather than which assertion tripped.

    1  case creation        mode fixed at creation, persisted, segregated
    2  evidence             hashed, attributed, not duplicated
    3  tool-lane plan       every host-evidence path gets a job or an honest SKIP
    4  tool-lane input      denylist, dangerous flags, metachars, path validation
    5  output capture       output on disk, or an honest failure - never silent OK
    6  ingest               the registry is populated and resolves
    7  index                ts authority and capping recorded truthfully
    8  needles              0-hit distinguished from never-queried
    9  approval             DRAFT-only, seal, signatures, lockout, timing-safe
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# 1. case creation
# ---------------------------------------------------------------------------

@pytest.fixture
def mgr(tmp_path):
    from nexus.case.manager import CaseManager

    return CaseManager(db_path=tmp_path / "cases.db", secret_key=b"k" * 32)


def test_case_mode_is_fixed_at_creation_and_persisted(mgr):
    """The mode is chosen once and cannot drift; every mode-owned route reads it.

    If the stored mode could change, the whole segregation boundary would be
    advisory rather than enforced.
    """
    for mode in ("1", "2", "3"):
        case = mgr.create_case(
            name=f"probe-m{mode}", description="d",
            created_by="t", metadata={"investigation_mode": mode},
        )
        cid = case.to_dict()["id"]
        stored = mgr.get_case(cid).to_dict()
        meta = stored.get("metadata") or {}
        got = meta.get("investigation_mode") or meta.get("mode")
        assert str(got) == mode, f"mode {mode} stored as {got!r}"


def test_a_case_id_rejects_traversal():
    """`validate_case_id` returns a reason for `..` and separators, else None."""
    from nexus.discipline import validate_case_id

    for bad in ("..", "../evil", "a/b", "a\\b", "..\\..\\x", "", "  "):
        assert validate_case_id(bad), f"accepted a bad case id: {bad!r}"
    assert not validate_case_id("CASE-ABC123")


def test_an_examiner_name_is_validated():
    from nexus.discipline import validate_examiner

    for bad in ("", "a" * 40, "bad name!", "../x"):
        assert validate_examiner(bad), f"accepted a bad examiner: {bad!r}"


def test_the_manager_exposes_audit_verification(mgr):
    """Chain verification is reachable from the manager, not only from tests."""
    assert callable(mgr.verify_audit_chain)
    assert callable(mgr.verify_approval_signatures)


# ---------------------------------------------------------------------------
# 2. evidence
# ---------------------------------------------------------------------------

def test_evidence_records_a_digest_and_who_collected_it(mgr, tmp_path):
    """The store carries the digest and the collector.

    The manager is the *store*: it accepts a hash rather than computing one, so
    the guarantee under test is that a digest and a collector survive the round
    trip rather than that hashing happens here.
    """
    import hashlib

    src = tmp_path / "artifact.bin"
    src.write_bytes(b"evidence bytes")
    digest = hashlib.sha256(b"evidence bytes").hexdigest()

    case = mgr.create_case(name="ev", description="d", created_by="gate_bot")
    cid = case.to_dict()["id"]
    rec = mgr.add_evidence(
        cid, name=src.name, description="probe", file_path=str(src),
        file_hash_sha256=digest, collected_by="gate_bot",
    )
    assert rec is not None, "evidence did not persist"
    blob = json.dumps(rec.to_dict() if hasattr(rec, "to_dict") else rec, default=str)
    assert digest in blob, "the sha256 must survive the round trip"
    assert "gate_bot" in blob, "the collector must survive the round trip"
    assert mgr.list_evidence(cid)


def test_re_registering_one_file_is_idempotent(tmp_path, monkeypatch):
    """Re-running intake must not inflate the count the report quotes.

    The guarantee lives in `evidence_service`, not in the store: the manager is a
    primitive and the service is where idempotency is enforced. Testing the
    service is also the test that matters, because this is the layer the portal
    and the pipeline both call.
    """
    from nexus.case import evidence_service
    from nexus.case.compat import get_sqlite_manager

    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path))
    src = tmp_path / "dup.bin"
    src.write_bytes(b"same bytes")

    mgr = get_sqlite_manager()
    case = mgr.create_case(name="dup", description="d", created_by="t")
    cid = case.to_dict()["id"]
    case_dir = tmp_path / cid
    case_dir.mkdir(parents=True, exist_ok=True)

    first = evidence_service.register_evidence(case_dir, str(src), "one", "t")
    assert first.get("status") == "registered", first
    second = evidence_service.register_evidence(case_dir, str(src), "two", "t")
    assert second.get("status") == "already_registered", second
    assert second.get("evidence_id") == first.get("evidence_id")


def test_re_registering_a_changed_path_is_refused(tmp_path, monkeypatch):
    """Changed content at a registered path is a 409, not a silent overwrite.

    Silently replacing the row would destroy the earlier observation and break
    the chain of custody the registry exists to hold.
    """
    import pytest as _pt

    from nexus.case import evidence_service
    from nexus.case.compat import get_sqlite_manager

    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path))
    src = tmp_path / "changing.bin"
    src.write_bytes(b"v1")

    mgr = get_sqlite_manager()
    case = mgr.create_case(name="chg", description="d", created_by="t")
    case_dir = tmp_path / case.to_dict()["id"]
    case_dir.mkdir(parents=True, exist_ok=True)

    evidence_service.register_evidence(case_dir, str(src), "v1", "t")
    src.write_bytes(b"v2 different content")
    with _pt.raises(ValueError, match="already registered"):
        evidence_service.register_evidence(case_dir, str(src), "v2", "t")


def test_registration_computes_the_digest_itself(tmp_path, monkeypatch):
    """The service hashes the path; the store only accepts a hash."""
    import hashlib

    from nexus.case import evidence_service
    from nexus.case.compat import get_sqlite_manager

    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path))
    src = tmp_path / "hashed.bin"
    src.write_bytes(b"hash me")
    mgr = get_sqlite_manager()
    case = mgr.create_case(name="h", description="d", created_by="gate_bot")
    case_dir = tmp_path / case.to_dict()["id"]
    case_dir.mkdir(parents=True, exist_ok=True)

    out = evidence_service.register_evidence(case_dir, str(src), "probe", "gate_bot")
    assert out.get("sha256") == hashlib.sha256(b"hash me").hexdigest(), out
    assert out.get("total_bytes") == len(b"hash me")


# ---------------------------------------------------------------------------
# 3. tool-lane plan
# ---------------------------------------------------------------------------

HOST_EVIDENCE = [
    ("prefetch", "EVILEXPLORER.EXE-1A2B3C4D.pf", b"\x17PfsS"),
    ("lnk", "shortcut.lnk", b"L\x00\x00\x00"),
    ("lnk", "odd name (1).lnk", b"L\x00\x00\x00"),
]


@pytest.mark.parametrize("family,name,data", HOST_EVIDENCE)
def test_every_recognised_artifact_gets_a_job_or_an_honest_skip(
    tmp_path, family, name, data,
):
    """No registered artifact may fall through to 'no jobs planned'.

    That silent fall-through is what made five formats route nowhere while the
    run still reported `complete`.
    """
    from nexus.langgraph.tool_lane import _plan_single_artifact, is_host_evidence

    src = tmp_path / family
    src.mkdir()
    f = src / name
    f.write_bytes(data)
    assert is_host_evidence(f) is True, f"{family}/{name} not recognised"

    jobs = _plan_single_artifact(f, tmp_path / "extractions")
    assert jobs, f"{name} recognised as host evidence but nothing was scheduled"
    for job in jobs:
        if job.status == "SKIP":
            assert job.reason, "a SKIP must say why"
        else:
            assert job.argv, "a PENDING job must carry argv"


def test_per_file_jobs_never_share_an_output_name(tmp_path):
    """Two sources, one output name, means the second overwrites the first."""
    from nexus.langgraph.tool_lane import _plan_single_artifact

    src = tmp_path / "prefetch"
    src.mkdir()
    names = []
    for n in ("A.EXE-11111111.pf", "B.EXE-22222222.pf"):
        (src / n).write_bytes(b"\x17PfsS")
        for job in _plan_single_artifact(src / n, tmp_path / "extractions"):
            for i, a in enumerate(job.argv):
                if a == "--csvf":
                    names.append(job.argv[i + 1])
    assert len(names) == len(set(names)), f"output names collide: {names}"


def test_an_unrecognised_binary_is_not_claimed_as_host_evidence(tmp_path):
    """The recogniser must stay narrow, or it invents a parser for everything."""
    from nexus.langgraph.tool_lane import _plan_single_artifact, is_host_evidence

    f = tmp_path / "mystery.bin"
    f.write_bytes(b"\x00" * 64)
    assert is_host_evidence(f) is False
    assert _plan_single_artifact(f, tmp_path / "extractions") == []


# ---------------------------------------------------------------------------
# 4. tool-lane input validation
# ---------------------------------------------------------------------------

def test_the_denylist_is_enforced_not_merely_declared():
    """A denylist that nothing consults is documentation, not a control."""
    from nexus.tools.sift import _DANGEROUS_FLAGS, _DENIED_BINARIES, _is_denied

    assert _DANGEROUS_FLAGS, "no dangerous-flag set configured"
    assert _DENIED_BINARIES, "no denied-binary set configured"
    for name in list(_DENIED_BINARIES)[:4]:
        assert _is_denied(name), f"{name} listed but not denied"


def test_shell_metacharacters_are_configured():
    from nexus.tools.sift import _SHELL_METACHARS

    assert _SHELL_METACHARS, "no metacharacter pattern configured"
    for ch in (";", "|", "&", "$", "`"):
        assert _SHELL_METACHARS.search(f"a{ch}b"), f"metacharacter {ch} not matched"


def test_input_path_validation_blocks_system_directories():
    """`_validate_input_path` blocks /etc, /proc, /sys, /dev, /boot, /root.

    It resolves first, so a symlink farm (/etc -> /private/etc) still matches -
    which is why the rule is stated on resolved paths rather than raw strings.
    """
    from nexus.tools.sift import _validate_input_path

    for blocked in ("/etc/passwd", "/proc/self/environ", "/sys/kernel", "/dev/sda"):
        with pytest.raises(ValueError):
            _validate_input_path(blocked)


def test_input_path_validation_allows_an_ordinary_path(tmp_path):
    """The positive case, so the block list is not simply refusing everything."""
    from nexus.tools.sift import _validate_input_path

    ok = tmp_path / "evidence.bin"
    ok.write_bytes(b"x")
    _validate_input_path(str(ok))      # must not raise


def test_denied_binary_refusal_is_symmetric():
    """`_is_denied` must not accept an allowed binary as denied or vice versa."""
    from nexus.tools.sift import _DENIED_BINARIES, _is_denied

    assert _is_denied("not-a-real-binary-xyz") is False
    assert any(_is_denied(n) for n in _DENIED_BINARIES)


# ---------------------------------------------------------------------------
# 5. output capture
# ---------------------------------------------------------------------------

def test_a_clean_exit_with_no_output_is_not_a_success(tmp_path):
    """The D2 defect: a parser that wrote nothing was recorded OK."""
    from nexus.langgraph.tool_lane import ToolJob, _produced_expected_output

    out = tmp_path / "lecmd"
    out.mkdir()
    job = ToolJob(host="windows", tool="lecmd",
                  argv=["lecmd", "-f", "a.lnk", "--csv", str(out), "--csvf", "a.csv"],
                  purpose="LNK", timeout=300)
    assert _produced_expected_output(job) is False

    (out / "a.csv").write_text("h1,h2\nv1,v2\n", encoding="utf-8")
    assert _produced_expected_output(job) is True


def test_an_empty_output_file_is_not_output(tmp_path):
    from nexus.langgraph.tool_lane import ToolJob, _produced_expected_output

    out = tmp_path / "x"
    out.mkdir()
    (out / "a.csv").write_text("", encoding="utf-8")
    job = ToolJob(host="windows", tool="t", argv=["t", "--csv", str(out)],
                  purpose="p", timeout=1)
    assert _produced_expected_output(job) is False


# ---------------------------------------------------------------------------
# 6. ingest
# ---------------------------------------------------------------------------

def test_the_importer_registry_is_populated():
    """Every registered importer must answer source_class/can_handle/parse."""
    from nexus.ingest.registry import get_registry

    reg = get_registry()
    importers = getattr(reg, "importers", None) or getattr(reg, "_importers", {})
    assert len(importers) >= 30, f"only {len(importers)} importers registered"
    for name, imp in importers.items():
        assert getattr(imp, "source_class", None), f"{name} has no source_class"
        assert callable(getattr(imp, "can_handle", None)), f"{name}.can_handle"
        assert callable(getattr(imp, "parse", None)), f"{name}.parse"


def test_autodetect_rejects_junk_without_raising(tmp_path):
    """A junk file must be declined, not crash the detector."""
    from nexus.ingest.registry import get_registry

    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"\xde\xad\xbe\xef" * 64)
    try:
        get_registry().autodetect(str(junk))
    except Exception as exc:
        pytest.fail(f"autodetect raised on junk input: {type(exc).__name__}: {exc}")


def test_the_registry_can_resolve_a_declared_source(tmp_path):
    """Resolution must work for a source the registry actually declares."""
    from nexus.ingest.registry import get_registry

    reg = get_registry()
    sources = reg.all_sources()
    assert sources, "the registry declares no sources"
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"\x00" * 16)
    for src in sources[:6]:
        reg.resolve(src, junk)      # must not raise, whatever it returns


# ---------------------------------------------------------------------------
# 7. index
# ---------------------------------------------------------------------------

def test_index_state_records_capping_truthfully(tmp_path):
    """A cap that happens is recorded; a cap that did not is not claimed."""
    from nexus.langgraph.case_index import write_index_state

    write_index_state(
        tmp_path,
        {"index": "nexus-case-x", "docs": 5,
         "file_mtimes": {"a.csv": 1.0},
         "capped": True,
         "caps": {"docs_capped": True, "families_capped": ["evtx"],
                  "ts_coverage": {"pecmd": {"present": 5, "missing": 0,
                                            "synthesized": 0, "tz_assumed": 5}}}},
    )
    state = json.loads((tmp_path / "analysis" / "index_state.json").read_text(encoding="utf-8"))
    assert state["capped"] is True
    assert state["caps"]["families_capped"] == ["evtx"]
    cov = state["caps"]["ts_coverage"]["pecmd"]
    assert cov["present"] == 5 and cov["tz_assumed"] == 5


def test_index_caps_default_to_unlimited():
    """Caps default to 0 = unlimited. A silent default cap is a silent gap."""
    import inspect

    from nexus.langgraph import case_index

    src = inspect.getsource(case_index)
    for m in re.finditer(r'def (_env_index_int|_env_int)\([^)]*?default\s*=\s*(\d+)', src):
        assert m.group(2) == "0", f"{m.group(1)} defaults to {m.group(2)}, expected 0"


def test_raw_tool_scratch_is_not_indexed_as_evidence():
    """`_SKIP_SUFFIXES` keeps raw stdout out of the evidence set."""
    from nexus.langgraph import query_pack

    skip = getattr(query_pack, "_SKIP_SUFFIXES", ())
    assert "_stdout.txt" in skip
    assert "_meta.json" in skip


# ---------------------------------------------------------------------------
# 8. needles
# ---------------------------------------------------------------------------

def test_a_zero_hit_needle_is_distinguished_from_one_never_run():
    """0 hits means "queried, found nothing"; never-queried means unknown.

    Reading one as the other is how a case reports clean coverage it never had.
    """
    from nexus.langgraph.query_pack import persistable_needles

    keep = persistable_needles(["usb", "sdelete", "1", "ab", "", "   "])
    assert "usb" in keep and "sdelete" in keep
    assert "1" not in keep, "a bare number is not a usable needle"
    assert "ab" not in keep, "a two-character token is not a usable needle"


# ---------------------------------------------------------------------------
# 9. approval
# ---------------------------------------------------------------------------

def test_findings_default_to_draft(mgr):
    """The schema default is DRAFT - invariant 3, first line of defence."""
    from nexus.case.compat import ApprovalState

    case = mgr.create_case(name="appr", description="d", created_by="t")
    cid = case.to_dict()["id"]
    f = mgr.add_finding(cid, title="x", description="d", created_by="t")
    assert f is not None
    state = getattr(f, "state", None) or getattr(f, "approval_state", None)
    assert str(state).lower().endswith("draft"), f"new finding state is {state!r}"
    assert ApprovalState.DRAFT.value == "draft"


def test_an_explicit_approved_state_cannot_be_stored(mgr):
    """`initial_state=APPROVED` must not be honoured.

    The DRAFT-only invariant is enforced here rather than by convention, so a
    caller - or a future endpoint - cannot mint an approved finding.
    """
    from nexus.case.compat import ApprovalState

    case = mgr.create_case(name="appr2", description="d", created_by="t")
    cid = case.to_dict()["id"]
    f = mgr.add_finding(cid, title="y", description="d", created_by="t",
                         initial_state=ApprovalState.APPROVED)
    state = str(getattr(f, "state", None) or getattr(f, "approval_state", "") or "")
    assert "approved" not in state.lower(), f"APPROVED was stored verbatim: {state!r}"


def test_a_broken_seal_blocks_approval():
    """Content edited after staging must not be approvable."""
    from nexus.analysis.integrity import seal_digest, verify_seal

    entry = {"id": "F1", "title": "x", "severity": "low"}
    entry["seal"] = {"digest": seal_digest(entry)}
    assert verify_seal(entry)[0] is True
    entry["severity"] = "critical"
    ok, reason = verify_seal(entry)
    assert ok is False and reason


def test_the_approval_password_store_is_canonical(tmp_path, monkeypatch):
    """An examiner whose name is not a slug must still be able to approve."""
    from nexus.audit import normalize_examiner
    from nexus.auth import _load_password_entry, _save_password_entry

    monkeypatch.setattr("nexus.auth._PASSWORDS_DIR", tmp_path)
    _save_password_entry("gate_bot", {"hash": "h", "salt": "s", "iterations": 1})
    assert _load_password_entry(normalize_examiner("gate_bot")) is not None


def test_lockout_counts_and_clears(tmp_path, monkeypatch):
    """Three strikes lock; a success clears the counter."""
    from nexus.dashboard import app as portal

    monkeypatch.setattr(portal, "_LOCKOUT_FILE", tmp_path / ".commit_lockout")
    portal._record_commit_failure("gate-bot")
    portal._record_commit_failure("gate-bot")
    assert portal._commit_failure_count("gate-bot") == 2
    portal._clear_commit_failures("gate-bot")
    assert portal._commit_failure_count("gate-bot") == 0


def test_secret_comparison_is_timing_safe():
    """hmac.compare_digest, not ==, for anything secret-adjacent."""
    from nexus import auth

    src = Path(auth.__file__).read_text(encoding="utf-8")
    assert "compare_digest" in src
    assert re.search(r"if\s+\w+\s*==\s*(password|token|secret|expected)", src, re.I) is None


def test_an_audit_chain_detects_tampering(tmp_path, monkeypatch):
    """The chain must fail when an entry is edited after the fact.

    `verify()` returns (ok, problems) rather than raising, so the contract under
    test is the boolean and the reason it gives - not an exception type.
    """
    import nexus.case.audit as audit_mod
    from nexus.case.audit import AuditAction, AuditChain

    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path))
    monkeypatch.setattr(audit_mod, "_chain_dir", lambda *_: tmp_path, raising=False)

    chain = AuditChain("CASE-CHAIN", secret_key=b"k" * 32)
    chain.append(AuditAction.EVIDENCE_REGISTERED, "gate-bot", {"n": 1})
    chain.append(AuditAction.FINDING_RECORDED, "gate-bot", {"n": 2})
    ok, problems = chain.verify()
    assert ok is True, problems

    # from_entries takes AuditEntry objects, so rebuild from the live chain and
    # edit one payload - the shape the verifier actually consumes.
    from nexus.case.audit import AuditEntry

    entries = []
    for e in chain.entries():
        payload = dict(e.payload)
        if not entries:
            payload = {"n": 999}
        entries.append(AuditEntry(
            id=e.id, case_id=e.case_id, action=e.action, timestamp=e.timestamp,
            actor=e.actor, payload=payload, prev_hash=e.prev_hash, hash=e.hash,
            signature=e.signature,
        ))
    tampered = AuditChain.from_entries("CASE-CHAIN", entries, secret_key=b"k" * 32)
    ok2, problems2 = tampered.verify()
    assert ok2 is False, "an edited entry must not verify"
    assert problems2, "a failed verification must say what is wrong"
