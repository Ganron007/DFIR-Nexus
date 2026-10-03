"""WO-K1 — the K1 runner and scorer.

Three things the work order requires proved, plus the two structural rules it
says must hold "not by intention":

* the scorer on a **synthetic manifest and case with known TP, FP and FN**;
* the agent **cannot read the manifest path** from any prompt or tool — asserted;
* a **benign-only set produces FP numbers and no recall** (and specifically does
  not report recall 1.0, which is what an empty expectation would otherwise
  score as);
* the labelling directories are **never registered** into a case;
* `--score-only` **never runs a mode**, so re-scoring cannot perturb a result.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules[name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


@pytest.fixture(scope="module")
def ev():
    return _load("eval_run_under_test", "scripts/eval_run.py")


ATTACK = "a" * 64
ATTACK2 = "b" * 64
BENIGN = "c" * 64
AUDIT_ATTACK = "nexus-test-0001"
AUDIT_BENIGN = "nexus-test-0002"
AUDIT_UNRESOLVABLE = "nexus-test-9999"


def _case(tmp_path: Path, findings: list[dict], *, benign_hash: str = BENIGN) -> Path:
    """A case with an evidence registry, an audit log and staged findings."""
    case = tmp_path / "CASE-K1SYN"
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text(
        "id: CASE-K1SYN\nmode: 1\nname: synthetic\n", encoding="utf-8"
    )
    (case / "evidence.json").write_text(
        json.dumps([
            {"name": "attack.log", "path": "/ev/attack.log", "sha256": ATTACK},
            {"name": "attack2.log", "path": "/ev/attack2.log", "sha256": ATTACK2},
            {"name": "clean.log", "path": "/ev/clean.log", "sha256": benign_hash},
        ]),
        encoding="utf-8",
    )
    rows = [
        {"audit_id": AUDIT_ATTACK, "tool": "es_search", "input_sha256s": [ATTACK]},
        {"audit_id": AUDIT_BENIGN, "tool": "es_search", "input_sha256s": [BENIGN]},
    ]
    (case / "audit" / "nexus.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )
    (case / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    return case


def _finding(fid: str, techniques: list[str], audit_id: str, ts: str = "2026-10-03T10:00:00+00:00") -> dict:
    return {
        "id": fid,
        "title": f"finding {fid}",
        "status": "DRAFT",
        "technique_ids": techniques,
        "audit_ids": [audit_id],
        "staged_at": ts,
    }


def _manifest(tmp_path: Path, entries: list[dict], name: str = "manifest.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"entries": entries}), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# the scorer, on known TP / FP / FN
# ---------------------------------------------------------------------------

def test_scorer_reports_known_tp_fp_and_fn(ev, tmp_path):
    """Expected {T1059.001, T1003.001}; found {T1059.001, T1112}.

    So: 1 true positive, 1 extra (a false positive in the precision sense), and
    1 miss (a false negative). Precision 1/2, recall 1/2, F1 1/2.
    """
    case = _case(tmp_path, [
        _finding("F-1", ["T1059.001"], AUDIT_ATTACK),
        _finding("F-2", ["T1112"], AUDIT_ATTACK),
    ])
    key = ev.AnswerKey.from_manifest(_manifest(tmp_path, [
        {"sha256": ATTACK, "techniques": ["T1059.001", "T1003.001"]},
    ]))

    scored = ev.score_case(case, key)
    tech = scored["dimensions"]["techniques"]

    # The metric dict reports expected/found/missing/extra; the true positive is
    # what both agree on.
    true_positive = set(tech["expected"]) & set(tech["found"])
    assert true_positive == {"T1059.001"}, tech
    assert tech["extra"] == ["T1112"], tech
    assert tech["missing"] == ["T1003.001"], tech
    assert tech["missed"] == ["T1003.001"], tech
    assert tech["precision"] == 0.5
    assert tech["recall"] == 0.5
    assert tech["f1"] == 0.5
    # The key is scoped to the case by hash: only the registered attack file matches.
    assert scored["key_scope"]["matched"] == 1


def test_an_unregistered_manifest_entry_is_ignored_not_counted(ev, tmp_path):
    """An expectation for a file the case does not hold must not depress recall."""
    case = _case(tmp_path, [_finding("F-1", ["T1059.001"], AUDIT_ATTACK)])
    key = ev.AnswerKey.from_manifest(_manifest(tmp_path, [
        {"sha256": ATTACK, "techniques": ["T1059.001"]},
        {"sha256": "f" * 64, "techniques": ["T9999"]},   # not in this case
    ]))
    scored = ev.score_case(case, key)
    assert scored["dimensions"]["techniques"]["recall"] == 1.0
    assert scored["key_scope"]["ignored"] == 1


# ---------------------------------------------------------------------------
# the false-positive metric
# ---------------------------------------------------------------------------

def test_a_finding_citing_only_benign_evidence_is_a_false_positive(ev, tmp_path):
    case = _case(tmp_path, [
        _finding("F-BENIGN", ["T1112"], AUDIT_BENIGN),
        _finding("F-REAL", ["T1059.001"], AUDIT_ATTACK),
    ])
    key = ev.AnswerKey.from_manifest(_manifest(tmp_path, [
        {"sha256": ATTACK, "techniques": ["T1059.001"]},
        {"sha256": BENIGN, "role": "benign"},
    ]))
    fp = ev.score_case(case, key)["false_positive"]

    assert fp["findings"] == 2
    assert fp["benign_only"] == 1
    assert fp["benign_only_ids"] == ["F-BENIGN"]
    assert fp["rate"] == 0.5
    assert fp["benign_files_declared"] == 1


def test_an_unresolvable_citation_is_not_read_as_benign(ev, tmp_path):
    """Otherwise a citation we cannot check would count as a clean result."""
    case = _case(tmp_path, [_finding("F-X", ["T1112"], AUDIT_UNRESOLVABLE)])
    key = ev.AnswerKey.from_manifest(_manifest(tmp_path, [
        {"sha256": ATTACK, "techniques": ["T1059.001"]},
        {"sha256": BENIGN, "role": "benign"},
    ]))
    fp = ev.score_case(case, key)["false_positive"]

    assert fp["benign_only"] == 0, "an unchecked citation must not be called benign-only"
    assert fp["unattributable"] == 1


def test_a_benign_only_set_produces_fp_numbers_and_no_recall(ev, tmp_path):
    """No expectation means no recall — never recall 1.0.

    `findings_dimension` scores an empty expectation as recall 1.0, which on a
    benign-only set reads as a perfect run. The scorer must say "not applicable".
    """
    case = _case(tmp_path, [
        _finding("F-1", [], AUDIT_BENIGN),
        _finding("F-2", ["T1112"], AUDIT_BENIGN),
    ])
    key = ev.AnswerKey.from_manifest(_manifest(tmp_path, [
        {"sha256": BENIGN, "role": "benign"},
    ]))
    scored = ev.score_case(case, key)
    tech = scored["dimensions"]["techniques"]

    assert tech["recall"] is None, tech
    assert "no expectation" in tech["recall_reason"]
    assert scored["key_scope"]["expected_techniques"] == 0
    # And the false-positive number is still produced.
    assert scored["false_positive"]["benign_only"] == 2
    assert scored["false_positive"]["findings"] == 2


# ---------------------------------------------------------------------------
# the leak guard
# ---------------------------------------------------------------------------

def test_the_manifest_path_never_reaches_the_case(ev, tmp_path):
    """Asserted, not intended: a planted occurrence is caught."""
    case = _case(tmp_path, [_finding("F-1", ["T1059.001"], AUDIT_ATTACK)])
    manifest = _manifest(tmp_path, [{"sha256": ATTACK, "techniques": ["T1059.001"]}])

    assert ev.leak_guard(case, manifest) == [], "a clean case must pass"

    # Now plant it where a prompt or a run record would leave it.
    (case / "analysis").mkdir()
    (case / "analysis" / "llm_context").mkdir()
    (case / "analysis" / "llm_context" / "turn-1.md").write_text(
        f"Consider {manifest}\n", encoding="utf-8"
    )
    hits = ev.leak_guard(case, manifest)
    assert hits, "the guard must catch the manifest path inside a packed prompt"
    assert any("llm_context" in h for h in hits), hits


def test_the_guard_catches_the_bare_filename_too(ev, tmp_path):
    """A basename is enough to locate the key, so it counts as a leak."""
    case = _case(tmp_path, [_finding("F-1", ["T1059.001"], AUDIT_ATTACK)])
    manifest = _manifest(tmp_path, [{"sha256": ATTACK, "techniques": ["T1059.001"]}],
                         name="operator-manifest.json")
    (case / "audit" / "nexus.jsonl").write_text(
        json.dumps({"audit_id": "x", "note": "see operator-manifest.json"}) + "\n",
        encoding="utf-8",
    )
    hits = ev.leak_guard(case, manifest)
    assert hits and any("audit" in h for h in hits), hits


# ---------------------------------------------------------------------------
# evidence discovery: the labels must never enter the case
# ---------------------------------------------------------------------------

def test_discover_evidence_skips_the_labelling_directories(ev, tmp_path):
    """A `labels/` folder inside the case is the answer key walking in."""
    set_dir = tmp_path / "testbed"
    (set_dir / "gather" / "host1" / "logs").mkdir(parents=True)
    (set_dir / "gather" / "host1" / "logs" / "auth.log").write_text("login\n", encoding="utf-8")
    (set_dir / "labels" / "host1").mkdir(parents=True)
    (set_dir / "labels" / "host1" / "auth.log").write_text("T1059.001\n", encoding="utf-8")
    (set_dir / "attacker_0" / "logs").mkdir(parents=True)
    (set_dir / "attacker_0" / "logs" / "attacks.log").write_text("attack at 10:00\n", encoding="utf-8")

    evidence, skipped = ev.discover_evidence(set_dir)
    names = {p.name for p in evidence}
    skipped_names = {p.name for p in skipped}

    assert "auth.log" in names
    assert "T1059.001" not in " ".join(
        p.read_text(encoding="utf-8") for p in evidence
    ), "no labelled content may be registered"
    assert skipped_names == {"auth.log", "attacks.log"} or len(skipped) == 2
    assert any("labels" in str(p) for p in skipped)
    assert any(p.name == "attacks.log" for p in skipped)


# ---------------------------------------------------------------------------
# --score-only must not run a mode
# ---------------------------------------------------------------------------

def test_the_manifest_itself_is_never_registered_as_evidence(ev, tmp_path):
    """Handing --set-dir the stage root (not its evidence/ child) must be safe.

    `manifest.json` holds the expected techniques, so registering it would put
    the answer inside the case.
    """
    stage = tmp_path / "stage"
    (stage / "evidence" / "vpn" / "logs").mkdir(parents=True)
    (stage / "evidence" / "vpn" / "logs" / "openvpn.log").write_text("vpn\n", encoding="utf-8")
    (stage / "manifest.json").write_text(
        json.dumps({"entries": [{"sha256": ATTACK, "techniques": ["T1133"]}]}),
        encoding="utf-8",
    )
    (stage / "mapping.json").write_text("{}", encoding="utf-8")

    evidence, skipped = ev.discover_evidence(stage)
    names = {p.name for p in evidence}
    assert names == {"openvpn.log"}, names
    assert {"manifest.json", "mapping.json"} <= {p.name for p in skipped}


def test_score_only_never_runs_a_mode(ev, tmp_path, monkeypatch):
    """Re-scoring an existing case must not perturb it."""
    case = _case(tmp_path, [_finding("F-1", ["T1059.001"], AUDIT_ATTACK)])
    # tests/conftest.py already redirects settings.cases_root to tmp_path/cases.
    cases_root = Path(ev.cases_root())
    assert cases_root == tmp_path / "cases"
    (tmp_path / case.name).rename(cases_root / case.name)

    def _boom(*_a, **_k):
        raise AssertionError("run_mode must not be called by --score-only")

    monkeypatch.setattr(ev, "run_mode", _boom)

    manifest = _manifest(tmp_path, [{"sha256": ATTACK, "techniques": ["T1059.001"]}])
    rc = ev.main([
        "--manifest", str(manifest),
        "--score-only", "--cases", case.name, "--modes", "1",
        "--json-out", str(tmp_path / "accuracy.json"),
        "--md-out", str(tmp_path / "ACCURACY.md"),
        "--label", "unit score-only",
    ])
    assert rc == 0
    written = json.loads((tmp_path / "accuracy.json").read_text(encoding="utf-8"))
    assert written["k_runs"][0]["cases"][0]["run"]["rc"] == "skipped"


def test_two_k_runs_both_survive_in_the_report(ev, tmp_path):
    """K1 re-runs the baseline after each of K2-K7 - a run must not erase one.

    Appending blindly would duplicate the legend; replacing the header alone
    would silently drop the earlier run. The section is regenerated from the
    run records instead.
    """
    case = _case(tmp_path, [_finding("F-1", ["T1059.001"], AUDIT_ATTACK)])
    cases_root = Path(ev.cases_root())
    (tmp_path / case.name).rename(cases_root / case.name)

    manifest = _manifest(tmp_path, [{"sha256": ATTACK, "techniques": ["T1059.001"]}])
    json_out, md_out = tmp_path / "a.json", tmp_path / "A.md"
    for label in ("K-run 0 baseline", "K-run 1 after WO-K2"):
        assert ev.main([
            "--manifest", str(manifest), "--score-only", "--cases", case.name,
            "--modes", "1", "--label", label,
            "--json-out", str(json_out), "--md-out", str(md_out),
        ]) == 0

    md = md_out.read_text(encoding="utf-8")
    assert md.count("## K-runs") == 1, "the header must appear once"
    assert "K-run 0 baseline" in md, "the first run must survive a later run"
    assert "K-run 1 after WO-K2" in md
    assert md.count("False-positive = DRAFTs") == 1, "the legend must appear once"

    runs = json.loads(json_out.read_text(encoding="utf-8"))["k_runs"]
    assert [r["label"] for r in runs] == ["K-run 0 baseline", "K-run 1 after WO-K2"]


def test_the_run_record_names_the_baseline_and_the_knowledge_versions(ev, tmp_path):
    """K-run 0 must be reproducible: HEAD, label and knowledge versions recorded."""
    case = _case(tmp_path, [_finding("F-1", ["T1059.001"], AUDIT_ATTACK)])
    cases_root = Path(ev.cases_root())
    (tmp_path / case.name).rename(cases_root / case.name)

    manifest = _manifest(tmp_path, [{"sha256": ATTACK, "techniques": ["T1059.001"]}])
    rc = ev.main([
        "--manifest", str(manifest), "--score-only", "--cases", case.name,
        "--modes", "1", "--label", "K-run 0 baseline",
        "--json-out", str(tmp_path / "a.json"), "--md-out", str(tmp_path / "A.md"),
    ])
    assert rc == 0
    record = json.loads((tmp_path / "a.json").read_text(encoding="utf-8"))["k_runs"][0]
    assert record["label"] == "K-run 0 baseline"
    assert record["head"]
    assert "skills" in record["knowledge"] or "skills_error" in record["knowledge"]
    assert record["leak_ok"] is True
    md = (tmp_path / "A.md").read_text(encoding="utf-8")
    assert "## K-runs" in md and "K-run 0 baseline" in md
