"""WO-K1 — the manifest builder's three "easy to get wrong" rules.

These are the rules that decide whether a score means anything:

* the labelling directory is never staged (it *is* the answer);
* the attacker's own host is never staged;
* **unlabelled is not benign** — declaring it so would score a correct
  detection as a false positive;
* a labelled file is staged even when it exceeds the size cap;
* window-derived labels are marked, so a reviewer can exclude them;
* an unmapped attack step is reported, never silently dropped.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def km():
    spec = importlib.util.spec_from_file_location("k1_manifest_under_test",
                                                 REPO / "scripts" / "k1_manifest.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["k1_manifest_under_test"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _testbed(tmp_path: Path, *, big_unlabelled: bool = False) -> Path:
    """A miniature testbed laid out the way AIT-LDS is."""
    root = tmp_path / "testbed"
    # The attacker's host: the schedule and the attacker's own tooling output.
    (root / "gather" / "attacker_0" / "logs").mkdir(parents=True)
    (root / "gather" / "attacker_0" / "logs" / "attacks.log").write_text(
        "2022-01-24 03:01:00 vpn_connect\n", encoding="utf-8"
    )
    (root / "gather" / "attacker_0" / "logs" / "traffic.json").write_text(
        "{}", encoding="utf-8"
    )
    # A labelled host with one attack log and one ordinary log.
    (root / "gather" / "vpn" / "logs").mkdir(parents=True)
    (root / "gather" / "vpn" / "logs" / "openvpn.log").write_text(
        "vpn login\n", encoding="utf-8"
    )
    (root / "gather" / "vpn" / "logs" / "syslog").write_text(
        "ordinary\n", encoding="utf-8"
    )
    # A monitoring host whose labels come from a time window.
    (root / "gather" / "monitoring" / "logs" / "logstash").mkdir(parents=True)
    (root / "gather" / "monitoring" / "logs" / "logstash" / "cpu.log").write_text(
        "cpu 1.0\n", encoding="utf-8"
    )
    # A host with no labels at all.
    (root / "gather" / "mail" / "logs").mkdir(parents=True)
    (root / "gather" / "mail" / "logs" / "mail.log").write_text("mail\n", encoding="utf-8")
    # The ground truth.
    (root / "labels" / "vpn" / "logs").mkdir(parents=True)
    (root / "labels" / "vpn" / "logs" / "openvpn.log").write_text(
        json.dumps({"line": 1, "labels": ["attacker_vpn", "foothold"]}) + "\n",
        encoding="utf-8",
    )
    (root / "labels" / "monitoring" / "logs" / "logstash").mkdir(parents=True)
    (root / "labels" / "monitoring" / "logs" / "logstash" / "cpu.log").write_text(
        json.dumps({"line": 1, "labels": ["crack_passwords", "escalate"]}) + "\n",
        encoding="utf-8",
    )
    (root / "labels" / "unknown").mkdir(parents=True)
    (root / "labels" / "unknown" / "mystery.log").write_text(
        json.dumps({"line": 1, "labels": ["brand_new_attack_step"]}) + "\n",
        encoding="utf-8",
    )
    if big_unlabelled:
        (root / "gather" / "vpn" / "logs" / "huge.log").write_text("x" * 2_000_000, encoding="utf-8")
    return root


def _run(km, testbed: Path, stage: Path, **kw):
    argv = ["--kind", "aitlds", "--testbed", str(testbed), "--stage", str(stage)]
    for key, value in kw.items():
        argv += [f"--{key.replace('_', '-')}", str(value)]
    assert km.main(argv) == 0
    return json.loads((stage / "manifest.json").read_text(encoding="utf-8"))


def test_the_labelling_directory_is_never_staged(km, tmp_path):
    manifest = _run(km, _testbed(tmp_path), tmp_path / "stage")
    paths = [e["path"] for e in manifest["entries"]]
    assert paths, "the testbed should stage something"
    assert not any("label" in p.lower() for p in paths), paths
    # Compare relative to the evidence root: the temp directory name itself can
    # contain "label" (as in this test's own name), which would fake a failure.
    evidence = tmp_path / "stage" / "evidence"
    staged = [str(p.relative_to(evidence)) for p in evidence.rglob("*")]
    assert not any("label" in p.lower() for p in staged), staged


def test_the_attacker_host_is_never_staged(km, tmp_path):
    """`attacks.log` is the schedule; the attacker's host is the operator's side."""
    manifest = _run(km, _testbed(tmp_path), tmp_path / "stage")
    assert not any(e["host"] == "attacker_0" for e in manifest["entries"])
    assert not any("attacker_0" in e["path"] for e in manifest["entries"])
    assert not (tmp_path / "stage" / "evidence" / "attacker_0").exists()


def test_unlabelled_files_are_not_declared_benign(km, tmp_path):
    """Unlabelled is not clean - it just has no expectation.

    Marking it benign would make the scorer count a *correct* finding on it as a
    false positive.
    """
    manifest = _run(km, _testbed(tmp_path), tmp_path / "stage")
    roles = {e["role"] for e in manifest["entries"]}
    assert "benign" not in roles, f"no AIT-LDS entry may be called benign: {roles}"
    by_path = {e["path"]: e for e in manifest["entries"]}
    # The ordinary syslog on a labelled host has no label file -> unlabelled.
    assert by_path["vpn/logs/syslog"]["role"] == "unlabelled"
    assert by_path["vpn/logs/syslog"]["techniques"] == []
    # And the labelled one is attack.
    assert by_path["vpn/logs/openvpn.log"]["role"] == "attack"


def test_the_expected_techniques_come_from_the_labels(km, tmp_path):
    manifest = _run(km, _testbed(tmp_path), tmp_path / "stage")
    by_path = {e["path"]: e for e in manifest["entries"]}
    vpn = by_path["vpn/logs/openvpn.log"]
    assert vpn["labels"] == ["attacker_vpn", "foothold"]
    assert vpn["techniques"] == ["T1133", "T1190"], vpn
    assert vpn["label_basis"] == "content"


def test_window_derived_labels_are_marked(km, tmp_path):
    """A CPU metric stream cannot evidence password cracking - say so."""
    manifest = _run(km, _testbed(tmp_path), tmp_path / "stage")
    by_path = {e["path"]: e for e in manifest["entries"]}
    cpu = by_path["monitoring/logs/logstash/cpu.log"]
    assert cpu["label_basis"] == "window"
    assert cpu["techniques"] == ["T1110.002", "T1548.003"]
    assert any("label_basis='window'" in c for c in manifest["caveats"])


def test_a_labelled_file_is_staged_even_over_the_cap(km, tmp_path):
    """The cap protects a case from unlabelled megafiles, never from evidence."""
    testbed = _testbed(tmp_path, big_unlabelled=True)
    manifest = _run(km, testbed, tmp_path / "stage", max_file_mb=1)
    by_path = {e["path"]: e for e in manifest["entries"]}
    # 2 MB unlabelled file: over the 1 MB cap -> skipped, and reported.
    assert "vpn/logs/huge.log" not in by_path
    assert manifest["counts"].get("skipped_over_cap") == 1
    # A labelled file is not subject to the cap.
    assert "vpn/logs/openvpn.log" in by_path


def test_an_unmapped_attack_step_is_reported_not_dropped(km, tmp_path, capsys):
    """An unmapped label must surface, or recall looks better than it is.

    The label file here belongs to a host that has no evidence at all, so it can
    only be caught by reading every label - which is the point.
    """
    _run(km, _testbed(tmp_path), tmp_path / "stage")
    mapping = json.loads((tmp_path / "stage" / "mapping.json").read_text(encoding="utf-8"))
    manifest = json.loads((tmp_path / "stage" / "manifest.json").read_text(encoding="utf-8"))
    assert "brand_new_attack_step" in mapping["unmapped_labels_seen"]
    assert "brand_new_attack_step" in capsys.readouterr().out
    assert "unknown/mystery.log" in manifest["labels_without_evidence"]


def test_flat_kind_declares_every_file_benign(km, tmp_path):
    """The clean baseline is where the false-positive rate is measured."""
    baseline = tmp_path / "baseline"
    (baseline / "evtx").mkdir(parents=True)
    (baseline / "evtx" / "security.evtx").write_text("log\n", encoding="utf-8")
    (baseline / "sysmon.evtx").write_text("log\n", encoding="utf-8")

    argv = ["--kind", "flat", "--testbed", str(baseline), "--stage", str(tmp_path / "s")]
    assert km.main(argv) == 0
    manifest = json.loads((tmp_path / "s" / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["entries"]) == 2
    assert {e["role"] for e in manifest["entries"]} == {"benign"}
    assert all(e["techniques"] == [] for e in manifest["entries"])


def test_a_non_empty_stage_is_refused(km, tmp_path, capsys):
    """Staging twice must not silently merge two manifests."""
    testbed = _testbed(tmp_path)
    stage = tmp_path / "stage"
    assert _run(km, testbed, stage) is not None
    argv = ["--kind", "aitlds", "--testbed", str(testbed), "--stage", str(stage)]
    assert km.main(argv) == 2
    assert "not empty" in capsys.readouterr().err
