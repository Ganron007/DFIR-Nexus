"""WO-KL2b (5/6): SigmaHQ rules translated by program into `es:` analytics.

The WO: "translate the `process_creation`, `registry_*`, `file_event` and
`ps_script` rules whose fields map to our registry into `es:` behavioural
analytics. Use a program: pySigma with a custom field mapping to our
`fields.<Name>`, or an equivalent. Report the counts: translated, skipped (no
field), failed."

These assert the generated pack and that the product actually loads it.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
PACK = REPO / "src" / "nexus" / "data" / "knowledge" / "needles" / "sigma_analytics.yaml"
IMPORTER = REPO / "devtools" / "knowledge" / "sigma_import.py"


@pytest.fixture(scope="module")
def pack() -> dict:
    assert PACK.is_file(), "the Sigma pack is missing - run devtools/knowledge/sigma_import.py"
    return yaml.safe_load(PACK.read_text(encoding="utf-8")) or {}


def test_the_pack_is_generated_and_names_its_pinned_source(pack):
    assert pack.get("generator") == "devtools/knowledge/sigma_import.py"
    assert str(pack.get("source") or "").startswith("https://github.com/SigmaHQ/sigma")
    assert len(str(pack.get("source_version") or "")) == 40, "the snapshot must be pinned to a commit"
    assert pack.get("packs"), "the pack is empty"


def test_the_translated_count_is_reported_and_real(pack):
    """The WO asks for the counts, so the pack records them and they add up."""
    counts = pack.get("counts") or {}
    assert counts.get("translated"), counts
    assert counts["translated"] == len(pack["packs"])
    assert counts.get("rules", 0) >= counts["translated"]


def test_every_translated_rule_carries_a_sigma_citation(pack):
    for item in pack["packs"]:
        cite = item.get("citation") or {}
        assert cite.get("type") == "sigma", item.get("id")
        assert cite.get("id"), item.get("id")
        assert "SigmaHQ/sigma" in str(cite.get("ref") or ""), item.get("id")


def test_every_translated_query_is_valid_es_json(pack):
    """Each rule passed `validate_stored_query` when it was generated; re-checked here."""
    import sys as _sys

    _sys.path.insert(0, str(REPO / "src"))
    from nexus.knowledge.query_validation import validate_stored_query

    bad: list[str] = []
    for item in pack["packs"]:
        problems = validate_stored_query(item.get("es"), declared_families=item.get("families"),
                                         citation=item.get("citation"))
        if problems:
            bad.append(f"{item.get('id')}: {problems[0]}")
    assert bad == [], f"{len(bad)} invalid: {bad[:6]}"


def test_no_translated_rule_is_a_match_all(pack):
    """A rule that matches every row asserts nothing (the KR2b defect class)."""
    offenders = [i["id"] for i in pack["packs"] if (i.get("es") or {}) == {"match_all": {}}]
    assert offenders == [], offenders[:8]


def test_the_product_loads_both_packs():
    """The generated pack is not decoration: `analytics()` returns it too."""
    sys.path.insert(0, str(REPO / "src"))
    from nexus.analysis import behavioural_analytics as ba

    hand = ba.analytics(str(ba.PACK_PATH))
    sigma = ba.analytics(str(ba.SIGMA_PACK_PATH))
    combined = ba.analytics()
    assert len(hand) >= 36, len(hand)
    assert len(sigma) >= 500, f"only {len(sigma)} Sigma analytics loaded"
    assert len(combined) == len(hand) + len(sigma), (len(combined), len(hand), len(sigma))
    assert any(str(i.get("id", "")).startswith("sigma-") for i in combined)
    # And they are offered for the families they declare.
    offered = ba.analytics_for(["evtxecmd", "hayabusa", "security", "sysmon"])
    assert len(offered) > len(hand)


def test_a_translated_query_targets_a_real_field_not_free_text(pack):
    """The translation maps Sigma fields to our columns, so a clause is typed.

    Not every rule can (some legitimately fall back to `text`), but the majority
    must land on `fields.<column>` - that is the point of the field mapping.
    """
    typed = 0
    for item in pack["packs"]:
        blob = json.dumps(item.get("es"))
        if "fields." in blob:
            typed += 1
    assert typed > len(pack["packs"]) * 0.8, f"only {typed} of {len(pack['packs'])} are typed"


def test_no_query_value_is_an_object_repr(pack):
    """A Python object's `str()` must never become a search value.

    Found while building this pack: a Sigma `null` reached the emitter and
    `str(SigmaNull)` produced the literal `"<sigma.types.SigmaNull object at
    0x...>"`. That can never match real data - and because the text carries a memory
    address it also made `--check` drift on every run. Null is now skipped and
    counted; this guard keeps any object repr out.
    """
    import re

    offenders: list[str] = []
    for item in pack["packs"]:
        for value in re.findall(r'"value":\s*"([^"]*)"', json.dumps(item.get("es"))):
            if "object at 0x" in value or value.startswith("<sigma."):
                offenders.append(f"{item['id']}: {value[:60]}")
    assert offenders == [], offenders[:6]


def test_the_importer_is_reproducible():
    """`--check` proves the pack on disk is what the snapshot produces.

    Skipped with a reason when the SigmaHQ snapshot is absent (it is a large
    external clone, pointed at by NEXUS_KL2B_SNAPSHOTS).
    """
    proc = subprocess.run([sys.executable, str(IMPORTER), "--check"],
                          cwd=str(REPO), capture_output=True, text=True, timeout=600, check=False)
    out = proc.stdout + proc.stderr
    if "snapshot not found" in out:
        pytest.skip("SigmaHQ snapshot absent - set NEXUS_KL2B_SNAPSHOTS")
    assert proc.returncode == 0, out[-600:]
