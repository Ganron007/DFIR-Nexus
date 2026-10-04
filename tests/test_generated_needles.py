"""WO-K4 part 3 — generated needle packs, and the retirement of evtx_attack_samples.

Two requirements:

* the pack is **generated** from the synced structured sources with **a source and
  a date per term**, and `--check` fails when it is stale;
* `evtx_attack_samples.yaml` is **retired** and its consumers updated.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
PACK = REPO / "src" / "nexus" / "data" / "knowledge" / "needles" / "generated_needles.yaml"
RETIRED = REPO / "src" / "nexus" / "data" / "knowledge" / "needles" / "evtx_attack_samples.yaml"


@pytest.fixture(scope="module")
def gen():
    spec = importlib.util.spec_from_file_location(
        "generate_needles_under_test", REPO / "scripts" / "generate_needles.py"
    )
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["generate_needles_under_test"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _pack() -> dict:
    assert PACK.is_file(), f"the generated pack is missing: {PACK}"
    return yaml.safe_load(PACK.read_text(encoding="utf-8")) or {}


# ---------------------------------------------------------------------------
# the generated pack carries provenance per term
# ---------------------------------------------------------------------------

def test_every_term_carries_a_source_and_a_date():
    """The work order's requirement, asserted over the whole pack."""
    terms = _pack().get("terms") or []
    assert len(terms) >= 100, f"only {len(terms)} terms were generated"
    without_source = [t for t in terms if not str(t.get("source") or "").strip()]
    without_date = [t for t in terms if not str(t.get("date") or "").strip()]
    assert without_source == [], f"{len(without_source)} term(s) have no source"
    assert without_date == [], f"{len(without_date)} term(s) have no date"


def test_dates_are_real_dates_not_a_wall_clock_stamp():
    """A single 'date' for every term would mean the date is meaningless.

    Real provenance has spread: the CVE dates come from each CVE's own
    `added_to_kev`, and the rest from the source file's last commit date.
    """
    dates = {str(t["date"]) for t in (_pack().get("terms") or [])}
    assert len(dates) > 1, f"every term shares one date {dates} - provenance is fake"
    for value in dates:
        assert len(value) == 10 and value[4] == "-" and value[7] == "-", value


def test_the_pack_names_its_sources():
    sources = _pack().get("sources") or {}
    assert sources, "the pack must name where its terms came from"
    for name, body in sources.items():
        assert isinstance(body, dict), name
        assert str(body.get("url") or "").strip(), f"{name} has no url"
        assert isinstance(body.get("date"), str), name


def test_it_is_generated_and_says_so():
    body = _pack()
    assert body.get("generator") == "scripts/generate_needles.py"
    assert "do not edit" in str(body.get("note") or "").lower()


def test_the_pack_is_technique_keyed_for_its_consumers():
    """Shaped like the retired pack so consumers keep working."""
    packs = _pack().get("packs") or []
    assert packs
    for pack in packs[:20]:
        assert str(pack.get("technique") or "").startswith("T"), pack
        assert isinstance(pack.get("events"), list), pack
        for event in pack["events"][:3]:
            assert isinstance(event.get("fields"), dict), event


# ---------------------------------------------------------------------------
# the generator is reproducible and self-checking
# ---------------------------------------------------------------------------

def test_the_pack_on_disk_is_current(gen):
    """`--check` must pass on a freshly generated pack, or it is not useful."""
    payload = gen.build_payload()
    on_disk = _pack()
    assert gen._comparable(on_disk) == gen._comparable(payload), (
        "generated_needles.yaml is stale - re-run scripts/generate_needles.py"
    )


def test_check_mode_detects_a_stale_pack(tmp_path, gen, monkeypatch):
    """A stale pack must fail the check rather than pass quietly."""
    stale = tmp_path / "generated_needles.yaml"
    stale.write_text("version: 1\nterms: []\n", encoding="utf-8")
    monkeypatch.setattr(gen, "OUT", stale)
    assert gen.main(["--check"]) == 1


def test_check_mode_passes_on_a_fresh_pack(tmp_path, gen, monkeypatch):
    payload = gen.build_payload()
    fresh = tmp_path / "generated_needles.yaml"
    fresh.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    monkeypatch.setattr(gen, "OUT", fresh)
    assert gen.main(["--check"]) == 0


def test_the_generated_at_stamp_is_excluded_from_the_comparison(gen):
    """Otherwise every run would differ and `--check` could never pass."""
    payload = gen.build_payload()
    other = dict(payload, generated="1999-01-01T00:00:00+00:00")
    assert gen._comparable(payload) == gen._comparable(other)


def test_the_generator_refuses_to_write_nothing(gen, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(gen, "build_payload", lambda: {"terms": [], "packs": []})
    monkeypatch.setattr(gen, "OUT", tmp_path / "out.yaml")
    assert gen.main([]) == 2
    assert not (tmp_path / "out.yaml").exists()


def test_running_the_generator_is_idempotent(gen):
    """Two builds over the same sources must be comparable."""
    first = gen.build_payload()
    second = gen.build_payload()
    assert gen._comparable(first) == gen._comparable(second)


# ---------------------------------------------------------------------------
# the retirement
# ---------------------------------------------------------------------------

def test_evtx_attack_samples_is_retired():
    assert not RETIRED.exists(), (
        "evtx_attack_samples.yaml is retired by WO-K4 - it was built from an "
        "outdated sample corpus and carried no per-term provenance"
    )


def test_no_code_still_calls_the_retired_loader():
    """Only prose may mention it; a call site would be a live break."""
    offenders: list[str] = []
    for pattern in ("*.py",):
        for path in list((REPO / "src").rglob(pattern)) + list((REPO / "scripts").rglob(pattern)):
            if "generate_needles" in path.name:
                continue  # its own docstring explains the retirement
            text = path.read_text(encoding="utf-8", errors="replace")
            for line_no, line in enumerate(text.splitlines(), 1):
                if "get_evtx_attack_samples" in line:
                    offenders.append(f"{path.relative_to(REPO)}:{line_no}")
    assert offenders == [], f"still calling the retired loader: {offenders}"


def test_the_replacement_is_exposed_and_usable():
    from nexus.knowledge.loader import get_generated_needle_terms, get_generated_needles

    packs = get_generated_needles()
    terms = get_generated_needle_terms()
    assert packs and terms
    # The technician filter the portal does must still work.
    hits = [p for p in packs if "T1059" in str(p.get("technique"))]
    assert hits, "no pack matches T1059 - the portal's technique filter would find nothing"


def test_the_retired_name_is_gone_from_the_loader():
    from nexus.knowledge import loader

    assert not hasattr(loader, "get_evtx_attack_samples"), (
        "the retired loader function should be removed, not left as a dead alias"
    )


def test_the_knowledge_version_manifest_tracks_the_new_pack():
    """The K-run record's knowledge versions must hash the pack that now exists."""
    text = (REPO / "scripts" / "eval_run.py").read_text(encoding="utf-8")
    assert "generated_needles.yaml" in text
    assert "evtx_attack_samples.yaml" not in text


def test_the_cli_check_runs_clean_end_to_end():
    """The real command, not just the function."""
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "generate_needles.py"), "--check"],
        cwd=str(REPO), capture_output=True, text=True, timeout=120, check=False,
    )
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-500:]
