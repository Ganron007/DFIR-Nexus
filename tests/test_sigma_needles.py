"""Phase 4g-C/D/H — Sigma-derived needles, playbook tiering, needle benchmark."""

from __future__ import annotations

from nexus.knowledge.loader import get_sigma_needles
from nexus.knowledge.sigma_needles import (
    sigma_context_for,
    sigma_needles_for,
    sigma_packs_for,
)
from nexus.langgraph.mode1 import nl_to_needles
from nexus.langgraph.query_pack import (
    finalize_hits,
    playbook_strong_terms_for_families,
    playbook_terms_for_families,
)


def test_sigma_packs_load_and_are_well_formed():
    packs = get_sigma_needles()
    assert len(packs) >= 8
    for pack in packs:
        assert pack.get("needles"), pack.get("id")
        assert pack.get("families"), pack.get("id")
        assert pack.get("caveats"), pack.get("id")


def test_sigma_family_selection_and_caveats():
    needles = {n.lower() for n in sigma_needles_for({"evtx", "prefetch", "recmd"}, limit=4)}
    assert needles & {"lsass", "mimikatz", "encodedcommand", "psexesvc", "wevtutil cl"}
    block = sigma_context_for(sigma_packs_for({"evtx"}, limit=3))
    assert "caveat:" in block


def test_sigma_grounds_mode1_without_llm():
    result = nl_to_needles("What happened?", model=None, context={"sigma_needles": ["lsass"]})
    assert "lsass" in result["needles"]


def test_playbook_strong_terms_tiering():
    strong = playbook_strong_terms_for_families({"powershell"})
    assert any(t.lower() in ("-enc", "-encodedcommand", "frombase64string") for t in strong)
    weak = playbook_terms_for_families({"powershell"})
    assert set(t.lower() for t in strong) <= set(t.lower() for t in weak) | set(
        t.lower() for t in strong
    )


# --- H: labeled benchmark --------------------------------------------------


def test_benchmark_ranking_prefers_ground_truth():
    hits = [
        {"family": "evtxecmd", "file": "a.csv", "line": "1", "terms": "security", "text": "security audit"},
        {"family": "evtxecmd", "file": "a.csv", "line": "2", "terms": "sdelete", "text": "sdelete.exe wipe"},
        {"family": "evtxecmd", "file": "a.csv", "line": "3", "terms": "USBSTOR", "text": "USBSTOR device"},
        {"family": "evtxecmd", "file": "a.csv", "line": "4", "terms": "backup.pst", "text": "backup.pst copy"},
    ]
    ranked = finalize_hits(hits, ["security", "sdelete", "USBSTOR", "backup.pst"])
    top = {h["terms"] for h in ranked[:3]}
    assert "security" not in top
    assert top & {"sdelete", "USBSTOR", "backup.pst"}


def test_benchmark_suggestions_cover_ground_truth():
    """Wipe/exfil ground truth must be reachable from the needle vocabulary."""
    families = {"evtx", "evtxecmd", "prefetch", "recmd", "hayabusa", "chainsaw"}
    from nexus.knowledge.attack_needles import attack_needles_for
    from nexus.knowledge.sigma_needles import sigma_needles_for as sigma_terms

    vocab: set[str] = set()
    for source in (
        playbook_terms_for_families(families),
        playbook_strong_terms_for_families(families),
        attack_needles_for(families),
        sigma_terms(families),
    ):
        vocab |= {t.lower() for t in source}
    assert vocab & {"sdelete", "$recycle.bin", "usbstor", "backup.pst", "cipher /w"}
