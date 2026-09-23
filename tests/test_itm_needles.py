"""ITM needle packs — hard artifacts only, family-gated, registry-valid ids."""

from __future__ import annotations

import re


def test_packs_are_valid_and_hard_artifacts_only():
    from nexus.knowledge.loader import get_itm_needles
    from nexus.langgraph.itm import itm_index

    data = get_itm_needles()
    packs = data.get("packs") or []
    assert len(packs) >= 10, len(packs)
    index = itm_index()
    for pack in packs:
        section = str(pack.get("itm") or "").split("/", 1)[-1]
        assert section in index, pack.get("itm")
        assert pack.get("families"), pack.get("name")
        assert pack.get("needles"), pack.get("name")
        assert pack.get("caveat"), pack.get("name")
        for needle in pack["needles"] + (pack.get("strong") or []):
            # Quality gate: no bare numbers / no schema-label words.
            assert not re.fullmatch(r"\d+", str(needle).strip()), needle


def test_family_selection_and_strong_terms():
    from nexus.knowledge.itm_needles import itm_needles_for, itm_strong_for

    staging = itm_needles_for({"prefetch"})
    assert "7z.exe" in staging
    assert "mega.nz" not in staging  # browser-only pack stays out

    web = itm_needles_for({"browser"})
    assert "mega.nz" in web

    strong = itm_strong_for({"evtxecmd", "hayabusa"})
    assert "vssadmin delete shadows" in strong
    assert "wevtutil cl" in strong

    assert itm_needles_for(set()) == []


def test_briefing_signal_map_sources_itm(tmp_path):
    from nexus.langgraph.briefing import _scan_needles

    chainsaw = _scan_needles(tmp_path, ["chainsaw"])
    assert chainsaw.get("mstsc.exe") == "itm"            # AR3/PR026
    assert chainsaw.get("clear-eventlog") == "itm-strong"  # AR5/AF002

    recmd = _scan_needles(tmp_path, ["recmd"])
    assert recmd.get("sc create") == "itm-strong"        # AR3/PR046

    web = _scan_needles(tmp_path, ["browser"])
    assert web.get("wetransfer.com") == "itm"            # AR4/IF001
