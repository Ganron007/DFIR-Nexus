"""WP 9.4 — synced upstream knowledge feeds (provenance + shape)."""
from __future__ import annotations

import re

from nexus.knowledge.loader import (
    get_attack_techniques,
    get_synced_entries,
    get_synced_source,
    synced_source_manifest,
)

_CITE = re.compile(r"^T\d{4}(\.\d{3})?$")


def test_manifest_lists_all_synced_sources():
    manifest = {m["name"]: m for m in synced_source_manifest()}
    for name in ("lolbas", "gtfobins", "wadcoms", "attack_techniques", "cisa_kev"):
        assert name in manifest, f"{name} not synced"
        assert manifest[name]["url"], f"{name} missing source url"
        assert manifest[name]["fetched"], f"{name} missing fetch date"
        assert int(manifest[name]["count"] or 0) > 0, f"{name} has no entries"


def test_every_feed_internally_consistent():
    for name in ("lolbas", "gtfobins", "wadcoms", "attack_techniques", "cisa_kev"):
        data = get_synced_source(name)
        entries = get_synced_entries(name)
        assert len(entries) == int(data.get("count") or 0), f"{name} count mismatch"


def test_lolbas_gtfobins_wadcoms_shape():
    lolbas = get_synced_entries("lolbas")
    assert any("certutil" in e.get("binary", "").lower() for e in lolbas)
    assert all(e.get("binary") for e in lolbas)

    gtfo = get_synced_entries("gtfobins")
    assert any(e.get("binary") == "curl" for e in gtfo)
    assert all(e.get("functions") for e in gtfo)

    wad = get_synced_entries("wadcoms")
    assert all(e.get("command") for e in wad)


def test_attack_techniques_cover_platforms():
    techs = get_attack_techniques()
    assert len(techs) > 500
    ids = {t.get("technique") for t in techs}
    assert "T1003.001" in ids and "T1059" in ids
    assert all(_CITE.match(str(t.get("technique"))) for t in techs)
    platforms = {p for t in techs for p in (t.get("platforms") or [])}
    for want in ("Windows", "Linux", "macOS"):
        assert want in platforms, f"missing platform {want}"
    matrices = {m for t in techs for m in (t.get("matrices") or [])}
    assert {"enterprise", "mobile", "ics"} <= matrices


def test_cisa_kev_shape():
    kev = get_synced_entries("cisa_kev")
    assert all(str(e.get("cve", "")).startswith("CVE-") for e in kev)
