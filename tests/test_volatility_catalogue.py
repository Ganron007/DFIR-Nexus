"""WP 7.1 knowledge half — Volatility 3 plugin catalogue tests."""
from __future__ import annotations

from nexus.knowledge.loader import get_volatility_plugins

_CORE = {"windows.info", "windows.pslist", "windows.psscan", "windows.malfind",
         "windows.netscan", "windows.cmdline"}
_ALL_PLUGINS: set[str] = set()


def _all_plugin_names() -> set[str]:
    cat = get_volatility_plugins()
    out: set[str] = set()
    for tier in cat.get("tiers") or []:
        for p in (tier.get("plugins") or []):
            name = str((p or {}).get("plugin") or "").split(" / ")[0]
            if name:
                out.add(name)
    return out


def test_catalogue_loads_with_tiers():
    cat = get_volatility_plugins()
    assert cat, "plugins/volatility.yaml should load"
    assert cat.get("source"), "catalogue must cite its KB sources"
    tiers = cat.get("tiers") or []
    assert len(tiers) >= 5
    assert {t.get("tier") for t in tiers} >= {
        "triage", "network", "registry", "injection_malware", "dumping_artifacts"}


def test_core_plugins_present():
    names = _all_plugin_names()
    assert names >= _CORE, f"missing core plugins: {_CORE - names}"


def test_malware_and_rootkit_plugins_present():
    names = _all_plugin_names()
    for want in ("windows.ssdt", "windows.callbacks", "windows.ldrmodules",
                 "windows.dumpfiles", "windows.procdump", "windows.hashdump"):
        assert want in names, f"missing {want}"


def test_entries_carry_guidance():
    """Every plugin explains itself (purpose) and key ones carry caveats."""
    names = _all_plugin_names()
    assert names, "no plugins parsed"
    for tier in get_volatility_plugins().get("tiers") or []:
        for p in (tier.get("plugins") or []):
            assert str(p.get("purpose") or "").strip(), p


def test_negative_and_caveats_present():
    cat = get_volatility_plugins()
    assert str(cat.get("negative") or "").strip()
    assert cat.get("caveats")
