"""windows_registry importer: text exports only (raw hives are the N-lane's job)."""

from __future__ import annotations

REG_EXPORT = (
    "Windows Registry Editor Version 5.00\r\n\r\n"
    "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n"
    '"Updater"="C:\\\\Temp\\\\evil.exe"\r\n'
    '@="default 1"\r\n\r\n'
    "[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]\r\n"
    '"Shell"="explorer.exe"\r\n'
)


def test_can_handle_reg_export(tmp_path):
    from nexus.ingest.df.registry import WindowsRegistryImporter

    p = tmp_path / "run.reg"
    p.write_text(REG_EXPORT, encoding="utf-8")
    assert WindowsRegistryImporter.can_handle(p)


def test_can_handle_refuses_raw_hives(tmp_path):
    from nexus.ingest.df.registry import WindowsRegistryImporter

    for name in (
        "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT",
        "NTUSER.DAT", "UsrClass.dat", "Amcache.hve",
    ):
        f = tmp_path / name
        f.write_bytes(b"regf\x00\x00\x00\x00" + b"\x00" * 64)
        assert WindowsRegistryImporter.can_handle(f) is False, name


def test_parse_run_and_winlogon_keys(tmp_path):
    from nexus.ingest.df.registry import WindowsRegistryImporter

    p = tmp_path / "run.reg"
    p.write_text(REG_EXPORT, encoding="utf-8")
    arts = [a.to_dict() for a in WindowsRegistryImporter().parse(p)]
    assert len(arts) == 3  # Updater, (Default), Shell
    run = next(a for a in arts if a["registry_value"] == "Updater")
    assert run["source"] == "windows_registry"
    assert run["technique_ids"] == ["T1547.001"]
    assert run["severity"] == "high"
    assert run["ts_synthesized"] is True
    dflt = next(a for a in arts if a["registry_value"] == "(Default)")
    assert dflt["severity"] == "informational"
    shell = next(a for a in arts if a["registry_value"] == "Shell")
    assert shell["technique_ids"] == ["T1547.004"]


def test_utf16_reg_export(tmp_path):
    from nexus.ingest.df.registry import WindowsRegistryImporter

    p = tmp_path / "run.reg"
    p.write_bytes(REG_EXPORT.encode("utf-16"))
    assert WindowsRegistryImporter.can_handle(p)
    result = WindowsRegistryImporter().ingest(p)
    assert result.success
    assert any("evil.exe" in str(a.raw).lower() for a in result.artifacts)


def test_sam_names_key_extracted(tmp_path):
    from nexus.ingest.df.registry import WindowsRegistryImporter

    text = (
        "Windows Registry Editor Version 5.00\n\n"
        "[HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names\\fredr]\n"
        '@=hex(0):\n'
    )
    p = tmp_path / "sam.reg"
    p.write_text(text, encoding="utf-8")
    arts = [a.to_dict() for a in WindowsRegistryImporter().parse(p)]
    assert len(arts) == 1
    assert arts[0]["description"] == "SAM local account: fredr"
    assert arts[0]["technique_ids"] == ["T1087.001"]


def test_hive_not_claimed_and_ingest_hint(tmp_path):
    from nexus.ingest.detect import lane_routing_hint
    from nexus.ingest.registry import get_registry

    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"regf\x00\x00\x00\x00" + b"\x00" * 64)
    assert "RECmd" in (lane_routing_hint(hive) or "")
    result = get_registry().import_path(hive)
    assert not result.success
    assert any("RECmd" in e for e in result.errors)
