"""windows_registry importer: binary routing, SAM accounts, source tagging."""

from __future__ import annotations


def test_binary_routing_for_all_hive_names(tmp_path, monkeypatch):
    from nexus.ingest.df.registry import WindowsRegistryImporter

    imp = WindowsRegistryImporter()
    called: list[str] = []
    monkeypatch.setattr(imp, "_parse_binary", lambda p: called.append(str(p)) or iter(()))
    monkeypatch.setattr(imp, "_parse_text", lambda p: called.append("TEXT:" + str(p)) or iter(()))

    for name in ("SECURITY", "NTUSER.DAT", "UsrClass.dat", "DEFAULT", "SAM", "SYSTEM"):
        f = tmp_path / name
        f.write_bytes(b"regf\x00\x00\x00\x00")
        list(imp.parse(f))
    assert all(not c.startswith("TEXT:") for c in called), called
    assert len(called) == 6


def test_sam_user_artifact_fields(tmp_path):
    from nexus.ingest.df.registry import WindowsRegistryImporter

    hive = tmp_path / "SAM"
    hive.write_bytes(b"regf")
    a = WindowsRegistryImporter()._sam_user_artifact(
        "fredr", hive, r"ROOT\SAM\Domains\Account\Users\Names\fredr"
    ).to_dict()
    assert a["source"] == "windows_registry"
    assert a["artifact_type"] == "registry"
    assert a["description"] == "SAM local account: fredr"
    assert a["technique_ids"] == ["T1087.001"]
    assert a["ts_synthesized"] is True
    assert "sam" in a["tags"]


def test_registry_value_artifact_source(tmp_path):
    from nexus.ingest.df.registry import WindowsRegistryImporter

    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(b"regf")
    info = next(iter(WindowsRegistryImporter.INTERESTING_KEYS.values()))
    a = WindowsRegistryImporter()._make_registry_artifact(
        r"\Software\Microsoft\Windows\CurrentVersion\Run", "Updater", "C:\\x\\evil.exe", info, str(hive)
    ).to_dict()
    assert a["source"] == "windows_registry"
    assert a["severity"] == "high"
    assert a["registry_value"] == "Updater"
