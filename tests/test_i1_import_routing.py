"""I1 keeps Windows-image files with host tools unless an importer confirms them."""

from nexus.langgraph.llm_pipeline import _i1_route


def test_unknown_windows_root_file_stays_with_host_lane(tmp_path):
    root = tmp_path / "image"
    (root / "Windows" / "System32").mkdir(parents=True)
    unknown = root / "Users" / "Public" / "desktop.ini"
    unknown.parent.mkdir(parents=True)
    unknown.write_text("[.ShellClassInfo]\n", encoding="utf-8")

    assert _i1_route(unknown, windows_root=root) == "host-unconfirmed"


def test_direct_file_registration_discovers_windows_root(tmp_path):
    evidence = tmp_path / "case" / "evidence"
    root = evidence / "_expanded" / "host" / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    unknown = root / "Users" / "Public" / "desktop.ini"
    unknown.parent.mkdir(parents=True)
    unknown.write_text("[.ShellClassInfo]\n", encoding="utf-8")

    assert _i1_route(unknown) == "host-unconfirmed"


def test_confirmed_log_inside_windows_root_reaches_importer(tmp_path):
    root = tmp_path / "image"
    (root / "Windows" / "System32").mkdir(parents=True)
    log = root / "logs" / "auth.log"
    log.parent.mkdir()
    log.write_text("Oct 10 10:00:00 host sshd[12]: Accepted publickey for user\n", encoding="utf-8")

    assert _i1_route(log, windows_root=root) == "importer"


def test_host_artifact_inside_windows_root_stays_with_host_lane(tmp_path):
    root = tmp_path / "image"
    logs = root / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    evtx = logs / "Security.evtx"
    evtx.write_bytes(b"EVTX")

    assert _i1_route(evtx) == "host"


def test_unrecognised_file_outside_windows_root_remains_visible_to_importer_lane(tmp_path):
    unknown = tmp_path / "misc" / "unknown.bin"
    unknown.parent.mkdir()
    unknown.write_bytes(b"opaque")

    assert _i1_route(unknown) == "importer"
