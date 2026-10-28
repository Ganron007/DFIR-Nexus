"""Entity/needle hygiene: machine paths and schema labels must not leak.

Live report (2026-09-23): a Mode 1 scan surfaced `domain_user`,
`STUDY\\Github`, `CADRE-Platform\\DFIR-Nexus` — the DOMAIN\\user regex matched
every segment of the local repo path, and the scan vocabulary accepted
path-like tokens / entity-type labels as needles.
"""

from __future__ import annotations

import pytest

REPO_TEXT = r"copy C:\STUDY\Github\CADRE-Platform\DFIR-Nexus\Evidence-files\01-windows to D:\out"


def test_is_needle_like_filters_paths_labels_and_numbers():
    from nexus.langgraph.query_pack import is_needle_like

    assert not is_needle_like("STUDY\\Github")
    assert not is_needle_like("CADRE-Platform\\DFIR-Nexus")
    assert not is_needle_like("domain_user")
    assert not is_needle_like("21")       # stray short number
    assert not is_needle_like("123")
    assert not is_needle_like("C:\\Windows\\Temp")
    assert is_needle_like("4624")         # event IDs are first-class needles
    assert is_needle_like("1102")
    assert is_needle_like("powershell")
    assert is_needle_like("sdelete")
    assert is_needle_like("10.0.0.5")


@pytest.mark.parametrize("token", ["STUDY\\Github", "CADRE-Platform\\DFIR-Nexus", "domain_user"])
def test_live_leak_tokens_are_filtered(token):
    from nexus.langgraph.query_pack import is_needle_like

    assert not is_needle_like(token.lower())
