"""D241: the entities a claim names, as L1.3 and the cross-mode check read them.

Mode 3 run 4's DRAFT F-claudebot-017 failed L1.3 on `rd01-memory-39e55fe9.img`: the memory image
`SRL_Evidence-rd01-memory-39e55fe9.img` was read as a host name that started mid-token, and the index has no
such host. A file name is not a host, and a host name does not begin inside a longer token.
"""

from __future__ import annotations

from nexus.analysis.cross_mode import _entities


def test_an_evidence_file_name_is_not_a_host():
    text = "memory image named SRL_Evidence-rd01-memory-39e55fe9.img; mailbox Outlook-tdungan.ost"
    assert [e for e in _entities(text) if e[0] == "domain"] == []


def test_a_host_name_does_not_begin_inside_a_longer_token():
    assert [e for e in _entities("archive SRL_case-host01.example.com.zip") if e[0] == "domain"] == []


def test_host_names_in_claims_are_still_read():
    text = ("tdungan used wacsvc credentials toward cifs/dev01.shieldbase.com and wkstn01.shieldbase.com; "
            "WinRM to dc01.shieldbase.com/wsman; mail from admin@evil-c2.net")
    domains = {v for t, v in _entities(text) if t == "domain"}
    assert {"dev01.shieldbase.com", "wkstn01.shieldbase.com", "dc01.shieldbase.com", "evil-c2.net"} <= domains
