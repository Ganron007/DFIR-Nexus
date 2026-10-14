"""D192: the egress anonymizer tokenizes identifiers, not dates or JSON escapes.

Measured on CASE-C5B04D31 (2026-10-14, Mode 1 run 5): of 3,330 HOST tokens, 248 were ``.exe``
and 56 ``.dll`` names (``powershell.exe`` became ``{{HOST_24}}``); 46 PATH tokens were dates
(``/01/1995``); 400 of 467 ACCT tokens were JSON escapes, relative paths or rule text. The model
then wrote ``HOST_21`` without braces, the restore missed it, and two DRAFTs carried the pseudonym.
"""
from __future__ import annotations

import json

from nexus.ingest.anonymize import Anonymizer, deanonymize


def _anon(text: str) -> tuple[str, dict[str, str]]:
    return Anonymizer().anonymize(text)


def test_internal_hosts_on_private_suffixes_are_still_tokenized():
    """A public-TLD rule would have let ``ws01.corp.local`` through: internal names use suffixes
    no registry lists (.local, .lan, .corp), so a dotted name stays a host by shape (D192)."""
    out, mapping = _anon("ws01.corp.local and fs02.office.lan and rd01.shieldbase.com")
    assert "corp.local" not in out and "office.lan" not in out and "shieldbase" not in out


def test_dates_are_not_paths_and_paths_still_are():
    out, mapping = _anon("seen 1/1/2022, /01/1995 and /usr/bin/curl")
    assert "1/1/2022," in out and "/01/1995" in out
    assert "/usr/bin/curl" not in out


def test_accounts_in_prose_and_in_json_are_tokenized():
    prose = r"logon by shieldbase\tdungan and RD01\SRLAdmin"
    out, mapping = _anon(prose)
    assert r"shieldbase\tdungan" in mapping and r"RD01\SRLAdmin" in mapping
    assert "tdungan" not in out and "SRLAdmin" not in out
    rows = json.dumps({"user": "shieldbase\\tdungan"})  # JSON text: the backslash is doubled
    out, _ = _anon(rows)
    assert "tdungan" not in out


def test_json_escapes_relative_paths_and_rule_text_are_not_accounts():
    text = json.dumps({"out": "0B80\n0C7C\n", "rule": "DET0593\nTechnique", "x": "\u0000s",
                       "sel": "4697\nselection1"})
    text += r" key SYSTEM\ControlSet001\Services and C:\x\Edge\Application\msedge.exe"
    out, mapping = _anon(text)
    assert not [k for k, v in mapping.items() if v.startswith("{{ACCT_")], mapping
    assert r"SYSTEM\ControlSet001\Services" in out


def test_a_token_written_without_braces_is_restored_and_only_known_tokens_are():
    _, mapping = _anon("host rd01.shieldbase.com")
    token = mapping["rd01.shieldbase.com"]
    bare = token.strip("{}")
    restored = deanonymize(f"on {token}, on {bare}. HOST_999 x{bare} {bare}9", mapping)
    assert restored == f"on rd01.shieldbase.com, on rd01.shieldbase.com. HOST_999 x{bare} {bare}9"


def test_a_restored_value_is_not_read_again_as_a_token():
    mapping = {"HOST_2 lab": "{{HOST_1}}", "real-two": "{{HOST_2}}"}
    assert deanonymize("{{HOST_1}}", mapping) == "HOST_2 lab"


def test_the_stream_restorer_never_restores_half_a_bare_token(tmp_path):
    from nexus.llm.egress import _StreamRestorer, _write_tokens

    (tmp_path / "analysis").mkdir()
    _write_tokens(tmp_path / "analysis" / "egress_tokens.json",
                  {"wrong.example.com": "{{HOST_2}}", "rd01.shieldbase.com": "{{HOST_21}}"})
    stream = _StreamRestorer(tmp_path)
    text = stream.push("on HOST_2") + stream.push("1 now") + stream.flush()
    assert text == "on rd01.shieldbase.com now"
