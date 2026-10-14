r"""A version written as a dotted quad is not an IPv4 indicator (2026-10-14).

CASE-C5B04D31's entity census listed 1.0.0.0 and 3.0.0.0 as IPv4 indicators; the rows were COM
registrations (``...\InprocServer32\1.0.0.0``), PowerShell module folders and a ``Revision`` value.
The census items became "IPv4 indicator observed" candidates the model had to address.
"""
from __future__ import annotations

from nexus.langgraph.ti_context import extract_iocs


def _ipv4(*texts: str) -> list[str]:
    return extract_iocs(list(texts))["ipv4"]


def test_a_version_key_or_folder_is_not_an_address():
    assert _ipv4(
        r'"HKLM\\SOFTWARE\\Classes\\CLSID\\{0F2CCD8E-7BCF-4F70-9379-CA9C16739489}\\InprocServer32\\1.0.0.0"',
        r"\1\Windows\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.LocalAccounts\1.0.0.0",
        r"\1\$_ORPHAN\3.0.0.0",
    ) == []


def test_a_version_value_or_a_longer_version_is_not_an_address():
    assert _ipv4("Partition.evtx,/EventData/Data,Revision,string,1.0.0.0",
                 "FileVersion: 4.0.0.0", "build 6.3.0.0.17763") == []


def test_addresses_are_still_found_in_text_urls_and_unc_paths():
    found = _ipv4("SourceIp: 45.33.32.156 DestinationPort: 443",
                  "GET http://93.184.216.34/payload.bin",
                  r"net use \\185.199.108.153\share",
                  "TLS version 1.2 to 8.8.4.4")
    assert found == ["185.199.108.153", "45.33.32.156", "8.8.4.4", "93.184.216.34"]
