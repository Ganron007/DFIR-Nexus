"""D210 / D205: a family is its producing tool's, and its evidence class is read from its name whole.

CASE-C5B04D31's index (2026-10-15) held MemProcFS's output as ten families named by the hints its
own sub-folders matched (`json`, `csv`, `ntfs`, `prefetch`, `amcache`, ..., one named after the
memory image), 3.18 M memory rows the digest called host evidence; LogFileParser's NTFS bitmap
records were the BITS family; and the digest called PowerShell transcripts email for their "pst".
The paths below are the case's own.
"""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path("C:/cases/CASE-X/runs/RUN-1/extractions")
IMAGE = "memprocfs/SRL_Evidence-rd01-memory-39e55fe9.img"


@pytest.mark.parametrize("rel, family", [
    (f"{IMAGE}/forensic/json/timeline.json", "memprocfs"),
    (f"{IMAGE}/forensic/csv/timeline_prefetch.csv", "memprocfs"),
    (f"{IMAGE}/forensic/prefetch/0-SVCHOST.EXE-00F6E14D.pf.txt", "memprocfs"),
    (f"{IMAGE}/forensic/amcache/applications.txt", "memprocfs"),
    (f"{IMAGE}/forensic/ntfs/ntfs_files.txt", "memprocfs"),
    (f"{IMAGE}/handles.csv", "memprocfs"),
    ("logfileparser/LogFile_2026-10-11_16-36-43/LogFile_BitsInNonresidentBitMap.csv", "logfileparser"),
    # Families whose names were right stay as they were.
    ("bitsparser/bits.json", "bits"),
    ("amcache/amcache_DeviceContainers.csv", "amcache"),
    ("appcompat/appcompat.csv", "appcompat"),
    ("mftecmd-usn/usn.csv", "mftecmd"),
    ("srum/20261011150610_SrumECmd_AppResourceUseInfo_Output.csv", "srumecmd"),
    ("vol/windows.pslist.csv", "vol"),
    ("vol3/windows.netscan.csv", "vol"),
    ("hayabusa/evtx-timeline.csv", "hayabusa"),
    ("evtxecmd/20261011_EvtxECmd_Output.csv", "evtxecmd"),
    ("pstranscript/20221018-PowerShell_transcript.RD01.aE_Z6SSx.txt", "pstranscript"),
    ("email/Outlook-tdungan_shieldbase.com-1ef3b7ce.ost.csv", "email"),
    ("deepbluecli-security-0a1b2c3d.txt", "deepbluecli"),
])
def test_a_file_belongs_to_the_tool_that_wrote_its_folder(rel, family):
    from nexus.langgraph.query_pack import _family

    assert _family(ROOT / rel, ROOT) == family


def test_the_digest_reads_a_family_name_whole():
    from nexus.langgraph.case_digest import _classify

    classes = _classify(["pstranscript", "email", "pff-ost", "memprocfs", "vol", "zeek_conn",
                         "oauth_audit", "hayabusa"])
    assert classes["email"] == ["email", "pff-ost"]
    assert classes["memory"] == ["memprocfs", "vol"]
    assert classes["network"] == ["zeek_conn"]
    assert classes["linux"] == []
    assert classes["host"] == ["hayabusa", "oauth_audit", "pstranscript"]
