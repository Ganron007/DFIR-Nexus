"""Scheduled-task definitions must be recognised, and recognised by content.

Found on the live real-corpus run, by the design monitor: 8 files under
`tasks/` were registered as evidence and never processed. They are the *anchor*
artifacts of the whole case plan - the task XML is what names the machine SID
and the S-1-5-21-... user, which is how the corpus was established as a merge of
two hosts in the first place.

Windows stores task definitions **with no file extension**, so a name-based
recogniser has nothing to match on. The only reliable signal is the document
itself, which arrives as UTF-16LE XML - every character followed by a NUL, so a
bytes sniff for `<Task` finds nothing either. Decoding first is what makes the
artefact visible at all.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus.langgraph.tool_lane import (
    _decode_head,
    _plan_single_artifact,
    _task_xml_kind,
    is_host_evidence,
)

TASK_XML = (
    '<?xml version="1.0" encoding="UTF-16"?>\r\n'
    '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\r\n'
    "  <RegistrationInfo><Author>CORP\\fredr</Author></RegistrationInfo>\r\n"
    "  <Principals><Principal id=\"Author\"><UserId>S-1-5-21-528816539-567677750-276746561-1002</UserId></Principal></Principals>\r\n"
    "  <Actions><Exec><Command>C:\\Users\\fredr\\AppData\\Local\\Temp\\payload.exe</Command>\r\n"
    "    <Arguments>-enc SQBFAFgA</Arguments></Exec></Actions>\r\n"
    "</Task>\r\n"
)


def _write_utf16(path: Path, text: str) -> Path:
    path.write_bytes(text.encode("utf-16"))       # emits the BOM, as Windows does
    return path


def _write_utf16le_no_bom(path: Path, text: str) -> Path:
    path.write_bytes(text.encode("utf-16-le"))
    return path


# ------------------------------------------------------------- the decoding

def test_utf16_head_decodes_so_the_task_element_is_visible(tmp_path):
    """Raw bytes contain every character interleaved with NUL, so sniffing fails."""
    f = _write_utf16(tmp_path / "T", TASK_XML)
    raw = f.read_bytes()
    assert b"<Task" not in raw, "raw bytes should not contain a plain <Task"
    assert "<Task" in _decode_head(f)


def test_a_utf16_file_without_a_bom_still_decodes(tmp_path):
    f = _write_utf16le_no_bom(tmp_path / "T", TASK_XML)
    assert "<Task" in _decode_head(f)


def test_utf8_and_ascii_files_are_left_alone(tmp_path):
    f = tmp_path / "plain.txt"
    f.write_text("hello world", encoding="utf-8")
    assert _decode_head(f) == "hello world"


# --------------------------------------------------------- the recognition

@pytest.mark.parametrize("writer", [_write_utf16, _write_utf16le_no_bom])
def test_a_task_definition_is_recognised_whatever_the_encoding(tmp_path, writer):
    """No extension to key on, so both UTF-16 forms must work."""
    f = writer(tmp_path / "Office Subscription Maintenance", TASK_XML)
    assert _task_xml_kind(f) == "task"
    assert is_host_evidence(f) is True


def test_a_task_definition_gets_a_job(tmp_path):
    f = _write_utf16(tmp_path / "GoogleUpdateTaskMachineUA", TASK_XML)
    jobs = _plan_single_artifact(f, tmp_path / "ex")
    assert jobs, "a recognised task definition must be scheduled"
    assert jobs[0].tool == "strings"
    # UTF-16 content needs the wide-string extractor or the Exec command and the
    # SID never make it out of the file.
    assert "-u" in jobs[0].argv, jobs[0].argv


def test_the_extracted_strings_carry_the_command_and_the_sid(tmp_path):
    """The point of staging it: the SID and Exec command must be reachable."""
    f = _write_utf16(tmp_path / "T", TASK_XML)
    head = _decode_head(f)
    assert "S-1-5-21-528816539-567677750-276746561-1002" in head
    assert "payload.exe" in head


# --------------------------------------------------------------- negatives

def test_a_plain_xml_file_is_not_a_task_definition(tmp_path):
    """Content, not extension: an unrelated XML document must not match."""
    f = tmp_path / "settings.xml"
    f.write_text('<?xml version="1.0"?><settings><a>1</a></settings>', encoding="utf-8")
    assert _task_xml_kind(f) == ""
    assert is_host_evidence(f) is False


def test_a_task_element_without_the_schema_is_refused(tmp_path):
    """`<Task` alone is too weak a signal to claim a file is a task definition."""
    f = tmp_path / "fake.xml"
    f.write_text('<?xml version="1.0"?><Task><name>x</name></Task>', encoding="utf-8")
    assert _task_xml_kind(f) == ""


def test_an_unreadable_path_is_refused_not_raised(tmp_path):
    assert _task_xml_kind(tmp_path / "missing") == ""
    assert _decode_head(tmp_path / "missing") == ""


def test_a_binary_blob_is_not_a_task_definition(tmp_path):
    f = tmp_path / "obj.DATA"
    f.write_bytes(bytes(range(256)) * 4)
    assert _task_xml_kind(f) == ""
    assert is_host_evidence(f) is False


# ------------------------------------------------ the real corpus artifacts

def test_the_real_corpus_task_files_are_recognised():
    """Run against the actual evidence when it is present, skip otherwise.

    This is the artifact the whole plan's provenance argument rests on: the task
    XML carries the machine identity that proves the corpus merges two hosts.
    """
    root = Path("Evidence-files/ES-Mapping/evidence/tasks")
    if not root.is_dir():
        pytest.skip("corpus not present")
    files = [f for f in root.rglob("*") if f.is_file()]
    assert files, "no task files in the corpus"
    recognised = [f for f in files if is_host_evidence(f)]
    assert len(recognised) == len(files), (
        f"{len(files) - len(recognised)} task file(s) still routed nowhere: "
        f"{[f.name for f in files if f not in recognised][:5]}"
    )


def test_a_recognised_task_file_yields_a_serialisable_job():
    """Whatever is scheduled must survive the ledger's JSON round trip."""
    root = Path("Evidence-files/ES-Mapping/evidence/tasks")
    if not root.is_dir():
        pytest.skip("corpus not present")
    f = next((x for x in root.rglob("*") if x.is_file()), None)
    if f is None:
        pytest.skip("no task file")
    jobs = _plan_single_artifact(f, Path("cases/_probe/extractions"))
    assert jobs
    json.dumps([{"tool": j.tool, "argv": j.argv, "purpose": j.purpose} for j in jobs])
