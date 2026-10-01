"""A4 (WP 13.4): lineage + the finding exhibit.

Lineage answers "which build wrote this row"; the exhibit answers "can you
reproduce it". Both are tested where they can lie: a real binary for the
version, a real audit chain for the argv, and a refusal for a DRAFT.
"""
from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

import pytest

from nexus.analysis.finding_exhibit import (
    ExhibitRefused,
    build_exhibit,
    cited_rows,
    render_rerun_ps1,
    render_rerun_sh,
    require_approved,
    rerun_plan,
    verify_row_reproduced,
)
from nexus.tools.lineage import (
    binary_lineage,
    clear_lineage_cache,
    interpreter_for,
    tool_version_lineage,
)

# --------------------------------------------------------------------------
# lineage
# --------------------------------------------------------------------------

def test_lineage_on_a_real_binary_has_a_version_and_caches():
    clear_lineage_cache()
    lineage = binary_lineage(sys.executable)
    assert len(lineage["binary_sha256"]) == 64
    assert lineage["binary_path"] == sys.executable
    # python.exe carries a version resource on Windows; elsewhere the hash is
    # still the identity and version_source says so rather than guessing
    assert lineage["version_source"] in {
        "pe-version-resource", "sha256-only", "script+interpreter",
    }
    if sys.platform == "win32":
        assert lineage["file_version"], lineage
        assert lineage["version_source"] == "pe-version-resource"

    again = binary_lineage(sys.executable)
    assert again == lineage  # cache hit returns the same answer

    if sys.platform == "win32":
        # The translation block is WORDs and its length counts WORDs. Reading it
        # as DWORDs walks past the block and yields the neighbouring resource
        # bytes - which still "looks like" a string, so pin the shape.
        import re

        assert re.match(r"^\d+(\.\d+)+", lineage["file_version"]), lineage["file_version"]


def test_lineage_refuses_to_guess_for_an_unknown_file(tmp_path):
    clear_lineage_cache()
    blob = tmp_path / "mystery.bin"
    blob.write_bytes(b"\x00\x01\x02")
    lineage = binary_lineage(blob)
    assert lineage["version_source"] == "sha256-only"
    assert lineage["file_version"] == "" and lineage["product_version"] == ""

    missing = binary_lineage(tmp_path / "not-there.exe")
    assert missing["version_source"] == "missing"
    assert missing["binary_sha256"] == ""


def test_script_lineage_names_its_interpreter(tmp_path):
    script = tmp_path / "parse.ps1"
    script.write_text("Get-ChildItem\n", encoding="utf-8")
    interpreter = interpreter_for(script)
    assert interpreter, "a .ps1 script must resolve its interpreter"
    assert interpreter.lower().endswith((".exe", "pwsh", "powershell"))
    lineage = binary_lineage(script)
    assert lineage["version_source"] in {"script+interpreter", "script-hash"}
    assert lineage["interpreter"]


def test_remote_tool_version_comes_from_its_own_flag():
    clear_lineage_cache()
    calls: list[str] = []

    def runner(command: str) -> str:
        calls.append(command)
        return "Volatility 3 Framework 2.26.2\n"

    lineage = tool_version_lineage("vol", host="sift-01", runner=runner)
    assert lineage["version_source"] == "tool-version-flag"
    assert "2.26.2" in lineage["file_version"]
    assert calls == ["vol --version"]

    # cached per host session: the probe does not run twice
    tool_version_lineage("vol", host="sift-01", runner=runner)
    assert len(calls) == 1


def test_remote_tool_version_is_undeclared_never_guessed():
    clear_lineage_cache()
    assert tool_version_lineage("some-tool")["version_source"] == "undeclared"

    def broken(command: str) -> str:
        raise RuntimeError("ssh: host unreachable")

    assert tool_version_lineage("vol", runner=broken)["version_source"] == "undeclared"
    assert tool_version_lineage("fls", runner=lambda _c: "")["version_source"] == "undeclared"


# --------------------------------------------------------------------------
# the exhibit
# --------------------------------------------------------------------------

@pytest.fixture()
def case_dir(tmp_path) -> Path:
    """A case with one APPROVED finding citing a real row + audit chain."""
    case = tmp_path / "CASE-EXHIBIT01"
    (case / "audit").mkdir(parents=True)
    (case / "extractions" / "wxtcmd").mkdir(parents=True)
    rows = case / "extractions" / "wxtcmd" / "Prefetch_Output.csv"
    rows.write_text(
        "Filename,Hash,RunCount\n"
        "POWERSHELL.EXE,A1B2C3D4,3\n"
        "RUNDLL32.EXE,E5F6A7B8,1\n",
        encoding="utf-8",
    )
    finding = {
        "id": "F-exhibit-001",
        "status": "APPROVED",
        "title": "powershell.exe ran from a temp directory",
        "approved_by": "examiner",
        "approved_at": "2026-10-01T00:00:00+00:00",
        "technique_ids": ["T1059.001"],
        "artifacts": [{
            "type": "audit",
            "audit_id": "audit-1",
            "value": "Prefetch row 2",
            "source": "extractions/wxtcmd/Prefetch_Output.csv:2",
        }],
    }
    (case / "findings.json").write_text(json.dumps([finding]), encoding="utf-8")
    entry = {
        "audit_id": "audit-1",
        "tool": "run_windows_command",
        "ts": "2026-10-01T00:00:00+00:00",
        "params": {"command": "PECmd -f memory.raw", "purpose": "prefetch"},
        "argv": [sys.executable, "-c", "print('POWERSHELL.EXE,A1B2C3D4,3')"],
        "input_files": [str(rows)],
        "input_sha256s": [
            __import__("hashlib").sha256(rows.read_bytes()).hexdigest()
        ],
        "tool_lineage": {
            "binary_path": sys.executable,
            "binary_sha256": "b" * 64,
            "file_version": "3.12.1",
            "product_version": "Python 3.12.1",
            "version_source": "pe-version-resource",
        },
    }
    (case / "audit" / "run_windows_command.jsonl").write_text(
        json.dumps(entry) + "\n", encoding="utf-8"
    )
    return case


def test_cited_rows_reads_the_physical_line(case_dir: Path):
    finding = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))[0]
    rows = cited_rows(case_dir, finding)
    assert len(rows) == 1
    assert rows[0]["readable"] is True
    assert rows[0]["line"] == 2
    assert rows[0]["text"] == "POWERSHELL.EXE,A1B2C3D4,3"


def test_rerun_plan_carries_argv_inputs_and_lineage(case_dir: Path):
    plan = rerun_plan(case_dir, "F-exhibit-001")
    assert plan.argv[0] == sys.executable
    assert plan.inputs and plan.inputs[0]["sha256"]
    assert plan.lineage["version_source"] == "pe-version-resource"
    assert "3.12.1" in plan.lineage["file_version"]

    sh = render_rerun_sh(plan)
    assert "sha256sum -c" in sh          # inputs verified, not trusted
    assert "rerun-out" in sh             # writes into a scratch dir
    assert "diff -u" in sh               # and diffs the reproduced rows
    assert "pe-version-resource" in sh   # the provenance of the version

    ps1 = render_rerun_ps1(plan)
    assert "Get-FileHash" in ps1
    assert "Compare-Object" in ps1
    assert "rerun-out" in ps1


def test_exhibit_zip_has_everything_a_third_party_needs(case_dir: Path, tmp_path):
    dest = tmp_path / "out"
    zip_path = build_exhibit(case_dir, "F-exhibit-001", dest_dir=dest)
    assert zip_path.is_file()
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
        assert {
            "README.md", "finding.json", "cited_rows.csv",
            "source_hashes.json", "manifest.json", "rerun_plan.json",
            "rerun.sh", "rerun.ps1", "audit/audit-1.json",
        } <= names
        cited = zf.read("cited_rows.csv").decode("utf-8")
        assert "POWERSHELL.EXE,A1B2C3D4,3" in cited
        hashes = json.loads(zf.read("source_hashes.json").decode("utf-8"))
        assert len(hashes[0]["sha256"]) == 64
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert manifest["read_only_on_case"] is True
        assert manifest["audit_entries"] == 1
        # the audit entry carries the argv AND the lineage
        entry = json.loads(zf.read("audit/audit-1.json").decode("utf-8"))
        assert entry["tool_lineage"]["version_source"] == "pe-version-resource"


def test_exhibit_is_refused_for_a_draft(case_dir: Path, tmp_path):
    findings = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    findings[0]["status"] = "DRAFT"
    (case_dir / "findings.json").write_text(json.dumps(findings), encoding="utf-8")

    with pytest.raises(ExhibitRefused) as err:
        build_exhibit(case_dir, "F-exhibit-001", dest_dir=tmp_path / "out")
    assert "APPROVED" in str(err.value)

    # and the bare guard says the same thing
    with pytest.raises(ExhibitRefused):
        require_approved({"status": "DRAFT"})


def test_exhibit_refuses_a_destination_inside_the_case(case_dir: Path):
    with pytest.raises(ExhibitRefused) as err:
        build_exhibit(case_dir, "F-exhibit-001", dest_dir=case_dir / "outputs")
    assert "inside the case" in str(err.value)


def test_rerun_reproduces_the_cited_row(case_dir: Path, tmp_path):
    """The acceptance path: the recorded argv re-run reproduces the cited row."""
    result = verify_row_reproduced(case_dir, "F-exhibit-001", work_dir=tmp_path / "work")
    assert result["reproduced"] is True, result
    assert result["cited_rows"] == 1
    assert result["matched_rows"] == 1
    # and nothing was written into the case
    assert sorted(p.name for p in (case_dir / "extractions" / "wxtcmd").iterdir()) == [
        "Prefetch_Output.csv"
    ]


def test_rerun_reports_an_input_hash_mismatch_instead_of_lying(case_dir: Path, tmp_path):
    rows = case_dir / "extractions" / "wxtcmd" / "Prefetch_Output.csv"
    rows.write_text("Filename,Hash,RunCount\nTAMPERED,X,0\n", encoding="utf-8")
    result = verify_row_reproduced(case_dir, "F-exhibit-001", work_dir=tmp_path / "work2")
    assert result["reproduced"] is False
    assert "hash mismatch" in result["reason"]


def test_missing_finding_is_a_refusal_not_a_crash(case_dir: Path, tmp_path):
    with pytest.raises(ExhibitRefused) as err:
        build_exhibit(case_dir, "F-does-not-exist", dest_dir=tmp_path / "out2")
    assert "not in this case" in str(err.value)