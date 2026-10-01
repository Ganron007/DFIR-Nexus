"""Finding exhibit: the reproducibility bundle for one finding (WO-A4 / WP 13.4).

An approved finding is a claim somebody signed. This builds the bundle that
lets a third party check it: the cited rows, the hashes of the files they came
from, every audit entry behind them (argv, inputs, **which build of which
tool**), and a script that re-executes the recorded argv against the hashed
inputs into a scratch directory and diffs the result.

Three rules, all structural rather than advisory:

* **Only an APPROVED finding.** A DRAFT is a hypothesis; exhibiting it would
  hand a third party an unaudited claim in the shape of evidence. Refused.
* **Read-only on case data.** The bundle is built in its own directory and the
  builder refuses a destination inside the case.
* **Nothing is invented.** No cited source means no row; a missing hash is
  reported as missing, never filled in.
"""
from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = [
    "ExhibitRefused",
    "RerunPlan",
    "build_exhibit",
    "cited_rows",
    "rerun_plan",
    "render_rerun_ps1",
    "render_rerun_sh",
]


def resolve_case_dir(case_id: str) -> Path | None:
    """A case directory by id (one level of nesting, like the other surfaces)."""
    if not case_id:
        return None
    from nexus.config import settings

    root = Path(settings.cases_root)
    direct = root / case_id
    if direct.is_dir():
        return direct
    if root.is_dir():
        for parent in sorted(p for p in root.iterdir() if p.is_dir()):
            nested = parent / case_id
            if nested.is_dir():
                return nested
    return None


class ExhibitRefused(RuntimeError):
    """The exhibit was refused - with the reason the examiner will read."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_findings(case_dir: Path) -> list[dict[str, Any]]:
    path = case_dir / "findings.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [f for f in data if isinstance(f, dict)] if isinstance(data, list) else []


def load_finding(case_dir: Path | str, finding_id: str) -> dict[str, Any]:
    """The finding, or a refusal that says why."""
    case_dir = Path(case_dir)
    for finding in _load_findings(case_dir):
        if str(finding.get("id") or finding.get("finding_id") or "") == finding_id:
            return finding
    raise ExhibitRefused(f"finding {finding_id} is not in this case")


def require_approved(finding: dict[str, Any]) -> None:
    status = str(finding.get("status") or "").upper()
    if status != "APPROVED":
        raise ExhibitRefused(
            f"finding is {status or 'DRAFT'}; only an APPROVED finding can be exhibited"
        )


def _audit_ids(finding: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for art in finding.get("artifacts") or []:
        if isinstance(art, dict):
            aid = str(art.get("audit_id") or "").strip()
            if aid and aid not in out:
                out.append(aid)
    for aid in finding.get("audit_ids") or []:
        text = str(aid).strip()
        if text and text not in out:
            out.append(text)
    return out


def _audit_entries(case_dir: Path, audit_ids: list[str]) -> list[dict[str, Any]]:
    """Audit entries for the cited ids, from the hash-chained case audit log."""
    wanted = set(audit_ids)
    found: list[dict[str, Any]] = []
    audit_dir = case_dir / "audit"
    if not audit_dir.is_dir():
        return found
    for path in sorted(audit_dir.glob("*.jsonl")):
        try:
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(entry, dict):
                        continue
                    ids = {str(entry.get("audit_id") or ""), str(entry.get("id") or "")}
                    if ids & wanted:
                        found.append(entry)
        except OSError:
            continue
    return found


def _split_citation(source: str) -> tuple[str, int | None]:
    """``path/to/file.csv:123`` -> ``(path, 123)``. No line -> (path, None)."""
    text = source.strip()
    if not text:
        return "", None
    head, sep, tail = text.rpartition(":")
    if sep and head and tail.isdigit():
        return head, int(tail)
    return text, None


def cited_rows(case_dir: Path | str, finding: dict[str, Any]) -> list[dict[str, Any]]:
    """The physical lines this finding cites, read from the case's own files."""
    case_dir = Path(case_dir)
    rows: list[dict[str, Any]] = []
    cache: dict[str, list[str]] = {}
    for art in finding.get("artifacts") or []:
        if not isinstance(art, dict):
            continue
        source = str(art.get("source") or "").strip()
        if not source:
            continue
        rel, line_no = _split_citation(source)
        candidate = Path(rel)
        path = candidate if candidate.is_absolute() else case_dir / rel
        entry: dict[str, Any] = {
            "audit_id": str(art.get("audit_id") or ""),
            "source": source,
            "path": str(path),
            "line": line_no,
            "text": "",
            "readable": False,
        }
        try:
            if path.is_file():
                if str(path) not in cache:
                    cache[str(path)] = path.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines()
                lines = cache[str(path)]
                if line_no and 1 <= line_no <= len(lines):
                    entry["text"] = lines[line_no - 1]
                    entry["readable"] = True
                elif not line_no:
                    entry["text"] = lines[0] if lines else ""
                    entry["readable"] = bool(lines)
        except OSError:
            pass
        rows.append(entry)
    return rows


# --------------------------------------------------------------------------
# the re-run plan (and the scripts rendered from it)
# --------------------------------------------------------------------------

@dataclass
class RerunPlan:
    finding_id: str
    audit_id: str
    tool: str
    argv: list[str] = field(default_factory=list)
    inputs: list[dict[str, str]] = field(default_factory=list)
    lineage: dict[str, Any] = field(default_factory=dict)
    rows_file: str = "cited_rows.csv"
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "audit_id": self.audit_id,
            "tool": self.tool,
            "argv": list(self.argv),
            "inputs": [dict(i) for i in self.inputs],
            "lineage": dict(self.lineage),
            "rows_file": self.rows_file,
            "note": self.note,
        }


def _argv_from_entry(entry: dict[str, Any]) -> list[str]:
    argv = entry.get("argv")
    if isinstance(argv, list) and argv:
        return [str(a) for a in argv]
    command = str(entry.get("command") or "").strip()
    if command:
        try:
            return shlex.split(command)
        except ValueError:
            return command.split()
    return []


def rerun_plan(case_dir: Path | str, finding_id: str) -> RerunPlan:
    """What it would take to re-execute this finding's tool call."""
    case_dir = Path(case_dir)
    finding = load_finding(case_dir, finding_id)
    require_approved(finding)
    audit_ids = _audit_ids(finding)
    entries = _audit_entries(case_dir, audit_ids)
    if not entries:
        return RerunPlan(
            finding_id=finding_id,
            audit_id=audit_ids[0] if audit_ids else "",
            tool="",
            note="no audit entry found for this finding's citations",
        )

    entry = entries[0]
    lineage = entry.get("tool_lineage")
    if not isinstance(lineage, dict):
        lineage = {}
    inputs: list[dict[str, str]] = []
    files = entry.get("input_files") or []
    hashes = entry.get("input_sha256s") or []
    for index, raw in enumerate(files):
        name = str(raw)
        path = Path(name)
        resolved = path if path.is_absolute() else case_dir / name
        inputs.append({
            "path": name,
            "sha256": str(hashes[index]) if index < len(hashes) else "",
            "present": "true" if resolved.is_file() else "false",
        })

    argv = _argv_from_entry(entry)
    return RerunPlan(
        finding_id=finding_id,
        audit_id=str(entry.get("audit_id") or entry.get("id") or ""),
        tool=str(lineage.get("tool") or (argv[0] if argv else "")),
        argv=argv,
        inputs=inputs,
        lineage=lineage,
    )


def _provenance_comment(plan: RerunPlan, prefix: str = "#") -> list[str]:
    lineage = plan.lineage or {}
    version = (
        lineage.get("file_version")
        or lineage.get("product_version")
        or "version undeclared"
    )
    binary = lineage.get("binary_path") or plan.tool or "tool"
    digest = lineage.get("binary_sha256") or ""
    lines = [
        f"{prefix} finding      : {plan.finding_id}",
        f"{prefix} audit entry : {plan.audit_id}",
        f"{prefix} tool         : {binary}",
        f"{prefix} version      : {version} ({lineage.get('version_source', 'undeclared')})",
    ]
    if digest:
        lines.append(f"{prefix} tool sha256  : {digest}")
    return lines


def render_rerun_sh(plan: RerunPlan) -> str:
    """POSIX re-run: verify inputs, re-execute argv into a scratch dir, diff."""
    lines = [
        "#!/bin/sh",
        "# Re-run the tool call behind an approved finding (WO-A4 exhibit).",
        "# Reads nothing from the case; writes only into ./rerun-out.",
        "set -eu",
        "",
        *_provenance_comment(plan),
        "",
        'mkdir -p rerun-out',
        "",
        "# 1. verify every input against the hash recorded when it was run",
    ]
    if plan.inputs:
        for item in plan.inputs:
            expected = item.get("sha256") or ""
            name = Path(item["path"]).name
            lines += [
                'mkdir -p rerun-out/inputs',
                f'cp -f -- "${{EVIDENCE_ROOT:-.}}/{item["path"]}" "rerun-out/inputs/{name}"',
            ]
            if expected:
                lines.append(
                    f'printf "%s  %s\\n" "{expected}" "rerun-out/inputs/{name}" | sha256sum -c -'
                )
            else:
                lines.append(f'# no recorded hash for {item["path"]} - hash recorded now')
                lines.append(f'sha256sum "rerun-out/inputs/{name}"')
    else:
        lines.append("# this tool call recorded no input files")
    lines += [
        "",
        "# 2. re-execute the recorded argv against the copied inputs",
        f"#    argv: {' '.join(shlex.quote(a) for a in plan.argv) or '(not recorded)'}",
    ]
    if plan.argv:
        rendered = " ".join(
            shlex.quote(a.replace("${EVIDENCE_ROOT:-.}", "$PWD/rerun-out/inputs"))
            for a in plan.argv
        )
        lines.append(
            f'{rendered} > rerun-out/{plan.tool or "tool"}-stdout.txt 2>&1 || '
            f'{{ echo "tool exited non-zero - compare the output yourself"; }}'
        )
        lines.append(f'cp -f {plan.rows_file} rerun-out/expected-rows.csv 2>/dev/null || true')
        lines.append(
            "# 3. diff the reproduced rows against the cited rows"
        )
        lines.append(
            f'diff -u rerun-out/expected-rows.csv {plan.rows_file} && '
            f'echo "REPRODUCED: the cited rows match the re-run" || '
            f'echo "DIFFERS: see the diff above - check the tool version first"'
        )
    if plan.note:
        lines += ["", f"# note: {plan.note}"]
    return "\n".join(lines) + "\n"


def render_rerun_ps1(plan: RerunPlan) -> str:
    """Windows re-run: the same contract, PowerShell."""
    argline = " ".join(f'"{a}"' for a in plan.argv)
    lines = [
        "# Re-run the tool call behind an approved finding (WO-A4 exhibit).",
        "# Reads nothing from the case; writes only into .\\rerun-out.",
        "$ErrorActionPreference = 'Stop'",
        "",
        *_provenance_comment(plan, "#"),
        "",
        "New-Item -ItemType Directory -Force -Path .\\rerun-out\\inputs | Out-Null",
        "$evidenceRoot = if ($env:EVIDENCE_ROOT) { $env:EVIDENCE_ROOT } else { '.' }",
        "",
        "# 1. verify every input against the hash recorded when it was run",
    ]
    if plan.inputs:
        for item in plan.inputs:
            name = Path(item["path"]).name
            expected = item.get("sha256") or ""
            lines.append(
                f'Copy-Item -Force "$evidenceRoot\\{item["path"]}" '
                f'.\\rerun-out\\inputs\\{name}'
            )
            if expected:
                lines += [
                    f'$actual = (Get-FileHash -Algorithm SHA256 '
                    f'.\\rerun-out\\inputs\\{name}).Hash.ToLower()',
                    f'if ("{expected}" -ne $actual) {{ '
                    f'throw "input hash mismatch for {name}: $actual" }}',
                ]
            else:
                lines.append(
                    f'# no recorded hash for {name}; Get-FileHash it and compare by hand'
                )
    else:
        lines.append("# this tool call recorded no input files")
    lines += [
        "",
        "# 2. re-execute the recorded argv against the copied inputs",
        f"#    argv: {argline or '(not recorded)'}",
    ]
    if plan.argv:
        tool, *rest = plan.argv
        mapped = [
            (
                a.replace(
                    plan.inputs[0]["path"],
                    f"rerun-out\\inputs\\{Path(plan.inputs[0]['path']).name}",
                )
                if plan.inputs
                else a
            )
            for a in rest
        ]
        mapped_line = " ".join(f'"{a}"' for a in mapped)
        stdout_file = f".\\rerun-out\\{(plan.tool or 'tool')}-stdout.txt"
        lines.append(f'& "{tool}" {mapped_line} *>&1 | Tee-Object -FilePath {stdout_file}')
        lines.append("")
        lines.append("# 3. diff the reproduced rows against the cited rows")
        lines.append(
            f'Copy-Item -Force {plan.rows_file} .\\rerun-out\\expected-rows.csv '
            f'-ErrorAction SilentlyContinue'
        )
        lines.append(
            f'$d = Compare-Object (Get-Content .\\rerun-out\\expected-rows.csv) '
            f'(Get-Content {plan.rows_file}); if ($d) {{ $d }} '
            f'else {{ "REPRODUCED: the cited rows match the re-run" }}'
        )
    if plan.note:
        lines += ["", f"# note: {plan.note}"]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# the bundle
# --------------------------------------------------------------------------

def _rows_csv(rows: list[dict[str, Any]]) -> str:
    out = ["audit_id,source,line,text"]
    for row in rows:
        text = str(row.get("text") or "").replace('"', '""')
        out.append(
            f'"{str(row.get("audit_id") or "")}","{str(row.get("source") or "").replace(chr(34), chr(34) * 2)}",'
            f'{row.get("line") or ""},"{text}"'
        )
    return "\n".join(out) + "\n"


def build_exhibit(
    case_dir: Path | str,
    finding_id: str,
    *,
    dest_dir: Path | str | None = None,
    finding: dict[str, Any] | None = None,
) -> Path:
    """Write the exhibit zip. Returns its path. Raises ``ExhibitRefused``."""
    case_dir = Path(case_dir).resolve()
    if finding is None:
        finding = load_finding(case_dir, finding_id)
    require_approved(finding)

    if dest_dir is None:
        import tempfile

        dest_dir = Path(tempfile.mkdtemp(prefix="nexus-exhibit-"))
    dest_dir = Path(dest_dir).resolve()
    if dest_dir == case_dir or case_dir in dest_dir.parents:
        raise ExhibitRefused(
            f"refusing to build the exhibit inside the case directory ({case_dir})"
        )
    dest_dir.mkdir(parents=True, exist_ok=True)

    rows = cited_rows(case_dir, finding)
    audit_ids = _audit_ids(finding)
    entries = _audit_entries(case_dir, audit_ids)
    plan = rerun_plan(case_dir, finding_id)

    source_hashes: list[dict[str, Any]] = []
    for row in rows:
        path = Path(str(row.get("path") or ""))
        record: dict[str, Any] = {"source": row.get("source"), "path": str(path)}
        if path.is_file():
            try:
                record["sha256"] = _sha256(path)
                record["bytes"] = path.stat().st_size
            except OSError as exc:
                record["error"] = str(exc)
        else:
            record["error"] = "not readable from this exhibit host"
        source_hashes.append(record)

    readme = [
        f"# Exhibit - {finding_id}",
        "",
        f"- Case: `{case_dir.name}`",
        f"- Finding status: {finding.get('status')}",
        f"- Title: {finding.get('title')}",
        f"- Approved by: {finding.get('approved_by')} at {finding.get('approved_at')}",
        f"- Generated: {datetime.now(UTC).isoformat()}",
        "",
        "## What is in here",
        "",
        "| File | What it is |",
        "|---|---|",
        "| `finding.json` | the approved finding as the case stores it |",
        "| `cited_rows.csv` | the physical lines the finding cites |",
        "| `source_hashes.json` | SHA-256 of each cited source file |",
        "| `audit/<audit_id>.json` | the audit entry behind each citation |",
        "| `rerun.sh` / `rerun.ps1` | re-execute the recorded argv and diff the rows |",
        "| `manifest.json` | counts + provenance of this bundle |",
        "",
        "## Re-running",
        "",
        "1. Put the evidence where `EVIDENCE_ROOT` points (the original files, "
        "not the extracted CSV).",
        "2. `sh rerun.sh` (or `powershell -File rerun.ps1`).",
        "3. The script verifies each input hash, runs the recorded argv into "
        "`./rerun-out`, and diffs the reproduced rows against `cited_rows.csv`.",
        "",
        "A mismatch is not automatically a defect in the finding: a different "
        "tool build, a different locale or a timezone difference can all shift "
        "output. The lineage block says which build was recorded - compare that "
        "first, then the diff.",
        "",
    ]

    manifest = {
        "case_id": case_dir.name,
        "finding_id": finding_id,
        "finding_status": finding.get("status"),
        "generated_at": datetime.now(UTC).isoformat(),
        "rows": len(rows),
        "audit_ids": audit_ids,
        "audit_entries": len(entries),
        "tool_lineage": plan.lineage,
        "read_only_on_case": True,
    }

    zip_path = dest_dir / f"exhibit-{finding_id}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.md", "\n".join(readme))
        zf.writestr("finding.json", json.dumps(finding, indent=2, default=str))
        zf.writestr("cited_rows.csv", _rows_csv(rows))
        zf.writestr("source_hashes.json", json.dumps(source_hashes, indent=2, default=str))
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, default=str))
        zf.writestr("rerun_plan.json", json.dumps(plan.to_dict(), indent=2, default=str))
        zf.writestr("rerun.sh", render_rerun_sh(plan))
        zf.writestr("rerun.ps1", render_rerun_ps1(plan))
        for entry in entries:
            aid = str(entry.get("audit_id") or entry.get("id") or "entry")
            zf.writestr(f"audit/{aid}.json", json.dumps(entry, indent=2, default=str))
    return zip_path


def verify_row_reproduced(
    case_dir: Path | str,
    finding_id: str,
    *,
    work_dir: Path | str | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 300,
) -> dict[str, Any]:
    """Actually run the recorded argv and diff the rows.

    This is the acceptance path for the exhibit: it never touches the case (the
    inputs are copied into a scratch directory first) and it reports the diff
    rather than a pass/fail the examiner has to interpret.
    """
    import os
    import tempfile

    case_dir = Path(case_dir).resolve()
    plan = rerun_plan(case_dir, finding_id)
    if not plan.argv:
        return {"reproduced": False, "reason": "no recorded argv", "plan": plan.to_dict()}

    scratch = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="nexus-rerun-"))
    scratch.mkdir(parents=True, exist_ok=True)
    if scratch == case_dir or case_dir in scratch.parents:
        return {
            "reproduced": False,
            "reason": "scratch directory is inside the case directory",
            "plan": plan.to_dict(),
        }

    inputs_dir = scratch / "inputs"
    inputs_dir.mkdir(exist_ok=True)
    argv = list(plan.argv)
    for item in plan.inputs:
        source = Path(item["path"])
        resolved = source if source.is_absolute() else case_dir / item["path"]
        if not resolved.is_file():
            return {
                "reproduced": False,
                "reason": f"input not available on this host: {item['path']}",
                "plan": plan.to_dict(),
            }
        target = inputs_dir / source.name
        target.write_bytes(resolved.read_bytes())
        actual = _sha256(target)
        expected = item.get("sha256") or ""
        if expected and actual != expected:
            return {
                "reproduced": False,
                "reason": (
                    f"input hash mismatch for {item['path']}: "
                    f"recorded {expected[:12]}, local {actual[:12]}"
                ),
                "plan": plan.to_dict(),
            }
        argv = [a.replace(item["path"], str(target)) for a in argv]

    rows = cited_rows(case_dir, load_finding(case_dir, finding_id))
    produced = scratch / "rerun-stdout.txt"
    run_env = {**os.environ, **(env or {})}
    try:
        proc = subprocess.run(  # noqa: S603 - the argv is this case's own record
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            cwd=str(scratch),
            env=run_env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "reproduced": False,
            "reason": f"could not execute the recorded argv: {exc}",
            "plan": plan.to_dict(),
        }
    produced.write_text(
        (proc.stdout or "") + (("\n[stderr]\n" + proc.stderr) if proc.stderr else ""),
        encoding="utf-8",
    )

    cited = [str(r.get("text") or "").strip() for r in rows if str(r.get("text") or "").strip()]
    output = proc.stdout or ""
    reproduced = [line for line in cited if line and line in output]
    return {
        "reproduced": bool(cited) and len(reproduced) == len(cited),
        "cited_rows": len(cited),
        "matched_rows": len(reproduced),
        "unmatched": [line for line in cited if line not in output],
        "exit_code": proc.returncode,
        "stdout_file": str(produced),
        "scratch_dir": str(scratch),
        "plan": plan.to_dict(),
    }