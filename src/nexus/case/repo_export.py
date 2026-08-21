"""Export a DFIR-Nexus case into the git repo under a stable case tree.

Default root: ``<repo>/Docs/cases/<case_id>/``

Override with ``NEXUS_REPO_CASE_ROOT`` (absolute or relative to CWD/repo).

Layout::

    Docs/cases/<case_id>/
      CASE.yaml
      findings.json
      evidence.json
      ledger/_tool_lane_ledger.json
      reports/REPORT.md
      extractions/          # copied tool outputs (large CSVs sampled)
      sift/                # pulled from SIFT host when available
      analysis/snippets.md # heads of tool outputs for LLM / examiners
      INVENTORY.json       # full path+size map (including omitted large files)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Do not copy multi-hundred-MB CSVs into git; write a sample + pointer instead.
_MAX_COPY_BYTES = int(os.environ.get("NEXUS_REPO_CASE_MAX_FILE_BYTES", str(8 * 1024 * 1024)))
_SAMPLE_LINES = 80


def resolve_repo_case_root() -> Path:
    raw = (os.environ.get("NEXUS_REPO_CASE_ROOT") or "").strip()
    if raw:
        p = Path(raw)
        return p if p.is_absolute() else (Path.cwd() / p).resolve()
    # Prefer DFIR-Nexus repo Docs/cases
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file() and (parent / "Docs").is_dir():
            return (parent / "Docs" / "cases").resolve()
    return (Path.cwd() / "Docs" / "cases").resolve()


def _copy_or_sample(src: Path, dest: Path, inventory: list[dict[str, Any]]) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    size = src.stat().st_size if src.is_file() else 0
    entry: dict[str, Any] = {
        "source": str(src),
        "dest": str(dest),
        "bytes": size,
        "copied": False,
        "sampled": False,
    }
    if not src.is_file():
        inventory.append(entry)
        return
    if size <= _MAX_COPY_BYTES:
        shutil.copy2(src, dest)
        entry["copied"] = True
    else:
        # Sample text/CSV; pointer for binary
        sample = dest.with_name(dest.stem + "_sample" + dest.suffix)
        pointer = dest.with_suffix(dest.suffix + ".path.txt")
        try:
            text = src.read_text(encoding="utf-8", errors="replace").splitlines()
            sample.write_text(
                "\n".join(text[:_SAMPLE_LINES])
                + f"\n\n# ... truncated sample of {len(text)} lines / {size} bytes ...\n"
                + f"# full file: {src}\n",
                encoding="utf-8",
            )
            entry["sampled"] = True
            entry["dest"] = str(sample)
        except OSError:
            pass
        pointer.write_text(f"{src}\nbytes={size}\n", encoding="utf-8")
        entry["pointer"] = str(pointer)
    inventory.append(entry)


def live_case_is_in_repo(case_dir: Path) -> bool:
    """True when the live case already lives under this git repo (no sample mirror)."""
    case_dir = Path(case_dir).resolve()
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file() and (parent / "Docs").is_dir():
            try:
                case_dir.relative_to(parent.resolve())
                return True
            except ValueError:
                return False
    return False


def export_case_to_repo(
    case_dir: Path,
    *,
    report_markdown: str | None = None,
    extra_sift_dir: Path | None = None,
) -> Path:
    """Mirror case artifacts into the repo case tree. Returns export root."""
    case_dir = Path(case_dir)
    case_id = case_dir.name
    root = resolve_repo_case_root() / case_id
    root.mkdir(parents=True, exist_ok=True)

    inventory: list[dict[str, Any]] = []

    for name in ("CASE.yaml", "findings.json", "evidence.json", "timeline.json"):
        src = case_dir / name
        if src.is_file():
            shutil.copy2(src, root / name)
            inventory.append({"source": str(src), "dest": str(root / name), "copied": True})

    ledger_src = case_dir / "extractions" / "_tool_lane_ledger.json"
    if ledger_src.is_file():
        led = root / "ledger"
        led.mkdir(exist_ok=True)
        shutil.copy2(ledger_src, led / "_tool_lane_ledger.json")

    ext_src = case_dir / "extractions"
    ext_dst = root / "extractions"
    if ext_src.is_dir():
        for path in ext_src.rglob("*"):
            if not path.is_file():
                continue
            if path.name.startswith("_") and path.suffix == ".json":
                rel = path.relative_to(ext_src)
                dest = ext_dst / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, dest)
                continue
            rel = path.relative_to(ext_src)
            _copy_or_sample(path, ext_dst / rel, inventory)

    if extra_sift_dir and Path(extra_sift_dir).is_dir():
        sift_dst = root / "sift"
        for path in Path(extra_sift_dir).rglob("*"):
            if path.is_file():
                rel = path.relative_to(extra_sift_dir)
                _copy_or_sample(path, sift_dst / rel, inventory)

    reports = root / "reports"
    reports.mkdir(exist_ok=True)
    # Prefer explicit markdown; else copy existing dfir-report.md
    if report_markdown:
        (reports / "REPORT.md").write_text(report_markdown, encoding="utf-8")
    else:
        for candidate in (
            case_dir / "reports" / "REPORT.md",
            case_dir / "reports" / "dfir-report.md",
        ):
            if candidate.is_file():
                shutil.copy2(candidate, reports / "REPORT.md")
                break

    snippets = case_dir / "analysis" / "snippets.md"
    if snippets.is_file():
        (root / "analysis").mkdir(exist_ok=True)
        shutil.copy2(snippets, root / "analysis" / "snippets.md")

    (root / "INVENTORY.json").write_text(
        json.dumps({"case_id": case_id, "files": inventory}, indent=2),
        encoding="utf-8",
    )
    (root / "README.md").write_text(
        f"# Case `{case_id}`\n\n"
        f"- Runtime case dir: `{case_dir}`\n"
        f"- Report: [reports/REPORT.md](reports/REPORT.md)\n"
        f"- Ledger: [ledger/_tool_lane_ledger.json](ledger/_tool_lane_ledger.json)\n"
        f"- Extractions: `extractions/` (large CSVs may be sampled — see INVENTORY.json)\n"
        f"- SIFT pull: `sift/`\n",
        encoding="utf-8",
    )
    log.info("Exported case %s -> %s", case_id, root)
    return root
