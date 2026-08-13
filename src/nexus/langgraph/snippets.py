"""Build bounded tool-output snippets for LLM interpretation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_MAX_PER_FILE = 6000
_MAX_TOTAL = 60000


def _head_text(path: Path, limit: int = _MAX_PER_FILE) -> str:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return f"(unreadable: {path})"
    if len(raw) <= limit:
        return raw
    return raw[:limit] + f"\n... [truncated {len(raw) - limit} bytes] ..."


def build_snippets_markdown(case_dir: Path, ledger: list[dict[str, Any]] | None = None) -> str:
    """Collect heads of stdout/CSV outputs for Windows + pulled SIFT trees."""
    case_dir = Path(case_dir)
    parts: list[str] = ["# Tool output snippets (for interpretation)\n"]
    total = 0

    if ledger is None:
        lp = case_dir / "extractions" / "_tool_lane_ledger.json"
        if lp.is_file():
            try:
                ledger = json.loads(lp.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                ledger = []
        else:
            ledger = []

    parts.append("## Ledger summary\n")
    for row in ledger or []:
        parts.append(
            f"- **{row.get('status')}** `{row.get('host')}/{row.get('tool')}` "
            f"audit=`{row.get('audit_id') or '-'}` "
            f"saved=`{row.get('output_saved_to') or '-'}` "
            f"{(row.get('reason') or '')[:120]}"
        )
    parts.append("")

    roots = [
        ("windows", case_dir / "extractions"),
        ("sift", case_dir / "sift" / "extractions"),
    ]
    # Prefer high-signal small files first so vol/fls/LNK are not crowded out
    preferred_names = (
        "pslist", "cmdline", "windows.info", "fls_stdout",
        "security-timeline", "prefetch_Timeline", "recent-lnk",
        "NetworkUsages", "NetworkConnections", "recmd",
    )

    def _prio(path: Path) -> tuple[int, str]:
        name = path.name.lower()
        for i, key in enumerate(preferred_names):
            if key.lower() in name or key.lower() in str(path).lower():
                return (i, name)
        if path.suffix.lower() == ".txt":
            return (50, name)
        if path.suffix.lower() == ".csv":
            return (80, name)
        return (99, name)

    for label, root in roots:
        if not root.is_dir():
            continue
        parts.append(f"## Extractions ({label})\n")
        files: list[Path] = []
        for pat in ("*_stdout.txt", "*.csv", "*.txt", "*.json"):
            files.extend(sorted(root.rglob(pat)))
        files = sorted(set(files), key=_prio)
        seen: set[Path] = set()
        for path in files:
            if path in seen or path.name.startswith("_"):
                continue
            seen.add(path)
            if path.stat().st_size > 50 * 1024 * 1024 and path.suffix.lower() == ".csv":
                block = (
                    f"### `{path.relative_to(root)}`\n\n"
                    f"(large CSV {path.stat().st_size} bytes — omitted; use sample if present)\n"
                )
            else:
                body = _head_text(path)
                block = f"### `{path.relative_to(root)}`\n\n```\n{body}\n```\n"
            if total + len(block) > _MAX_TOTAL:
                parts.append("\n_(snippet budget exhausted)_\n")
                break
            parts.append(block)
            total += len(block)
        else:
            continue
        break

    return "\n".join(parts)


def write_snippets(case_dir: Path, ledger: list[dict[str, Any]] | None = None) -> Path:
    case_dir = Path(case_dir)
    out_dir = case_dir / "analysis"
    out_dir.mkdir(parents=True, exist_ok=True)
    md = build_snippets_markdown(case_dir, ledger)
    path = out_dir / "snippets.md"
    path.write_text(md, encoding="utf-8")
    return path
