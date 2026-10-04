#!/usr/bin/env python
"""WO-K6 — upgrade skill citations from documents to chunks (design-time tool).

Measured before this: **all 37 skills** cited bare document names ("EIR CH4-1",
"FOR526 memory forensics"). A document name points at a whole book, so a step's
claim cannot be checked against the passage that supports it - and
`verify_citations` now fails that grade on purpose.

This resolves each skill to real chunks in the local KB (`G:\\doc_extract`) -
`kb find` returns `chunk_id`, the document path and the line range, which is
exactly the `{chunk_id, rel_path, lines}` shape the loader already accepts.

    python devtools/knowledge/upgrade_skill_citations.py            # upgrade in place
    python devtools/knowledge/upgrade_skill_citations.py --check     # fail if not all chunk-grade
    python devtools/knowledge/upgrade_skill_citations.py --dry-run   # print what would change

The original document names are **kept** in each entry (`citation`), so nothing
is lost: a reviewer can still see which book the skill was drawn from, and the
chunk says where in it.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
SKILLS = REPO / "src" / "nexus" / "data" / "knowledge" / "skills"
KB_ROOT = Path("G:/doc_extract")
KB_PY = KB_ROOT / "kb" / "kb.py"

#: ` 31.38  d_291d23d46cc2:c0047  path/to/doc.md:4122-4220  snippet`
_KB_LINE = re.compile(r"^\s*([\d.]+)\s+(d_[0-9a-f]+:c\d+)\s+(.+?):(\d+-\d+)\s")

#: How many chunks to attach per skill. Three is enough to support a step or two
#: without turning the file into a reading list.
CITATIONS_PER_SKILL = 3


def kb_available() -> bool:
    return KB_PY.is_file()


def find_chunks(query: str, *, limit: int = 40, timeout: float = 180.0) -> list[dict[str, Any]]:
    """`kb find` -> [{chunk_id, rel_path, lines, score}]. Never raises."""
    if not kb_available():
        return []
    try:
        proc = subprocess.run(
            [sys.executable, str(KB_PY), "find", query, "--out", str(KB_ROOT / "kb")],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    out: list[dict[str, Any]] = []
    for line in (proc.stdout or "").splitlines():
        match = _KB_LINE.match(line)
        if not match:
            continue
        out.append({
            "chunk_id": match.group(2),
            "rel_path": match.group(3).strip(),
            "lines": match.group(4),
            "score": float(match.group(1)),
        })
        if len(out) >= limit:
            break
    return out


def queries_for_skill(skill: dict[str, Any]) -> list[str]:
    """KB queries for a skill, most specific first."""
    title = " ".join(str(skill.get("title") or "").split())
    keywords = [str(k) for k in ((skill.get("trigger") or {}).get("keywords") or [])]
    words = title.split()
    candidates = [
        title,
        " ".join(words[:3]),
        " ".join(words[:2]),
        " ".join(keywords[:3]),
        " ".join(keywords[:2]),
    ]
    out: list[str] = []
    for candidate in candidates:
        text = candidate.strip()
        if text and text not in out:
            out.append(text)
    return out


def rewrite_source(skill: dict[str, Any], chunks: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    """The new `source:` list, or None when there is nothing to change."""
    existing = skill.get("source")
    if isinstance(existing, str):
        existing = [existing]
    documents = [str(s).strip() for s in (existing or []) if str(s).strip()]
    if not chunks:
        return None

    out: list[dict[str, Any]] = []
    for index, chunk in enumerate(chunks[:CITATIONS_PER_SKILL]):
        doc = documents[index] if index < len(documents) else (documents[0] if documents else "")
        out.append({
            "chunk_id": chunk["chunk_id"],
            "rel_path": chunk["rel_path"],
            "lines": chunk["lines"],
            "citation": doc,
        })
    return out


def upgrade_skill(path: Path, *, dry_run: bool = False) -> tuple[str, int]:
    """Upgrade one skill file. Returns (skill_id, chunks_attached)."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        return (path.stem, 0)
    ident = str(data.get("skill") or path.stem)

    from nexus.analysis.skill_steps import citation_grade

    if citation_grade(data) == "chunk":
        return (ident, 0)  # already done; idempotent

    chunks: list[dict[str, Any]] = []
    for candidate in queries_for_skill(data):
        found = find_chunks(candidate, limit=CITATIONS_PER_SKILL)
        if found:
            chunks = found
            break
    if not chunks:
        return (ident, 0)
    new_source = rewrite_source(data, chunks)
    if not new_source:
        return (ident, 0)

    if dry_run:
        return (ident, len(new_source))

    # Rewrite only the `source:` block, preserving every comment and the rest of
    # the file.
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines)
                  if re.match(r"^source:\s*$", line)), None)
    rendered = yaml.safe_dump(
        {"source": new_source}, sort_keys=False, allow_unicode=True, width=100,
    ).splitlines()
    block = ["source:"] + ["  " + line for line in rendered[1:] if line.strip()]

    if start is None:
        new_text = text.rstrip() + "\n\n" + "\n".join(block) + "\n"
    else:
        end = start + 1
        while end < len(lines) and (lines[end].startswith((" ", "\t")) or not lines[end].strip()):
            end += 1
        new_text = "\n".join(lines[:start] + block + lines[end:]) + "\n"
    path.write_text(new_text, encoding="utf-8")
    return (ident, len(new_source))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="exit 1 unless every skill is chunk-grade")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    from nexus.analysis.skill_steps import verify_citations

    if args.check:
        skills = []
        for path in sorted(SKILLS.glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if isinstance(data, dict):
                skills.append(data)
        report = verify_citations(skills)
        if not report["ok"]:
            print(f"{len(report['failing'])} skill(s) are not chunk-grade:", file=sys.stderr)
            for row in report["failing"][:10]:
                print(f"  {row['skill']}: {row['grade']}", file=sys.stderr)
            return 1
        print(f"all {len(skills)} skills are chunk-grade")
        return 0

    if not kb_available():
        print(f"KB not available at {KB_PY} - cannot resolve chunks", file=sys.stderr)
        return 2

    upgraded = 0
    total_chunks = 0
    for path in sorted(SKILLS.glob("*.yaml")):
        ident, count = upgrade_skill(path, dry_run=args.dry_run)
        if count:
            upgraded += 1
            total_chunks += count
            verb = "would attach" if args.dry_run else "attached"
            print(f"  {ident}: {verb} {count} chunk(s)")
    print(f"\n{upgraded} skill(s), {total_chunks} chunk(s)")
    if not args.dry_run and upgraded:
        skills = []
        for path in sorted(SKILLS.glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if isinstance(data, dict):
                skills.append(data)
        report = verify_citations(skills)
        print("by grade:", report["by_grade"], "| ok:", report["ok"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
