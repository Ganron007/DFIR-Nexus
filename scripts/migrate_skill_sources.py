"""Migrate `# kb:` comment provenance into machine-readable `source:` fields.

WP 9.1 completion — makes skill→KB citations machine-readable for every
shipped skill so that:
  - `skill_provenance()` carries real chunk citations (agent→skill→KB chain),
  - `kb verify-cites` can validate every shipped skill,
  - the distillation pipeline's `source:` schema is uniform.

The edit is a surgical text insertion after the ``mitre:`` line — the file is
never re-serialized, so hand-written comments and formatting survive intact.
Idempotent: files that already declare ``source:`` are skipped.
"""
from __future__ import annotations

import contextlib
import re
import sys
from pathlib import Path

with contextlib.suppress(Exception, AttributeError):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]

REPO = Path(__file__).resolve().parents[1]
SKILLS = REPO / "src" / "nexus" / "data" / "knowledge" / "skills"
# Resolvable chunk citations (d_xxx:cNNNN) plus doc-level pointers (d_xxx).
# Doc-level ids are documentation pointers — resolvable via `kb card <doc_id>`
# and ignored by `kb verify-cites` (which only matches chunk ids).
_ID_RE = re.compile(r"\bd_[0-9a-f]{4,}(?::c[0-9a-f]{1,8})?\b")


def extract_chunk_ids(text: str) -> list[str]:
    """Citations from the skill's provenance comments (chunk + doc ids)."""
    ids: list[str] = []
    for m in re.finditer(r"#\s*kb[ :](.*)", text):
        for cid in re.findall(_ID_RE.pattern, m.group(1)):
            cid = cid.strip()
            if cid and cid.lower() not in {c.lower() for c in ids}:
                ids.append(cid)
    return ids[:24]


def extract_prose_citations(text: str) -> list[str]:
    """Free-text KB citations (``# kb: EIR CH4-1 (...)``) as source strings."""
    blocks: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        m = re.match(r"^\s*#\s*(.*)$", line)
        if not m or line.strip().startswith("# !/"):
            if current:
                blocks.append(" ".join(current))
                current = []
            continue
        body = m.group(1).strip()
        if re.match(r"^kb[ :]", body, re.I):
            if current:
                blocks.append(" ".join(current))
            current = [re.sub(r"^kb\s*:?\s*", "", body, flags=re.I).strip()]
        elif current and line.lstrip().startswith("#"):
            current.append(body)
    if current:
        blocks.append(" ".join(current))
    out: list[str] = []
    for b in blocks:
        b = re.sub(r"\s+", " ", b).strip(" ,;")
        if b and b.lower() not in {c.lower() for c in out}:
            out.append(b[:240])
    return out[:24]


def migrate(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    if re.search(r"^source:", text, re.M):
        return "skip (source present)"
    ids = extract_chunk_ids(text)
    if not ids:
        ids = extract_prose_citations(text)
        if not ids:
            return "no citations found"
    m = re.search(r"^mitre:.*$", text, re.M)
    if not m:
        return "no mitre line to anchor on"
    entries = [i if _ID_RE.fullmatch(i) else f"{i}" for i in ids]
    block = "source:\n" + "\n".join(f'  - "{e}"' for e in entries) + "\n"
    at = m.end()
    if not text[at:].startswith("\n"):
        block = "\n" + block
    path.write_text(text[:at] + "\n" + block + text[at + 1:], encoding="utf-8")
    return f"+{len(entries)} citations"


def main() -> int:
    changed = 0
    for f in sorted(SKILLS.glob("*.yaml")):
        note = migrate(f)
        if note.startswith("+"):
            changed += 1
        print(f"{f.name}: {note}")
    print(f"migrated {changed} skills")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
