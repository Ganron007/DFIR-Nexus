"""Steer-chat persistence — per-case examiner/LLM conversation log.

Transcript lives in ``<case>/chat.jsonl`` (append-only JSONL). Every
examiner question and LLM response is recorded so the investigation has
an auditable record of what was asked and what the model answered. The
LLM never edits or deletes entries.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path


def _chat_path(case_dir: Path) -> Path:
    return Path(case_dir) / "chat.jsonl"


def append_chat(case_dir: Path, role: str, action: str, text: str, meta: dict | None = None) -> dict:
    """Append one chat entry. Roles: examiner | llm | system."""
    entry = {
        "ts": datetime.now(UTC).isoformat(),
        "role": role,
        "action": action,
        "text": str(text)[:2000],
    }
    if meta:
        entry["meta"] = {k: str(v)[:300] for k, v in meta.items() if v}
    path = Path(case_dir) / "chat.jsonl"
    line = json.dumps(entry, default=str)
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    return entry


def load_chat(case_dir: Path, limit: int = 200) -> list[dict]:
    path = Path(case_dir) / "chat.jsonl"
    if not path.is_file():
        return []
    out: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if isinstance(entry, dict):
                    out.append(entry)
            except ValueError:
                continue
    except OSError:
        return []
    return out[-limit:] if limit else out


def clear_chat(case_dir: Path) -> dict:
    p = Path(case_dir) / "chat.jsonl"
    if p.exists():
        p.unlink()
    return {"status": "cleared"}
