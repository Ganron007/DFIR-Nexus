"""Steer-chat persistence — per-case examiner/LLM conversation log.

Transcript lives in ``<case>/chat.jsonl`` (append-only JSONL). Every
examiner question and LLM response is recorded so the investigation has
an auditable record of what was asked and what the model answered. The
LLM never edits or deletes entries.

Action ids follow the final product numbering. Transcripts written before
the rename carry the old ids and are translated on read (and defensively on
write), so historical entries render exactly like new ones:

- ``mode2_*`` (old guided-chat numbering) -> ``mode1_*`` (Mode 1 — LLM)
- ``mode3_*`` (old plan/execute sliver numbering) -> ``mode2_*`` (Mode 2)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

LEGACY_ACTION_ALIASES: dict[str, str] = {
    # Guided chat / iterative loop was product Mode 2 before the rename.
    "mode2_iter0": "mode1_iter0",
    "mode2_stop": "mode1_stop",
    "mode2_error": "mode1_error",
    "mode2_aggregation": "mode1_aggregation",
    "mode2_proposal": "mode1_proposal",
    "mode2_no_proposals": "mode1_no_proposals",
    "mode2_done": "mode1_done",
    "mode2_start": "mode1_start",
    "mode2_draft": "mode1_draft",
    "mode2_iterate_question": "mode1_iterate_question",
    "mode2_iteration": "mode1_iteration",
    # Plan/execute sliver was product Mode 3 before the rename.
    "mode3_plan": "mode2_plan",
    "mode3_execute": "mode2_execute",
    "mode3_seal": "mode2_seal",
    "mode3_draft": "mode2_draft",
    "mode3_draft_finding": "mode2_draft_finding",
    "mode3_iterative": "mode2_iterative",
}


def canonical_action(action: str) -> str:
    """Translate a pre-rename chat action id to its canonical value."""
    text = str(action or "")
    return LEGACY_ACTION_ALIASES.get(text, text)


def _chat_path(case_dir: Path) -> Path:
    return Path(case_dir) / "chat.jsonl"


def append_chat(
    case_dir: Path,
    role: str,
    action: str,
    text: str,
    meta: dict | None = None,
    data: dict | None = None,
) -> dict:
    """Append one chat entry. Roles: examiner | llm | system.

    ``data`` carries structured payloads (e.g. hit lists for the portal
    transcript) that must survive reload verbatim — unlike ``meta``,
    which is stringified and truncated for display.
    """
    entry = {
        "ts": datetime.now(UTC).isoformat(),
        "role": role,
        "action": canonical_action(action),
        "text": str(text)[:2000],
    }
    if meta:
        entry["meta"] = {k: str(v)[:300] for k, v in meta.items() if v}
    if data:
        entry["data"] = data
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
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict):
                if entry.get("action"):
                    entry["action"] = canonical_action(entry["action"])
                out.append(entry)
    except OSError:
        return []
    return out[-limit:] if limit else out


def clear_chat(case_dir: Path) -> dict:
    p = Path(case_dir) / "chat.jsonl"
    if p.exists():
        p.unlink()
    return {"status": "cleared"}
