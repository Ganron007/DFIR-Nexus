"""Persist forensic tool stdout/stderr into the active case.

Design contract: every MCP tool execution that produces output must leave
an on-disk artifact under ``case/extractions/`` with a SHA-256, and that
path must be returned to the LLM so findings can cite it (FD-001).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_ACTIVE_CASE_FILE = Path.home() / ".nexus" / "active_case"


def resolve_active_case_dir() -> Path | None:
    """Resolve the active case directory (active_case file or NEXUS_CASE_DIR)."""
    try:
        from nexus.case_manager import CaseManager

        return CaseManager().resolve_case_dir()
    except Exception:  # noqa: BLE001 — no active case is normal
        pass

    env_dir = os.environ.get("NEXUS_CASE_DIR")
    if env_dir:
        p = Path(env_dir)
        if p.is_dir():
            return p

    if _ACTIVE_CASE_FILE.is_file():
        try:
            content = _ACTIVE_CASE_FILE.read_text(encoding="utf-8").strip()
        except OSError:
            content = ""
        if content:
            from nexus.config import settings

            case_dir = Path(content) if os.path.isabs(content) else settings.cases_root / content
            if case_dir.is_dir():
                return case_dir
    return None


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def persist_tool_output(
    *,
    tool_key: str,
    stdout: str = "",
    stderr: str = "",
    command: str = "",
    purpose: str = "",
    case_dir: Path | None = None,
    register_evidence: bool = True,
) -> dict[str, Any]:
    """Write tool stdout/stderr (+ meta) under ``case/extractions/``.

    Always writes when an active case exists and there is any stdout/stderr.
    Returns ``{output_files: [...], case_dir, warning?}``.
    """
    out: dict[str, Any] = {"output_files": [], "case_dir": None, "warning": ""}
    case = case_dir or resolve_active_case_dir()
    if case is None:
        out["warning"] = "No active case — tool output was not persisted to extractions/"
        return out

    out["case_dir"] = str(case)
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", (tool_key or "tool").lower())[:64] or "tool"
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    extractions = case / "extractions" / safe
    try:
        extractions.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        out["warning"] = f"Could not create extractions dir: {exc}"
        return out

    meta = {
        "tool": tool_key,
        "command": (command or "")[:2000],
        "purpose": (purpose or "")[:500],
        "saved_at": datetime.now(UTC).isoformat(),
        "stdout_bytes": len((stdout or "").encode("utf-8", errors="replace")),
        "stderr_bytes": len((stderr or "").encode("utf-8", errors="replace")),
    }
    files: list[dict[str, str]] = []

    def _write(name: str, body: str) -> Path | None:
        if body is None:
            return None
        # Persist even empty stdout when paired with stderr, but skip both-empty
        path = extractions / f"{ts}_{safe}_{name}"
        try:
            path.write_text(body, encoding="utf-8", errors="replace")
        except OSError as exc:
            log.warning("Failed writing %s: %s", path, exc)
            return None
        return path

    # Always keep a meta sidecar so the run is discoverable even if stdout empty
    meta_path = extractions / f"{ts}_{safe}_meta.json"
    stdout_path = _write("stdout.txt", stdout if stdout is not None else "")
    stderr_path = None
    if stderr:
        stderr_path = _write("stderr.txt", stderr)

    if stdout_path:
        digest = _sha256_file(stdout_path)
        files.append({"path": str(stdout_path), "sha256": digest, "kind": "stdout"})
        meta["stdout_sha256"] = digest
        meta["stdout_path"] = str(stdout_path)
    if stderr_path:
        digest = _sha256_file(stderr_path)
        files.append({"path": str(stderr_path), "sha256": digest, "kind": "stderr"})
        meta["stderr_sha256"] = digest
        meta["stderr_path"] = str(stderr_path)

    try:
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        files.append({
            "path": str(meta_path),
            "sha256": _sha256_file(meta_path),
            "kind": "meta",
        })
    except OSError as exc:
        log.warning("Failed writing meta %s: %s", meta_path, exc)

    out["output_files"] = files

    if register_evidence and stdout_path and (stdout or "").strip():
        # Register into *this* case_dir (not whatever happens to be active —
        # dual-MCP hosts must not cross-wire evidence into the wrong case).
        try:
            out["evidence_register"] = _register_extraction_evidence(
                case,
                stdout_path,
                tool_key=tool_key,
                purpose=purpose,
            )
        except Exception as exc:  # noqa: BLE001
            out["evidence_register_warning"] = str(exc)
            log.debug("evidence register for tool output skipped: %s", exc)

    return out


def _register_extraction_evidence(
    case_dir: Path,
    path: Path,
    *,
    tool_key: str,
    purpose: str = "",
) -> dict[str, Any]:
    """Append an extraction file to ``case_dir/evidence.json`` (idempotent by path)."""
    registry_path = case_dir / "evidence.json"
    evidence: list[Any] = []
    if registry_path.is_file():
        try:
            raw = json.loads(registry_path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                evidence = raw
            elif isinstance(raw, dict):
                evidence = list(raw.get("files") or raw.get("items") or [])
        except (OSError, json.JSONDecodeError):
            evidence = []

    abs_path = str(path.resolve())
    for entry in evidence:
        if isinstance(entry, dict) and entry.get("path") == abs_path:
            return {
                "status": "already_registered",
                "path": abs_path,
                "sha256": entry.get("sha256", ""),
            }

    digest = _sha256_file(path)
    desc = f"Tool output: {tool_key}" + (f" — {purpose}" if purpose else "")
    entry = {
        "path": abs_path,
        "sha256": digest,
        "description": desc[:500],
        "examiner": "system",
        "registered_at": datetime.now(UTC).isoformat(),
        "status": "registered",
        "kind": "tool_extraction",
        "tool": tool_key,
    }
    evidence.append(entry)
    registry_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    return {"status": "registered", "path": abs_path, "sha256": digest}
