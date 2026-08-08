"""SHA-256 audit trail logging for DFIR-Nexus.

Each tool call is logged as a JSONL entry with a unique audit_id,
examiner identity, and SHA-256 content hash. Entries are append-only
and written to {case_dir}/audit/{mcp_name}.jsonl.
"""

import hashlib
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nexus.config import settings

logger = logging.getLogger(__name__)

_EXAMINER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")


def resolve_examiner() -> str:
    """Resolve examiner identity.

    Precedence: NEXUS_EXAMINER env -> configured examiner (config.yaml /
    settings) -> OS username -> "unknown". The configured examiner is what
    `nexus config --examiner` sets, so audit rows carry the identity the
    examiner actually chose.
    """
    raw = (
        os.environ.get("NEXUS_EXAMINER")
        or (settings.examiner if settings.examiner else "")
        or os.environ.get("USER")
        or os.environ.get("USERNAME")
        or "unknown"
    )
    slug = raw.strip().lower().replace(" ", "-").replace("_", "-")
    slug = re.sub(r"[^a-z0-9-]", "", slug)
    if not slug:
        slug = "unknown"
    if not _EXAMINER_PATTERN.match(slug):
        slug = slug[:20]
        if not slug:
            slug = "unknown"
    return slug


class AuditWriter:
    """Append-only audit trail writer.

    Writes JSONL entries to {audit_dir}/{mcp_name}.jsonl with:
    - ts: ISO 8601 timestamp
    - mcp: server name
    - tool: tool name
    - audit_id: unique ID per entry
    - examiner: resolved examiner
    - case_id: active case
    - params, result_summary: call data
    - sha256: content hash of the entry
    """

    def __init__(self, mcp_name: str, audit_dir: str | Path | None = None):
        self.mcp_name = mcp_name
        self._audit_dir_override = Path(audit_dir) if audit_dir else None
        self._lock = threading.Lock()
        self._seq_cache: dict[str, int] = {}
        self._seq_lock = threading.Lock()

    @property
    def last_audit_id(self) -> str | None:
        return getattr(self, "_last_audit_id", None)

    def log(
        self,
        tool: str,
        params: dict[str, Any] | None = None,
        result_summary: dict[str, Any] | None = None,
        source: str = "mcp",
        audit_id: str | None = None,
        input_files: list[str] | None = None,
        input_sha256s: list[str] | None = None,
        elapsed_ms: float | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str | None:
        """Write an audit entry. Returns the audit_id or None on failure."""
        try:
            case_id = os.environ.get("NEXUS_ACTIVE_CASE", "")
            examiner = resolve_examiner()

            if audit_id is None:
                audit_id = self._next_audit_id(examiner)

            entry: dict[str, Any] = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "mcp": self.mcp_name,
                "tool": tool,
                "audit_id": audit_id,
                "examiner": examiner,
                "case_id": case_id,
                "source": source,
                "params": self._summarize(params) if params else {},
                "result_summary": self._summarize(result_summary) if result_summary else {},
            }
            if input_files:
                entry["input_files"] = input_files
            if input_sha256s:
                entry["input_sha256s"] = input_sha256s
            if elapsed_ms is not None:
                entry["elapsed_ms"] = round(elapsed_ms, 1)
            if extra:
                entry.update(extra)

            entry["sha256"] = hashlib.sha256(
                json.dumps(entry, sort_keys=True, default=str).encode()
            ).hexdigest()

            audit_dir = self._get_audit_dir()
            if audit_dir is None:
                return None

            audit_dir.mkdir(parents=True, exist_ok=True)
            log_path = audit_dir / f"{self.mcp_name}.jsonl"

            with self._lock:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
                    f.flush()
                    os.fsync(f.fileno())

            self._last_audit_id = audit_id
            return audit_id
        except Exception as e:
            logger.error("Audit write failed [%s]: %s", type(e).__name__, e)
            self._last_audit_id = None
            return None

    def _get_audit_dir(self) -> Path | None:
        if self._audit_dir_override:
            return self._audit_dir_override
        env_audit = os.environ.get("NEXUS_AUDIT_DIR")
        if env_audit:
            return Path(env_audit)
        env_case = os.environ.get("NEXUS_CASE_DIR")
        if env_case:
            case_path = Path(env_case)
            if case_path.is_dir():
                return case_path / "audit"
        active_file = Path.home() / ".nexus" / "active_case"
        if active_file.exists():
            try:
                content = active_file.read_text().strip()
            except OSError:
                content = ""
            if content:
                case_dir = Path(content) if os.path.isabs(content) else settings.cases_root / content
                if case_dir.is_dir():
                    return case_dir / "audit"
        return None

    def _next_audit_id(self, examiner: str) -> str:
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        with self._seq_lock:
            key = f"{date_str}"
            seq = self._seq_cache.get(key, 0)
            if seq == 0:
                seq = self._resume_sequence(date_str)
            seq += 1
            self._seq_cache[key] = seq
        prefix = self.mcp_name.replace("-", "_")
        return f"{prefix}-{examiner}-{date_str}-{seq:03d}"

    def _resume_sequence(self, date_str: str) -> int:
        """Read existing JSONL to find highest seq for today."""
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            return 0
        log_path = audit_dir / f"{self.mcp_name}.jsonl"
        if not log_path.exists():
            return 0
        pattern = f"{date_str}-"
        max_seq = 0
        try:
            with open(log_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or pattern not in line:
                        continue
                    try:
                        entry = json.loads(line)
                        aid = entry.get("audit_id", "")
                        if pattern in aid:
                            parts = aid.rsplit("-", 1)
                            if len(parts) == 2:
                                try:
                                    seq = int(parts[1])
                                    max_seq = max(max_seq, seq)
                                except ValueError:
                                    pass
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass
        return max_seq

    @staticmethod
    def _summarize(obj: Any, max_len: int = 500) -> Any:
        """Truncate strings to prevent audit log bloat."""
        if isinstance(obj, str):
            return obj[:max_len]
        if isinstance(obj, dict):
            return {k: AuditWriter._summarize(v, max_len) for k, v in obj.items()}
        if isinstance(obj, list):
            return [AuditWriter._summarize(item, max_len) for item in obj[:20]]
        return obj

    def get_entries(self, case_dir: Path, since: str = "") -> list[dict]:
        """Read back audit entries for a case."""
        audit_dir = case_dir / "audit"
        log_path = audit_dir / f"{self.mcp_name}.jsonl"
        if not log_path.exists():
            return []
        entries = []
        try:
            with open(log_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if since and entry.get("ts", "") < since:
                            continue
                        entries.append(entry)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass
        return entries
