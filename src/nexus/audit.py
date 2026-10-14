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
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.config import settings

logger = logging.getLogger(__name__)

_EXAMINER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")


def normalize_examiner(raw: str | None) -> str:
    """The one canonical form of an examiner identity.

    Every consumer of an examiner name - the audit chain, the password store,
    the commit lockout, the verification ledger - must agree on this string. It
    is factored out of ``resolve_examiner`` because the password store used to
    key on the *raw* name while the audit chain used the slug: an examiner
    named ``gate_bot`` wrote ``gate_bot.json`` and then looked up
    ``gate-bot.json``, so approval was permanently 403 "No password configured".
    """
    text = (raw or "").strip().lower().replace(" ", "-").replace("_", "-")
    slug = re.sub(r"[^a-z0-9-]", "", text)
    if not slug:
        return "unknown"
    if not _EXAMINER_PATTERN.match(slug):
        slug = slug[:20]
        if not slug:
            return "unknown"
    return slug


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
    return normalize_examiner(raw)


# One writer at a time per log file, in this process and across processes. The pipeline process and
# its stdio MCP child append to the same case log; each kept its own counter and both minted the same
# ids (16 in CASE-C5B04D31 on 2026-10-13/14: an es_search and a record_finding shared each id).
_PATH_LOCKS: dict[str, threading.Lock] = {}
_PATH_LOCKS_GUARD = threading.Lock()
# What this process has read of each log: path -> (bytes read, {day: highest sequence}).
_SEQ_SEEN: dict[str, tuple[int, dict[str, int]]] = {}
_LOCK_TIMEOUT_S = 30.0


def _path_lock(path: Path) -> threading.Lock:
    with _PATH_LOCKS_GUARD:
        return _PATH_LOCKS.setdefault(str(path), threading.Lock())


@contextmanager
def _exclusive(log_path: Path) -> Iterator[None]:
    """Hold the log's lock, across processes, while an id is minted and its row appended."""
    lock_path = log_path.with_name(log_path.name + ".lock")
    with _path_lock(log_path), open(lock_path, "a+b") as handle:
        if os.name == "nt":
            import msvcrt

            deadline = time.monotonic() + _LOCK_TIMEOUT_S
            handle.seek(0)
            while True:
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.005)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _highest_sequence(log_path: Path, date_str: str) -> int:
    """The highest sequence any writer has used on ``date_str`` in this log. Called under its lock.

    Reads only what was appended since this process last looked, so the ids every other process
    minted are seen before the next one is chosen.
    """
    key = str(log_path)
    offset, highest = _SEQ_SEEN.get(key, (0, {}))
    try:
        size = log_path.stat().st_size
    except FileNotFoundError:
        size = 0
    if size < offset:
        offset, highest = 0, {}
    if size > offset:
        with open(log_path, "rb") as f:
            f.seek(offset)
            chunk = f.read(size - offset)
        whole = chunk.rfind(b"\n") + 1
        for raw in chunk[:whole].splitlines():
            try:
                aid = str(json.loads(raw).get("audit_id") or "")
            except (ValueError, AttributeError):
                continue
            parts = aid.rsplit("-", 2)
            if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
                highest[parts[1]] = max(highest.get(parts[1], 0), int(parts[2]))
        offset += whole
    _SEQ_SEEN[key] = (offset, highest)
    return highest.get(date_str, 0)


def _named_case(params: Any) -> str:
    """The case a call names in its params (``case_id``), or '' when it names none, or an invalid one.

    A call names its case: the lane's Windows calls carry the run's case (D41). The audit row belongs to that case,
    whatever case the active pointer names at the moment (CASE-C5B04D31's calls were written into SC1's audit this way).
    """
    if not isinstance(params, dict):
        return ""
    from nexus.discipline import validate_case_id

    value = str(params.get("case_id") or "").strip()
    if not value or validate_case_id(value):
        return ""
    return value


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
            named = _named_case(params)
            case_id = named or os.environ.get("NEXUS_ACTIVE_CASE", "")
            examiner = resolve_examiner()

            audit_dir = self._get_audit_dir(named)
            if audit_dir is None:
                return None
            audit_dir.mkdir(parents=True, exist_ok=True)
            log_path = audit_dir / f"{self.mcp_name}.jsonl"

            # The id is minted from the log the row is written to, under that log's lock: the
            # sequence used to be resumed from the active case's log while the row went to the
            # named case's log, and every process kept its own counter.
            with _exclusive(log_path):
                if audit_id is None:
                    date_str = datetime.now(UTC).strftime("%Y%m%d")
                    seq = _highest_sequence(log_path, date_str) + 1
                    prefix = self.mcp_name.replace("-", "_")
                    audit_id = f"{prefix}-{examiner}-{date_str}-{seq:03d}"

                entry: dict[str, Any] = {
                    "ts": datetime.now(UTC).isoformat(),
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

    def _get_audit_dir(self, named: str = "") -> Path | None:
        if self._audit_dir_override:
            return self._audit_dir_override
        if named:
            # The call names its case: its row goes to that case's audit folder, and never to another case's.
            # A case that does not exist keeps the row in the process audit folder, not in any case.
            case_path = settings.cases_root / named
            return case_path / "audit" if case_path.is_dir() else settings.audit_dir
        env_audit = os.environ.get("NEXUS_AUDIT_DIR")
        if env_audit:
            return Path(env_audit)
        env_case = os.environ.get("NEXUS_CASE_DIR")
        if env_case:
            case_path = Path(env_case)
            if case_path.is_dir():
                return case_path / "audit"
        active_file = Path(
            os.environ.get(
                "NEXUS_ACTIVE_CASE_FILE",
                str(Path.home() / ".nexus" / "active_case"),
            )
        )
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
