"""Central protected LLM invocation journal with correlation IDs (WP 12.0, WP 12.1, ER-08).

Records provider/model metadata, correlation IDs, prompt/response hashes, usage tokens,
latencies, finish reasons, and egress-anonymized excerpts into
``cases/<case_id>/analysis/llm_journal.jsonl``.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_CURRENT_JOURNAL: ContextVar[LLMJournal | None] = ContextVar("llm_journal", default=None)


def _sha256(text: str) -> str:
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class LLMJournal:
    """Manages atomic, append-only, protected LLM invocation recording for a case."""

    def __init__(self, case_dir: Path | str, run_id: str | None = None) -> None:
        self.case_dir = Path(case_dir).resolve()
        self.case_id = self.case_dir.name
        self.run_id = run_id or ""
        self.path = self.case_dir / "analysis" / "llm_journal.jsonl"
        self._lock = threading.RLock()
        self._calls: list[dict[str, Any]] = []
        self._error = ""

    def record_call(
        self,
        *,
        correlation_id: str | None = None,
        run_id: str | None = None,
        provider: str = "",
        model: str = "",
        latency_ms: float = 0.0,
        input_tokens: int = 0,
        output_tokens: int = 0,
        prompt: str = "",
        response: str = "",
        finish_reason: str = "stop",
        status: str = "completed",
        error: str | None = None,
        tool_calls: list[str] | None = None,
    ) -> dict[str, Any]:
        """Record one protected invocation entry."""
        cid = correlation_id or str(uuid.uuid4())
        rid = run_id or self.run_id
        at = datetime.now(UTC).isoformat()
        prompt_str = str(prompt or "")
        response_str = str(response or "")

        egress_mode = os.environ.get("NEXUS_LLM_EGRESS", "").strip().lower()
        is_raw = egress_mode == "raw"
        redaction_profile = "raw" if is_raw else "anonymized"

        prompt_excerpt = prompt_str[:500]
        response_excerpt = response_str[:500]

        if not is_raw:
            try:
                from nexus.llm.egress import load_anonymizer

                anon = load_anonymizer(self.case_dir)
                prompt_excerpt, _ = anon.anonymize(prompt_excerpt)
                response_excerpt, _ = anon.anonymize(response_excerpt)
            except Exception as exc:  # noqa: BLE001 - protect logging from failing invocation
                log.debug("could not anonymize journal excerpts: %s", exc)

        entry = {
            "correlation_id": cid,
            "case_id": self.case_id,
            "run_id": rid,
            "at": at,
            "provider": provider,
            "model": model,
            "latency_ms": round(float(latency_ms), 2),
            "input_tokens": int(input_tokens or 0),
            "output_tokens": int(output_tokens or 0),
            "prompt_chars": len(prompt_str),
            "response_chars": len(response_str),
            "prompt_hash": _sha256(prompt_str),
            "response_hash": _sha256(response_str),
            "prompt_excerpt": prompt_excerpt,
            "response_excerpt": response_excerpt,
            "finish_reason": finish_reason,
            "status": status,
            "error": error,
            "tool_calls": list(tool_calls or []),
            "redaction_profile": redaction_profile,
        }

        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                self._calls.append(entry)
            except (OSError, ValueError, TypeError) as exc:
                self._error = f"{type(exc).__name__}: {exc}"
                log.error("Failed to write LLM journal at %s: %s", self.path, self._error)
        return entry

    def section(self, run_id: str | None = None) -> dict[str, Any]:
        """Aggregate summary of journaled calls."""
        with self._lock:
            calls = self._calls
            if run_id:
                calls = [c for c in calls if c.get("run_id") == run_id]
            completed = [c for c in calls if c.get("status") == "completed"]
            failed = [c for c in calls if c.get("status") == "failed"]
            return {
                "status": "available" if not self._error else "error",
                "error": self._error or None,
                "path": str(self.path.relative_to(self.case_dir)) if self.path.exists() else None,
                "total_calls": len(calls),
                "completed_calls": len(completed),
                "failed_calls": len(failed),
                "total_input_tokens": sum(int(c.get("input_tokens") or 0) for c in calls),
                "total_output_tokens": sum(int(c.get("output_tokens") or 0) for c in calls),
                "total_latency_ms": sum(float(c.get("latency_ms") or 0.0) for c in calls),
            }


def bind_journal(case_dir: Path | str, run_id: str | None = None) -> LLMJournal:
    """Bind the active LLM journal in the current context."""
    journal = LLMJournal(case_dir, run_id=run_id)
    _CURRENT_JOURNAL.set(journal)
    return journal


def current_journal() -> LLMJournal | None:
    """The active LLM journal, if bound."""
    return _CURRENT_JOURNAL.get()


def record_llm_invocation(
    case_dir: Path | str | None,
    *,
    correlation_id: str | None = None,
    run_id: str | None = None,
    provider: str = "",
    model: str = "",
    latency_ms: float = 0.0,
    input_tokens: int = 0,
    output_tokens: int = 0,
    prompt: str = "",
    response: str = "",
    finish_reason: str = "stop",
    status: str = "completed",
    error: str | None = None,
    tool_calls: list[str] | None = None,
) -> dict[str, Any] | None:
    """Global entry point to record an LLM invocation."""
    journal = current_journal()
    if journal is None and case_dir is not None:
        journal = LLMJournal(case_dir, run_id=run_id)
    if journal is None:
        return None
    return journal.record_call(
        correlation_id=correlation_id,
        run_id=run_id,
        provider=provider,
        model=model,
        latency_ms=latency_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        prompt=prompt,
        response=response,
        finish_reason=finish_reason,
        status=status,
        error=error,
        tool_calls=tool_calls,
    )
