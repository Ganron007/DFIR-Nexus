"""Context budget allocator — project-wide (operator rule, 2026-09-17).

**The rule:** the context budget is derived from the model's maximum context
window (the operator's model: **1,000,000 tokens**), not from hand-picked
small numbers. ``NEXUS_LLM_CONTEXT_WINDOW`` declares the window,
``NEXUS_CONTEXT_FILL_RATIO`` (default 0.7) is the share we pack, and the
ceiling is the window itself — no artificial small caps anywhere.

Every packed context is estimated, reported and **persisted**
(``analysis/llm_context/<name>-<ts>.md``) so the examiner can review exactly
what the LLM was given. Usage telemetry is logged — it never caps content.
"""
from __future__ import annotations

import logging
import os
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_CONTEXT_WINDOW = 1_000_000
DEFAULT_FILL_RATIO = 0.7
CHARS_PER_TOKEN = 4  # the starting estimate (English/code mix); see chars_per_token()
_MAX_PERSISTED_CONTEXTS = 60

# D380 (2026-10-24): characters per token, measured. Four was an assumption. On evidence agnes-3.0-flash counted about
# 1.9 (T09 Mode 3: a 1,461,571-character prompt was 772,709 tokens), so packing to window x fill x 4 characters sent
# 516k-803k tokens to a model with a 524,288-token window, and every such seat turn was refused. Each call's real
# count is recorded (``TokenMeter``, attached to every client by ``llm_pipeline.get_model``, and the provider's own
# count when it refuses a prompt), and packing uses the densest ratio this process has measured. The window and the
# fill ratio stay the operator's; only the conversion from tokens to characters is measured instead of assumed.
_MIN_MEASURED_CHARS = 1_000  # a short call says little about how evidence tokenizes
_measured_lock = threading.Lock()
_measured: list[float] = []
_OVERFLOW_PATTERNS = (
    re.compile(r"The input \((\d+) tokens\) is longer than the model's context length", re.IGNORECASE),
    re.compile(r"(\d+) tokens from the input messages", re.IGNORECASE),
)


def chars_per_token() -> float:
    """Characters per token for packing: the densest ratio measured in this process, never above the start (4)."""
    with _measured_lock:
        return min([float(CHARS_PER_TOKEN), *_measured])


def record_token_count(chars: int, tokens: int, source: str = "") -> None:
    """Record one prompt's character count and the provider's token count for it."""
    if chars < _MIN_MEASURED_CHARS or tokens <= 0:
        return
    ratio = max(1.0, chars / tokens)
    with _measured_lock:
        _measured.append(ratio)
        del _measured[:-200]
    log.info("prompt tokens measured%s: %d chars = %d tokens (%.2f chars/token; packing uses %.2f)",
             f" ({source})" if source else "", chars, tokens, ratio, chars_per_token())


def reset_token_measurements() -> None:
    """Forget the measured ratios (tests; a new process starts empty anyway)."""
    with _measured_lock:
        _measured.clear()


def context_overflow_tokens(text: str) -> int | None:
    """The input-token count a provider names when it refuses a prompt as longer than its window, or None."""
    for pattern in _OVERFLOW_PATTERNS:
        match = pattern.search(text or "")
        if match:
            return int(match.group(1))
    return None


def context_window() -> int:
    """Model context window in tokens (NEXUS_LLM_CONTEXT_WINDOW)."""
    try:
        value = int(os.environ.get("NEXUS_LLM_CONTEXT_WINDOW", "") or DEFAULT_CONTEXT_WINDOW)
    except ValueError:
        value = DEFAULT_CONTEXT_WINDOW
    return max(8_000, value)


def case_window(case_dir: Path) -> int:
    """The CASE's own window (analysis/mode1_run_options.json, set before the
    run; the legacy mode2_ name is still read) — falls back to the process
    default. This is what keeps two cases with different windows from racing
    over a process-wide env var."""
    try:
        from nexus.case.run_options import load_run_options

        value = int(load_run_options(case_dir).get("context_window") or 0)
        if value >= 8_000:
            return value
    except (OSError, ValueError, TypeError):
        pass
    return context_window()


def fill_ratio() -> float:
    """Share of the window we pack (NEXUS_CONTEXT_FILL_RATIO, default 0.7)."""
    try:
        value = float(os.environ.get("NEXUS_CONTEXT_FILL_RATIO", "") or DEFAULT_FILL_RATIO)
    except ValueError:
        value = DEFAULT_FILL_RATIO
    return min(max(value, 0.1), 0.95)


def budget_chars(window: int | None = None, ratio: float | None = None) -> int:
    """Character budget derived from the window (tokens × the measured characters per token)."""
    win = window if window is not None else context_window()
    rat = ratio if ratio is not None else fill_ratio()
    return int(win * rat * chars_per_token())


def estimate_tokens(text: str) -> int:
    return max(1, int(len(text) / chars_per_token())) if text else 0


try:
    from langchain_core.callbacks import BaseCallbackHandler as _CallbackBase
except ImportError:  # pragma: no cover - the package depends on langchain-core; this keeps the module importable
    _CallbackBase = object  # type: ignore[assignment,misc]


class TokenMeter(_CallbackBase):  # type: ignore[misc,valid-type]
    """A LangChain callback that records each chat call's characters and the provider's input-token count (D380)."""

    run_inline = True  # Keep the native run ContextVar on async callback starts.

    def __init__(self, model: dict[str, str] | None = None) -> None:
        super().__init__()
        self._chars: dict[Any, int] = {}
        self._tickets: dict[Any, tuple[Any, float]] = {}
        self._lock = threading.Lock()
        self._model = dict(model or {})

    def _start(self, run_id: Any, chars: int) -> None:
        from nexus.analysis.knowledge_record import current

        with self._lock:
            self._chars[run_id] = chars
            record = current()
            if record is not None:
                if record.model_calls is None:
                    record.unbound_model_calls += 1
                else:
                    calls = record.model_calls
                    self._tickets[run_id] = (calls, calls.start(str(run_id), chars, self._model))

    def _finish(self, run_id: Any, *, input_tokens: int = 0, error: BaseException | None = None) -> int:
        with self._lock:
            chars = self._chars.pop(run_id, 0)
            ticket = self._tickets.pop(run_id, None)
        if ticket is not None:
            calls, started = ticket
            calls.finish(str(run_id), started, input_tokens=input_tokens, error=error)
        return chars

    def on_chat_model_start(self, serialized: Any, messages: Any, *, run_id: Any = None, **_: Any) -> None:
        self._start(run_id, sum(len(str(getattr(m, "content", m))) for batch in messages for m in batch))

    def on_llm_start(self, serialized: Any, prompts: Any, *, run_id: Any = None, **_: Any) -> None:
        self._start(run_id, sum(len(str(p)) for p in prompts or []))

    def on_llm_end(self, response: Any, *, run_id: Any = None, **_: Any) -> None:
        tokens = _input_tokens(response)
        chars = self._finish(run_id, input_tokens=tokens)
        record_token_count(chars, tokens, "usage")

    def on_llm_error(self, error: BaseException, *, run_id: Any = None, **_: Any) -> None:
        chars = self._finish(run_id, error=error)
        tokens = context_overflow_tokens(str(error))
        if tokens:
            record_token_count(chars, tokens, "refused prompt")


def _input_tokens(response: Any) -> int:
    """The provider's input-token count from an LLMResult (usage block or message usage metadata), or 0."""
    usage = (getattr(response, "llm_output", None) or {}).get("token_usage") or {}
    value = usage.get("prompt_tokens") or usage.get("input_tokens")
    if not value:
        for generations in getattr(response, "generations", None) or []:
            for gen in generations:
                meta = getattr(getattr(gen, "message", None), "usage_metadata", None) or {}
                value = value or meta.get("input_tokens")
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def retry_budget_chars(chars: int | None = None) -> int:
    """Downgrade budget used when the provider rejects an over-long prompt."""
    base = chars if chars is not None else budget_chars()
    try:
        factor = float(os.environ.get("NEXUS_CONTEXT_RETRY_RATIO", "0.5"))
    except ValueError:
        factor = 0.5
    return int(base * min(max(factor, 0.1), 1.0))


def pack_sections(
    sections: list[tuple[int, str, str]],
    *,
    chars: int | None = None,
    window: int | None = None,
) -> tuple[str, dict[str, Any]]:
    """Pack ``(priority, name, text)`` sections into one context, lowest
    priority number first, until the budget is exhausted.

    Returns ``(packed_text, report)`` where report records per-section chars,
    estimated tokens and truncation, plus the totals. Every section is given
    a fair first share (equal split of the budget), then remaining space is
    handed out in priority order until it runs out — so no section is starved
    by a giant earlier one. Duplicate section names are de-duplicated (a
    repeated name would otherwise be emitted twice and double-counted);
    ``window`` overrides the process default with the case's own window.
    """
    limit = chars if chars is not None else budget_chars(window=window)
    seen_names: dict[str, int] = {}
    ordered: list[tuple[int, str, str]] = []
    for pri, name, text in sorted(sections, key=lambda s: s[0]):
        seen_n = seen_names.get(name, 0)
        seen_names[name] = seen_n + 1
        ordered.append((pri, name if seen_n == 0 else f"{name}#{seen_n + 1}", text))
    total_sections = max(1, len(ordered))
    fair = max(2_000, limit // total_sections)

    texts: dict[str, str] = {}
    report: dict[str, Any] = {"sections": {}, "budget_chars": limit, "used_chars": 0}
    used = 0

    # Pass 1 — fair share per section (priority order)
    for _pri, name, text in ordered:
        text = str(text or "")
        share = min(len(text), fair, max(0, limit - used))
        texts[name] = text[:share]
        used += share
        report["sections"][name] = {
            "chars": share, "tokens": estimate_tokens(text[:share]),
            "truncated": share < len(text),
        }

    # Pass 2 — remaining budget to sections that were truncated, in priority order
    for _pri, name, text in ordered:
        remaining = limit - used
        if remaining <= 0:
            break
        current = len(texts.get(name, ""))
        full = str(text or "")
        if current >= len(full):
            continue
        extra = min(len(full) - current, remaining)
        texts[name] = full[: current + extra]
        used += extra
        report["sections"][name] = {
            "chars": current + extra, "tokens": estimate_tokens(texts[name]),
            "truncated": (current + extra) < len(full),
        }

    report["used_chars"] = used
    report["used_tokens"] = estimate_tokens("\n".join(texts.values()))
    # The window ACTUALLY used (case override when provided) — the audit
    # header used to report the process default even when the case set its own.
    report["ceiling_tokens"] = int(window) if window is not None else context_window()

    packed = "\n\n".join(texts[name] for _pri, name, _t in ordered if texts.get(name))
    return packed, report


def persist_context(
    case_dir: Path,
    name: str,
    packed: str,
    report: dict[str, Any],
    *,
    meta: dict[str, Any] | None = None,
) -> Path | None:
    """Write the EXACT packed context for audit (what the LLM was given)."""
    try:
        out = Path(case_dir) / "analysis" / "llm_context"
        out.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:60]
        path = out / f"{stamp}-{safe}.md"
        header = [
            f"# LLM context — {name}",
            "",
            f"- window tokens: {report.get('ceiling_tokens')}",
            f"- budget chars: {report.get('budget_chars')} (~{estimate_tokens('x' * int(report.get('budget_chars', 0)))} tokens)",
            f"- used chars: {report.get('used_chars')} (~{report.get('used_tokens')} tokens)",
        ]
        for section, stats in (report.get("sections") or {}).items():
            trunc = " (truncated)" if stats.get("truncated") else ""
            header.append(f"- {section}: {stats.get('chars')} chars{trunc}")
        if meta:
            for key, value in meta.items():
                header.append(f"- {key}: {value}")
        path.write_text("\n".join(header) + "\n\n---\n\n" + packed, encoding="utf-8")
        _prune_contexts(out)
        return path
    except OSError as exc:
        log.warning("llm context persist failed: %s", exc)
        return None


def _prune_contexts(out_dir: Path) -> None:
    """Compress the oldest contexts past the cap — NEVER delete them (D39).

    Deleting them destroyed the audit of what the model was given: SC1 lost
    every Mode 1 context to this, so the utilization audit (KA1) could not be
    read from the case afterwards and the cause was invisible. The reviewer
    found it at R1 and the WO's rule is explicit: "If disk use matters, compress;
    never delete."
    """
    try:
        files = sorted(out_dir.glob("*.md"))
        stale = files[:-_MAX_PERSISTED_CONTEXTS]
        for path in stale:
            _compress_context(path)
    except OSError:
        pass


def _compress_context(path: Path) -> None:
    """gzip a context file and remove the plain one. Idempotent."""
    if path.suffix != ".md":
        return
    target = path.with_suffix(".md.gz")
    try:
        if not target.exists():
            import gzip

            with path.open("rb") as src, gzip.open(target, "wb") as dst:
                dst.write(src.read())
        path.unlink(missing_ok=True)
    except OSError as exc:
        # Never lose the audit to a failed compression: leave the plain file.
        log.debug("context compression failed for %s: %s", path, exc)


def log_usage(name: str, report: dict[str, Any], *, model: str = "") -> None:
    """Telemetry only — never caps. Lets the operator see pack sizes/cost."""
    log.info(
        "llm context[%s] model=%s ~%s tokens (budget %s chars, ceiling %s tokens)",
        name,
        model or "?",
        report.get("used_tokens"),
        report.get("budget_chars"),
        report.get("ceiling_tokens"),
    )
