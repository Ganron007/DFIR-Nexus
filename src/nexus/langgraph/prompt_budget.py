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

import json
import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_CONTEXT_WINDOW = 1_000_000
DEFAULT_FILL_RATIO = 0.7
CHARS_PER_TOKEN = 4  # conservative fast estimate (English/code mix)
_MAX_PERSISTED_CONTEXTS = 60


def context_window() -> int:
    """Model context window in tokens (NEXUS_LLM_CONTEXT_WINDOW)."""
    try:
        value = int(os.environ.get("NEXUS_LLM_CONTEXT_WINDOW", "") or DEFAULT_CONTEXT_WINDOW)
    except ValueError:
        value = DEFAULT_CONTEXT_WINDOW
    return max(8_000, value)


def case_window(case_dir: Path) -> int:
    """The CASE's own window (analysis/mode2_run_options.json, set before the
    run) — falls back to the process default. This is what keeps two cases
    with different windows from racing over a process-wide env var."""
    try:
        opts = json.loads(
            (Path(case_dir) / "analysis" / "mode2_run_options.json")
            .read_text(encoding="utf-8")
        )
        value = int(opts.get("context_window") or 0)
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
    """Character budget derived from the window (tokens × CHARS_PER_TOKEN)."""
    win = window if window is not None else context_window()
    rat = ratio if ratio is not None else fill_ratio()
    return int(win * rat * CHARS_PER_TOKEN)


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // CHARS_PER_TOKEN) if text else 0


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
    report["ceiling_tokens"] = context_window()

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
    try:
        files = sorted(out_dir.glob("*.md"))
        for path in files[:-_MAX_PERSISTED_CONTEXTS]:
            path.unlink(missing_ok=True)
    except OSError:
        pass


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
