"""KA1 design-time prompt tracer — **not part of the product**.

WO-KA1: "Add `devtools/trace_prompts.py`. It wraps the model that
`langgraph.llm_pipeline.get_model` returns with a recorder that writes **every
message list sent to the model**, in full, to `<case>/.trace/model_calls.jsonl`."

Why it exists: the utilization audit (KA1) has to say, per source, whether it
reached the model *whole or cut*. Reading that off the packed-context files is
not enough — those are per-*stage* snapshots, they can be absent after the fact,
and they do not cover the on-demand calls. A recorder at the model boundary
captures what the model was actually given, every time, whatever the stage.

It patches the model and then runs a real entry point, so nothing about the
production path changes. Trace files live in the case's `.trace/` and are deleted
with the case. Nothing is added to `src/nexus`.

Usage::

    python devtools/trace_prompts.py --case CASE-D6B93BF1 --mode 1
    python devtools/trace_prompts.py --case CASE-D6B93BF1 --mode 2
    python devtools/trace_prompts.py --case CASE-D6B93BF1 --mode 3

Mode 1 = the interpret pipeline; 2 = `mode2 run`; 3 = `mode3 run`. The neutral
question matches the K-run default so the trace is comparable with a scored run.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_DEFAULT_QUESTION = "Investigate this host for compromise"

_lock = threading.Lock()


def _content_text(content: Any) -> Any:
    """Message content as JSON-safe text.

    A content list (multimodal parts) is preserved as a list of its text pieces;
    anything else is stringified so a trace never raises on an odd payload.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for part in content:
            if isinstance(part, dict):
                out.append(str(part.get("text") or part.get("content") or part))
            else:
                out.append(str(part))
        return out
    return str(content)


def _serialize(messages: Any) -> list[dict[str, Any]]:
    """Normalize whatever the caller sent into ``[{role, content}, …]``."""
    out: list[dict[str, Any]] = []
    for m in messages or []:
        if isinstance(m, dict):
            role = m.get("role") or m.get("type") or "unknown"
            content = m.get("content")
        else:
            role = getattr(m, "type", None) or getattr(m, "role", None)
            role = role or type(m).__name__
            content = getattr(m, "content", None)
        out.append({"role": str(role), "content": _content_text(content)})
    return out


class _Tracer:
    """Append one JSONL record per model call, with the full message list."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.n = 0

    def record(self, messages: Any, *, streamed: bool) -> None:
        payload = _serialize(messages)
        with _lock:
            self.n += 1
            entry = {
                "ts": datetime.now(UTC).isoformat(),
                "seq": self.n,
                "streamed": streamed,
                "messages": payload,
                "chars": sum(len(m["content"]) if isinstance(m["content"], str)
                             else sum(len(p) for p in m["content"])
                             for m in payload),
            }
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")


class _RecordingModel:
    """Delegates everything; records the messages on the call paths."""

    def __init__(self, inner: Any, tracer: _Tracer):
        self._inner = inner
        self._tracer = tracer

    def invoke(self, messages, **kwargs):  # noqa: ANN001, ANN201
        self._tracer.record(messages, streamed=False)
        return self._inner.invoke(messages, **kwargs)

    async def ainvoke(self, messages, **kwargs):  # noqa: ANN001, ANN201
        self._tracer.record(messages, streamed=False)
        return await self._inner.ainvoke(messages, **kwargs)

    def stream(self, messages, **kwargs):  # noqa: ANN001, ANN201
        self._tracer.record(messages, streamed=True)
        return self._inner.stream(messages, **kwargs)

    async def astream(self, messages, **kwargs):  # noqa: ANN001, ANN201
        self._tracer.record(messages, streamed=True)
        return self._inner.astream(messages, **kwargs)

    def __getattr__(self, name: str) -> Any:
        # bind_tools, with_structured_output, the Runnable surface — all pass
        # through, so wrapping cannot change how the graph builds its agent.
        return getattr(self._inner, name)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<_RecordingModel {self._inner!r}>"


def install(case_dir: Path) -> _Tracer:
    """Patch ``llm_pipeline.get_model`` to record every call for this case."""
    import nexus.langgraph.llm_pipeline as lp

    tracer = _Tracer(Path(case_dir) / ".trace" / "model_calls.jsonl")
    original = lp.get_model

    def traced_get_model(*args: Any, **kwargs: Any) -> Any:
        return _RecordingModel(original(*args, **kwargs), tracer)

    lp.get_model = traced_get_model  # type: ignore[assignment]
    return tracer


def _cli_for(mode: str, case_id: str, question: str) -> list[str]:
    if mode == "1":
        return ["pipeline", "--mode", "interpret", "--from-case", case_id]
    if mode == "2":
        return ["mode2", "run", "--case", case_id, "--question", question]
    if mode == "3":
        return ["mode3", "run", "--case", case_id, "--question", question]
    raise SystemExit(f"mode must be 1, 2 or 3 (got {mode!r})")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="KA1 prompt tracer (design-time)")
    parser.add_argument("--case", required=True, help="Case id to trace")
    parser.add_argument("--mode", required=True, choices=["1", "2", "3"])
    parser.add_argument("--question", default=_DEFAULT_QUESTION)
    args = parser.parse_args(argv)

    from nexus.config import settings

    case_dir = settings.cases_root / args.case
    if not case_dir.is_dir():
        raise SystemExit(f"case not found: {case_dir}")

    tracer = install(case_dir)
    print(f"[trace] recording model calls -> {tracer.path}")

    from nexus.cli.main import app

    sys.argv = ["nexus", *_cli_for(args.mode, args.case, args.question)]
    try:
        app()
    finally:
        print(f"[trace] {tracer.n} model call(s) recorded -> {tracer.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
