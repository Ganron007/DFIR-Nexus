"""One call through the product's own model constructor: what was built, what answered, how fast (Part 10, 10.2).

    python devtools/runbook/llm_ping.py
Prints no secret. Expected on the operator's settings: built ChatOpenAI deepseek-flash, record
{"provider": "openai-compatible", "model": "deepseek-flash"}, content "OK", a few seconds.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from nexus.langgraph import llm_pipeline  # noqa: E402


def main() -> int:
    model = llm_pipeline.get_model()
    print("built:", type(model).__name__, getattr(model, "model_name", None) or getattr(model, "model", None))
    print("record:", json.dumps(llm_pipeline.built_model_record()))
    start = time.monotonic()
    reply = model.invoke("Reply with the single word OK and nothing else.")
    meta = getattr(reply, "response_metadata", {}) or {}
    print(f"seconds: {time.monotonic() - start:.1f}")
    print("content:", repr(str(reply.content)[:200]))
    print("model answered:", meta.get("model_name") or meta.get("model"), "| finish:", meta.get("finish_reason"))
    print("usage:", getattr(reply, "usage_metadata", None))
    return 0 if "OK" in str(reply.content) else 1


if __name__ == "__main__":
    raise SystemExit(main())
