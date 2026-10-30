"""Durable metadata for native model invocations, bound to an explicit case and run.

These are LangChain client invocations, including failed ones, not HTTP retry or
billing counts. Prompt characters count message content only. No prompt, response,
credential, or provider error body is written here.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

log = logging.getLogger(__name__)


class ModelCalls:
    def __init__(self, case_dir: Path, run_id: str, *, metered: bool, unbound_calls: int = 0,
                 resuming: bool = False, previous: dict[str, Any] | None = None) -> None:
        from nexus.langgraph.pipeline_runs import _RUN_ID

        if not _RUN_ID.fullmatch(run_id):
            raise ValueError("Invalid model measurement run_id")
        self.case_dir = Path(case_dir).resolve()
        self.run_id = run_id
        self.path = self.case_dir / ".trace" / f"model_calls-{run_id}.jsonl"
        self._lock = threading.RLock()
        self._metered = metered
        self._unbound_calls = unbound_calls
        self._missing_history = resuming and not self.path.exists()
        self._error = ""
        self._coverage_gap = ""
        self._calls: dict[str, dict[str, Any]] = {}
        self._inputs: dict[str, Any] | None = None
        try:
            if self.path.exists():
                events = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line]
                if not events or events[0].get("event") != "measurement_started":
                    raise ValueError("Existing model trace has no native measurement header; left unchanged")
                for event in events:
                    if event.get("case_id") != self.case_dir.name or event.get("run_id") != run_id:
                        raise ValueError("Existing model trace belongs to another case or run; left unchanged")
                    self._remember(event)
            else:
                self._append({"event": "measurement_started", "version": 1, "metered": metered,
                              "unbound_calls": unbound_calls, "missing_history": self._missing_history})
            if previous is not None and previous.get("status") == "unavailable":
                self._coverage_gap = str(previous.get("reason") or "earlier measurement unavailable")
                self._append({"event": "measurement_resumed", "coverage_gap": self._coverage_gap})
        except (OSError, ValueError, TypeError, KeyError) as exc:
            self._failed(exc)

    def matches(self, case_dir: Path, run_id: str | None = None) -> bool:
        return self.case_dir == Path(case_dir).resolve() and (run_id is None or run_id == self.run_id)

    def _failed(self, exc: Exception) -> None:
        self._error = f"{type(exc).__name__}: {exc}"
        log.error("Native model measurement unavailable at %s: %s", self.path, self._error)

    def _remember(self, event: dict[str, Any]) -> None:
        kind = event["event"]
        if kind == "measurement_started":
            self._metered = self._metered and bool(event.get("metered"))
            self._unbound_calls = max(self._unbound_calls, int(event.get("unbound_calls") or 0))
            self._missing_history |= bool(event.get("missing_history"))
        elif kind == "call_started":
            self._calls[event["call_id"]] = dict(event)
        elif kind in {"call_finished", "call_failed"}:
            call = self._calls.get(event["call_id"])
            if call is None:
                raise ValueError("Model trace has a terminal event without its start")
            call.update(event)
        elif kind == "inputs":
            self._inputs = event["inputs"]
        elif kind == "measurement_resumed":
            self._coverage_gap = str(event["coverage_gap"])
        else:
            raise ValueError(f"Unrecognized native model measurement event: {kind}")

    def _append(self, event: dict[str, Any]) -> None:
        if self._error:
            return
        event = {**event, "case_id": self.case_dir.name, "run_id": self.run_id,
                 "at": datetime.now(UTC).isoformat()}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._remember(event)
        except (OSError, ValueError, TypeError) as exc:
            self._failed(exc)

    def start(self, call_id: str, chars: int, model: dict[str, str]) -> float:
        with self._lock:
            self._append({"event": "call_started", "call_id": call_id, "prompt_chars": chars, "model": model})
        return perf_counter()

    def finish(self, call_id: str, started: float, *, input_tokens: int = 0, error: BaseException | None = None) -> None:
        with self._lock:
            self._append({"event": "call_failed" if error is not None else "call_finished", "call_id": call_id,
                          "seconds": perf_counter() - started, "input_tokens": input_tokens or None,
                          "error_type": type(error).__name__ if error is not None else None})

    def inputs(self, brief: dict[str, Any]) -> None:
        """Snapshot the first native briefing's lead counts and the index's exact family counts."""
        with self._lock:
            if self._inputs is not None:
                return
            from nexus.langgraph.es_native import family_doc_counts

            measured: dict[str, Any] = {"indexed_rows": None, "families": None, "leads": None}
            try:
                families = family_doc_counts(self.case_dir.name)
                measured.update(families=families, indexed_rows=sum(families.values()))
            except Exception as exc:  # noqa: BLE001 - unavailable measurement stays explicit, never zero
                measured["index_error"] = str(exc)
            leads = brief.get("lead_counts") or {}
            if leads.get("error"):
                measured["lead_error"] = str(leads["error"])
            elif isinstance(leads.get("total"), int):
                measured["leads"] = leads["total"]
            else:
                measured["lead_error"] = "briefing did not supply lead_counts.total"
            self._append({"event": "inputs", "inputs": measured})

    def section(self) -> dict[str, Any]:
        with self._lock:
            available = (self._metered and not self._error and not self._unbound_calls
                         and not self._missing_history and not self._coverage_gap)
            calls = list(self._calls.values())
            finished = [c for c in calls if c["event"] in {"call_finished", "call_failed"}]
            return {
                "status": "available" if available else "unavailable",
                "reason": self._error or self._coverage_gap or (
                                          "earlier run has no native measurement" if self._missing_history else
                                          "calls occurred before run binding" if self._unbound_calls else
                                          "model has no native callback" if not self._metered else ""),
                "path": str(self.path.relative_to(self.case_dir)),
                "scope": "client invocations; message content characters; excludes HTTP retries and schema overhead",
                "calls": len(calls) if available else None,
                "prompt_chars": sum(c["prompt_chars"] for c in calls) if available else None,
                "finished": len(finished), "failed": sum(c["event"] == "call_failed" for c in finished),
                "pending": len(calls) - len(finished),
                "model_seconds_sum": sum(c["seconds"] for c in finished),
                "inputs": self._inputs,
            }


def bind(case_dir: Path, run_id: str, model: Any = None, *, resuming: bool = False,
         previous: dict[str, Any] | None = None) -> None:
    """Bind the existing run-recording scope; never infer a case from an active pointer."""
    from nexus.analysis.knowledge_record import current
    from nexus.langgraph.prompt_budget import TokenMeter

    record = current()
    if record is None:
        return
    if record.model_calls is not None:
        if not record.model_calls.matches(case_dir, run_id):
            raise ValueError("Model measurement is already bound to another case or run")
        return
    metered = record.model_meter_available or any(isinstance(cb, TokenMeter) for cb in
                                                 (getattr(model, "callbacks", None) or []))
    record.model_calls = ModelCalls(case_dir, run_id, metered=metered, unbound_calls=record.unbound_model_calls,
                                    resuming=resuming, previous=previous)


def section(case_dir: Path, run_id: str) -> dict[str, Any] | None:
    from nexus.analysis.knowledge_record import current

    record = current()
    calls = record.model_calls if record is not None else None
    return calls.section() if calls is not None and calls.matches(case_dir, run_id) else None


def note_inputs(case_dir: Path, brief: dict[str, Any]) -> None:
    from nexus.analysis.knowledge_record import current

    record = current()
    calls = record.model_calls if record is not None else None
    if calls is not None and calls.matches(case_dir):
        calls.inputs(brief)
