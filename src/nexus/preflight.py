"""Case-start preflight gate — WIRING-PLAN 5.2 (split out of Phase 5).

`nexus doctor --gate` runs :func:`run_gate` and exits non-zero with an ordered
fix list. The same function is importable, so the portal's Case Setup step can
call it later without shelling out.

Two severities, because a blanket "fail on anything" is noise:

``required``
    Without this the run would be **wrong or refused** — a hard fail.
``warn``
    Degraded but working: a deterministic fallback exists, or the item is
    optional/offline-first. Reported, never fatal.

Mode-aware by design. Modes 2 and 3 hard-refuse to run on the CSV backend
(``stop_reason=elasticsearch_required``), so for those cases Elasticsearch and a
built case index are ``required``; for Mode 1 they are ``warn`` because the
tools lane and the CSV backend are a legitimate degraded path.

Never raises: a probe that explodes becomes a failed item with the exception
text, because a preflight that crashes tells the examiner nothing.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REQUIRED = "required"
WARN = "warn"

#: Canonical modes that cannot run without Elasticsearch (mode 3 = multi-agent).
ES_REQUIRED_MODES = (2, 3)
#: Canonical modes whose runtime is model-driven (2 = multi-role, 3 = multi-agent).
LLM_REQUIRED_MODES = (2, 3)

_FIX_ES = "start Elasticsearch (docker compose up -d nexus-es) or unset NEXUS_ES_URL for the CSV backend"
_FIX_INDEX = "nexus index rebuild --case <case-dir>"
_FIX_LLM = "set NEXUS_LLM_BASE_URL / NEXUS_LLM_MODEL / NEXUS_LLM_API_KEY in .env"
_FIX_RAG = "nexus data rag-download (or accept the deterministic fallback)"
_FIX_CASE = "nexus case init \"<name>\" then nexus case activate <id>"
_FIX_KB = "set NEXUS_KB_DIR (optional — the KB is inert without it and never leaves the host)"


@dataclass
class GateItem:
    """One preflight observation."""

    name: str
    ok: bool
    detail: str = ""
    fix: str = ""
    severity: str = REQUIRED

    @property
    def fatal(self) -> bool:
        return self.severity == REQUIRED and not self.ok

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "detail": self.detail,
            "fix": self.fix,
            "severity": self.severity,
        }


@dataclass
class GateReport:
    """Ordered preflight result. ``ok`` is False only on a required failure."""

    items: list[GateItem] = field(default_factory=list)
    mode: int | None = None
    mode_label: str = ""
    case_id: str = ""
    case_dir: str = ""

    @property
    def failures(self) -> list[GateItem]:
        return [i for i in self.items if i.fatal]

    @property
    def warnings(self) -> list[GateItem]:
        return [i for i in self.items if not i.ok and i.severity == WARN]

    @property
    def ok(self) -> bool:
        return not self.failures

    def add(self, name: str, ok: bool, detail: str = "", fix: str = "", severity: str = REQUIRED) -> GateItem:
        item = GateItem(name=name, ok=ok, detail=detail, fix=fix, severity=severity)
        self.items.append(item)
        return item

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "mode": self.mode,
            "mode_label": self.mode_label,
            "case_id": self.case_id,
            "case_dir": self.case_dir,
            "failures": [i.to_dict() for i in self.failures],
            "warnings": [i.to_dict() for i in self.warnings],
            "items": [i.to_dict() for i in self.items],
        }


def _guard(report: GateReport, name: str, fn, *, fix: str = "", severity: str = REQUIRED):
    """Run a probe; a crashing probe becomes a failed item, never an exception."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - a crashing probe is a finding
        report.add(name, False, f"probe failed: {exc}"[:200], fix, severity)
        return None
    if isinstance(result, GateItem):
        report.items.append(result)
        return result
    if isinstance(result, tuple):
        ok, detail = result[0], result[1] if len(result) > 1 else ""
        report.add(name, bool(ok), str(detail)[:200], fix, severity)
        return bool(ok)
    report.add(name, bool(result), "", fix, severity)
    return bool(result)


def _resolve_case() -> tuple[str, Path | None]:
    """(case_id, case_dir) for the active case; empty id when none is active."""
    try:
        from nexus.case.outputs import resolve_active_case_dir
    except Exception:  # noqa: BLE001
        return "", None
    try:
        case_dir = resolve_active_case_dir()
    except Exception:  # noqa: BLE001
        return "", None
    if not case_dir:
        return "", None
    path = Path(case_dir)
    return path.name, path


def _case_mode(case_dir: Path | None) -> int | None:
    if not case_dir:
        return None
    meta_file = case_dir / "CASE.yaml"
    if not meta_file.is_file():
        return None
    try:
        import yaml

        meta = yaml.safe_load(meta_file.read_text(encoding="utf-8")) or {}
        if not isinstance(meta, dict):
            return None
        from nexus.langgraph.mode_mapping import resolve_stored_mode

        raw = meta.get("investigation_mode")
        if raw in (None, ""):
            return None
        return resolve_stored_mode(raw, meta.get("mode_scheme"))
    except Exception:  # noqa: BLE001
        return None


def _index_state(case_dir: Path) -> dict[str, Any]:
    """`analysis/index_state.json` as a dict; {} when the case was never indexed."""
    state = case_dir / "analysis" / "index_state.json"
    if not state.is_file():
        return {}
    try:
        import json

        data = json.loads(state.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _es_probe() -> tuple[bool, str]:
    from nexus.langgraph.case_index import es_available, es_url

    if not es_url():
        return False, "NEXUS_ES_URL unset — CSV pack backend only"
    if es_available():
        return True, f"{es_url()} reachable"
    return False, f"configured but unreachable: {es_url()}"


def _llm_probe() -> tuple[bool, str]:
    base = (os.environ.get("NEXUS_LLM_BASE_URL") or "").strip()
    model = (os.environ.get("NEXUS_LLM_MODEL") or "").strip()
    key = "set" if (os.environ.get("NEXUS_LLM_API_KEY") or "").strip() else "unset"
    if not base or not model:
        return False, "unset — deterministic fallback active (no base/model)"
    return True, f"model={model} base={base} key={key}"


def _rag_probe() -> tuple[bool, str, bool]:
    """(index present, detail, embedder resolvable)."""
    from nexus.tools.rag import _get_index_dir, resolve_embedding_source

    idx = _get_index_dir()
    present = (idx / "chroma").is_dir()
    src = resolve_embedding_source()
    detail = f"{src['model_id']} via {src['source']}"
    if not present:
        detail = f"{idx / 'chroma'} missing; {detail}"
    return present, detail, src["source"] in ("hf_hub_cache", "explicit_dir")


def _knowledge_probe() -> tuple[bool, str]:
    from nexus.knowledge.loader import synced_source_manifest

    feeds = synced_source_manifest()
    total = sum(int(f.get("count") or 0) for f in feeds)
    empty = [str(f.get("name")) for f in feeds if int(f.get("count") or 0) <= 0]
    if not feeds:
        return False, "no synced knowledge feeds"
    if empty:
        return False, f"{len(feeds)} feed(s), {total} entries; EMPTY: {', '.join(sorted(empty))}"
    return True, f"{len(feeds)} feed(s), {total} entries"


def _kb_probe() -> tuple[bool, str]:
    from nexus.tools.kb import _kb_py, kb_root

    kb = _kb_py()
    if not kb or not kb_root():
        return False, "KB not configured (NEXUS_KB_DIR unset and default KB absent)"
    return True, f"{kb}"


def _mcp_probe() -> tuple[bool, str]:
    from nexus.app import create_server

    return len(create_server()._tool_manager._tools) > 0, ""  # type: ignore[union-attr]


def _triage_probe() -> tuple[bool, str]:
    triage = Path.home() / ".nexus" / "data" / "triage"
    return triage.is_dir() and any(triage.iterdir()), str(triage)


def run_gate(
    *,
    case_dir: Path | None = None,
    mode: int | None = None,
    deep: bool = False,
) -> GateReport:
    """Run the case-start gate.

    ``case_dir``/``mode`` default to the active case and its stored mode.
    ``deep`` adds the slow probes (RAG model load / embedder query).
    """
    report = GateReport()

    resolved_id, resolved_dir = _resolve_case()
    if case_dir is None:
        case_dir = resolved_dir
    if case_dir is not None:
        report.case_id = resolved_id or Path(case_dir).name
        report.case_dir = str(case_dir)
    if mode is None:
        mode = _case_mode(case_dir)
    report.mode = mode
    if mode is not None:
        try:
            from nexus.langgraph.mode_mapping import mode_label

            report.mode_label = mode_label(mode)
        except Exception:  # noqa: BLE001
            report.mode_label = f"mode {mode}"

    es_required = mode in ES_REQUIRED_MODES
    llm_required = mode in LLM_REQUIRED_MODES
    es_sev = REQUIRED if es_required else WARN
    llm_sev = REQUIRED if llm_required else WARN

    # ── process + catalog ──
    report.add(
        "python>=3.12",
        sys.version_info >= (3, 12),
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "install Python 3.12+",
    )
    _guard(report, "mcp catalog", _mcp_probe, fix="pip install -e '.[all]'")

    # ── case ──
    if case_dir is None:
        report.add("active case", False, "no active case", _FIX_CASE)
    else:
        writable = os.access(case_dir, os.W_OK)
        report.add(
            "case writable",
            writable,
            f"{case_dir}{'' if writable else ' (read-only)'}",
            "fix filesystem permissions on the case directory",
        )
        if mode is None:
            report.add(
                "case mode",
                True,
                "not stored — pre-mode case, any mode may run",
                "",
                WARN,
            )
        else:
            report.add("case mode", True, f"stored mode {mode} ({report.mode_label})")

    # ── elasticsearch + case index ──
    es_ok = _guard(report, "elasticsearch", _es_probe, fix=_FIX_ES, severity=es_sev)
    if es_ok and case_dir is not None:
        state = _index_state(case_dir)
        if not state:
            report.add(
                "case index",
                not es_required,
                "never indexed (analysis/index_state.json absent)",
                _FIX_INDEX,
                es_sev,
            )
        else:
            docs = int(state.get("docs") or 0)
            capped = bool(state.get("capped"))
            report.add(
                "case index",
                docs > 0 and not capped,
                f"docs={docs:,} capped={capped} index={state.get('index', '?')} "
                f"indexed_at={state.get('indexed_at', '?')}",
                _FIX_INDEX if (docs <= 0 or capped) else "",
                es_sev,
            )
    elif es_ok and case_dir is None:
        report.add("case index", True, "skipped — no case", "", WARN)

    if not es_ok and es_required:
        report.add(
            "csv backend refusal",
            False,
            "Mode 2/3 refuse to run on the CSV backend (stop_reason=elasticsearch_required)",
            _FIX_ES,
        )
    elif not es_ok and mode is None:
        report.add(
            "csv backend fallback",
            True,
            "mode unknown (no case) — Mode 1 accepts the CSV backend, Modes 2/3 will require ES",
            _FIX_ES,
            WARN,
        )
    elif not es_ok:
        report.add(
            "csv backend fallback",
            True,
            "Mode 1 accepts the CSV backend — tools lane and DRAFT staging still work",
            _FIX_ES,
            WARN,
        )

    # ── model ──
    _guard(report, "llm", _llm_probe, fix=_FIX_LLM, severity=llm_sev)

    # ── rag + embedder ──
    try:
        present, detail, embedder_ok = _rag_probe()
        report.add("rag index", present, detail, _FIX_RAG, WARN)
        report.add("embedding model", embedder_ok, detail, _FIX_RAG, WARN)
    except Exception as exc:  # noqa: BLE001
        report.add("rag index", False, f"probe failed: {exc}"[:200], _FIX_RAG, WARN)
        report.add("embedding model", False, "unknown (rag probe failed)", _FIX_RAG, WARN)

    if deep:
        _guard(
            report,
            "rag preflight",
            lambda: __import__("nexus.tools.rag_preflight", fromlist=["rag_preflight"]).rag_preflight(),
            fix=_FIX_RAG,
            severity=WARN,
        )

    # ── knowledge backbone (9.10/9.11) ──
    if es_required:
        _guard(
            report,
            "knowledge sources",
            _knowledge_probe,
            fix="python scripts/sync_knowledge_sources.py --apply",
        )
    else:
        _guard(
            report,
            "knowledge sources",
            _knowledge_probe,
            fix="python scripts/sync_knowledge_sources.py --apply",
            severity=WARN,
        )
    _guard(report, "kb configured", _kb_probe, fix=_FIX_KB, severity=WARN)

    # ── optional ──
    _guard(report, "triage baseline", _triage_probe, fix="nexus data triage-download", severity=WARN)

    return report


def format_report(report: GateReport) -> list[str]:
    """Human lines: status marks, then the ordered fix list for every failure."""
    lines = [f"case-start gate — mode {report.mode or '?'} ({report.mode_label or 'unset'})"]
    if report.case_id:
        lines.append(f"case: {report.case_id}")
    for item in report.items:
        mark = "ok" if item.ok else "FAIL" if item.severity == REQUIRED else "warn"
        suffix = f" — {item.detail}" if item.detail else ""
        lines.append(f"  [{mark}] {item.name}{suffix}")
    if report.failures:
        lines.append("")
        lines.append(f"BLOCKED: {len(report.failures)} required check(s) failed. Fix in this order:")
        for n, item in enumerate(report.failures, 1):
            lines.append(f"  {n}. {item.name}: {item.fix or item.detail or 'see above'}")
    if report.warnings:
        lines.append("")
        lines.append(f"degraded but not blocking: {len(report.warnings)} warning(s)")
        for item in report.warnings:
            lines.append(f"  - {item.name}: {item.fix or item.detail}")
    lines.append("")
    lines.append("gate: PASS" if report.ok else "gate: FAIL")
    return lines
