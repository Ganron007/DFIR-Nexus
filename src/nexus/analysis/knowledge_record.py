"""The knowledge a mode run used, recorded where it is chosen (TA-5.2, the T2-38 slice).

A run record named its skills in Modes 2/3 and nothing in Mode 1, and no record named a playbook or an executed
analytic: the R1 coverage matrix read every playbook "not recorded". The selection points note what they choose, in
the run that chose it: skill ranking (`knowledge.skills.skills_for` / `retrieve_skills`, with the score and the reasons
the ranking itself gave), playbook matching (`query_pack._family_matched_playbooks`, with the families that matched,
and the playbooks the intake names), and the behavioural analytics the lead builder executes (`leads.
behavioural_analytics_leads`, with each one's hit count or why it did not run). Each mode wraps its run in
:func:`recording` and writes :meth:`KnowledgeRecord.section` as the record's ``knowledge``. Nothing is re-derived
after the run; outside a recorded run the notes do nothing.
"""
from __future__ import annotations

import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

_CURRENT: ContextVar[KnowledgeRecord | None] = ContextVar("nexus_knowledge_record", default=None)


class KnowledgeRecord:
    """One run's knowledge, merged: a skill or playbook chosen several times is one entry with every reason."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._skills: dict[tuple[str, str], dict[str, Any]] = {}
        self._playbooks: dict[str, dict[str, Any]] = {}
        self._analytics: dict[str, dict[str, Any]] = {}
        # Native call measurement shares this run's lifecycle and ContextVar;
        # it is kept out of the knowledge section and written as its own field.
        self.model_calls: Any = None
        self.model_meter_available = False
        self.unbound_model_calls = 0

    def skill(self, skill_id: str, version: str, score: int, why: Iterable[str]) -> None:
        with self._lock:
            entry = self._skills.setdefault((skill_id, version), {
                "skill": skill_id, "version": version, "best_score": score, "why": [], "times_chosen": 0})
            entry["best_score"] = max(entry["best_score"], score)
            entry["times_chosen"] += 1
            entry["why"].extend(reason for reason in why if reason not in entry["why"])

    def playbook(self, slug: str, why: str) -> None:
        with self._lock:
            entry = self._playbooks.setdefault(slug, {"playbook": slug, "why": [], "times_chosen": 0})
            entry["times_chosen"] += 1
            if why not in entry["why"]:
                entry["why"].append(why)

    def analytic(self, analytic_id: str, name: str, *, hits: int | None, outcome: str) -> None:
        """``outcome`` is "ran" with its ``hits``, or why the analytic did not run."""
        with self._lock:
            self._analytics[analytic_id] = {"analytic": analytic_id, "name": name, "outcome": outcome, "hits": hits}

    def merge(self, section: dict[str, Any] | None) -> None:
        """Take a resumed run's earlier section back in, so the record it writes keeps what was chosen before."""
        section = section or {}
        with self._lock:
            for entry in section.get("skills") or []:
                key = (str(entry.get("skill") or ""), str(entry.get("version") or ""))
                if not key[0]:
                    continue
                score = int(entry.get("best_score") or 0)
                merged = self._skills.setdefault(key, {
                    "skill": key[0], "version": key[1], "best_score": score, "why": [], "times_chosen": 0})
                merged["best_score"] = max(merged["best_score"], score)
                merged["times_chosen"] += int(entry.get("times_chosen") or 0)
                merged["why"].extend(r for r in entry.get("why") or [] if r not in merged["why"])
            for entry in section.get("playbooks") or []:
                slug = str(entry.get("playbook") or "")
                if not slug:
                    continue
                merged = self._playbooks.setdefault(slug, {"playbook": slug, "why": [], "times_chosen": 0})
                merged["times_chosen"] += int(entry.get("times_chosen") or 0)
                merged["why"].extend(r for r in entry.get("why") or [] if r not in merged["why"])
            for entry in section.get("analytics") or []:
                analytic_id = str(entry.get("analytic") or "")
                if analytic_id:
                    self._analytics.setdefault(analytic_id, dict(entry))

    def section(self) -> dict[str, Any]:
        with self._lock:
            return {
                "skills": sorted((dict(e, why=list(e["why"])) for e in self._skills.values()),
                                 key=lambda e: (-e["best_score"], e["skill"])),
                "playbooks": sorted((dict(e, why=list(e["why"])) for e in self._playbooks.values()),
                                    key=lambda e: e["playbook"]),
                "analytics": sorted((dict(e) for e in self._analytics.values()),
                                    key=lambda e: (e["hits"] is None, -(e["hits"] or 0), e["analytic"])),
            }


@contextmanager
def recording() -> Iterator[KnowledgeRecord]:
    """Record the knowledge chosen inside this block (and the tasks it starts) for one run."""
    record = KnowledgeRecord()
    token = _CURRENT.set(record)
    try:
        yield record
    finally:
        _CURRENT.reset(token)


def current() -> KnowledgeRecord | None:
    """The recording run's record, or None outside a recorded run."""
    return _CURRENT.get()


def note_skill(skill_id: str, version: str, score: int, why: Iterable[str]) -> None:
    record = _CURRENT.get()
    if record is not None and skill_id:
        record.skill(skill_id, version, score, why)


def note_playbook(slug: str, why: str) -> None:
    record = _CURRENT.get()
    if record is not None and slug:
        record.playbook(slug, why)


def note_analytic(analytic_id: str, name: str, *, hits: int | None, outcome: str) -> None:
    record = _CURRENT.get()
    if record is not None and analytic_id:
        record.analytic(analytic_id, name, hits=hits, outcome=outcome)
