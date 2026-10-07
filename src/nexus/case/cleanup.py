"""Delete a case completely: folder, DB rows and ES indexes.

One implementation, because the two places that delete cases had drifted:

* `nexus case clean` globbed ``CASE-*`` only (so ``INC-*`` survived), left the
  ES indexes behind and could not remove read-only evidence copies;
* `scripts/prune_cases.py` used ``shutil.rmtree(..., ignore_errors=True)``, which
  swallowed every read-only failure and still reported the case deleted, and it
  touched neither the DB nor ES.

The result was orphans: a folder that reappeared after every clean, a case the
DB still listed, and an index that outlived its case (reviewer, R1 / WO-R1F
step 0b). Each part is reported separately and a failure is a failure.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DeleteResult:
    """What each part of a case deletion did."""

    case_id: str
    parts: list[tuple[str, bool, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(good for _name, good, _detail in self.parts)

    def add(self, name: str, good: bool, detail: str) -> None:
        self.parts.append((name, good, detail))


def _clear_readonly(root: Path) -> None:
    """Make a case tree deletable.

    The tool lane stages evidence with ``shutil.copy2``, which carries the
    source file's ReadOnly attribute across — and the corpus' ``.evtx`` files
    are read-only. A read-only file cannot be unlinked on Windows, so ``rmtree``
    raises; that is the failure ``ignore_errors=True`` used to swallow.
    """
    with contextlib.suppress(OSError):
        for path in root.rglob("*"):
            if path.is_file():
                with contextlib.suppress(OSError):
                    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)


def delete_case_data(
    case_id: str,
    *,
    cases_root: Path,
    db_path: Path | None = None,
    drop_indexes: bool = True,
) -> DeleteResult:
    """Remove one case's ES indexes, folder and DB rows. Never raises."""
    result = DeleteResult(case_id)

    if drop_indexes:
        try:
            from nexus.langgraph.case_index import delete_index, es_url

            if not es_url():
                result.add("es index", True, "skipped (NEXUS_ES_URL unset)")
            else:
                docs = bool(delete_index(case_id).get("deleted"))
                events = False
                with contextlib.suppress(Exception):
                    from nexus.langgraph.timeline_events import delete_events_index

                    delete_events_index(case_id)
                    events = True
                result.add("es index", docs or events,
                           f"docs={docs} events={events}")
        except Exception as exc:  # noqa: BLE001 — reported, never silent
            result.add("es index", False, f"{type(exc).__name__}: {exc}")

    case_dir = Path(cases_root) / case_id
    if case_dir.is_dir():
        _clear_readonly(case_dir)
        try:
            shutil.rmtree(case_dir)
        except OSError as exc:
            result.add("folder", False, str(exc))
        else:
            gone = not case_dir.exists()
            result.add("folder", gone,
                       "removed" if gone else "still present after rmtree")
    else:
        result.add("folder", True, "already absent")

    try:
        from nexus.case import CaseManager

        mgr = CaseManager(Path(db_path) if db_path else Path(cases_root) / "cases.db")
        deleted = mgr.delete_case(case_id)
        result.add("db rows", True, "deleted" if deleted else "no row")
    except Exception as exc:  # noqa: BLE001
        result.add("db rows", False, f"{type(exc).__name__}: {exc}")

    return result
