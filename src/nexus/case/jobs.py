"""Persisted job table and durable background run execution (WP 13.6, T2-26, ER-03).

Runs are tracked in a persistent SQLite table so server restarts or portal disconnections
do not destroy run identity, checkpoints, or state. Interrupted runs can be resumed.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.case.records import records_db_path

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS persisted_jobs (
    job_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    run_id TEXT NOT NULL,
    status TEXT NOT NULL,
    question TEXT NOT NULL DEFAULT '',
    context_policy TEXT NOT NULL DEFAULT 'independent',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_persisted_jobs_case ON persisted_jobs(case_id);
CREATE INDEX IF NOT EXISTS idx_persisted_jobs_status ON persisted_jobs(status);
"""


def _connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or records_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(_SCHEMA)
    return conn


def create_job(
    case_id: str,
    mode: str,
    run_id: str,
    *,
    question: str = "",
    context_policy: str = "independent",
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Insert a new persisted job record."""
    job_id = f"JOB-{uuid.uuid4().hex[:12].upper()}"
    now = datetime.now(UTC).isoformat()
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO persisted_jobs (job_id, case_id, mode, run_id, status, question, context_policy, created_at, updated_at, error)
            VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?, NULL)
            """,
            (job_id, case_id, mode, run_id, question, context_policy, now, now),
        )
    return {
        "job_id": job_id,
        "case_id": case_id,
        "mode": mode,
        "run_id": run_id,
        "status": "queued",
        "question": question,
        "context_policy": context_policy,
        "created_at": now,
        "updated_at": now,
        "error": None,
    }


def update_job_status(
    job_id: str,
    status: str,
    *,
    error: str | None = None,
    db_path: Path | None = None,
) -> None:
    """Update job status and timestamp."""
    now = datetime.now(UTC).isoformat()
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE persisted_jobs
            SET status = ?, error = ?, updated_at = ?
            WHERE job_id = ?
            """,
            (status, error, now, job_id),
        )


def get_job(job_id: str, *, db_path: Path | None = None) -> dict[str, Any] | None:
    """Retrieve job by ID."""
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM persisted_jobs WHERE job_id = ?", (job_id,)).fetchone()
        return dict(row) if row is not None else None


def list_jobs(
    *,
    case_id: str | None = None,
    status: str | None = None,
    limit: int = 50,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """List jobs filtered by case and/or status."""
    query = "SELECT * FROM persisted_jobs"
    params: list[Any] = []
    clauses: list[str] = []
    if case_id:
        clauses.append("case_id = ?")
        params.append(case_id)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with _connect(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def reconcile_interrupted_jobs(*, db_path: Path | None = None) -> list[str]:
    """Mark any running jobs as interrupted on server startup.

    A job marked running that outlived its server process was interrupted;
    its checkpoint remains on disk ready for resume.
    """
    now = datetime.now(UTC).isoformat()
    reconciled: list[str] = []
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT job_id FROM persisted_jobs WHERE status = 'running'").fetchall()
        for r in rows:
            jid = r["job_id"]
            conn.execute(
                """
                UPDATE persisted_jobs
                SET status = 'interrupted', error = 'Server restarted during execution; checkpoint preserved for resume', updated_at = ?
                WHERE job_id = ?
                """,
                (now, jid),
            )
            reconciled.append(jid)
    if reconciled:
        log.info("Reconciled %d interrupted job(s) from previous server session: %s", len(reconciled), reconciled)
    return reconciled


def start_durable_run(
    case_dir: Path | str,
    mode: str,
    run_id: str,
    *,
    question: str = "",
    model: Any = None,
    resume: bool = False,
    context_policy: str = "independent",
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Create a persisted job record and launch execution in a tracked worker thread."""
    case_dir = Path(case_dir).resolve()
    job = create_job(
        case_dir.name,
        mode,
        run_id,
        question=question,
        context_policy=context_policy,
        db_path=db_path,
    )
    job_id = job["job_id"]

    def _worker() -> None:
        update_job_status(job_id, "running", db_path=db_path)
        try:
            if mode == "mode2":
                from nexus.modes.multi_role import run_mode2

                run_mode2(
                    case_dir,
                    question,
                    model=model,
                    run_id=run_id,
                    resume=resume,
                    context_policy=context_policy,
                )
            elif mode == "mode3":
                from nexus.modes.multi_agent import resume_mode3, run_mode3

                if resume:
                    resume_mode3(case_dir, run_id, model=model, context_policy=context_policy)
                else:
                    run_mode3(case_dir, question, model=model, run_id=run_id, context_policy=context_policy)
            else:
                raise ValueError(f"Unknown mode for durable execution: {mode}")
            update_job_status(job_id, "completed", db_path=db_path)
        except Exception as exc:  # noqa: BLE001 - job error is recorded in table
            log.exception("Durable job %s (%s) failed: %s", job_id, mode, exc)
            update_job_status(job_id, "failed", error=f"{type(exc).__name__}: {exc}"[:300], db_path=db_path)

    thread = threading.Thread(target=_worker, name=f"job-{job_id}", daemon=True)
    thread.start()
    return job
