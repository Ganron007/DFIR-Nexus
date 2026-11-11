"""Tests for T2-26: Persisted job table and durable execution (WP 13.6)."""
from __future__ import annotations

from pathlib import Path

from nexus.case.jobs import (
    create_job,
    get_job,
    list_jobs,
    reconcile_interrupted_jobs,
    update_job_status,
)


def test_create_and_update_job(tmp_path: Path):
    db_path = tmp_path / "cases.db"
    job = create_job("CASE-A", "mode2", "RUN-01", question="Check persistence", db_path=db_path)
    assert job["job_id"].startswith("JOB-")
    assert job["status"] == "queued"
    assert job["case_id"] == "CASE-A"
    assert job["mode"] == "mode2"

    retrieved = get_job(job["job_id"], db_path=db_path)
    assert retrieved is not None
    assert retrieved["status"] == "queued"

    update_job_status(job["job_id"], "running", db_path=db_path)
    running = get_job(job["job_id"], db_path=db_path)
    assert running["status"] == "running"

    update_job_status(job["job_id"], "completed", db_path=db_path)
    completed = get_job(job["job_id"], db_path=db_path)
    assert completed["status"] == "completed"


def test_reconcile_interrupted_jobs(tmp_path: Path):
    db_path = tmp_path / "cases.db"
    job1 = create_job("CASE-A", "mode2", "RUN-01", db_path=db_path)
    job2 = create_job("CASE-A", "mode3", "RUN-02", db_path=db_path)

    update_job_status(job1["job_id"], "running", db_path=db_path)
    update_job_status(job2["job_id"], "completed", db_path=db_path)

    reconciled = reconcile_interrupted_jobs(db_path=db_path)
    assert job1["job_id"] in reconciled
    assert job2["job_id"] not in reconciled

    interrupted = get_job(job1["job_id"], db_path=db_path)
    assert interrupted["status"] == "interrupted"
    assert "restarted" in interrupted["error"]


def test_list_jobs_filtering(tmp_path: Path):
    db_path = tmp_path / "cases.db"
    create_job("CASE-1", "mode2", "R1", db_path=db_path)
    create_job("CASE-2", "mode3", "R2", db_path=db_path)

    c1_jobs = list_jobs(case_id="CASE-1", db_path=db_path)
    assert len(c1_jobs) == 1
    assert c1_jobs[0]["case_id"] == "CASE-1"

    all_jobs = list_jobs(db_path=db_path)
    assert len(all_jobs) == 2
