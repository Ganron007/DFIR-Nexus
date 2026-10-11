"""The retry's summary counts each status as itself (WO-TA item 12; honest reporting, 2026-10-11).

Found on the fresh lane run of CASE-C5B04D31: the retry reported "91 of 92 job(s) now OK" for a ledger of
69 OK, 21 SKIP, 1 BLOCKED and 1 FAIL, because every row that was not FAIL counted as OK.
"""

from __future__ import annotations

from nexus.cli.lane_retry_cmd import retry_summary_line


def test_each_status_is_counted_as_itself():
    ledger = (
        [{"status": "OK"}] * 69
        + [{"status": "SKIP"}] * 21
        + [{"status": "BLOCKED"}]
        + [{"status": "FAIL"}]
    )
    assert retry_summary_line(ledger) == (
        "Retry complete: 69 OK, 21 SKIP, 1 BLOCKED, 1 FAIL of 92 job(s)."
    )


def test_a_clean_ledger_has_no_blocked_or_fail_rows():
    assert retry_summary_line([{"status": "OK"}, {"status": "OK"}]) == (
        "Retry complete: 2 OK, 0 SKIP, 0 BLOCKED, 0 FAIL of 2 job(s)."
    )
