"""Email Date-field metadata controls, without authored message/event records.

Only date primitives exercise the existing complete time-field interface.
Actual captured-message retention is proved through the normal native lane.
"""
from datetime import UTC, datetime, timedelta, timezone
from email.utils import format_datetime

import pytest

from nexus.ingest.generic.email_import import EmailImporter


@pytest.mark.parametrize("zone", [UTC, timezone(timedelta(hours=5, minutes=30)), timezone(timedelta(hours=-8))])
def test_rfc_date_field_keeps_the_explicit_source_instant(zone):
    instant = datetime.now(UTC).replace(microsecond=0)
    source = format_datetime(instant.astimezone(zone))
    fields = EmailImporter.resolve_timestamp_fields(source)
    assert not fields["ts_synthesized"]
    assert fields["timestamp"].astimezone(UTC) == instant
    assert not fields["ts_tz_assumed"] and not fields["ts_year_assumed"]


def test_gmt_date_field_is_an_explicit_clock():
    instant = datetime.now(UTC).replace(microsecond=0)
    fields = EmailImporter.resolve_timestamp_fields(format_datetime(instant, usegmt=True))
    assert not fields["ts_synthesized"] and not fields["ts_tz_assumed"]
    assert fields["timestamp"].astimezone(UTC) == instant


def test_unknown_source_zone_remains_qualified_after_normalization():
    source_clock = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
    fields = EmailImporter.resolve_timestamp_fields(format_datetime(source_clock))
    assert not fields["ts_synthesized"] and fields["ts_tz_assumed"]
    assert fields["timestamp"] == source_clock.replace(tzinfo=UTC)


@pytest.mark.parametrize("form", ["datetime", "iso", "epoch"])
def test_preexisting_non_rfc_clock_forms_keep_their_contract(form):
    instant = datetime.now(UTC).replace(microsecond=0)
    value = {"datetime": instant, "iso": instant.isoformat(), "epoch": instant.timestamp()}[form]
    fields = EmailImporter.resolve_timestamp_fields(value)
    assert fields["timestamp"].astimezone(UTC) == instant
    assert not fields["ts_synthesized"] and not fields["ts_tz_assumed"] and not fields["ts_year_assumed"]


@pytest.mark.parametrize("value", [None, "not a date"])
def test_absent_or_invalid_date_remains_explicitly_synthesized(value):
    before = datetime.now(UTC)
    fields = EmailImporter.resolve_timestamp_fields(value)
    after = datetime.now(UTC)
    assert fields["ts_synthesized"]
    assert before <= fields["timestamp"] <= after
    assert not fields["ts_tz_assumed"] and not fields["ts_year_assumed"]
