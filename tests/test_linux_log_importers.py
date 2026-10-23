"""Real tiny T18 Linux logs exercise content detection and importer lineage."""

from __future__ import annotations

from datetime import UTC
from pathlib import Path

import pytest

from nexus.ingest.detect import detect_format
from nexus.ingest.registry import get_registry
from nexus.ingest.schemas import ArtifactSource, ArtifactType

REPO = Path(__file__).resolve().parents[1]
T18 = REPO / "Evidence-files" / "_tiny" / "T18"
LINUX_LOGS = (
    "web01/var/log/anaconda.yum.log",
    "gw01/var/log/anaconda.yum.log",
    "gw01/var/log/dracut.log",
    "web01/var/log/httpd/access_log",
    "web01/var/log/httpd/error_log",
    "web01/var/log/httpd/ssl_access_log",
    "web01/var/log/httpd/ssl_error_log",
    "web01/var/log/httpd/ssl_request_log",
    "web01/var/log/vboxadd-install-x11.log",
    "gw01/var/log/vboxadd-install-x11.log",
    "web01/var/log/VBoxGuestAdditions-uninstall.log",
    "web01/var/log/VBoxGuestAdditions.log",
    "gw01/var/log/VBoxGuestAdditions-uninstall.log",
    "gw01/var/log/VBoxGuestAdditions.log",
    "web01/var/log/yum.log",
    "web01/var/log/yum.log-20130811",
    "gw01/var/log/yum.log",
    "gw01/var/log/yum.log-20130802",
)
UTMP_LOGS = (
    "web01/var/log/wtmp",
    "web01/var/log/btmp",
    "web01/var/log/btmp-20130811",
    "web01/var/log/lastlog",
    "gw01/var/log/wtmp",
    "gw01/var/log/btmp",
    "gw01/var/log/btmp-20130802",
    "gw01/var/log/lastlog",
)


def _evidence(relative_path: str) -> Path:
    path = T18 / relative_path
    if not path.is_file():
        pytest.skip("the staged T18 evidence set is not available")
    return path


@pytest.mark.parametrize("relative_path", LINUX_LOGS)
def test_real_t18_text_logs_are_detected_and_imported_with_lineage(relative_path: str):
    path = _evidence(relative_path)

    assert detect_format(path) is ArtifactSource.LINUX_LOG
    result = get_registry().import_path(path)

    assert result.success, result.errors
    assert result.source is ArtifactSource.LINUX_LOG
    assert result.parsed_lines > 0
    assert not result.errors
    assert all(artifact.raw["source_file"] == str(path) for artifact in result.artifacts)
    assert all("source_line" in artifact.raw for artifact in result.artifacts)


@pytest.mark.parametrize("relative_path", UTMP_LOGS)
def test_real_t18_binary_accounting_logs_are_parsed_without_text_conversion(relative_path: str):
    path = _evidence(relative_path)

    assert detect_format(path) is ArtifactSource.UTMP
    result = get_registry().import_path(path)

    assert result.success, result.errors
    assert result.source is ArtifactSource.UTMP
    assert result.parsed_lines > 0
    assert not result.errors
    assert all(artifact.raw["source_file"] == str(path) for artifact in result.artifacts)
    assert all("record_offset" in artifact.raw for artifact in result.artifacts)
    assert all(not artifact.ts_synthesized for artifact in result.artifacts)


def test_yum_yearless_timestamp_is_explicitly_assumed_on_real_evidence():
    path = _evidence("web01/var/log/yum.log")
    result = get_registry().import_path(path)

    assert result.success, result.errors
    assert result.artifacts
    artifact = result.artifacts[0]
    assert artifact.ts_year_assumed
    assert artifact.ts_tz_assumed
    assert artifact.raw["timestamp_text"].startswith("Aug 11 ")


def test_apache_access_timestamp_and_client_are_parsed_from_real_evidence():
    path = _evidence("web01/var/log/httpd/access_log")
    result = get_registry().import_path(path)

    assert result.success, result.errors
    artifact = result.artifacts[0]
    assert artifact.artifact_type is ArtifactType.HTTP
    assert artifact.source_ip == "172.16.62.42"
    assert artifact.timestamp == artifact.timestamp.replace(tzinfo=UTC)
    assert artifact.timestamp.isoformat() == "2013-08-29T14:24:00+00:00"
    assert not artifact.ts_synthesized


def test_apache_error_timezone_assumption_is_visible_on_real_evidence():
    path = _evidence("web01/var/log/httpd/error_log")
    result = get_registry().import_path(path)

    assert result.success, result.errors
    artifact = result.artifacts[0]
    assert artifact.ts_tz_assumed
    assert artifact.timestamp.isoformat() == "2013-08-29T07:12:45+00:00"
    which_result = next(item for item in result.artifacts if item.process_name == "which")
    assert which_result.action == "not_found"
    assert which_result.raw["command"] == "lcc"
    assert which_result.ts_synthesized


def test_dracut_timezone_and_date_are_parsed_from_real_evidence():
    path = _evidence("gw01/var/log/dracut.log")
    result = get_registry().import_path(path)

    assert result.success, result.errors
    assert result.artifacts[0].timestamp.isoformat() == "2013-04-06T03:01:31+00:00"
    assert not result.artifacts[0].ts_tz_assumed


def test_lastlog_preserves_the_record_uid_from_real_binary_evidence():
    path = _evidence("web01/var/log/lastlog")
    result = get_registry().import_path(path)

    assert result.success, result.errors
    assert len(result.artifacts) == 1
    assert result.artifacts[0].raw["uid"] == 0
    assert result.artifacts[0].raw["record_offset"] == 0
