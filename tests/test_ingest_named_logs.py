"""A log is read by what its lines are, not by its name or a comma (sample S03, 2026-10-18).

S03's mail server log is named smtp.log, a Zeek log name: detection sent it to the Zeek importer, which read 0 rows
of 75. With the name hint confirmed by the importer, its commas then made it a CSV whose first line was the header.
Its BIND query log was read by no importer at all. The lines below are S03's, verbatim (SEC503 scenario 1).
"""
from __future__ import annotations

from pathlib import Path

from nexus.ingest.detect import detect_format
from nexus.ingest.registry import get_registry
from nexus.ingest.schemas import ArtifactSource, ArtifactType

SMTP = [
    "Jul 12 09:50:56 services dovecot: imap-login: Login: user=<ecoli>, method=PLAIN, rip=10.10.10.44, "
    "lip=10.10.10.5, mpid=23796, session=<sTZ6ZXE3R8AKCgos>",
    "Jul 12 09:51:10 services dovecot: imap-login: Login: user=<ecoli>, method=PLAIN, rip=10.10.10.44, "
    "lip=10.10.10.5, mpid=23812, session=<fqRNZnE3ScAKCgos>",
    "Jul 12 09:51:36 services dovecot: imap-login: Login: user=<tburr>, method=PLAIN, rip=10.10.10.42, "
    "lip=10.10.10.5, mpid=23842, session=<PxrWZ3E3KMAKCgoq>",
]
BIND = [
    "12-Jul-2016 09:45:59.115 client 10.10.10.5#42935 (google.com): query: google.com IN A +E (10.10.10.5)",
    "12-Jul-2016 09:49:46.413 client 10.10.10.44#61936 (isatap.pwnd.biz): query: isatap.pwnd.biz IN A + "
    "(10.10.10.5)",
    "12-Jul-2016 09:49:46.604 client 10.10.10.44#56345 (_ldap._tcp.dc._msdcs.pwnd.biz): query: "
    "_ldap._tcp.dc._msdcs.pwnd.biz IN SRV + (10.10.10.5)",
]


def _write(tmp_path: Path, name: str, lines: list[str]) -> Path:
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _import(path: Path):
    source = detect_format(path)
    return source, get_registry().import_path(path, source=source).artifacts


def test_a_mail_servers_syslog_named_like_a_zeek_log_is_syslog(tmp_path):
    source, rows = _import(_write(tmp_path, "smtp.log", SMTP))
    assert source == ArtifactSource.SYSLOG
    assert len(rows) == 3, "every line is a row; none is taken for a header"
    assert rows[0].host == "services" and rows[0].process_name == "dovecot"
    assert rows[0].description.startswith("imap-login: Login: user=<ecoli>")


def test_a_real_zeek_log_of_that_name_is_still_zeek(tmp_path):
    zeek = ["#separator \\x09", "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p",
            "1468316996.1\tC1\t10.10.10.44\t49152\t10.10.10.5\t25"]
    assert detect_format(_write(tmp_path, "smtp.log", zeek)) == ArtifactSource.ZEEK


def test_a_bind_query_log_is_read_query_by_query(tmp_path):
    source, rows = _import(_write(tmp_path, "bind.log", BIND))
    assert source == ArtifactSource.BIND
    assert len(rows) == 3
    first = rows[0]
    assert first.artifact_type == ArtifactType.DNS
    assert first.timestamp.isoformat() == "2016-07-12T09:45:59.115000+00:00"
    assert (first.source_ip, first.source_port, first.dest_ip) == ("10.10.10.5", 42935, "10.10.10.5")
    assert (first.raw["query"], first.raw["qtype"], first.raw["flags"]) == ("google.com", "A", "+E")
    assert rows[2].raw["qtype"] == "SRV" and rows[2].raw["query"] == "_ldap._tcp.dc._msdcs.pwnd.biz"
    assert not first.iocs, "a queried name is not an indicator by being queried"


def test_a_csv_with_a_header_is_not_taken_for_syslog(tmp_path):
    csv_lines = ["Time,Host,Message", "Jul 12 09:50:56,services,login"]
    assert detect_format(_write(tmp_path, "export.csv", csv_lines)) != ArtifactSource.SYSLOG
