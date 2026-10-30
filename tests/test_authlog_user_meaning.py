"""Only explicit user-bearing log grammar identifies an auth principal (T18)."""
from pathlib import Path

import pytest

from nexus.ingest.linux.authlog import AuthLogImporter


@pytest.fixture(params=["web01", "gw01"])
def actual_auth_rows(request):
    source = Path(__file__).parent / "fixtures" / "d514_authlog" / request.param / "secure"
    assert AuthLogImporter.can_handle(source)
    return list(AuthLogImporter().parse(source))


def test_session_close_keeps_the_explicit_authenticated_user(actual_auth_rows):
    closed = [row for row in actual_auth_rows if "session closed for user root" in row.description]
    assert closed
    assert all(row.user == "root" and row.action == "session_close" for row in closed)


def test_session_open_keeps_the_explicit_authenticated_user(actual_auth_rows):
    opened = [row for row in actual_auth_rows if "session opened for user root" in row.description]
    assert opened
    assert all(row.user == "root" and row.action == "session_open" for row in opened)


def test_ssh_disconnect_does_not_invent_a_user():
    source = Path(__file__).parent / "fixtures" / "d514_authlog" / "web01" / "secure"
    rows = list(AuthLogImporter().parse(source))
    disconnect = [row for row in rows if row.description.startswith("Received disconnect from ")]
    assert len(disconnect) == 1
    assert disconnect[0].user is None
    assert disconnect[0].source_ip == "172.16.62.42"
    # The preceding actual successful authentication still identifies its user.
    success = [row for row in rows if row.description.startswith("Accepted password for root from ")]
    assert len(success) == 1
    assert success[0].user == "root" and success[0].action == "logon_success"
