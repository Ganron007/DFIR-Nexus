"""The SIFT MCP restarts through its systemd unit when the unit is installed, and starts detached otherwise (2026-10-13).

Boot persistence depends on this: a restart through setup must not leave a second, unmanaged server on the port.
"""
from __future__ import annotations

from nexus.cli.sift_cmd import MCP_UNIT, mcp_start_command


def test_a_host_with_the_unit_restarts_the_server_through_systemd():
    cmd = mcp_start_command(True)
    assert f"sudo -n systemctl restart {MCP_UNIT}" in cmd
    assert "setsid nohup" not in cmd


def test_a_host_without_the_unit_starts_the_server_detached_as_before():
    cmd = mcp_start_command(False)
    assert "setsid nohup .venv/bin/python -m nexus serve --http --host 0.0.0.0 --port 4508" in cmd
    assert "systemctl" not in cmd


def test_both_paths_stop_whatever_holds_the_port_first():
    for unit_managed in (True, False):
        cmd = mcp_start_command(unit_managed)
        assert "grep ':4508'" in cmd and "kill" in cmd
        assert cmd.index("kill") < cmd.index("sleep 12")
