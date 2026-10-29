"""D486: the case digest's evidence classes come from the family registry, not from typed name lists.

Measured on the 22 tiny indexes (2026-10-29, `scratch/agent/digest_buckets.py`): the typed lists put T13-T16's
capture flows (`network`) and T13's BIND log under host, T14's OSSEC alerts under host, T15's two email messages
under host as `generic_jsonl` (so the digest told every mode "email archives: explicitly absent"), and T18's NetFlow
and utmp under host with auditd/authlog/linux_log in two classes. The family sets below are those indexes'.
"""
from __future__ import annotations

from nexus.langgraph.case_digest import _classify


def _present(classes: dict[str, list[str]]) -> dict[str, list[str]]:
    return {key: value for key, value in classes.items() if value}


def test_t13s_dns_log_and_flows_are_network_and_its_syslog_linux():
    classes = _classify(["bind", "network", "suricata", "syslog", "wireshark", "zeek"])
    assert _present(classes) == {"network": ["bind", "network", "suricata", "wireshark", "zeek"], "linux": ["syslog"]}


def test_t15s_email_rows_count_through_their_evidence_group():
    groups = [{"generic_jsonl", "email"}, {"network"}, {"wireshark"}, {"zeek"}, {"suricata"}]
    classes = _classify(["generic_jsonl", "network", "suricata", "wireshark", "zeek"], groups)
    assert classes["email"] == ["email"]
    assert "generic_jsonl" not in [name for names in classes.values() for name in names]


def test_t18s_netflow_is_network_and_its_linux_logs_linux_once():
    classes = _classify(["auditd", "authlog", "generic_csv", "linux_log", "nfdump", "syslog", "utmp"])
    assert _present(classes) == {"network": ["nfdump"],
                                 "linux": ["auditd", "authlog", "linux_log", "syslog", "utmp"]}


def test_t14s_ossec_alerts_are_siem_and_t19s_flows_cloud_and_network():
    assert _classify(["encoded_file", "network", "ossec", "suricata", "wireshark", "zeek"])["siem"] == ["ossec"]
    t19 = _classify(["aws_s3_access", "aws_vpc_flow", "cloudtrail"])
    assert t19["cloud"] == ["aws_s3_access", "aws_vpc_flow", "cloudtrail"] and t19["network"] == ["aws_vpc_flow"]


def test_a_memory_image_is_memory_whatever_its_tables_hold():
    assert _present(_classify(["memprocfs", "vol"])) == {"memory": ["memprocfs", "vol"]}
