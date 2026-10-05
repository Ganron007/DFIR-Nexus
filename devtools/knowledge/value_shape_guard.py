"""The KR2c rule-1 guard: a value of the wrong KIND for its column.

The WO's own table says it directly:

  | IPs / ports | IP/port columns, **only for IP- or port-shaped values** |
  | protocols / product names / column names / plugin names | **never** an IP, port, host or process field; they go to `text.wc` |

The R0' defects were all this rule broken by a shape-blind resolution:

  `ics_ot:asset_and_zone_inventory`  "Modbus/DNP3/PLC"      -> `dest_ip`
  `network_session:byte_asymmetry`   "bytes/orig_bytes"     -> `source_ip`
  `ics_ot:plc_hmi_evidence`          "PLC log"/"HMI event"  -> `host`
  `linux_compromise:process_memory_check` "pslist/malfind"  -> `process_name`
  `email_phishing:execution_chain`   interpreters as the PARENT

This module holds the guard as DATA - what kind of value each typed column carries, and
the patterns that make a value the wrong kind - so the converter can refuse a clause
and fall back to `text.wc` with a recorded reason, which is what the WO asks for.
"""
from __future__ import annotations

import re
from functools import lru_cache

#: The kinds a typed column can carry. Anything else must go to `text.wc`.
IP_COLUMNS = frozenset({"dest_ip", "source_ip", "ip_src", "ip_dst", "remotehost",
                        "localaddress", "destination_ip", "source_address"})
PORT_COLUMNS = frozenset({"dest_port", "source_port", "port", "lport", "rport"})
PROCESS_COLUMNS = frozenset({"process_name", "parent_process", "image_path",
                             "executable_info"})
#: `host` holds a HOSTNAME, not a description of what was collected from a device.
#: "PLC log" / "HMI event" / "alarm" are the `ics_ot:plc_hmi_evidence` values that
#: were searched in `host` and could never match.
HOST_COLUMNS = frozenset({"host", "hostname", "computer", "computername",
                          "dnsname", "destinationhostname", "workstation"})

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6 = re.compile(r"^[0-9a-f:]*:[0-9a-f:.]*$", re.I)
_PORT = re.compile(r"^\d{1,5}$")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
                       r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", re.I)

#: Words that name a PROTOCOL, a PRODUCT or a COLUMN - never an IP, port, host or
#: process. From the WO's own table; the same vocabulary the reviewer sampled.
NOT_AN_IP_OR_PORT = frozenset({
    "modbus", "dnp3", "scada", "plc", "hmi", "historian", "purdue", "level 1",
    "level 2", "level 3", "s7comm", "profinet", "ethernet/ip", "opc", "opcua",
    "bytes", "orig_bytes", "resp_bytes", "res_bytes", "sent", "received", "packets",
    "pslist", "malfind", "psscan", "netscan", "psxview", "getsids", "procdump",
    "mimikatz", "wce", "pwdump", "gsecdump", "lazagne", "sharphound", "rubeus",
    "kape", "velociraptor", "chainsaw", "hayabusa", "zircolite", "deepbluecli",
    "evtxecmd", "mftecmd", "lecmd", "jlecmd", "recmd", "amcacheparser", "pecmd",
    "sbcmd", "sbecmd", "thumbcache", "appcompat", "shimcache", "bitsadmin",
})

#: Words that name a DEVICE or EVENT, not a hostname. The column holds a host name;
#: a description of what was collected is not one.
NOT_A_HOST = frozenset({
    "plc log", "hmi event", "alarm", "controller", "firmware", "operator action",
    "diagnostic buffer", "configuration backup", "device", "zone", "conversation",
    "traffic", "boundary", "asset", "controller log", "plc program",
})

#: Words that name a PROCESS, not a file path or a process image.
NOT_A_PROCESS = frozenset({
    "pslist", "malfind", "psscan", "netscan", "psxview", "volatility", "plugin",
    "kmem", "/proc", "memfd", "/dev/shm", "memory region", "anonymous memory",
})


def value_is_ip_like(value: str) -> bool:
    v = str(value or "").strip()
    if not v or v.lower() in NOT_AN_IP_OR_PORT:
        return False
    return bool(_IPV4.match(v) or (_IPV6.match(v) and ":" in v))


def value_is_port_like(value: str) -> bool:
    v = str(value or "").strip()
    if not v or v.lower() in NOT_AN_IP_OR_PORT:
        return False
    return bool(_PORT.match(v) and int(v) <= 65535)


def value_is_host_like(value: str) -> bool:
    v = str(value or "").strip().lower()
    if not v or v in NOT_A_HOST:
        return False
    # "PLC log" / "HMI event" are two words describing a collected artifact, and a
    # hostname has no space. Any value with whitespace is a description, not a host.
    if any(ch.isspace() for ch in v):
        return False
    if _IPV4.match(v) or (_IPV6.match(v) and ":" in v):
        return True
    return bool(_HOSTNAME.match(v))


def value_is_process_like(value: str) -> bool:
    v = str(value or "").strip().lower()
    if not v or v in NOT_A_PROCESS:
        return False
    return bool(re.match(r"^[\w .-]+\.(exe|dll|sys|com|scr|bat|cmd|ps1)$", v)) or v.endswith(
        ("\\", "/")) is False and bool(re.match(r"^[\w .-]{3,}$", v))


@lru_cache(maxsize=1)
def typed_columns() -> dict[str, str]:
    """column -> the kind of value it carries."""
    out: dict[str, str] = {}
    for c in IP_COLUMNS:
        out[c] = "ip"
    for c in PORT_COLUMNS:
        out[c] = "port"
    for c in PROCESS_COLUMNS:
        out[c] = "process"
    for c in HOST_COLUMNS:
        out[c] = "host"
    return out


def compatible(column: str, value: str) -> bool:
    """Whether `value` may be asserted against `column`.

    False means the value is of the wrong kind - the clause must not be built, and the
    term goes to `text.wc` with `es_text_only_reason` saying so. The WO's shape guards
    "raise" on exactly this; here the fallback is the WO's own recorded outcome.
    """
    col = str(column or "").lower()
    col = col[7:] if col.startswith("fields.") else col
    col = col[:-3] if col.endswith(".kw") else col
    kind = typed_columns().get(col)
    if kind is None:
        return True  # an untyped/text column accepts anything
    if kind == "ip":
        return value_is_ip_like(value)
    if kind == "port":
        return value_is_port_like(value)
    if kind == "process":
        return value_is_process_like(value)
    if kind == "host":
        return value_is_host_like(value)
    return True


if __name__ == "__main__":
    cases = [
        ("dest_ip", "Modbus"), ("dest_ip", "DNP3"), ("dest_ip", "192.168.77.10"),
        ("source_ip", "bytes"), ("source_ip", "orig_bytes"),
        ("source_ip", "203.0.113.99"),
        ("host", "PLC log"), ("host", "HMI event"), ("host", "ws01.corp.local"),
        ("process_name", "pslist"), ("process_name", "malfind"),
        ("process_name", "cmd.exe"), ("process_name", "powershell.exe"),
    ]
    for col, val in cases:
        print(f"  {col:14s} {val!r:22s} -> "
              f"{'clause' if compatible(col, val) else 'text.wc'}")
