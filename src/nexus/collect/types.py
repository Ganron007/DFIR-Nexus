"""Stage 0 collect types — no secrets in dumps."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

OsName = Literal["windows", "linux"]
TransportName = Literal["local", "ssh", "winrm"]
CollectorStatus = Literal["ok", "skipped", "failed", "planned"]


@dataclass
class AuthSpec:
    user: str = ""
    identity: str = ""  # SSH private key path
    password_env: str = "NEXUS_COLLECT_PASSWORD"
    port: int = 0  # 0 = default (22 ssh / 5985 winrm)

    def has_key(self) -> bool:
        return bool(self.identity) and Path(self.identity).is_file()

    def public_dict(self) -> dict[str, Any]:
        return {
            "user": self.user,
            "identity": "set" if self.has_key() else "",
            "password": "env" if self.password_env else "",
            "port": self.port or None,
        }


@dataclass
class HostSpec:
    os: OsName
    address: str = "localhost"
    hostname: str = ""
    transport: TransportName = "local"
    auth: AuthSpec = field(default_factory=AuthSpec)
    sudo: bool = False
    tsource: str = ""  # KAPE --tsource override (live C: or mounted image)


@dataclass
class CollectorStep:
    name: str
    status: CollectorStatus
    reason: str = ""
    path: str = ""
    seconds: float = 0.0
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class CollectOptions:
    """Default profile is *full*: every FOSS collector we can run.

    Examiners opt out with ``--no-*`` / ``--only`` / ``--profile disk|volatile``.
    Missing binaries become skipped steps with a reason — never a silent omit.
    """

    profile: str = "full"
    kansa: bool = True
    kape: bool = True
    kape_target: str = "!SANS_Triage"
    kape_module: str = "!EZParser"
    kape_remote_path: str = ""
    memory: bool = True
    orc: bool = True
    uac: bool = True
    uac_profile: str = "full"
    vr: bool = True
    vr_client_id: str = ""
    sysinternals: bool = True
    persistencesniper: bool = True
    hayabusa: bool = True
    suzaku: bool = True
    chainsaw: bool = True
    wevtutil: bool = True
    linux_volatile: bool = True
    journal: bool = True
    timeout_kape: int = 7200
    timeout_kansa: int = 3600
    timeout_orc: int = 7200
    timeout_linux: int = 7200
    timeout_memory: int = 1800
    timeout_probe: int = 30
    timeout_hayabusa: int = 3600
    timeout_vr: int = 1800


@dataclass
class HostResult:
    hostname: str
    address: str
    os: OsName
    transport: TransportName
    user: str
    steps: list[CollectorStep] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "address": self.address,
            "os": self.os,
            "transport": self.transport,
            "user": self.user,
            "collectors": [s.to_dict() for s in self.steps],
        }


@dataclass
class CollectManifest:
    schema: str = "nexus.collect.v1"
    started: str = ""
    finished: str = ""
    examiner: str = ""
    pack_dir: str = ""
    dry_run: bool = False
    hosts: list[HostResult] = field(default_factory=list)
    next_hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "started": self.started,
            "finished": self.finished,
            "examiner": self.examiner,
            "pack_dir": self.pack_dir,
            "dry_run": self.dry_run,
            "hosts": [h.to_dict() for h in self.hosts],
            "next": self.next_hint,
        }
