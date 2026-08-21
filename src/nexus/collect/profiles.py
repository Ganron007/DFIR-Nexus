"""Stage 0 collector profiles — full by default; examiner opts out."""

from __future__ import annotations

from nexus.collect.types import CollectOptions

WINDOWS_COLLECTORS = (
    "kansa",
    "sysinternals",
    "persistencesniper",
    "wevtutil",
    "hayabusa",
    "suzaku",
    "chainsaw",
    "kape",
    "orc",
    "winpmem",
    "velociraptor",
)

LINUX_COLLECTORS = (
    "linux_volatile",
    "journal",
    "uac",
    "avml",
    "velociraptor",
)

ALL_COLLECTORS = WINDOWS_COLLECTORS + tuple(c for c in LINUX_COLLECTORS if c not in WINDOWS_COLLECTORS)

PROFILES: dict[str, frozenset[str]] = {
    "full": frozenset(ALL_COLLECTORS),
    "disk": frozenset(ALL_COLLECTORS) - frozenset({"winpmem", "avml"}),
    "volatile": frozenset({
        "kansa",
        "sysinternals",
        "persistencesniper",
        "wevtutil",
        "linux_volatile",
        "journal",
        "velociraptor",
    }),
}

_ALIASES = {
    "dfir_orc": "orc",
    "dfir-orc": "orc",
    "orc": "orc",
    "memory": "winpmem",
    "winpmem": "winpmem",
    "vr": "velociraptor",
    "velociraptor": "velociraptor",
    "psniper": "persistencesniper",
    "persistence-sniper": "persistencesniper",
}


def parse_collector_list(raw: str) -> list[str]:
    names: list[str] = []
    for part in (raw or "").split(","):
        token = part.strip().lower()
        if not token:
            continue
        names.append(_ALIASES.get(token, token))
    bad = [n for n in names if n not in set(ALL_COLLECTORS)]
    if bad:
        raise ValueError(
            f"Unknown collector(s): {', '.join(bad)}. "
            f"Known: {', '.join(ALL_COLLECTORS)}"
        )
    return names


def enabled_set(
    profile: str,
    *,
    only: str = "",
    disable: list[str] | None = None,
) -> set[str]:
    key = (profile or "full").strip().lower()
    if key not in PROFILES:
        raise ValueError(f"--profile must be full, disk, or volatile (got {profile!r})")
    enabled = set(PROFILES[key])
    if only.strip():
        enabled = set(parse_collector_list(only))
    for name in disable or []:
        enabled.discard(_ALIASES.get(name, name))
    return enabled


def apply_enabled(opts: CollectOptions, enabled: set[str]) -> CollectOptions:
    opts.kansa = "kansa" in enabled
    opts.sysinternals = "sysinternals" in enabled
    opts.persistencesniper = "persistencesniper" in enabled
    opts.wevtutil = "wevtutil" in enabled
    opts.hayabusa = "hayabusa" in enabled
    opts.suzaku = "suzaku" in enabled
    opts.chainsaw = "chainsaw" in enabled
    opts.kape = "kape" in enabled
    opts.orc = "orc" in enabled
    opts.memory = "winpmem" in enabled or "avml" in enabled
    opts.vr = "velociraptor" in enabled
    opts.linux_volatile = "linux_volatile" in enabled
    opts.journal = "journal" in enabled
    opts.uac = "uac" in enabled
    opts.uac_profile = "full" if opts.profile in {"full", "disk"} else "ir_triage"
    return opts
