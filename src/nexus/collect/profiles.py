"""Stage 0 collector profiles — disk (live IR spine) by default; full opts in."""

from __future__ import annotations

from nexus.collect.types import CollectOptions

WINDOWS_COLLECTORS = (
    "kansa",
    "sysinternals",
    "persistencesniper",
    "wevtutil",
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

# Live SSH/WinRM IR on current Windows 11 / modern Linux. Broader collectors
# stay on --profile full (skip with a reason; we fix unmaintained tools later).
DEFAULT_PROFILE = "disk"

PROFILES: dict[str, frozenset[str]] = {
    "full": frozenset(ALL_COLLECTORS),
    # Ship spine: collectors proven on current Windows 11 / Ubuntu. Broader /
    # unmaintained tools stay on --profile full (skip with a reason; fix later).
    "disk": frozenset({
        "sysinternals",
        "persistencesniper",
        "wevtutil",
        "kape",
        "velociraptor",
        "linux_volatile",
        "journal",
        "uac",
    }),
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
    key = (profile or DEFAULT_PROFILE).strip().lower()
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
    opts.kape = "kape" in enabled
    opts.orc = "orc" in enabled
    opts.memory = "winpmem" in enabled or "avml" in enabled
    opts.vr = "velociraptor" in enabled
    opts.linux_volatile = "linux_volatile" in enabled
    opts.journal = "journal" in enabled
    opts.uac = "uac" in enabled
    # UAC ir_triage is the industry IR profile (SANS-style live response).
    # UAC full is files/* bulk collection — only --profile full.
    opts.uac_profile = "full" if opts.profile == "full" else "ir_triage"
    return opts
