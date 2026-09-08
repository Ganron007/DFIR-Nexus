"""Entity extraction from N4 hit rows — users, hosts, IPs, processes, paths.

Feeds the Explore entity-pivot panel: click an entity to filter the view.
Extraction is regex-based over row text (CSV rows are not column-parsed),
so entities are best-effort and always verified against the row text.
"""

from __future__ import annotations

import re
from collections import Counter

_NOISE_IPS = frozenset({"0.0.0.0", "127.0.0.1", "255.255.255.255", "::", "::1"})
_NOISE_USERS = frozenset({
    "nt authority\\system", "nt authority\\network service",
    "nt authority\\local service", "nt authority\\anonymous logon",
})

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"\b[A-Za-z0-9][\w.-]{1,30}\\[\w.$-]{2,32}\b")
_EXE_RE = re.compile(r"\b[\w][\w .-]{0,50}\.(?:exe|dll|ps1|bat|cmd|js|vbs)\b", re.IGNORECASE)
_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s,;\"']{2,120}")


def extract_entities(texts: list[str], top: int = 12) -> dict[str, dict[str, int]]:
    """Extract entity counts from hit-row texts.

    Returns {"ips": {...}, "users": {...}, "processes": {...}, "paths": {...}}
    with the most frequent first.
    """
    ips: Counter[str] = Counter()
    users: Counter[str] = Counter()
    procs: Counter[str] = Counter()
    paths: Counter[str] = Counter()

    for text in texts:
        for ip in _IP_RE.findall(text):
            if ip not in _NOISE_IPS:
                ips[ip] += 1
        for user in _USER_RE.findall(text):
            if user.lower() not in _NOISE_USERS:
                users[user] += 1
        for exe in _EXE_RE.findall(text):
            procs[exe.lower()] += 1
        for p in _PATH_RE.findall(text)[:2]:
            paths[p] += 1

    return {
        "ips": dict(ips.most_common(top)),
        "users": dict(users.most_common(top)),
        "processes": dict(procs.most_common(top)),
        "paths": dict(paths.most_common(top)),
    }
