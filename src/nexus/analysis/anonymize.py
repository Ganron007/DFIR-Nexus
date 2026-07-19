"""Reversible anonymization for LLM-bound text."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

AnonCategory = Literal["IP", "EMAIL", "USER", "HOST", "DOMAIN", "PATH", "CMD", "REG"]
AnonTokenCategory = AnonCategory | Literal["OTHER"]

SECRET_PLACEHOLDER = "[REDACTED_SECRET]"
TOKEN_RE = re.compile(r"ANON_(?:IP|EMAIL|USER|HOST|DOMAIN|PATH|CMD|REG|OTHER)_\d+", re.I)

NON_VICTIM_DOMAINS = frozenset({
    "nt", "authority", "service", "builtin", "workgroup", "hku", "hklm", "hkcu",
    "local", "windows", "system32", "users", "programdata", "execution", "persistence",
    "discovery", "lateral", "movement", "defender", "explorer", "malware", "tools",
})


@dataclass
class CustomEntity:
    value: str
    category: AnonTokenCategory


@dataclass
class AnonPolicy:
    enabled: bool = True
    categories: dict[AnonCategory, bool] = field(
        default_factory=lambda: dict.fromkeys(("IP", "EMAIL", "USER", "HOST", "DOMAIN", "PATH", "CMD", "REG"), True)
    )
    redact_secrets: bool = True


@dataclass
class KnownEntities:
    hosts: list[str] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)
    internal_domains: list[str] = field(default_factory=list)
    custom: list[CustomEntity] = field(default_factory=list)
    suppressed: list[str] = field(default_factory=list)


class Anonymizer:
    def __init__(self, policy: AnonPolicy, known: KnownEntities) -> None:
        self.policy = policy
        self.known = known
        self._to_token: dict[str, str] = {}
        self._to_real: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._suppressed = {s.lower() for s in known.suppressed}

    def _assign(self, category: AnonTokenCategory, real: str) -> str:
        if real.lower() in self._suppressed:
            return real
        key = f"{category}:{real.lower()}"
        if key in self._to_token:
            return self._to_token[key]
        self._counters[category] = self._counters.get(category, 0) + 1
        token = f"ANON_{category}_{self._counters[category]}"
        self._to_token[key] = token
        self._to_real[token.upper()] = real
        return token

    def discoveries(self) -> list[CustomEntity]:
        out: list[CustomEntity] = []
        seen: set[str] = set()
        for token, real in self._to_real.items():
            m = re.match(r"^ANON_([A-Z]+)_\d+$", token, re.I)
            cat = (m.group(1) if m else "OTHER")
            key = f"{cat}:{real.lower()}"
            if key in seen:
                continue
            seen.add(key)
            out.append(CustomEntity(real, cat))  # type: ignore[arg-type]
        return out

    def apply(self, text: str) -> str:
        if not self.policy.enabled:
            return text
        t = text
        for ent in sorted(self.known.custom, key=lambda e: len(e.value), reverse=True):
            if ent.value:
                t = re.sub(
                    rf"\b{re.escape(ent.value)}\b",
                    lambda m, c=ent.category: self._assign(c, m.group(0)),  # type: ignore[misc]
                    t,
                    flags=re.I,
                )
        if self.policy.redact_secrets:
            t = re.sub(
                r"\b(password|passwd|pwd|secret|api[_-]?key|token|authorization|bearer)\b(\s*[:=]\s*)(?:bearer\s+|basic\s+)?[\"']?([^\s\"'<>,;]{3,})",
                rf"\1\2{SECRET_PLACEHOLDER}",
                t,
                flags=re.I,
            )
        if self.policy.categories.get("USER"):
            t = re.sub(
                r"(?<![\\/:.\w])([A-Za-z][A-Za-z0-9.-]{1,14})\\([A-Za-z0-9._$-]{2,20})(?![\\/\w])",
                lambda m: self._assign("USER", f"{m.group(1)}\\{m.group(2)}"),
                t,
            )
        if self.policy.categories.get("EMAIL"):
            t = re.sub(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                lambda m: self._assign("EMAIL", m.group(0)),
                t,
            )
        if self.policy.categories.get("HOST"):
            for h in sorted(self.known.hosts, key=len, reverse=True):
                if len(h) >= 2:
                    t = re.sub(rf"\b{re.escape(h)}\b", lambda m: self._assign("HOST", m.group(0)), t, flags=re.I)
        if self.policy.categories.get("DOMAIN"):
            for d in sorted(self.known.internal_domains, key=len, reverse=True):
                if len(d) >= 2:
                    t = re.sub(rf"\b{re.escape(d)}\b", lambda m: self._assign("DOMAIN", m.group(0)), t, flags=re.I)
        if self.policy.categories.get("IP"):
            t = re.sub(
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                lambda m: self._assign("IP", m.group(0)) if is_internal_ip(m.group(0)) else m.group(0),
                t,
            )
        if self.policy.categories.get("CMD"):
            t = re.sub(
                r"(?<![A-Za-z0-9])(-(?:e|ec|enc|encodedcommand)\s+)([A-Za-z0-9+/]{16,}={0,2})",
                lambda m: m.group(1) + self._assign("CMD", m.group(2)),
                t,
                flags=re.I,
            )
        if self.policy.categories.get("REG"):
            t = re.sub(
                r"\bS-1-5-21(?:-\d{1,10}){4}\b",
                lambda m: self._assign("REG", m.group(0)),
                t,
                flags=re.I,
            )
        return t

    def restore(self, text: str) -> str:
        return TOKEN_RE.sub(lambda m: self._to_real.get(m.group(0).upper(), m.group(0)), text)

    def restore_deep(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.restore(value)
        if isinstance(value, list):
            return [self.restore_deep(v) for v in value]
        if isinstance(value, dict):
            return {k: self.restore_deep(v) for k, v in value.items()}
        return value


def is_internal_ip(ip: str) -> bool:
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    if not m:
        return False
    a, b = int(m.group(1)), int(m.group(2))
    if any(int(m.group(i)) > 255 for i in range(1, 5)):
        return False
    if a in (10, 127):
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 100 and 64 <= b <= 127:
        return True
    return False


def is_noise_domain(domain: str) -> bool:
    d = domain.lower().strip()
    if not d or "." in d:
        return not d
    return d in NON_VICTIM_DOMAINS


def derive_known_entities_from_artifacts(artifacts: list[Any]) -> KnownEntities:
    hosts: set[str] = set()
    accounts: set[str] = set()
    domains: set[str] = set()
    acct_re = re.compile(
        r"(?<![\\/:.\w])([A-Za-z][A-Za-z0-9.-]{1,14})\\([A-Za-z0-9._$-]{2,20})(?![\\/\w])"
    )
    for art in artifacts:
        host = getattr(art, "host", None) or (art.get("host") if isinstance(art, dict) else None)
        if host:
            hosts.add(str(host).strip())
        desc = getattr(art, "description", "") or (art.get("description", "") if isinstance(art, dict) else "")
        cmd = getattr(art, "command_line", "") or (art.get("command_line", "") if isinstance(art, dict) else "")
        text = f"{desc} {cmd}"
        for m in acct_re.finditer(text):
            acct = f"{m.group(1)}\\{m.group(2)}"
            dom = m.group(1).lower()
            if dom not in NON_VICTIM_DOMAINS:
                accounts.add(acct)
                domains.add(dom)
        user = getattr(art, "user", None) or (art.get("user") if isinstance(art, dict) else None)
        if user and "\\" in str(user):
            accounts.add(str(user))
            domains.add(str(user).split("\\")[0].lower())
    for h in hosts:
        if "." in h:
            domains.add(h.split(".", 1)[1].lower())
    return KnownEntities(
        hosts=sorted(hosts, key=len, reverse=True),
        accounts=sorted(accounts),
        internal_domains=sorted({d for d in domains if not is_noise_domain(d)}, key=len, reverse=True),
    )


def create_anonymizer(
    policy: AnonPolicy | None = None,
    known: KnownEntities | None = None,
) -> Anonymizer:
    return Anonymizer(policy or AnonPolicy(), known or KnownEntities())
