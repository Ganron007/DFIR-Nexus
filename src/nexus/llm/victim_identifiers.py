"""The case's own identifiers, read from its index, for LLM egress (D192, operator 2026-10-15).

Rule Five: victim identifiers are anonymized before AI analysis; adversary IOCs are preserved.
The regex anonymizer could not tell the two apart by shape, so it tokenized everything dotted,
pathed or hex: on CASE-C5B04D31 the model read ``powershell.exe`` as ``{{HOST_24}}``, every path
as ``{{PATH_n}}`` and every hash as ``{{HASH_n}}``. The victim's identifiers are known to the case
instead, and are read from authoritative columns of its index:

- **hosts**: the EVTX ``Computer`` column, the LNK/JumpList ``Hostname``, the logon
  ``WorkstationName``, and the machine accounts (``DEV01$``) of the victim's domains;
- **domains**: every logon domain one of whose accounts has a domain or machine SID
  (``S-1-5-21-...``). ``NT AUTHORITY``, ``Builtin``, ``Window Manager`` and ``WORKGROUP`` never
  have one, so no list of well-known names is typed here;
- **user names**: the accounts of those domains whose RID is 1000 or more. A built-in account
  (Administrator, RID 500) names no one and stays visible.

The engine is ``nexus.analysis.anonymize`` (the victim-aware design): those identifiers, emails,
internal IPv4 addresses and the domain part of a SID are tokenized as ``ANON_<KIND>_<n>``; file
names, paths, command lines, hashes, public addresses and external domains reach the model.

The identifiers and the tokens issued for them persist in ``analysis/egress_identifiers.json``
in the case, so a token means the same value in every call. It stays on disk. When the index
cannot be read, ``case_engine`` returns None and egress keeps the shape-based anonymizer: a
failure keeps more out of the model, never less.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import tempfile
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.analysis.anonymize import (
    TOKEN_RE,
    AnonPolicy,
    Anonymizer,
    CustomEntity,
    KnownEntities,
)

log = logging.getLogger(__name__)

IDENTIFIERS_FILE = "egress_identifiers.json"

#: Columns that name the machine a row came from or talked to.
HOST_FIELDS = (
    "fields.Computer.kw",
    "fields.Hostname.kw",
    "fields.HostName.kw",
    "ecs.winlog.event_data.WorkstationName",
)
_EVENT_DATA = "ecs.winlog.event_data."
#: A domain or machine SID; its last sub-authority is the RID.
_DOMAIN_SID = re.compile(r"^S-1-5-21-\d+-\d+-\d+-(\d+)$", re.IGNORECASE)
#: Placeholders the columns carry, and the loopback names, which identify no one.
_NOT_A_NAME = frozenset({"", "-", "localhost", "127.0.0.1", "::1"})
#: The first RID Windows gives an account it did not build in.
_FIRST_USER_RID = 1000

_LOCK = threading.Lock()
_WARNED: set[str] = set()


def egress_policy() -> AnonPolicy:
    """What egress tokenizes: victim identifiers, never evidence content.

    ``CMD`` (an ``-EncodedCommand`` payload) is evidence the model must read, not a person or a
    machine, so it is off. ``PATH`` has no rule in the engine: paths pass, and the user name inside
    one is a known user name.
    """
    policy = AnonPolicy(user_shape_requires_known=True)
    policy.categories["CMD"] = False
    policy.categories["PATH"] = False
    return policy


def known_from_values(hosts: Iterable[str], principals: Iterable[tuple[str, str, str]]) -> KnownEntities:
    """The identifiers in a set of host names and (domain, account, SID) triples.

    Pure, so the rule is tested without an index. A host's DNS suffix is a victim domain, and its
    first label a host in its own right (``rd01.shieldbase.com`` also gives ``rd01``).
    """
    host_set: set[str] = set()
    domains: set[str] = set()
    users: set[str] = set()
    for raw in hosts:
        name = str(raw or "").strip()
        if name.lower() in _NOT_A_NAME:
            continue
        host_set.add(name)
        if "." in name and not name.replace(".", "").isdigit():
            short, suffix = name.split(".", 1)
            host_set.add(short)
            domains.add(suffix)
    for domain, account, sid in principals:
        match = _DOMAIN_SID.match(str(sid or "").strip())
        if not match:
            continue
        domain = str(domain or "").strip()
        account = str(account or "").strip()
        if domain.lower() not in _NOT_A_NAME:
            domains.add(domain)
        if account.endswith("$"):
            if account[:-1]:
                host_set.add(account[:-1])
        elif account and int(match.group(1)) >= _FIRST_USER_RID:
            users.add(account)
    return KnownEntities(
        hosts=_one_per_spelling(host_set),
        internal_domains=_one_per_spelling(domains),
        custom=[CustomEntity(u, "USER") for u in _one_per_spelling(users)],
    )


def _one_per_spelling(values: set[str]) -> list[str]:
    """One value per case-insensitive spelling (matching ignores case), longest first."""
    seen: dict[str, str] = {}
    for value in sorted(values):
        seen.setdefault(value.lower(), value)
    return sorted(seen.values(), key=lambda v: (-len(v), v.lower()))


def _terms(client: Any, index: str, field: str) -> list[str]:
    body = {"size": 0, "aggs": {"v": {"terms": {"field": field, "size": 1000}}}}
    resp = client.post(f"/{index}/_search", json=body)
    if resp.status_code >= 400:
        return []
    return [str(b["key"]) for b in resp.json().get("aggregations", {}).get("v", {}).get("buckets", [])]


def _principals(client: Any, index: str, side: str) -> list[tuple[str, str, str]]:
    sources = [
        {"d": {"terms": {"field": f"{_EVENT_DATA}{side}DomainName"}}},
        {"u": {"terms": {"field": f"{_EVENT_DATA}{side}UserName"}}},
        {"s": {"terms": {"field": f"{_EVENT_DATA}{side}UserSid"}}},
    ]
    out: list[tuple[str, str, str]] = []
    after: dict[str, Any] | None = None
    for _page in range(50):  # 50 x 1,000 distinct triples; a domain has far fewer accounts
        composite: dict[str, Any] = {"size": 1000, "sources": sources}
        if after:
            composite["after"] = after
        resp = client.post(f"/{index}/_search", json={"size": 0, "aggs": {"p": {"composite": composite}}})
        if resp.status_code >= 400:
            break
        agg = resp.json().get("aggregations", {}).get("p", {})
        out.extend((b["key"]["d"], b["key"]["u"], b["key"]["s"]) for b in agg.get("buckets", []))
        after = agg.get("after_key")
        if not after:
            break
    return out


def derive_known_entities(case_id: str) -> KnownEntities | None:
    """The case's identifiers, read from its index; None when the index cannot be read.

    None, too, when the index names no host at all: without one the case's machines cannot be
    told from anything else, and the caller keeps the shape-based anonymizer.
    """
    from nexus.langgraph.case_index import IndexMissing, _client, index_name

    try:
        index = index_name(case_id)
        with _client() as client:
            if client.head(f"/{index}").status_code != 200:
                return None
            hosts = [h for field in HOST_FIELDS for h in _terms(client, index, field)]
            principals = _principals(client, index, "Target") + _principals(client, index, "Subject")
    except IndexMissing:
        return None  # no ES configured: the fallback is expected, not an error
    except Exception as exc:  # noqa: BLE001 - an unreadable index means the fallback, logged once
        if case_id not in _WARNED:
            _WARNED.add(case_id)
            log.warning("egress identifiers for %s could not be read (%s); the shape-based "
                        "anonymizer is used", case_id, exc)
        return None
    known = known_from_values(hosts, principals)
    return known if known.hosts else None


def _path(case_dir: Path) -> Path:
    return Path(case_dir) / "analysis" / IDENTIFIERS_FILE


def _load(case_dir: Path) -> dict[str, Any]:
    try:
        data = json.loads(_path(case_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(case_dir: Path, data: dict[str, Any]) -> None:
    """Atomic replace: a half-written file would lose every token issued before it."""
    path = _path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        os.close(fd)
        Path(tmp).write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _index_built_at(case_dir: Path) -> str:
    """When the case index was last built, so identifiers follow a rebuild."""
    try:
        state = json.loads((Path(case_dir) / "analysis" / "index_state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    return str(state.get("indexed_at") or "") if isinstance(state, dict) else ""


def _known_to_json(known: KnownEntities) -> dict[str, list[str]]:
    return {"hosts": list(known.hosts), "internal_domains": list(known.internal_domains),
            "users": [c.value for c in known.custom if c.category == "USER"]}


def _known_from_json(data: dict[str, Any]) -> KnownEntities:
    return KnownEntities(
        hosts=[str(h) for h in data.get("hosts") or []],
        internal_domains=[str(d) for d in data.get("internal_domains") or []],
        custom=[CustomEntity(str(u), "USER") for u in data.get("users") or []],
    )


def _known_for(case_dir: Path) -> KnownEntities | None:
    """The identifiers on file, re-read from the index after it is rebuilt."""
    data = _load(case_dir)
    built = _index_built_at(case_dir)
    if isinstance(data.get("known"), dict) and data.get("index_built_at", "") == built:
        return _known_from_json(data["known"])
    known = derive_known_entities(Path(case_dir).name)
    if known is None:
        return None
    with _LOCK:
        data = _load(case_dir)
        data.update({"version": 1, "known": _known_to_json(known), "index_built_at": built,
                     "derived_at": datetime.now(UTC).isoformat()})
        data.setdefault("tokens", {})
        _write(case_dir, data)
    return known


def _engine(known: KnownEntities, tokens: dict[str, str]) -> Anonymizer:
    """An engine that keeps every token already issued for this case."""
    engine = Anonymizer(egress_policy(), known)
    engine.seed(tokens)
    return engine


class CaseEgress:
    """Tokenize and restore one case's victim identifiers."""

    def __init__(self, case_dir: Path, known: KnownEntities) -> None:
        self.case_dir = Path(case_dir)
        self.known = known

    def anonymize(self, text: str) -> str:
        return self.anonymize_many([text])[0]

    def anonymize_many(self, texts: list[str]) -> list[str]:
        with _LOCK:
            data = _load(self.case_dir)
            tokens = dict(data.get("tokens") or {})
            engine = _engine(self.known, tokens)
            out = [engine.apply(text) for text in texts]
            issued = engine.tokens()
            if issued != tokens:
                data["tokens"] = issued
                _write(self.case_dir, data)
        return out


def case_engine(case_dir: Path | None) -> CaseEgress | None:
    """The victim-aware egress of a case, or None to keep the shape-based anonymizer."""
    if case_dir is None:
        return None
    known = _known_for(Path(case_dir))
    return CaseEgress(Path(case_dir), known) if known is not None else None


def restore_victim_tokens(text: str, case_dir: Path | None) -> str:
    """Put a case's identifiers back into a model reply. Reads the file only, never the index."""
    if case_dir is None or not text or not TOKEN_RE.search(text):
        return text
    tokens = {str(k).upper(): str(v) for k, v in (_load(Path(case_dir)).get("tokens") or {}).items()}
    if not tokens:
        return text
    return TOKEN_RE.sub(lambda m: tokens.get(m.group(0).upper(), m.group(0)), text)
