"""One machine under several names, read from its own event logs (D212).

A machine renamed during its life logs each era under the name it had: CASE-C5B04D31's host was
built as `tpl-packer`, first booted as `rd01` and joined to the domain as `rd01.shieldbase.com`.
Every mode read those names as different hosts; the case's DRAFTs called `tpl-packer` a separate
lateral-movement tier and `rd01` a second host carrying the same beacon.

The proof that two names are one machine is in the log itself. An event channel numbers its
records in one sequence per log file, so when the records logged under one name continue, in the
same channel, the records logged under the previous name, the log is the same and so is the
machine: Security record 12965 was the last under `tpl-packer` and 12968 the first under `rd01`.
A name whose records restart (a separate log) is not linked. Forwarded events are excluded: that
channel holds other machines' records.

A machine also acts under its own account (D468). A domain-joined Windows computer logs on to the network, runs its
services and applies policy as its computer account, its name followed by `$`. T22-R1z3d's Mode 3 read
`BASE-RD-01$`'s network logons and its service install on base-rd-01.shieldbase.lan as an outside actor. A `$` account
whose name is a host's first label is paired with that host, from the index's typed users and hosts.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

#: Channels that hold other machines' records.
FORWARDED = frozenset({"forwardedevents"})
#: How far apart, in record numbers and in time, the last record under one name and the first under
#: the next may be. A rename takes a reboot; the case's own gaps were 1 to 12 records and seconds.
MAX_RECORD_GAP = 64
MAX_TIME_GAP_S = 86_400

_CACHE = "analysis/host_identity.json"
#: The cached identity's shape: 2 adds the machine accounts (D468). A cache of another shape is recomputed.
CACHE_SCHEMA = 2
#: The typed fields that hold a row's account and a row's host (D470/D471 type them for every producer).
USER_FIELDS = ("user", "ecs.user.name", "ecs.user.target.name")
HOST_FIELDS = ("host", "ecs.host.name")


def _ts(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _record(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def link_names(edges: list[dict[str, Any]]) -> dict[str, Any]:
    """The machines the edges prove, and the renames that prove them.

    ``edges`` holds one item per (channel, name): ``channel``, ``name`` and the first and last
    record under that name, ``first_ts``/``first_record``/``last_ts``/``last_record``.
    """
    by_channel: dict[str, list[dict[str, Any]]] = {}
    eras: dict[str, dict[str, Any]] = {}
    for edge in edges:
        name = str(edge.get("name") or "").strip()
        channel = str(edge.get("channel") or "").strip()
        first, last = _ts(edge.get("first_ts")), _ts(edge.get("last_ts"))
        if not name or not channel or first is None or last is None:
            continue
        era = eras.setdefault(name.lower(), {"name": name, "first": first, "last": last})
        era["first"], era["last"] = min(era["first"], first), max(era["last"], last)
        if channel.lower() not in FORWARDED:
            by_channel.setdefault(channel, []).append(
                {**edge, "name": name, "first": first, "last": last,
                 "first_id": _record(edge.get("first_record")), "last_id": _record(edge.get("last_record"))})
    proofs: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for channel, items in by_channel.items():
        for a in items:
            for b in items:
                if a["name"].lower() == b["name"].lower() or a["last_id"] is None or b["first_id"] is None:
                    continue
                gap = b["first_id"] - a["last_id"]
                seconds = (b["first"] - a["last"]).total_seconds()
                if 0 < gap <= MAX_RECORD_GAP and 0 <= seconds <= MAX_TIME_GAP_S:
                    proofs.setdefault((a["name"].lower(), b["name"].lower()), []).append(
                        {"channel": channel, "last_record": a["last_id"], "first_record": b["first_id"]})
    parent: dict[str, str] = {}

    def root(key: str) -> str:
        while parent.get(key, key) != key:
            key = parent[key]
        return key

    for a, b in proofs:
        parent[root(b)] = root(a)
    groups: dict[str, list[str]] = {}
    for key in {k for pair in proofs for k in pair}:
        groups.setdefault(root(key), []).append(key)
    machines = []
    for keys in groups.values():
        ordered = sorted(keys, key=lambda k: (eras[k]["first"], eras[k]["last"]))
        # Each rename is a name and the next one; a link that skips a name is implied by the steps.
        steps = [(a, b) for a, b in zip(ordered, ordered[1:], strict=False) if (a, b) in proofs]
        machines.append({
            "names": [eras[k]["name"] for k in ordered],
            "eras": [{"name": eras[k]["name"], "first": _iso(eras[k]["first"]),
                      "last": _iso(eras[k]["last"])} for k in ordered],
            "renames": [
                {"from": eras[a]["name"], "to": eras[b]["name"],
                 "proof": sorted(proofs[(a, b)], key=_channel_order)}
                for a, b in (steps or [pair for pair in proofs if pair[0] in keys])
            ],
        })
    machines.sort(key=lambda m: m["eras"][0]["first"])
    return {"machines": machines, "channels_checked": len(by_channel)}


#: The channels every Windows machine keeps, shown first as a rename's proof.
_CORE_CHANNELS = ("security", "system", "application")


def _channel_order(proof: dict[str, Any]) -> tuple[int, str]:
    channel = str(proof.get("channel") or "")
    low = channel.lower()
    return (_CORE_CHANNELS.index(low) if low in _CORE_CHANNELS else len(_CORE_CHANNELS), low)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def channel_edges(case_dir: Path) -> list[dict[str, Any]]:
    """The first and last record under each name in each event channel, from the case index."""
    from nexus.langgraph.case_index import _client, index_name

    def bound(order: str) -> dict[str, Any]:
        return {"top_hits": {"size": 1, "sort": [{"ts": order}],
                             "_source": ["ts", "ecs.winlog.record_id"]}}

    body = {
        "size": 0,
        "query": {"bool": {"filter": [{"exists": {"field": "ecs.winlog.record_id"}},
                                      {"exists": {"field": "ts"}}]}},
        "aggs": {"channel": {"terms": {"field": "ecs.winlog.channel", "size": 200}, "aggs": {
            "name": {"terms": {"field": "ecs.host.name", "size": 100},
                     "aggs": {"first": bound("asc"), "last": bound("desc")}}}}},
    }
    with _client() as client:
        response = client.post(f"/{index_name(Path(case_dir).name)}/_search", json=body)
    response.raise_for_status()
    edges: list[dict[str, Any]] = []
    for channel in response.json().get("aggregations", {}).get("channel", {}).get("buckets", []):
        for name in channel.get("name", {}).get("buckets", []):
            first = (name["first"]["hits"]["hits"] or [{}])[0].get("_source") or {}
            last = (name["last"]["hits"]["hits"] or [{}])[0].get("_source") or {}
            edges.append({
                "channel": channel["key"], "name": name["key"], "records": name["doc_count"],
                "first_ts": first.get("ts"), "last_ts": last.get("ts"),
                "first_record": ((first.get("ecs") or {}).get("winlog") or {}).get("record_id"),
                "last_record": ((last.get("ecs") or {}).get("winlog") or {}).get("record_id"),
            })
    return edges


def pair_machine_accounts(accounts: dict[str, int], hosts: list[str]) -> list[dict[str, Any]]:
    """Each `$` account whose name is a host's first label, paired with that host (D468).

    ``accounts`` maps a typed account value (`shieldbase\\BASE-RD-01$`, `BASE-RD-01$`) to its row count; the name is
    what follows the domain separator. ``hosts`` are typed host names. An account no host's first label matches
    (another machine's, or a managed service account) is not paired.
    """
    by_label: dict[str, list[str]] = {}
    for host in hosts:
        name = str(host or "").strip()
        if name:
            by_label.setdefault(name.split(".", 1)[0].lower(), []).append(name)
    pairs: dict[str, dict[str, Any]] = {}
    for value, rows in accounts.items():
        account = str(value or "").strip().rsplit("\\", 1)[-1]
        if len(account) < 2 or not account.endswith("$"):
            continue
        names = by_label.get(account[:-1].lower())
        if not names:
            continue
        key = account.lower()
        # The host is named by its longest form (the domain name over the bare one). The account keeps the event data's
        # own spelling: the envelope `user` is stored lower-cased.
        pair = pairs.setdefault(key, {"account": account, "host": max(names, key=len), "forms": [], "rows": 0})
        if pair["account"] == pair["account"].lower() and account != account.lower():
            pair["account"] = account
        pair["forms"] = sorted({*pair["forms"], str(value)})
        pair["rows"] += int(rows or 0)
    return sorted(pairs.values(), key=lambda p: (-p["rows"], p["account"].lower()))


def machine_accounts(case_dir: Path) -> list[dict[str, Any]]:
    """The case's computer accounts paired with their hosts, from the index's typed users and hosts."""
    from nexus.langgraph.case_index import _client, index_name

    aggs: dict[str, Any] = {}
    for i, field in enumerate(USER_FIELDS):
        # A `$` at the end, in Lucene's regular-expression syntax (a class, so no character is an operator).
        aggs[f"u{i}"] = {"terms": {"field": field, "include": ".*[$]", "size": 10000}}
    for i, field in enumerate(HOST_FIELDS):
        aggs[f"h{i}"] = {"terms": {"field": field, "size": 10000}}
    with _client() as client:
        response = client.post(f"/{index_name(Path(case_dir).name)}/_search",
                               json={"size": 0, "track_total_hits": False, "aggs": aggs})
    response.raise_for_status()
    found = response.json().get("aggregations") or {}
    if any((found.get(key) or {}).get("sum_other_doc_count") for key in found):
        raise RuntimeError("the account or host aggregation omitted values")
    accounts: dict[str, int] = {}
    for i in range(len(USER_FIELDS)):
        for bucket in (found.get(f"u{i}") or {}).get("buckets") or []:
            accounts[str(bucket["key"])] = accounts.get(str(bucket["key"]), 0) + int(bucket["doc_count"])
    hosts = [str(b["key"]) for i in range(len(HOST_FIELDS)) for b in (found.get(f"h{i}") or {}).get("buckets") or []]
    return pair_machine_accounts(accounts, hosts)


def _index_stamp(case_dir: Path) -> str:
    try:
        state = json.loads((case_dir / "analysis" / "index_state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    return str(state.get("indexed_at") or "")


def host_identity(case_dir: Path) -> dict[str, Any]:
    """The case's machines, their names and their own accounts, computed once per index build. Never raises."""
    case_dir = Path(case_dir)
    stamp = _index_stamp(case_dir)
    cache = case_dir / _CACHE
    try:
        cached = json.loads(cache.read_text(encoding="utf-8"))
        if stamp and cached.get("index_stamp") == stamp and cached.get("schema") == CACHE_SCHEMA:
            return cached
    except (OSError, ValueError):
        pass
    try:
        result = link_names(channel_edges(case_dir))
        result["machine_accounts"] = machine_accounts(case_dir)
    except Exception as exc:  # noqa: BLE001 - an unreadable index leaves the names as they are
        log.debug("host identity unavailable: %s", exc)
        return {"machines": [], "channels_checked": 0, "machine_accounts": []}
    result["index_stamp"] = stamp
    result["schema"] = CACHE_SCHEMA
    if stamp:
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(result, indent=1), encoding="utf-8")
        except OSError:
            pass
    return result


def host_identity_lines(identity: dict[str, Any]) -> list[str]:
    """One line per machine known under several names, with its proof, and one per machine's own account."""
    lines: list[str] = []
    for machine in identity.get("machines") or []:
        eras = ", ".join(f"{e['name']} ({e['first']} to {e['last']})" for e in machine.get("eras") or [])
        proof = "; ".join(
            f"{p['channel']} {p['last_record']} -> {p['first_record']} ({r['from']} -> {r['to']})"
            for r in machine.get("renames") or [] for p in (r.get("proof") or [])[:2])
        lines.append(f"- One machine logged under {len(machine.get('names') or [])} names, in this order: "
                     f"{eras}. Its own event logs continue one record sequence across each rename "
                     f"({proof}), so these names are one host renamed over time, not separate hosts.")
    for pair in identity.get("machine_accounts") or []:
        lines.append(f"- `{pair['account']}` is the computer account of {pair['host']} (its name followed by `$`; "
                     f"{pair['rows']} row(s), typed as {', '.join(pair['forms'])}). A logon, service or policy event "
                     f"under it is that machine acting as itself (its services and SYSTEM processes): it says which "
                     f"host acted, not which person, and is not another actor.")
    return lines


def host_identity_block(case_dir: Path) -> str:
    """The prompt block every investigative prompt carries; empty when no machine was renamed or named its account."""
    lines = host_identity_lines(host_identity(case_dir))
    if not lines:
        return ""
    return "HOST IDENTITY (deterministic, from the case index):\n" + "\n".join(lines)
