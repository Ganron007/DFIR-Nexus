"""MITRE ATT&CK threat actor seed profiles (CADRE-aligned)."""

from __future__ import annotations

from typing import Any

from nexus.mitre.schemas import ThreatActorProfile

CADRE_ACTORS: list[ThreatActorProfile] = [
    ThreatActorProfile(
        id="cadre-default-ad",
        name="CADRE Default AD Campaign",
        aliases=["CADRE-Spine"],
        description="Canonical CADRE 8-phase AD attack spine (Kerberoast → privesc → domain dominance).",
        motivation=["espionage", "domain-dominance"],
        technique_ids=[
            "T1558.003", "T1003.001", "T1003.006", "T1482", "T1068",
            "T1558.004", "T1550.002", "T1021.002", "T1021.006",
        ],
        campaigns=["CADRE-main"],
    ),
    ThreatActorProfile(
        id="cadre-ransomware",
        name="CADRE Ransomware Operator",
        aliases=["CADRE-Impact"],
        description="Post-domain ransomware / impact path (WT093, encryption staging).",
        motivation=["financial"],
        technique_ids=["T1486", "T1490", "T1070.001", "T1021.001", "T1059.001"],
        campaigns=["CADRE-E"],
    ),
    ThreatActorProfile(
        id="cadre-supply-chain",
        name="CADRE Supply-Chain Actor",
        aliases=["Shai-Hulud-style"],
        description="npm / CI supply-chain emulation (Campaign F).",
        motivation=["financial", "espionage"],
        technique_ids=["T1195.002", "T1071.001", "T1059.007", "T1552.001", "T1078"],
        campaigns=["CADRE-F"],
    ),
    ThreatActorProfile(
        id="apt29",
        name="APT29 (reference profile)",
        aliases=["Cozy Bear", "The Dukes"],
        description="Reference profile for CRTE-style tradecraft (not attribution).",
        motivation=["espionage"],
        technique_ids=[
            "T1566.001", "T1059.001", "T1003.001", "T1078", "T1027",
            "T1071.001", "T1105", "T1021.002",
        ],
        campaigns=["reference"],
    ),
    ThreatActorProfile(
        id="fin7",
        name="FIN7 (reference profile)",
        aliases=["Carbanak"],
        description="Reference financially motivated profile for phishing + lateral movement labs.",
        motivation=["financial"],
        technique_ids=["T1566.001", "T1059.001", "T1053.005", "T1021.002", "T1003.001"],
        campaigns=["reference"],
    ),
    ThreatActorProfile(
        id="cadre-linux",
        name="CADRE Linux Substrate",
        aliases=["linux01-attacker"],
        description="Linux AD-joined attacks: Kerberos, MSSQL, container escape.",
        motivation=["espionage"],
        technique_ids=["T1550.003", "T1558", "T1078", "T1611", "T1059.004"],
        campaigns=["CADRE-D"],
    ),
]

_ACTOR_BY_ID = {a.id: a for a in CADRE_ACTORS}


def list_actors() -> list[ThreatActorProfile]:
    return list(CADRE_ACTORS)


def get_actor(actor_id: str) -> ThreatActorProfile | None:
    return _ACTOR_BY_ID.get(actor_id)


def _technique_matches(observed_tid: str, catalog_tid: str) -> bool:
    o = observed_tid.upper()
    c = catalog_tid.upper()
    if o == c:
        return True
    return o.startswith(f"{c}.") or c.startswith(f"{o}.")


def match_actors(technique_ids: list[str], *, min_overlap: int = 1) -> list[dict[str, Any]]:
    observed = {t.strip().upper() for t in technique_ids if t.strip()}
    ranked: list[dict[str, Any]] = []
    for actor in CADRE_ACTORS:
        overlap: set[str] = set()
        for obs in observed:
            for at in actor.technique_ids:
                if _technique_matches(obs, at):
                    overlap.add(obs)
                    break
        if len(overlap) >= min_overlap:
            ranked.append(
                {
                    "actor_id": actor.id,
                    "name": actor.name,
                    "overlap_count": len(overlap),
                    "overlap_techniques": sorted(overlap),
                    "confidence": round(len(overlap) / max(len(actor.technique_ids), 1), 3),
                }
            )
    ranked.sort(key=lambda x: (-x["overlap_count"], x["actor_id"]))
    return ranked
