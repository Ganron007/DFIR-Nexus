"""Tests for D.0.3 MITRE Navigator, threat actors, and RBA (P2.6)."""

from __future__ import annotations

from nexus.mitre import (
    build_observed_layer,
    create_rba_scorer,
    match_actors,
)
from nexus.mitre.catalog import get_actor, list_actors
from nexus.mitre.service import create_mitre_service


def test_navigator_v45_layer_metadata() -> None:
    layer = build_observed_layer(["T1003.001"])
    assert layer["versions"]["layer"] == "4.5"
    assert len(layer["techniques"]) == 1
    assert layer["techniques"][0]["metadata"][0]["name"] == "source"


def test_list_actors_seed_count() -> None:
    assert len(list_actors()) >= 6


def test_match_actors_lab_ad() -> None:
    matches = match_actors(["T1558.003", "T1003.006", "T1482"], min_overlap=2)
    assert matches[0]["actor_id"] == "nexus-default-ad"


def test_rba_score_high_tier() -> None:
    scorer = create_rba_scorer()
    result = scorer.score(
        technique_ids=["T1003.001", "T1486"],
        severities=["critical", "high"],
        malicious_ioc_count=2,
    )
    assert result.score >= 55
    assert result.tier in ("high", "critical")
    assert result.factors


def test_get_actor() -> None:
    actor = get_actor("nexus-ransomware")
    assert actor is not None
    assert "T1486" in actor.technique_ids


def test_mitre_service_actor_layer() -> None:
    svc = create_mitre_service()
    layer = svc.navigator_actor_layer("apt29")
    assert layer is not None
    assert layer["versions"]["layer"] == "4.5"
    assert len(layer["techniques"]) >= 5
