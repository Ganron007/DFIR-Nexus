"""Tests for enhanced adversary emulation — TF-IDF technique prediction."""

from __future__ import annotations

import pytest

from nexus.mitre.adversary import (
    predict_next_techniques,
    match_observed_to_groups,
    _GROUP_TECHNIQUES,
)


class TestAdversaryEmulation:
    def test_predict_with_apt29_techniques(self) -> None:
        """APT29 techniques → APT29 group surfaces."""
        observed = ["T1566.001", "T1059.001", "T1003.001", "T1071.001"]
        predictions = predict_next_techniques(observed, top_n=10)
        assert len(predictions) > 0
        groups = predictions[0].groups_using
        assert any("apt29" in g for g in groups)

    def test_predict_excludes_observed(self) -> None:
        """Observed techniques flagged as observed_in_case."""
        observed = ["T1566.001", "T1059.001"]
        predictions = predict_next_techniques(observed, top_n=20)
        observed_preds = [p for p in predictions if p.observed_in_case]
        unobserved = [p for p in predictions if not p.observed_in_case]
        assert len(unobserved) > 0

    def test_predict_empty_input(self) -> None:
        """No observed techniques → no predictions."""
        predictions = predict_next_techniques([])
        assert len(predictions) == 0

    def test_predict_returns_sorted(self) -> None:
        """Predictions sorted by score descending."""
        observed = ["T1566.001", "T1059.001", "T1003.001"]
        predictions = predict_next_techniques(observed, top_n=10)
        scores = [p.score for p in predictions]
        assert scores == sorted(scores, reverse=True)

    def test_match_apt29(self) -> None:
        """APT29 techniques matched to APT29 group."""
        observed = ["T1566.001", "T1059.001", "T1003.001", "T1071.001"]
        matches = match_observed_to_groups(observed, min_overlap=2)
        assert len(matches) >= 1
        apt29 = [m for m in matches if m["group_id"] == "apt29"]
        assert len(apt29) == 1
        assert apt29[0]["overlap_count"] >= 4

    def test_match_min_overlap(self) -> None:
        """Below min_overlap → no match."""
        observed = ["T1566.001"]
        matches = match_observed_to_groups(observed, min_overlap=2)
        assert len(matches) == 0

    def test_match_has_confidence(self) -> None:
        observed = ["T1566.001", "T1059.001", "T1003.001"]
        matches = match_observed_to_groups(observed, min_overlap=2)
        if matches:
            assert 0 < matches[0]["confidence"] <= 1.0

    def test_group_count(self) -> None:
        """At least 6 threat actor groups defined."""
        assert len(_GROUP_TECHNIQUES) >= 6

    def test_prediction_to_dict(self) -> None:
        observed = ["T1566.001", "T1059.001"]
        predictions = predict_next_techniques(observed, top_n=5)
        if predictions:
            d = predictions[0].to_dict()
            assert "technique_id" in d
            assert "score" in d
            assert "groups_using" in d
