"""
tests.test_ml_scorer
=====================
Basic sanity tests for the Isolation Forest comparison scorer.

These are deliberately looser than the rule-based tests - Isolation
Forest scores are not deterministic thresholds the way rule weights are,
so tests check relative ordering and sane bounds, not exact values.
"""

from datetime import datetime

import pytest

from engine.models import UserBaseline, DeviceProfile, AuthEvent
from engine.ml_scorer import MLAnomalyScorer, generate_synthetic_normal_logins


@pytest.fixture(scope="module")
def fitted_scorer():
    scorer = MLAnomalyScorer(random_state=42)
    data = generate_synthetic_normal_logins(
        n_samples=300, usual_countries=["GB"], usual_hours=list(range(8, 18)), random_state=42,
    )
    scorer.fit(data)
    return scorer


@pytest.fixture
def baseline():
    return UserBaseline(user_id="u001", usual_countries=["GB"], usual_hours_utc=list(range(8, 18)))


@pytest.fixture
def trusted_device():
    return DeviceProfile(
        device_id="d001", user_id="u001", device_fingerprint="fp1",
        is_trusted=True, total_logins=50,
    )


def make_event(**overrides):
    defaults = dict(
        user_id="u001", event_time=datetime(2026, 1, 1, 9, 0),
        source_ip="1.2.3.4", provider="azure_ad", country_code="GB",
        outcome="success", mfa_used=True, recent_failure_count=0,
    )
    defaults.update(overrides)
    return AuthEvent(**defaults)


class TestMLScorerBasics:
    def test_score_is_within_bounds(self, fitted_scorer, baseline, trusted_device):
        event = make_event()
        result = fitted_scorer.score_event(event, baseline, trusted_device)
        assert 0 <= result.anomaly_score <= 100

    def test_unfitted_model_raises(self):
        scorer = MLAnomalyScorer()
        with pytest.raises(RuntimeError):
            scorer.score_event(make_event())

    def test_normal_login_scores_lower_than_extreme_anomaly(self, fitted_scorer, baseline, trusted_device):
        normal = make_event()
        extreme = make_event(
            event_time=datetime(2026, 1, 1, 3, 0),
            country_code="RU",
            mfa_used=False,
            recent_failure_count=20,
            outcome="failure",
        )
        normal_result = fitted_scorer.score_event(normal, baseline, trusted_device)
        extreme_result = fitted_scorer.score_event(extreme, baseline, None)
        assert extreme_result.anomaly_score > normal_result.anomaly_score

    def test_extreme_anomaly_flagged_as_outlier(self, fitted_scorer, baseline):
        extreme = make_event(
            event_time=datetime(2026, 1, 1, 3, 0),
            country_code="RU",
            mfa_used=False,
            recent_failure_count=20,
            outcome="failure",
        )
        result = fitted_scorer.score_event(extreme, baseline, None)
        assert result.is_outlier is True

    def test_contributing_features_are_non_empty_for_anomaly(self, fitted_scorer, baseline):
        extreme = make_event(
            event_time=datetime(2026, 1, 1, 3, 0),
            country_code="RU",
            recent_failure_count=20,
        )
        result = fitted_scorer.score_event(extreme, baseline, None)
        assert len(result.contributing_features) > 0

    def test_save_and_load_roundtrip(self, fitted_scorer, baseline, trusted_device, tmp_path):
        path = tmp_path / "test_model.joblib"
        fitted_scorer.save(path)
        loaded = MLAnomalyScorer.load(path)

        event = make_event()
        original_result = fitted_scorer.score_event(event, baseline, trusted_device)
        loaded_result = loaded.score_event(event, baseline, trusted_device)
        assert original_result.anomaly_score == loaded_result.anomaly_score
