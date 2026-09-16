"""
tests.test_scorer
==================
Unit tests for the AADRS risk scoring engine.

Each detection rule is tested in isolation (does it fire when it should,
stay silent when it shouldn't) and then a handful of integration-style
scenarios check the combined score/tier/MITRE output, matching the
scenarios demonstrated in main.py.

Run with: pytest tests/ -v
"""

from datetime import datetime

import pytest

from engine.models import User, AuthEvent, UserBaseline, DeviceProfile
from engine.scorer import compute_risk_score
from engine import rules as rule_defs


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def user():
    return User(user_id="u001", upn="alice@company.com")


@pytest.fixture
def baseline():
    return UserBaseline(
        user_id="u001",
        usual_countries=["GB"],
        usual_hours_utc=list(range(8, 18)),  # 08:00-17:00
    )


@pytest.fixture
def trusted_device():
    return DeviceProfile(
        device_id="d001",
        user_id="u001",
        device_fingerprint="fp_alice_laptop",
        is_trusted=True,
        total_logins=50,
    )


def make_event(**overrides):
    defaults = dict(
        user_id="u001",
        event_time=datetime(2025, 6, 1, 9, 30),
        source_ip="82.132.200.10",
        provider="azure_ad",
        country_code="GB",
        outcome="success",
        mfa_used=True,
        recent_failure_count=0,
    )
    defaults.update(overrides)
    return AuthEvent(**defaults)


# ---------------------------------------------------------------------------
# Individual rule tests
# ---------------------------------------------------------------------------

class TestUnusualCountryRule:
    def test_fires_outside_baseline(self, baseline):
        event = make_event(country_code="FR")
        result = rule_defs.rule_unusual_country(event, baseline)
        assert result is not None
        assert result.rule_id == "R001"

    def test_silent_inside_baseline(self, baseline):
        event = make_event(country_code="GB")
        assert rule_defs.rule_unusual_country(event, baseline) is None

    def test_silent_without_baseline(self):
        event = make_event(country_code="FR")
        assert rule_defs.rule_unusual_country(event, None) is None


class TestHighRiskCountryRule:
    @pytest.mark.parametrize("country", ["RU", "KP", "IR", "SY"])
    def test_fires_for_high_risk_countries(self, country):
        event = make_event(country_code=country)
        result = rule_defs.rule_high_risk_country(event)
        assert result is not None
        assert result.mitre_technique_id == "T1078"

    def test_silent_for_benign_country(self):
        event = make_event(country_code="DE")
        assert rule_defs.rule_high_risk_country(event) is None


class TestOffHoursRule:
    def test_fires_outside_usual_hours(self, baseline):
        event = make_event(event_time=datetime(2025, 6, 1, 3, 0))
        result = rule_defs.rule_off_hours(event, baseline)
        assert result is not None

    def test_silent_inside_usual_hours(self, baseline):
        event = make_event(event_time=datetime(2025, 6, 1, 9, 0))
        assert rule_defs.rule_off_hours(event, baseline) is None


class TestDeviceRules:
    def test_unknown_device_fires_when_none(self):
        assert rule_defs.rule_unknown_device(make_event(), None) is not None

    def test_unknown_device_silent_when_present(self, trusted_device):
        assert rule_defs.rule_unknown_device(make_event(), trusted_device) is None

    def test_untrusted_device_fires(self):
        untrusted = DeviceProfile(
            device_id="d002", user_id="u001", device_fingerprint="fp_x",
            is_trusted=False, total_logins=20,
        )
        assert rule_defs.rule_untrusted_device(untrusted) is not None

    def test_trusted_device_silent(self, trusted_device):
        assert rule_defs.rule_untrusted_device(trusted_device) is None

    def test_low_history_device_fires(self):
        new_device = DeviceProfile(
            device_id="d003", user_id="u001", device_fingerprint="fp_y",
            is_trusted=True, total_logins=1,
        )
        assert rule_defs.rule_low_history_device(new_device) is not None

    def test_established_device_silent(self, trusted_device):
        assert rule_defs.rule_low_history_device(trusted_device) is None


class TestBruteForceRules:
    def test_brute_force_fires_at_threshold(self):
        event = make_event(recent_failure_count=5)
        assert rule_defs.rule_brute_force(event) is not None

    def test_brute_force_silent_below_threshold(self):
        event = make_event(recent_failure_count=4)
        assert rule_defs.rule_brute_force(event) is None

    def test_credential_stuffing_fires_at_threshold(self):
        event = make_event(recent_failure_count=8)
        result = rule_defs.rule_credential_stuffing(event)
        assert result is not None
        assert result.mitre_technique_id == "T1110.004"

    def test_credential_stuffing_silent_below_threshold(self):
        event = make_event(recent_failure_count=7)
        assert rule_defs.rule_credential_stuffing(event) is None

    def test_extreme_failure_volume_fires_at_threshold(self):
        event = make_event(recent_failure_count=50)
        result = rule_defs.rule_extreme_failure_volume(event)
        assert result is not None
        assert result.rule_id == "R012"

    def test_extreme_failure_volume_silent_below_threshold(self):
        event = make_event(recent_failure_count=49)
        assert rule_defs.rule_extreme_failure_volume(event) is None

    def test_severity_scales_past_credential_stuffing_threshold(self, user, baseline):
        """
        A 10-failure event and a 100-failure event must NOT score
        identically - R012 exists specifically to keep severity scaling
        past R008's threshold instead of plateauing.
        """
        moderate = make_event(recent_failure_count=10)
        extreme = make_event(recent_failure_count=100)
        moderate_result = compute_risk_score(moderate, user, baseline, None)
        extreme_result = compute_risk_score(extreme, user, baseline, None)
        assert extreme_result.risk_score > moderate_result.risk_score


class TestMfaRule:
    def test_fires_when_no_mfa_and_risk_present(self):
        event = make_event(mfa_used=False)
        assert rule_defs.rule_no_mfa_on_risky_login(event, running_score_before_this_rule=20) is not None

    def test_silent_when_no_mfa_but_low_risk(self):
        event = make_event(mfa_used=False)
        assert rule_defs.rule_no_mfa_on_risky_login(event, running_score_before_this_rule=0) is None

    def test_silent_when_mfa_used(self):
        event = make_event(mfa_used=True)
        assert rule_defs.rule_no_mfa_on_risky_login(event, running_score_before_this_rule=50) is None


# ---------------------------------------------------------------------------
# Integration scenarios (mirrors main.py)
# ---------------------------------------------------------------------------

class TestScoringScenarios:
    def test_normal_login_is_low_risk(self, user, baseline, trusted_device):
        event = make_event()
        result = compute_risk_score(event, user, baseline, trusted_device)
        assert result.risk_score == 0
        assert result.risk_tier == "LOW"
        assert result.risk_factors == []

    def test_high_risk_country_off_hours_no_device(self, user, baseline):
        event = make_event(
            event_time=datetime(2025, 6, 1, 3, 0),
            source_ip="95.213.0.100",
            country_code="RU",
            mfa_used=False,
        )
        result = compute_risk_score(event, user, baseline, None)
        assert result.risk_tier in ("HIGH", "CRITICAL")
        assert "T1078" in result.mitre_technique_id

    def test_brute_force_scenario_flags_mitre_technique(self, user, baseline):
        event = make_event(
            event_time=datetime(2025, 6, 1, 2, 0),
            source_ip="185.220.101.50",
            country_code="NL",
            outcome="success",
            recent_failure_count=10,
            mfa_used=False,
        )
        result = compute_risk_score(event, user, baseline, None)
        assert result.risk_tier in ("HIGH", "CRITICAL")
        assert "T1110" in result.mitre_technique_id
        assert "T1110.004" in result.mitre_technique_id

    def test_score_never_exceeds_max(self, user, baseline):
        # Stack every possible risk factor to check the 100-point cap holds.
        event = make_event(
            event_time=datetime(2025, 6, 1, 3, 0),
            country_code="RU",
            outcome="failure",
            recent_failure_count=20,
            mfa_used=False,
        )
        result = compute_risk_score(event, user, baseline, None)
        assert result.risk_score <= 100

    def test_missing_baseline_does_not_crash(self, user):
        event = make_event()
        result = compute_risk_score(event, user, baseline=None, device=None)
        assert 0 <= result.risk_score <= 100
