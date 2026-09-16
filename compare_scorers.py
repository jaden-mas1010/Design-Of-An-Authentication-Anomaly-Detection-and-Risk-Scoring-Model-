"""
compare_scorers.py
===================
Runs the same three scenarios from main.py through BOTH the rule-based
scorer and the Isolation Forest scorer, side by side. This is a first
look at the comparison PMS Ltd asked for - not a formal evaluation
(that needs labelled CERT/LANL data per O4), but useful for sanity
checking the ML layer behaves sensibly before investing more in it.
"""

from datetime import datetime

from engine.models import User, AuthEvent, UserBaseline, DeviceProfile
from engine.scorer import compute_risk_score
from engine.ml_scorer import load_or_train

user = User(user_id="u001", upn="alice@company.com")
baseline = UserBaseline(
    user_id="u001",
    usual_countries=["GB"],
    usual_hours_utc=list(range(8, 18)),
)
trusted_device = DeviceProfile(
    device_id="d001", user_id="u001", device_fingerprint="fp_alice_laptop",
    is_trusted=True, total_logins=50,
)

print("Training/loading Isolation Forest model...")
ml = load_or_train(usual_countries=["GB"], usual_hours=list(range(8, 18)))
print("Done.\n")


def compare(label, event, device=None):
    rule_result = compute_risk_score(event, user, baseline, device)
    ml_result = ml.score_event(event, baseline, device)

    print(f"=== {label} ===")
    print(f"  Rule-based : {rule_result.risk_score:>3} ({rule_result.risk_tier})")
    print(f"  Isolation F: {ml_result.anomaly_score:>3} ({ml_result.risk_tier})  "
          f"outlier={ml_result.is_outlier}  top features={ml_result.contributing_features}")
    print()


compare(
    "Scenario 1: Normal login",
    AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 9, 30),
              source_ip="82.132.200.10", provider="azure_ad", country_code="GB",
              mfa_used=True),
    device=trusted_device,
)

compare(
    "Scenario 2: Login from Russia at 3am",
    AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 3, 0),
              source_ip="95.213.0.100", provider="azure_ad", country_code="RU",
              mfa_used=False),
)

compare(
    "Scenario 3: Brute force attack",
    AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 2, 0),
              source_ip="185.220.101.50", provider="azure_ad", country_code="NL",
              outcome="success", recent_failure_count=10, mfa_used=False),
)

# A couple of extra edge cases worth a second look
compare(
    "Extra: Legit login but slightly early (07:00, still no big deal)",
    AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 7, 0),
              source_ip="82.132.200.10", provider="azure_ad", country_code="GB",
              mfa_used=True),
    device=trusted_device,
)

compare(
    "Extra: Unknown device but everything else normal",
    AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 10, 0),
              source_ip="82.132.200.10", provider="azure_ad", country_code="GB",
              mfa_used=True),
)
