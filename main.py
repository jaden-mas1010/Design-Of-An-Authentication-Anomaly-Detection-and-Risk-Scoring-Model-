from engine.models import User, AuthEvent, UserBaseline, DeviceProfile
from engine.scorer import compute_risk_score
from datetime import datetime

# --- Scenario 1: Normal login ---
alice = User(user_id="u001", upn="alice@company.com")

baseline = UserBaseline(
    user_id="u001",
    usual_countries=["GB"],
    usual_hours_utc=[8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
)

device = DeviceProfile(
    device_id="d001",
    user_id="u001",
    device_fingerprint="fp_alice_laptop",
    is_trusted=True,
    total_logins=50
)

event = AuthEvent(
    user_id="u001",
    event_time=datetime(2025, 6, 1, 9, 30),
    source_ip="82.132.200.10",
    provider="azure_ad",
    country_code="GB"
)

result = compute_risk_score(event, alice, baseline, device)
print("=== Scenario 1: Normal login ===")
print(f"Score : {result.risk_score}")
print(f"Tier  : {result.risk_tier}")
print(f"Factors: {result.risk_factors}")
print()

# --- Scenario 2: Login from Russia at 3am ---
event2 = AuthEvent(
    user_id="u001",
    event_time=datetime(2025, 6, 1, 3, 0),
    source_ip="95.213.0.100",
    provider="azure_ad",
    country_code="RU"
)

result2 = compute_risk_score(event2, alice, baseline, None)
print("=== Scenario 2: Login from Russia at 3am ===")
print(f"Score : {result2.risk_score}")
print(f"Tier  : {result2.risk_tier}")
print(f"Factors: {result2.risk_factors}")
print()

# --- Scenario 3: Brute force attack ---
event3 = AuthEvent(
    user_id="u001",
    event_time=datetime(2025, 6, 1, 2, 0),
    source_ip="185.220.101.50",
    provider="azure_ad",
    country_code="NL",
    outcome="success",
    recent_failure_count=10
)

result3 = compute_risk_score(event3, alice, baseline, None)
print("=== Scenario 3: Brute force attack ===")
print(f"Score : {result3.risk_score}")
print(f"Tier  : {result3.risk_tier}")
print(f"Factors: {result3.risk_factors}")
print(f"MITRE : {result3.mitre_technique_id}")