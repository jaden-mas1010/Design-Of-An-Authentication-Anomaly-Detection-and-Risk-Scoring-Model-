from datetime import datetime
from engine.models import User, AuthEvent, UserBaseline, DeviceProfile
from engine.scorer import compute_risk_score
from engine.explain import explain_result
from engine.mock_narrator import MockNarrator
from engine.groq_narrator import GroqNarrator

user = User(user_id="u001", upn="alice@company.com")
baseline = UserBaseline(user_id="u001", usual_countries=["GB"], usual_hours_utc=list(range(8, 18)))
trusted_device = DeviceProfile(device_id="d001", user_id="u001", device_fingerprint="fp1", is_trusted=True, total_logins=50)

e_normal = AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 9, 30),
                      source_ip="1.2.3.4", provider="azure_ad", country_code="GB", mfa_used=True)
e_attack = AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 3, 0),
                      source_ip="1.2.3.4", provider="azure_ad", country_code="RU",
                      mfa_used=False, recent_failure_count=10)

result_normal = compute_risk_score(e_normal, user, baseline, trusted_device)
result_attack = compute_risk_score(e_attack, user, baseline, None)

alert_normal = explain_result(result_normal)
alert_attack = explain_result(result_attack)

print("=== MockNarrator (no API needed) ===")
mock = MockNarrator(seed=42)
r1 = mock.generate_narrative(alert_normal)
r2 = mock.generate_narrative(alert_attack)
print(f"Normal login [{r1.source}]: {r1.narrative}")
print(f"Attack login [{r2.source}]: {r2.narrative}")

print("\n=== GroqNarrator (uses GROQ_API_KEY if set, else falls back to mock) ===")
groq = GroqNarrator()
r3 = groq.generate_narrative(alert_attack)
print(f"[{r3.source}]: {r3.narrative}")

print("\nDone.")