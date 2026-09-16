"""
scratch_boundary_tests.py
==========================
Manual, eyeball-friendly boundary testing for the AADRS scorer.

Not part of the pytest suite - this is for manually sanity-checking rule
behaviour right at the edges of each threshold, where bugs most commonly
hide. Run directly: python3 scratch_boundary_tests.py
"""

from datetime import datetime
from engine.models import User, AuthEvent, UserBaseline, DeviceProfile
from engine.scorer import compute_risk_score

user = User(user_id="u001", upn="alice@company.com")
baseline = UserBaseline(
    user_id="u001",
    usual_countries=["GB"],
    usual_hours_utc=list(range(8, 18)),
)


def show(label, event, device=None, use_baseline=True):
    result = compute_risk_score(event, user, baseline if use_baseline else None, device)
    print(f"--- {label} ---")
    print(f"Score: {result.risk_score}  Tier: {result.risk_tier}")
    for f in result.risk_factors:
        print(f"   {f}")
    if not result.risk_factors:
        print("   (no rules triggered)")
    print()
    return result


# ---------------------------------------------------------------------------
# 1. Brute-force threshold boundary: 4 vs 5 recent failures
# ---------------------------------------------------------------------------
e_below = AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 9, 0),
                     source_ip="1.2.3.4", provider="azure_ad", country_code="GB",
                     mfa_used=True, recent_failure_count=4)
e_at = AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 9, 0),
                  source_ip="1.2.3.4", provider="azure_ad", country_code="GB",
                  mfa_used=True, recent_failure_count=5)

show("Brute-force: 4 failures (should NOT trigger R007)", e_below)
show("Brute-force: 5 failures (SHOULD trigger R007)", e_at)


# ---------------------------------------------------------------------------
# 2. Credential-stuffing threshold boundary: 7 vs 8
# ---------------------------------------------------------------------------
e_below2 = AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 9, 0),
                      source_ip="1.2.3.4", provider="azure_ad", country_code="GB",
                      mfa_used=True, recent_failure_count=7)
e_at2 = AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 9, 0),
                   source_ip="1.2.3.4", provider="azure_ad", country_code="GB",
                   mfa_used=True, recent_failure_count=8)

show("Cred-stuffing: 7 failures (R007 yes, R008 NO)", e_below2)
show("Cred-stuffing: 8 failures (R007 AND R008 both fire)", e_at2)


# ---------------------------------------------------------------------------
# 3. Trusted device but low history - should fire R006 only, NOT R005
# ---------------------------------------------------------------------------
new_trusted_device = DeviceProfile(
    device_id="d999", user_id="u001", device_fingerprint="fp_new",
    is_trusted=True, total_logins=1,
)
e3 = AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 9, 0),
               source_ip="1.2.3.4", provider="azure_ad", country_code="GB",
               mfa_used=True)
show("Trusted but new device (expect ONLY R006, not R005)", e3, device=new_trusted_device)


# ---------------------------------------------------------------------------
# 4. Untrusted device with plenty of history - should fire R005 only, NOT R006
# ---------------------------------------------------------------------------
untrusted_established_device = DeviceProfile(
    device_id="d888", user_id="u001", device_fingerprint="fp_old_untrusted",
    is_trusted=False, total_logins=40,
)
show("Untrusted but established device (expect ONLY R005, not R006)", e3, device=untrusted_established_device)


# ---------------------------------------------------------------------------
# 5. Off-hours boundary: hour 7 (outside) vs hour 8 (inside, baseline is 8-17)
# ---------------------------------------------------------------------------
e_hour7 = AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 7, 59),
                     source_ip="1.2.3.4", provider="azure_ad", country_code="GB", mfa_used=True)
e_hour8 = AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 8, 0),
                     source_ip="1.2.3.4", provider="azure_ad", country_code="GB", mfa_used=True)

show("07:59 login (SHOULD trigger R003 - outside 8-17)", e_hour7)
show("08:00 login (should NOT trigger R003 - inside 8-17)", e_hour8)

trusted_established_device = DeviceProfile(
    device_id="d777",
    user_id="u001",
    device_fingerprint="fp_normal",
    is_trusted=True,
    total_logins=40,
)

# ---------------------------------------------------------------------------
# 6. No-MFA compounding rule: should stay silent alone, fire when stacked
# ---------------------------------------------------------------------------
e_no_mfa_clean = AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 9, 0),
                            source_ip="1.2.3.4", provider="azure_ad", country_code="GB", mfa_used=False)
e_no_mfa_risky = AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 3, 0),
                            source_ip="1.2.3.4", provider="azure_ad", country_code="FR", mfa_used=False)

show(
    "No MFA, otherwise totally normal login (R009 should NOT fire)",
    e_no_mfa_clean,
    device=trusted_established_device,
)

show(
    "No MFA + unusual country + off hours (R009 SHOULD fire)",
    e_no_mfa_risky,
    device=trusted_established_device,
)


# ---------------------------------------------------------------------------
# 7. Score cap: stack everything, confirm it never exceeds 100
# ---------------------------------------------------------------------------
e_everything = AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 3, 0),
                          source_ip="1.2.3.4", provider="azure_ad", country_code="RU",
                          outcome="failure", mfa_used=False, recent_failure_count=20)
result = show("Everything stacked at once (score must cap at 100)", e_everything)
assert result.risk_score <= 100, "SCORE EXCEEDED CAP - BUG"


# ---------------------------------------------------------------------------
# 8. No baseline at all - should not crash, should score only what it can
# ---------------------------------------------------------------------------
e_no_baseline = AuthEvent(user_id="u001", event_time=datetime(2025, 6, 1, 3, 0),
                           source_ip="1.2.3.4", provider="azure_ad", country_code="RU", mfa_used=False)
show("No baseline available (R001/R003 can't evaluate, R002 still can)", e_no_baseline, use_baseline=False)

print("All boundary scenarios ran without errors.")
