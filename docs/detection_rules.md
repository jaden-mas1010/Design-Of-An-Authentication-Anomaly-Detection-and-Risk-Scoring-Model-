# AADRS — Detection Rules and Risk Scoring Methodology

This document satisfies Objective O2: a documented rule-based detection
framework of 10+ rules, and a documented weighted risk scoring model
(0–100).

## Design rationale

Per the literature review (Sommer & Paxson, 2010), anomaly detection
systems that perform well on clean research data tend to degrade under
real operational load because not every statistical anomaly is a
meaningful threat. Rather than a single opaque model, AADRS uses a set of
small, independently-named rules, each contributing a fixed point value
to a running total. This means:

- Every point in a score can be traced to a specific, human-readable reason.
- Rules can be tuned, disabled, or re-weighted individually as evaluation
  data (CERT/LANL, Phase 5–6) reveals false-positive-heavy rules.
- The framework generalises: the same "sum of weighted, named indicators"
  approach can be reused for other event domains (per PMS Ltd's interest
  in a cross-domain methodology), by swapping in domain-specific rules.

## Rule catalogue

| ID | Rule | Trigger condition | Weight | MITRE ATT&CK |
|----|------|-------------------|--------|--------------|
| R001 | Unusual country | `country_code` not in the user's baseline `usual_countries` | +15 | — |
| R002 | High-risk country | `country_code` in a maintained high-risk source list (currently: RU, KP, IR, SY — illustrative, intended to be fed from threat intel) | +25 | T1078 (Valid Accounts) |
| R003 | Off-hours login | Login hour (UTC) not in the user's baseline `usual_hours_utc` | +10 | — |
| R004 | Unknown device | No `DeviceProfile` exists for this login at all | +15 | T1078 |
| R005 | Untrusted device | A `DeviceProfile` exists but `is_trusted = False` | +10 | — |
| R006 | Low-history device | Device exists but has fewer than 3 recorded logins (recently enrolled) | +5 | — |
| R007 | Brute-force precursor | `recent_failure_count` ≥ 5 | +20 | T1110 (Brute Force) |
| R008 | Credential-stuffing indicator | `recent_failure_count` ≥ 8 (stacks with R007) | +15 | T1110.004 (Credential Stuffing) |
| R009 | No MFA on risky login | `mfa_used = False` **and** score already ≥ 15 from other rules | +10 | — |
| R010 | Failed outcome | The event's own `outcome` is `"failure"` | +5 | — |
| R011 | Legacy/unusual protocol | Reserved extension point — not yet exercised by current models | — | — |
| R012 | Extreme failure volume | `recent_failure_count` ≥ 50 (stacks with R007 and R008) | +20 | T1110.004 |

R009 is deliberately **compounding rather than standalone**: MFA-less
login is extremely common and not, on its own, a signal worth scoring —
it only matters once other indicators suggest the login itself is
already questionable.

## Scoring formula

```
raw_score   = sum(points for each triggered rule)
final_score = min(raw_score, 100)
```

## Risk tiers

| Score range | Tier |
|-------------|------|
| 0–29 | LOW |
| 30–59 | MEDIUM |
| 60–84 | HIGH |
| 85–100 | CRITICAL |

These thresholds are provisional defaults, to be validated during Phase 6
against labelled CERT/LANL red-team events (comparing detection rate vs
false-positive rate per tier boundary, as required by O4).

## Explainability

`compute_risk_score()` returns both:
- `risk_factors`: human-readable strings, one per triggered rule (for logs/UI)
- `risk_factor_details`: structured `RiskFactor` objects (rule ID, description,
  points, MITRE technique) for programmatic consumption

This directly addresses the explainability requirement raised by PMS Ltd —
any score can be decomposed back into the exact rules that produced it,
rather than requiring trust in an opaque model.

## Known limitations / future work

- `HIGH_RISK_COUNTRIES` is a static illustrative set; a production version
  should draw from a maintained threat-intel feed.
- No impossible-travel (geo-velocity) rule yet — would require tracking
  the user's *previous* login location/time, not just the current event.
  Natural extension once `UserBaseline` tracks last-login state.
- Weights are additive and manually chosen; Phase 6 evaluation against
  labelled data should validate or retune them, and could compare this
  rule-based approach against the planned Isolation Forest layer (O4).
- R007/R008/R012 are still discrete thresholds, not a continuous function
  of failure count — a login with 50 failures and one with 5,000 failures
  score identically under R012. A continuous/logarithmic scaling function
  would be more precise but less immediately explainable; the discrete
  tiers were chosen to keep the "one sentence per rule" explainability
  property intact. Worth revisiting if Phase 6 evaluation shows this
  under-differentiates genuinely extreme attacks.
