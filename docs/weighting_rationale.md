# Weighting Rationale — AADRS Detection Rules

Every rule weight below is derived from a named threat technique (MITRE ATT&CK)
or control framework (CIS Controls v8) rather than an arbitrary judgment call.
This document exists so the methodology can be independently reviewed and
challenged, per the 04.08.2026 progress meeting with PMS Ltd.

Weights are provisional pending Phase 5/6 evaluation against labelled
CERT/LANL data (see engine/rules.py module docstring).

---

### R001 — Unusual Country (Baseline-Relative)
- **Factor measured:** Login from a country outside the user's established baseline
- **Why it represents risk:** Deviation from a personal behavioural baseline is a
  standard signal for compromised-credential use (attacker geography differs
  from the legitimate user's)
- **Supporting standard:** CIS Control 6 (Access Control Management) —
  anomalous access pattern detection; conceptually adjacent to MITRE ATT&CK
  T1078 (Valid Accounts) but scored separately from R002 since it is
  baseline-relative, not a fixed threat-intel list
- **Weight assigned:** +15
- **Effect on score:** Below MEDIUM tier alone; compounds with R003/R009
- **Review trigger:** Re-evaluate if legitimate travel generates excessive
  false positives in Phase 6 testing

### R002 — High-Risk Country (Fixed List)
- **Factor measured:** Login from a country on a static high-risk source list (RU, KP, IR, SY)
- **Why it represents risk:** These jurisdictions feature disproportionately in
  published credential-based attack telemetry
- **Supporting standard:** MITRE ATT&CK T1078 (Valid Accounts) — already
  mapped in code
- **Weight assigned:** +25 — highest single-rule weight, reflecting that this
  is a fixed threat-intel signal rather than a personal-baseline deviation
- **Effect on score:** Alone, reaches MEDIUM tier (25/30 threshold — just below)
- **Review trigger:** The hard-coded country list should migrate to a
  maintained threat-intel feed before production use (already noted in code
  comments)

### R003 — Off-Hours Login
- **Factor measured:** Login outside the user's usual active hours (UTC)
- **Why it represents risk:** Compromised accounts are frequently accessed
  outside the legitimate user's normal working pattern
- **Supporting standard:** CIS Control 8 (Audit Log Management) — anomalous
  timing as a log-review signal; NIST SP 800-63B recommends contextual
  authentication factors including time-of-access
- **Weight assigned:** +10 — lowest standalone weight, since off-hours access
  alone is common and weak evidence
- **Effect on score:** Cannot reach MEDIUM tier alone; exists to compound with
  R001/R002 and to help trigger R009
- **Review trigger:** Consider per-user timezone handling rather than a single UTC baseline

### R004 — Unknown Device
- **Factor measured:** No device profile exists at all for this login
- **Why it represents risk:** A first-ever device is consistent with an
  attacker using stolen credentials from new infrastructure
- **Supporting standard:** MITRE ATT&CK T1078 (Valid Accounts) — already mapped
- **Weight assigned:** +15
- **Effect on score:** Same weight as R001, reflecting comparable risk strength
- **Review trigger:** N/A — stable signal

### R005 — Untrusted Device
- **Factor measured:** Device profile exists but is explicitly marked not trusted
- **Why it represents risk:** Distinct from R004 — this is a device the
  organisation has seen and deliberately not trusted (e.g. flagged/shared/BYOD)
- **Supporting standard:** CIS Control 4 (Secure Configuration of Enterprise Assets)
- **Weight assigned:** +10 — lower than R004, since some visibility into the
  device already exists
- **Effect on score:** Mutually exclusive with R006 by design (see code comment
  in scratch_boundary_tests.py, test case 3/4)
- **Review trigger:** N/A — stable signal

### R006 — Low-History Device
- **Factor measured:** Device profile exists, is trusted, but has fewer than 3 total logins
- **Why it represents risk:** A newly enrolled device — even trusted — has
  limited behavioural history to validate against
- **Supporting standard:** CIS Control 4 — asset lifecycle awareness
- **Weight assigned:** +5 — lowest weight in the entire ruleset, since a
  trusted-but-new device is materially lower risk than an untrusted one
- **Effect on score:** Deliberately weak signal; exists mainly to feed context
  rather than drive tier changes alone
- **Review trigger:** Reconsider LOW_HISTORY_LOGIN_THRESHOLD (currently 3) once
  real login-volume data is available

### R007 — Brute Force Precursor
- **Factor measured:** ≥5 recent failed login attempts before this event
- **Why it represents risk:** A failure cluster immediately preceding success
  is the standard signature of credential-guessing
- **Supporting standard:** MITRE ATT&CK T1110 (Brute Force) — already mapped
- **Weight assigned:** +20
- **Effect on score:** Combined with any other rule, reliably reaches HIGH tier
- **Review trigger:** BRUTE_FORCE_THRESHOLD (5) should be validated against
  real authentication logs — currently a design assumption

### R008 — Credential Stuffing
- **Factor measured:** ≥8 recent failures (stacks on top of R007, does not replace it)
- **Why it represents risk:** Failure volume at this scale is more consistent
  with automated tooling than manual retry
- **Supporting standard:** MITRE ATT&CK T1110.004 (Credential Stuffing) —
  already mapped
- **Weight assigned:** +15 additional (on top of R007's +20)
- **Effect on score:** R007+R008 together = +35, well into HIGH/CRITICAL
- **Review trigger:** CREDENTIAL_STUFFING_THRESHOLD (8) — same caveat as R007

### R009 — No MFA on an Already-Risky Login
- **Factor measured:** MFA absent, AND accumulated score from other rules ≥15
- **Why it represents risk:** No-MFA alone is common and weak evidence; no-MFA
  *combined with* an already-suspicious login materially raises risk of
  successful account takeover
- **Supporting standard:** NIST SP 800-63B — MFA as a primary compensating
  control for authentication risk
- **Weight assigned:** +10
- **Effect on score:** Deliberately compounding-only by design (see docstring)
  — this is the rule most worth highlighting to reviewers as evidence of
  non-arbitrary design, since a naive implementation would score no-MFA
  standalone
- **Review trigger:** The ≥15 compounding threshold is itself a design choice
  worth citing evidence for — currently undocumented rationale, flag as an
  open question

### R010 — Failed Outcome
- **Factor measured:** The event itself is a failed authentication attempt
- **Why it represents risk:** A failure is weak evidence alone but contributes
  to a fuller picture when correlated with other events
- **Supporting standard:** CIS Control 8 (Audit Log Management)
- **Weight assigned:** +5 — lowest tier, single failed attempts are common and expected
- **Effect on score:** Minimal individual impact by design
- **Review trigger:** N/A

### R011 — New/Unusual Provider Pattern — NOT IMPLEMENTED
- **Status:** Documented extension point only. Function always returns `None`
  and is excluded from `SIMPLE_RULES`. Included here for completeness and to
  be transparent that the >=10 rule count includes one placeholder.
- **Intended factor:** A user switching from modern auth to a legacy
  protocol (IMAP/POP) unexpectedly
- **Supporting standard (for future implementation):** MITRE ATT&CK T1114 /
  legacy authentication abuse patterns are commonly discussed in Microsoft's
  legacy-auth deprecation guidance
- **Not yet weighted — left as future work**

### R012 — Extreme Failure Volume
- **Factor measured:** ≥50 recent failures — distinguishes botnet-scale
  automation from a persistent individual attacker
- **Why it represents risk:** Without this rule, 10 failures and 10,000
  failures score identically once R008's threshold is crossed — this closes
  that gap (documented directly in the code docstring)
- **Supporting standard:** MITRE ATT&CK T1110.004 — same technique as R008,
  differentiated by scale
- **Weight assigned:** +20 additional (stacks on R007 + R008)
- **Effect on score:** R007+R008+R012 = +55, guarantees CRITICAL tier alone
- **Review trigger:** EXTREME_FAILURE_THRESHOLD (50) is a placeholder value —
  flag explicitly as needing real-world calibration