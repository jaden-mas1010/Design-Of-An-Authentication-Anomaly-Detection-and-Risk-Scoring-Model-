# AADRS — Rule-Based vs Isolation Forest Comparison

Added following David Douglas's email (7 July 2026), which greenlit
exploring Isolation Forest "as an interesting comparison against the
rule-based approach already proposed," while flagging practical
applicability and explainability as PMS Ltd's priorities.

## Why Isolation Forest specifically

Unsupervised — trained only on examples of normal behaviour, then flags
events that are structurally easy to isolate (few decision-tree splits
needed) as anomalous. This fits the constraint in the proposal (Section
1.2): no large labelled attack dataset is assumed to exist at deployment
time, only a stream of (mostly normal) authentication history.

## Equal-footing feature design

`engine/features.py` defines a single feature vector shared by both
approaches:

```
hour_of_day, country_is_usual, country_is_high_risk,
device_known, device_trusted, device_total_logins,
recent_failure_count, mfa_used, outcome_is_failure
```

This is deliberate: the comparison is about detection *method*
(transparent additive rules vs. learned anomaly boundary), not about one
approach having access to richer signal than the other.

## Training data — a stated limitation, not a hidden one

`generate_synthetic_normal_logins()` produces synthetic "normal" logins
consistent with a single baseline (usual countries/hours, a trusted
device most of the time). This stands in for what would be a rolling
window of a real user's historical successful logins in production.

**This is a narrow training distribution** — a single synthetic user
profile, not real organisational traffic variety. Any conclusions drawn
from it should be treated as provisional until validated against
CERT/LANL data per O4. This limitation is worth stating explicitly in
the dissertation rather than glossed over — it's directly relevant to
the Sommer & Paxson critique already in the literature review.

## Explainability comparison — the core trade-off

The rule-based engine's explainability is exact: every point in a score
traces to a named rule (`R001`, `R007`, etc.) with a documented weight
and rationale.

Isolation Forest has no equivalent by default. `MLScoreResult.contributing_features`
approximates an explanation — it reports which features deviate most
from the training population's mean — but this is a heuristic
post-hoc approximation, not a decomposable "why." It cannot say "+15
points because X," only "this feature looks unusual compared to what the
model was trained on."

This gap is the single most citable finding for the dissertation's
evaluation chapter: it's a direct, concrete illustration of the
transparent-vs-opaque tension the whole project (per its Problem
Statement, Section 1.2) is designed to investigate.

## Initial observations (informal — not a substitute for O4 evaluation)

Running both scorers on the same scenarios (`compare_scorers.py`):

- **Clear-cut cases agree.** A fully normal login and an obvious brute-force
  attack score similarly under both methods (LOW/LOW and CRITICAL/CRITICAL).
- **Borderline cases diverge, and the divergence has a pattern.** Isolation
  Forest tends to score borderline events *more* aggressively than the
  rule engine — e.g. a login one hour outside the usual window, or a
  login from an otherwise-unknown-but-unremarkable device, scored
  noticeably higher under Isolation Forest than under the rules.
- **Interpretation:** this is consistent with Isolation Forest treating
  any statistically rare combination as anomalous, regardless of whether
  that combination is actually threatening — precisely the false-positive
  concern Sommer & Paxson (2010) raise about ML-based anomaly detection
  in operational (not research) conditions. The rule-based engine's fixed,
  human-chosen weights are less sensitive to rare-but-benign variation
  by design.

## API access

`POST /score/compare` returns both scores together, plus a `tiers_agree`
boolean, so this comparison can be run against live/replayed data rather
than only the handful of scenarios in `compare_scorers.py`.

## Next steps toward a formal O4 evaluation

1. Replace synthetic training data with real historical login windows
   from the CERT/LANL datasets once available.
2. Run both scorers across the full labelled dataset and compute
   detection rate / false-positive rate per method, per O4's requirement.
3. Consider whether a **hybrid** approach (rules for the transparent
   base score, ML as a secondary "worth a second look" flag rather than
   a primary score) better serves PMS Ltd's stated priority on practical
   applicability and explainability than either method alone.
