# AADRS — Evaluation Plan (Phase 5/6)

This document defines how the rule weights, tier thresholds, and the
Isolation Forest comparison will be validated against real data, rather
than left as design-time placeholders (see docs/weighting_rationale.md
and docs/engineering_handoff.md, both of which flag this as outstanding).

## 1. Data Source

CERT Insider Threat datasets (Carnegie Mellon SEI) or the LANL
Comprehensive Cyber Security Events dataset — both contain real or
realistic authentication event logs with some ground-truth labelling
(insider-threat scenarios in CERT; red-team activity in LANL).

**Action for you:** confirm which one Kingston/PMS Ltd expects — they
differ in structure and labelling density, so the choice affects how
much manual labelling you need to do yourself.

## 2. What "Evaluation" Actually Means Here

Two separate things are currently described as "provisional" in your code
and need separate evidence:

**(a) Rule weights and thresholds** (BRUTE_FORCE_THRESHOLD=5,
CREDENTIAL_STUFFING_THRESHOLD=8, tier boundaries at 30/60/85, etc.)
→ tested by running your existing rule engine unmodified against
labelled data and measuring outcomes.

**(b) The rule-based approach vs the ML approach**
→ tested by running both scorers against the same labelled data and
comparing which one classifies better — this is the comparison
compare_scorers.py already sets up manually; evaluation formalises it.

## 3. Metrics to Compute

For (a), standard binary classification metrics, treating each labelled
malicious event as positive:

- **True Positive Rate / Recall** — of all real attacks in the data,
  what fraction did AADRS flag at MEDIUM or above?
- **False Positive Rate** — of all legitimate events, what fraction got
  flagged unnecessarily? This is the number Question 2 and Question 5 of
  the meeting both specifically asked about.
- **Precision** — of everything AADRS flagged, how much was real?
- **ROC curve / AUC** — sweep the tier thresholds across a range and plot
  TPR against FPR, rather than only evaluating the current fixed
  thresholds. This directly answers whether 30/60/85 are good choices or
  arbitrary ones — the exact challenge the meeting raised.

For (b), the same metrics computed separately for the Isolation Forest
scorer, so you can honestly state which approach performs better on this
dataset — and where each fails differently. Your ML docstring already
notes this needs formal comparison; this closes that gap.

## 4. Per-Rule Contribution Analysis

Beyond overall score accuracy, evaluate each rule individually:

- For each of R001–R010/R012, isolate cases where *only that rule* fired,
  and check: does it correlate with a real attack in this dataset, or
  mostly with false positives?
- This lets you revisit individual weights (e.g. "R007's +20 might be
  too aggressive if brute-force precursors show a high false-positive
  rate in CERT data") rather than only tuning the total score.
- This is also what finally answers R009's currently-undocumented
  compounding threshold — you can empirically check whether ≥15 is a
  reasonable cutoff or should move.

## 5. Suggested Process

1. Pull a representative subset of the chosen dataset (don't need the
   full CERT/LANL corpus — a labelled subset is enough for a dissertation
   scope)
2. Write a mapping/adapter script converting the dataset's log format
   into your `AuthEvent` / `UserBaseline` / `DeviceProfile` shapes —
   this is new code you'll need to write, since CERT/LANL won't match
   your schema natively
3. Run both scorers (rule-based, Isolation Forest) across the full subset
4. Compute the metrics in Section 3, overall and per-rule
5. Document findings the same way weighting_rationale.md documents design
   decisions — one section per rule, with the empirical result next to
   the original justification

## 6. What Changes Afterward

Once this runs, docs/weighting_rationale.md and engine/rules.py's
threshold constants should be updated to cite empirical support rather
than "provisional pending evaluation" — that phrase should disappear
from the codebase once this phase completes, replaced by references to
the specific dataset and metric that justifies each number.

## 7. Honest Limitations to State in the Dissertation

- CERT/LANL data reflects specific organisational contexts (a US
  insider-threat research corpus, or LANL's internal network) —
  performance here doesn't guarantee generalisation to arbitrary
  organisations
- Labelling in these datasets isn't perfect ground truth; note this
  rather than treating computed metrics as exact
- Sample size and class imbalance (real attacks are rare) should be
  reported alongside any single accuracy number, since accuracy alone is
  misleading on imbalanced data — recall and precision matter more here