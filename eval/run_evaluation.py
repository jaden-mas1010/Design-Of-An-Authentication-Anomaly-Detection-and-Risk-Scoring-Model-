"""
eval/run_evaluation.py

LANL evaluation runner for AADRS.

Supports:
- behavioural baseline caching
- periodic evaluation checkpoints
- safe resume after interruption
- final JSON result export

Important:
Resume replays earlier LANL events without rescoring them so that the
rolling state maintained by lanl_adapter.py is reconstructed correctly.
"""

from __future__ import annotations

import json
import os
import pickle
from collections import defaultdict
from pathlib import Path

from engine.models import User
from engine.scorer import compute_risk_score
from eval.lanl_adapter import (
    load_redteam_labels,
    build_baselines,
    stream_labelled_events,
)


AUTH_PATH = "data/auth.txt.gz"
REDTEAM_PATH = "data/redteam.txt.gz"

# First 50 events per user establish the behavioural baseline.
# They are not included in the evaluation results.
TRAINING_WINDOW = 50

# MEDIUM or above is treated as a positive detection.
FLAG_THRESHOLD_TIER = "MEDIUM"

TIER_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Progress is still printed every 100,000 events.
PROGRESS_INTERVAL = 100_000

# Save evaluation state every 1 million scored events.
CHECKPOINT_INTERVAL = 1_000_000

EVIDENCE_DIR = Path("evidence")

CHECKPOINT_PATH = EVIDENCE_DIR / "lanl_checkpoint.json"
BASELINE_CACHE_PATH = EVIDENCE_DIR / "lanl_baselines.pkl"
FINAL_RESULTS_PATH = EVIDENCE_DIR / "lanl_results.json"


def tier_at_or_above(tier: str, threshold: str) -> bool:
    """Return True when the event tier meets or exceeds the flag threshold."""
    return TIER_ORDER.index(tier) >= TIER_ORDER.index(threshold)


def auth_file_metadata() -> dict:
    """Return metadata used to ensure caches belong to the current dataset."""
    path = Path(AUTH_PATH)

    return {
        "auth_path": str(path),
        "auth_size": path.stat().st_size,
        "auth_mtime": path.stat().st_mtime,
        "training_window": TRAINING_WINDOW,
        "flag_threshold_tier": FLAG_THRESHOLD_TIER,
    }


def metadata_matches(saved: dict) -> bool:
    """Check whether saved state belongs to the current evaluation setup."""
    current = auth_file_metadata()

    return all(
        saved.get(key) == value
        for key, value in current.items()
    )


def save_baselines(baselines) -> None:
    """Persist behavioural baselines after the expensive baseline pass."""
    payload = {
        "metadata": auth_file_metadata(),
        "baselines": baselines,
    }

    temp_path = BASELINE_CACHE_PATH.with_suffix(".tmp")

    with open(temp_path, "wb") as f:
        pickle.dump(payload, f)

    os.replace(temp_path, BASELINE_CACHE_PATH)


def load_cached_baselines():
    """Load cached baselines if they match the current LANL file/config."""
    if not BASELINE_CACHE_PATH.exists():
        return None

    try:
        with open(BASELINE_CACHE_PATH, "rb") as f:
            payload = pickle.load(f)

        if not metadata_matches(payload.get("metadata", {})):
            print("  Baseline cache does not match current configuration.")
            return None

        return payload["baselines"]

    except Exception as exc:
        print(f"  Could not load baseline cache: {exc}")
        return None


def save_checkpoint(
    event_count: int,
    tp: int,
    fp: int,
    tn: int,
    fn: int,
    total_risk_score: int,
    tier_counts: dict,
    rule_hits,
) -> None:
    """Atomically save current evaluation progress."""

    payload = {
        "metadata": auth_file_metadata(),
        "event_count": event_count,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "total_risk_score": total_risk_score,
        "tier_counts": dict(tier_counts),
        "rule_hits": {
            rule_id: list(values)
            for rule_id, values in rule_hits.items()
        },
    }

    temp_path = CHECKPOINT_PATH.with_suffix(".tmp")

    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    os.replace(temp_path, CHECKPOINT_PATH)


def load_checkpoint():
    """Load a valid evaluation checkpoint if one exists."""

    if not CHECKPOINT_PATH.exists():
        return None

    try:
        with open(CHECKPOINT_PATH, "r", encoding="utf-8") as f:
            payload = json.load(f)

        if not metadata_matches(payload.get("metadata", {})):
            print(
                "Checkpoint exists but does not match the current "
                "dataset/configuration. Starting a fresh evaluation."
            )
            return None

        return payload

    except Exception as exc:
        print(f"Could not load checkpoint: {exc}")
        return None


def save_final_results(
    event_count: int,
    tp: int,
    fp: int,
    tn: int,
    fn: int,
    recall: float,
    precision: float,
    fpr: float,
    f1: float,
    mean_risk_score: float,
    tier_counts: dict,
    rule_hits,
) -> None:
    """Save final results in machine-readable JSON form."""

    rule_results = {}

    for rule_id, (attack_hits, benign_hits) in sorted(rule_hits.items()):

        total = attack_hits + benign_hits

        rule_precision = (
            attack_hits / total
            if total
            else 0.0
        )

        rule_results[rule_id] = {
            "fired": total,
            "attack_hits": attack_hits,
            "benign_hits": benign_hits,
            "precision": rule_precision,
        }

    payload = {
        "metadata": auth_file_metadata(),
        "total_events_evaluated": event_count,
        "confusion_matrix": {
            "TP": tp,
            "FP": fp,
            "TN": tn,
            "FN": fn,
        },
        "metrics": {
            "recall": recall,
            "precision": precision,
            "f1": f1,
            "false_positive_rate": fpr,
        },
        "mean_risk_score": mean_risk_score,
        "tier_counts": dict(tier_counts),
        "rule_results": rule_results,
    }

    temp_path = FINAL_RESULTS_PATH.with_suffix(".tmp")

    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    os.replace(temp_path, FINAL_RESULTS_PATH)


def main():

    EVIDENCE_DIR.mkdir(exist_ok=True)

    # -----------------------------------------------------------------------
    # Load ground truth
    # -----------------------------------------------------------------------

    print("Loading red-team ground-truth labels...")

    redteam_labels = load_redteam_labels(REDTEAM_PATH)

    print(
        f"  {len(redteam_labels)} confirmed attack events loaded.\n"
    )

    # -----------------------------------------------------------------------
    # Load or build behavioural baselines
    # -----------------------------------------------------------------------

    baselines = load_cached_baselines()

    if baselines is not None:

        print(
            "Loading cached behavioural baselines..."
        )

        print(
            f"  {len(baselines)} user baselines loaded.\n"
        )

    else:

        print(
            f"Building baselines from first "
            f"{TRAINING_WINDOW} events per user..."
        )

        baselines = build_baselines(
            AUTH_PATH,
            TRAINING_WINDOW,
        )

        print(
            f"  {len(baselines)} user baselines built."
        )

        print(
            "Saving behavioural baseline cache..."
        )

        save_baselines(baselines)

        print(
            f"  Saved to {BASELINE_CACHE_PATH}\n"
        )

    # -----------------------------------------------------------------------
    # Load checkpoint if available
    # -----------------------------------------------------------------------

    checkpoint = load_checkpoint()

    if checkpoint:

        event_count = int(
            checkpoint["event_count"]
        )

        tp = int(checkpoint["tp"])
        fp = int(checkpoint["fp"])
        tn = int(checkpoint["tn"])
        fn = int(checkpoint["fn"])

        total_risk_score = int(
            checkpoint["total_risk_score"]
        )

        tier_counts = {
            tier: int(
                checkpoint["tier_counts"].get(tier, 0)
            )
            for tier in TIER_ORDER
        }

        rule_hits = defaultdict(
            lambda: [0, 0]
        )

        for rule_id, values in checkpoint[
            "rule_hits"
        ].items():

            rule_hits[rule_id] = [
                int(values[0]),
                int(values[1]),
            ]

        resume_event_count = event_count

        print(
            "Valid checkpoint found."
        )

        print(
            f"  Evaluation previously completed through "
            f"{resume_event_count:,} events."
        )

        print(
            "  Replaying earlier events to reconstruct "
            "rolling LANL state."
        )

        print(
            "  These replayed events will NOT be scored again.\n"
        )

    else:

        tp = fp = tn = fn = 0

        event_count = 0
        total_risk_score = 0

        tier_counts = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }

        rule_hits: dict[str, list[int]] = defaultdict(
            lambda: [0, 0]
        )

        resume_event_count = 0

    # -----------------------------------------------------------------------
    # Stream and evaluate events
    # -----------------------------------------------------------------------

    print("Streaming LANL events...")

    stream_position = 0

    try:

        for labelled in stream_labelled_events(
            AUTH_PATH,
            baselines,
            redteam_labels,
            TRAINING_WINDOW,
        ):

            stream_position += 1

            # ---------------------------------------------------------------
            # Resume replay
            # ---------------------------------------------------------------

            if stream_position <= resume_event_count:

                if (
                    stream_position % 10_000_000 == 0
                    or stream_position == resume_event_count
                ):
                    print(
                        f"  ...replayed "
                        f"{stream_position:,} / "
                        f"{resume_event_count:,} events"
                    )

                continue

            # ---------------------------------------------------------------
            # New event: score normally
            # ---------------------------------------------------------------

            event_count += 1

            user = User(
                user_id=labelled.event.user_id,
                upn=labelled.event.user_id,
            )

            baseline = baselines.get(
                labelled.event.user_id
            )

            result = compute_risk_score(
                labelled.event,
                user,
                baseline,
                device=labelled.device,
            )

            # ---------------------------------------------------------------
            # Risk distribution
            # ---------------------------------------------------------------

            total_risk_score += result.risk_score

            tier_counts[result.risk_tier] += 1

            # ---------------------------------------------------------------
            # Binary detection result
            # ---------------------------------------------------------------

            flagged = tier_at_or_above(
                result.risk_tier,
                FLAG_THRESHOLD_TIER,
            )

            if labelled.is_real_attack and flagged:
                tp += 1

            elif labelled.is_real_attack and not flagged:
                fn += 1

            elif not labelled.is_real_attack and flagged:
                fp += 1

            else:
                tn += 1

            # ---------------------------------------------------------------
            # Per-rule contribution
            # ---------------------------------------------------------------

            for factor in result.risk_factor_details:

                outcome_index = (
                    0 if labelled.is_real_attack else 1
                )

                rule_hits[
                    factor.rule_id
                ][outcome_index] += 1

            # ---------------------------------------------------------------
            # Progress
            # ---------------------------------------------------------------

            if event_count % PROGRESS_INTERVAL == 0:

                print(
                    f"  ...{event_count:,} events processed"
                )

            # ---------------------------------------------------------------
            # Periodic checkpoint
            # ---------------------------------------------------------------

            if event_count % CHECKPOINT_INTERVAL == 0:

                save_checkpoint(
                    event_count,
                    tp,
                    fp,
                    tn,
                    fn,
                    total_risk_score,
                    tier_counts,
                    rule_hits,
                )

                print(
                    f"  [checkpoint saved at "
                    f"{event_count:,} events]"
                )

    except KeyboardInterrupt:

        print(
            "\nEvaluation interrupted by user."
        )

        print(
            "Saving checkpoint before exiting..."
        )

        save_checkpoint(
            event_count,
            tp,
            fp,
            tn,
            fn,
            total_risk_score,
            tier_counts,
            rule_hits,
        )

        print(
            f"Checkpoint saved at "
            f"{event_count:,} evaluated events."
        )

        return

    except Exception:

        print(
            "\nUnexpected error occurred."
        )

        print(
            "Saving checkpoint before re-raising error..."
        )

        save_checkpoint(
            event_count,
            tp,
            fp,
            tn,
            fn,
            total_risk_score,
            tier_counts,
            rule_hits,
        )

        print(
            f"Checkpoint saved at "
            f"{event_count:,} evaluated events."
        )

        raise

    # -----------------------------------------------------------------------
    # Calculate metrics
    # -----------------------------------------------------------------------

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0.0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0.0
    )

    fpr = (
        fp / (fp + tn)
        if (fp + tn)
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    mean_risk_score = (
        total_risk_score / event_count
        if event_count
        else 0.0
    )

    # -----------------------------------------------------------------------
    # Print results
    # -----------------------------------------------------------------------

    print("\n==============================")
    print("AADRS LANL EVALUATION RESULTS")
    print("==============================")

    print(
        f"\nTotal events evaluated: "
        f"{event_count:,}"
    )

    print(
        f"TP={tp:,}  "
        f"FP={fp:,}  "
        f"TN={tn:,}  "
        f"FN={fn:,}"
    )

    print("\nDetection Metrics")
    print("-----------------")

    print(f"Recall (TPR):        {recall:.4f}")
    print(f"Precision:           {precision:.4f}")
    print(f"F1 Score:            {f1:.4f}")
    print(f"False Positive Rate: {fpr:.4f}")

    print("\nRisk Score Summary")
    print("------------------")

    print(
        f"Mean risk score: "
        f"{mean_risk_score:.2f}/100"
    )

    print("\nRisk-tier distribution:")

    for tier in TIER_ORDER:

        count = tier_counts[tier]

        percentage = (
            (count / event_count) * 100
            if event_count
            else 0.0
        )

        print(
            f"  {tier:<8} "
            f"{count:>12,} "
            f"({percentage:6.2f}%)"
        )

    # -----------------------------------------------------------------------
    # Per-rule analysis
    # -----------------------------------------------------------------------

    print(
        "\nPer-rule contribution "
        "(attack hits vs benign hits)"
    )

    print("------------------------------------------")

    for rule_id, (
        attack_hits,
        benign_hits,
    ) in sorted(rule_hits.items()):

        total = attack_hits + benign_hits

        rule_precision = (
            attack_hits / total
            if total
            else 0.0
        )

        print(
            f"{rule_id}: "
            f"fired={total:,} | "
            f"attack={attack_hits:,} | "
            f"benign={benign_hits:,} | "
            f"precision={rule_precision:.3f}"
        )

    # -----------------------------------------------------------------------
    # Save final structured results
    # -----------------------------------------------------------------------

    save_final_results(
        event_count,
        tp,
        fp,
        tn,
        fn,
        recall,
        precision,
        fpr,
        f1,
        mean_risk_score,
        tier_counts,
        rule_hits,
    )

    print(
        f"\nFinal results saved to "
        f"{FINAL_RESULTS_PATH}"
    )

    # Evaluation completed successfully.
    # Remove the temporary resume checkpoint.
    if CHECKPOINT_PATH.exists():
        CHECKPOINT_PATH.unlink()

    print(
        "Checkpoint removed because the "
        "evaluation completed successfully."
    )


if __name__ == "__main__":
    main()