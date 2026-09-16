"""
engine.ml_scorer
=================
Isolation Forest anomaly scorer - the ML comparison arm discussed with
David Douglas (PMS Ltd) on 7 July 2026: "an interesting comparison
against the rule-based approach already proposed."
 
Design choices, and why:
 
- Isolation Forest is unsupervised - it's trained only on examples of
  NORMAL behaviour and flags events that are structurally easy to
  isolate (few splits needed) as anomalous. This matches the real
  constraint stated in the proposal (Section 1.2): no large labelled
  attack dataset is assumed to be available at deployment time.
 
- It uses the SAME feature set as the rule-based rules (engine.features),
  so the comparison in the dissertation's evaluation chapter is about
  detection *method*, not about the ML model having access to extra
  signal the rules don't. NOTE the limit of that claim: identical
  features do not mean an identical notion of "normal". The synthetic
  training population below contains MFA-less logins and logins with a
  recent failure, so the model learns those are unremarkable, while the
  rule engine penalises them. That asymmetry is in the training
  distribution, not the feature set, and belongs in the evaluation
  discussion.
 
- Training data here is SYNTHETIC (generate_synthetic_normal_logins),
  standing in for what would be a rolling window of a real user's
  historical successful logins in production. This is flagged explicitly
  as a limitation - a synthetic, single-baseline population is a much
  narrower training distribution than real organisational traffic, and
  that narrowness should itself be discussed in the evaluation writeup.
  A second limitation: MODEL_PATH is a single global artefact, so the
  deployed shape is one population-level model, whereas the rule engine
  scores against a per-user UserBaseline.
 
- Score calibration is QUANTILE-based, not min-max. Min-max against the
  training range anchors 100 to "the most anomalous normal event ever
  seen", so anything genuinely anomalous clamps to 100 and every true
  positive lands in CRITICAL. Instead, training quantiles are mapped to
  fixed anchor scores (see _QUANTILES / _ANCHOR_SCORES) and the tail
  above the training maximum saturates smoothly towards 100. Tier
  boundaries therefore mean something relative to the observed normal
  distribution.
 
- Explainability (raised explicitly by PMS as a requirement): Isolation
  Forest itself does not produce a "why" in the way individual named
  rules do. MLScoreResult.contributing_features approximates an
  explanation by reporting which features deviate most from the training
  population's mean, measured in training standard deviations, so that
  features on wider numeric scales do not dominate the ranking by
  construction. A partial mitigation, not a full solution. This gap is
  exactly the trade-off Sommer & Paxson (2010) warn about, and is worth
  stating plainly in the dissertation rather than glossed over.
 
- Persistence stores a plain state dict, not a pickled instance of this
  class. Pickling `self` binds the artefact to this module path and to
  the current class definition, so any refactor silently invalidates
  saved models. Note also that deserialising a model file executes
  arbitrary code: in a security product, ml_model.joblib is an
  untrusted-deserialisation sink and should be integrity-checked before
  loading in any real deployment. Documented as a limitation.
"""
 
from __future__ import annotations
 
import math
import random
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
 
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
 
from .features import extract_features, FEATURE_NAMES
from .models import AuthEvent, UserBaseline, DeviceProfile
 
MODEL_PATH = Path(__file__).parent.parent / "ml_model.joblib"
 
# Bumped whenever the persisted state dict changes shape.
MODEL_FORMAT_VERSION = 2
 
_EPS = 1e-9
 
# Calibration anchors. Percentiles of the raw training score distribution
# are mapped to these fixed output scores, piecewise-linearly. Chosen so
# that a typical normal event sits mid-LOW, the top decile of normal
# events reaches the MEDIUM boundary, the top percentile reaches the HIGH
# boundary, and the most anomalous training event sits exactly at the
# CRITICAL boundary. Anything more anomalous than anything seen in
# training scores above 85 on a saturating tail.
_QUANTILES: Sequence[float] = (50.0, 90.0, 99.0, 100.0)
_ANCHOR_SCORES: Sequence[float] = (15.0, 30.0, 60.0, 85.0)
 
# A feature must deviate by at least this many training standard
# deviations before it is reported as a contributing feature.
_MIN_REPORTABLE_Z = 1.0
 
# Columns with training std below this are treated as degenerate: they
# carry no information the forest could have split on, and their z-scores
# would explode at inference, so they are excluded from explanations.
_DEGENERATE_STD = 1e-6
 
 
@dataclass
class MLScoreResult:
    anomaly_score: int              # 0-100, calibrated, higher = more anomalous
    risk_tier: str                  # LOW / MEDIUM / HIGH / CRITICAL, same thresholds as rule engine
    is_outlier: bool                # raw IsolationForest.predict() == -1
    raw_isolation_score: float      # unnormalised score, for debugging/analysis
    contributing_features: List[str]  # approximate explanation, biggest deviations from training mean
    # Deviation of each contributing feature, in training standard
    # deviations. Same order as contributing_features. Kept alongside the
    # names so the evaluation chapter can report *how* atypical a feature
    # was, not just that it ranked top-3.
    contributing_feature_z: List[float] = field(default_factory=list)
 
 
def _tier_from_score(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"
 
 
def generate_synthetic_normal_logins(
    n_samples: int = 500,
    usual_countries: Optional[List[str]] = None,
    usual_hours: Optional[List[int]] = None,
    source_ips: Optional[List[str]] = None,
    span_days: int = 90,
    random_state: int = 42,
) -> List[List[float]]:
    """
    Generate synthetic feature vectors representing "normal" logins, for
    training the Isolation Forest. Stands in for a rolling window of a
    real user's historical successful, low-risk logins in production.
 
    Events are spread over `span_days` rather than sharing a single
    calendar date, and drawn from a small pool of source IPs rather than
    a single constant. A constant column has zero variance, so the forest
    can never split on it and any derived feature (day-of-week, time
    since previous login, known-IP flag) is dead weight in training while
    still deviating at inference. Run diagnose_training_features() after
    fitting to confirm which columns still carry no variance.
    """
    rng = random.Random(random_state)
    usual_countries = usual_countries or ["GB"]
    usual_hours = usual_hours or list(range(8, 18))
    # TEST-NET-3 (RFC 5737) addresses: routable-looking, never resolvable,
    # safe to embed in a repo.
    source_ips = source_ips or ["203.0.113.10", "203.0.113.11", "203.0.113.12"]
 
    dummy_baseline = UserBaseline(user_id="synthetic", usual_countries=usual_countries, usual_hours_utc=usual_hours)
    dummy_device = DeviceProfile(
        device_id="synthetic_device", user_id="synthetic",
        device_fingerprint="synthetic_fp", is_trusted=True, total_logins=50,
    )
 
    base_date = datetime(2026, 1, 1)
    rows: List[List[float]] = []
    for _ in range(n_samples):
        hour = rng.choice(usual_hours)
        country = rng.choice(usual_countries)
        # Occasionally no device on record yet, but still a legitimate normal login
        # (e.g. first login of the day from a slightly-varying fingerprint capture)
        device = dummy_device if rng.random() > 0.1 else None
        event_time = base_date + timedelta(
            days=rng.randrange(span_days), hours=hour, minutes=rng.randint(0, 59)
        )
        event = AuthEvent(
            user_id="synthetic",
            event_time=event_time,
            source_ip=rng.choice(source_ips),
            provider="azure_ad",
            country_code=country,
            outcome="success",
            mfa_used=rng.random() > 0.3,
            recent_failure_count=rng.choice([0, 0, 0, 1]),
        )
        rows.append(extract_features(event, dummy_baseline, device))
    return rows
 
 
class MLAnomalyScorer:
    """Wraps a fitted IsolationForest with calibration and persistence."""
 
    def __init__(self, n_estimators: int = 200, contamination: float = 0.05, random_state: int = 42):
        # NOTE: with quantile calibration, `contamination` no longer affects
        # anomaly_score at all - it only sets the decision threshold behind
        # IsolationForest.predict(), i.e. MLScoreResult.is_outlier. Since the
        # training set is entirely normal by construction, contamination=0.05
        # means ~5% of normal training events are labelled outliers by design.
        self.model = IsolationForest(
            n_estimators=n_estimators, contamination=contamination, random_state=random_state
        )
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
 
        self._fitted = False
        self._feature_names: List[str] = list(FEATURE_NAMES)
        self._train_score_min: float = 0.0
        self._train_score_quantiles: np.ndarray = np.zeros(len(_QUANTILES))
        self._train_feature_means: np.ndarray = np.zeros(len(FEATURE_NAMES))
        self._train_feature_stds: np.ndarray = np.ones(len(FEATURE_NAMES))
        self._degenerate_mask: np.ndarray = np.zeros(len(FEATURE_NAMES), dtype=bool)
        self.training_config: Dict[str, Any] = {}
 
    # ------------------------------------------------------------------ fit
 
    def fit(self, training_features: List[List[float]], training_config: Optional[Dict[str, Any]] = None) -> None:
        X = np.asarray(training_features, dtype=float)
        if X.ndim != 2 or X.shape[0] == 0:
            raise ValueError("training_features must be a non-empty 2-D array of feature vectors.")
        if X.shape[1] != len(FEATURE_NAMES):
            raise ValueError(
                f"Feature width mismatch: training data has {X.shape[1]} columns, "
                f"FEATURE_NAMES declares {len(FEATURE_NAMES)}."
            )
        if not np.isfinite(X).all():
            raise ValueError("training_features contains NaN or inf; check extract_features.")
 
        self.model.fit(X)
        raw_scores = -self.model.score_samples(X)  # higher = more anomalous
 
        self._train_score_min = float(raw_scores.min())
        q = np.percentile(raw_scores, _QUANTILES)
        # np.interp requires a non-decreasing x; percentiles can tie on
        # small or highly discrete training sets.
        self._train_score_quantiles = np.maximum.accumulate(q)
 
        self._train_feature_means = X.mean(axis=0)
        self._train_feature_stds = X.std(axis=0)
        self._degenerate_mask = self._train_feature_stds < _DEGENERATE_STD
        self._feature_names = list(FEATURE_NAMES)
        self.training_config = dict(training_config or {})
        self._fitted = True
 
        if self._degenerate_mask.any():
            flat = [FEATURE_NAMES[i] for i in np.flatnonzero(self._degenerate_mask)]
            warnings.warn(
                "Zero-variance features in training data; the forest cannot split on them "
                f"and they are excluded from explanations: {flat}",
                RuntimeWarning,
                stacklevel=2,
            )
 
    def diagnose_training_features(self) -> List[Dict[str, Any]]:
        """
        Per-feature mean/std of the training population, plus a degenerate
        flag. Intended for the evaluation chapter: run it once and report
        which features actually carried signal.
        """
        self._require_fitted()
        return [
            {
                "feature": name,
                "mean": float(self._train_feature_means[i]),
                "std": float(self._train_feature_stds[i]),
                "degenerate": bool(self._degenerate_mask[i]),
            }
            for i, name in enumerate(self._feature_names)
        ]
 
    # ---------------------------------------------------------- calibration
 
    def _calibrate(self, raw: float) -> float:
        """Map a raw isolation score to 0-100 using training quantiles."""
        q = self._train_score_quantiles
        anchors = np.asarray(_ANCHOR_SCORES, dtype=float)
 
        if raw <= q[0]:
            # Below the training median: linear from (min, 0) to (p50, 15).
            span = max(q[0] - self._train_score_min, _EPS)
            return float(np.clip(anchors[0] * (raw - self._train_score_min) / span, 0.0, anchors[0]))
 
        if raw <= q[-1]:
            return float(np.interp(raw, q, anchors))
 
        # Above anything seen in training. Saturate towards 100 rather than
        # clamping, so genuinely extreme events remain separable from
        # merely unusual ones.
        scale = max(q[-1] - q[1], _EPS)
        return float(anchors[-1] + (100.0 - anchors[-1]) * (1.0 - math.exp(-(raw - q[-1]) / scale)))
 
    # ---------------------------------------------------------------- score
 
    def score_event(
        self,
        event: AuthEvent,
        baseline: Optional[UserBaseline] = None,
        device: Optional[DeviceProfile] = None,
    ) -> MLScoreResult:
        self._require_fitted()
 
        features = extract_features(event, baseline, device)
        if len(features) != len(self._feature_names):
            raise ValueError(
                f"Feature width mismatch at inference: got {len(features)}, "
                f"model was trained on {len(self._feature_names)}."
            )
        X = np.asarray([features], dtype=float)
 
        raw = float(-self.model.score_samples(X)[0])
        score_0_100 = int(round(np.clip(self._calibrate(raw), 0.0, 100.0)))
 
        is_outlier = bool(self.model.predict(X)[0] == -1)
 
        # Approximate explanation: which features deviate most from the
        # training population's mean, measured in training standard
        # deviations so that features on wider numeric scales do not
        # dominate the ranking purely by their units.
        stds = np.maximum(self._train_feature_stds, _EPS)
        z = np.abs(X[0] - self._train_feature_means) / stds
        z[self._degenerate_mask] = 0.0  # meaningless where training variance was ~0
 
        order = np.argsort(z)[::-1][:3]
        contributing: List[str] = []
        contributing_z: List[float] = []
        for i in order:
            if z[i] < _MIN_REPORTABLE_Z:
                continue
            contributing.append(self._feature_names[i])
            contributing_z.append(round(float(z[i]), 2))
 
        return MLScoreResult(
            anomaly_score=score_0_100,
            risk_tier=_tier_from_score(score_0_100),
            is_outlier=is_outlier,
            raw_isolation_score=raw,
            contributing_features=contributing,
            contributing_feature_z=contributing_z,
        )
 
    def _require_fitted(self) -> None:
        if not self._fitted:
            raise RuntimeError("MLAnomalyScorer is not fitted - call .fit() or load_or_train() first.")
 
    # ---------------------------------------------------------- persistence
 
    def to_state(self) -> Dict[str, Any]:
        self._require_fitted()
        return {
            "format_version": MODEL_FORMAT_VERSION,
            "model": self.model,
            "feature_names": list(self._feature_names),
            "train_score_min": self._train_score_min,
            "train_score_quantiles": self._train_score_quantiles,
            "train_feature_means": self._train_feature_means,
            "train_feature_stds": self._train_feature_stds,
            "degenerate_mask": self._degenerate_mask,
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "random_state": self.random_state,
            "training_config": self.training_config,
        }
 
    @classmethod
    def from_state(cls, state: Dict[str, Any]) -> "MLAnomalyScorer":
        version = state.get("format_version")
        if version != MODEL_FORMAT_VERSION:
            raise ValueError(
                f"Model artefact format {version!r} is not supported by this build "
                f"(expected {MODEL_FORMAT_VERSION}). Retrain with force_retrain=True."
            )
 
        saved_names = list(state["feature_names"])
        if saved_names != list(FEATURE_NAMES):
            raise ValueError(
                "Feature schema drift: the saved model was trained on a different feature set "
                f"({len(saved_names)} features) than engine.features currently declares "
                f"({len(FEATURE_NAMES)}). Retrain with force_retrain=True."
            )
 
        scorer = cls(
            n_estimators=state["n_estimators"],
            contamination=state["contamination"],
            random_state=state["random_state"],
        )
        scorer.model = state["model"]
        scorer._feature_names = saved_names
        scorer._train_score_min = float(state["train_score_min"])
        scorer._train_score_quantiles = np.asarray(state["train_score_quantiles"], dtype=float)
        scorer._train_feature_means = np.asarray(state["train_feature_means"], dtype=float)
        scorer._train_feature_stds = np.asarray(state["train_feature_stds"], dtype=float)
        scorer._degenerate_mask = np.asarray(state["degenerate_mask"], dtype=bool)
        scorer.training_config = dict(state.get("training_config", {}))
        scorer._fitted = True
        return scorer
 
    def save(self, path: Path = MODEL_PATH) -> None:
        joblib.dump(self.to_state(), path)
 
    @staticmethod
    def load(path: Path = MODEL_PATH) -> "MLAnomalyScorer":
        # SECURITY: joblib.load executes arbitrary code from the artefact.
        # Only load model files from a trusted, integrity-checked path.
        return MLAnomalyScorer.from_state(joblib.load(path))
 
 
def load_or_train(
    usual_countries: Optional[List[str]] = None,
    usual_hours: Optional[List[int]] = None,
    n_samples: int = 500,
    random_state: int = 42,
    force_retrain: bool = False,
    path: Path = MODEL_PATH,
) -> MLAnomalyScorer:
    """
    Convenience entry point for the API: load a previously-trained model
    from disk if present, otherwise train on synthetic data and persist it.
 
    A cached model is only reused if it was trained under the *same*
    configuration. Reusing a GB-baseline model to score events under an
    IN baseline silently produces wrong scores, so a mismatch triggers a
    retrain rather than a quiet fallback.
    """
    requested_config: Dict[str, Any] = {
        "usual_countries": list(usual_countries) if usual_countries else ["GB"],
        "usual_hours": list(usual_hours) if usual_hours else list(range(8, 18)),
        "n_samples": n_samples,
        "random_state": random_state,
    }
 
    if path.exists() and not force_retrain:
        try:
            cached = MLAnomalyScorer.load(path)
        except (ValueError, KeyError, EOFError) as exc:
            warnings.warn(f"Cached model at {path} unusable ({exc}); retraining.", RuntimeWarning, stacklevel=2)
        else:
            if cached.training_config == requested_config:
                return cached
            warnings.warn(
                "Cached model was trained under a different configuration "
                f"({cached.training_config} != {requested_config}); retraining.",
                RuntimeWarning,
                stacklevel=2,
            )
 
    scorer = MLAnomalyScorer(random_state=random_state)
    training_data = generate_synthetic_normal_logins(
        n_samples=n_samples,
        usual_countries=usual_countries,
        usual_hours=usual_hours,
        random_state=random_state,
    )
    scorer.fit(training_data, training_config=requested_config)
    scorer.save(path)
    return scorer
 
