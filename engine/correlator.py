"""
engine.correlator
=================
 
Stateful event correlation for AADRS.
 
Detects:
1. FAILURE_THEN_SUCCESS
2. SAME_IP_MULTIPLE_USERS
3. REPEATED_HIGH_RISK_USER
 
Design note - why this module is stateful
-----------------------------------------
The previous implementation recomputed every case from scratch on each
call, over a rolling `now - 30 minutes` window, and derived case_id from
the earliest event in the case. Two consequences:
 
  * A case's identity changed whenever its membership changed, because
    min(event_time) moved as old events aged out. The UI saw the same
    ongoing incident as a brand-new card each refresh.
  * `now` was the newest event's timestamp rather than wall clock, so an
    unrelated burst of traffic could slide the window forward and delete
    cases the analyst was still reading.
 
Commercial SIEMs do not work this way. A Splunk ES notable event or a
Microsoft Sentinel incident is *written once* when the correlation fires,
gets an immutable ID, and then accumulates members. It disappears when an
analyst dispositions it or when retention expires - never because the
detection window moved.
 
This module follows that model:
 
  * CorrelationStore holds cases keyed by ENTITY (user or source IP), not
    by timestamp. case_id is assigned at creation and never changes.
  * Detection still runs over a rolling buffer of recent events, but its
    output is *reconciled* into persisted cases rather than replacing
    them.
  * A case stops accepting new members after GROUPING_WINDOW of silence
    (status becomes CLOSED), but remains visible until RETENTION expires
    or an analyst dispositions it.
  * Ingestion is idempotent: events are deduplicated by ID, so calling
    ingest() repeatedly with overlapping batches is safe. This matters
    because the API layer re-sends recent events on every push.
  * Every case carries a monotonic `rev`, bumped only on real mutation,
    so the dashboard can skip re-rendering cards that have not changed.
 
Scoring is deliberately non-saturating. The previous formula
(highest_event_score + sum(signal points), capped at 100) pinned almost
every case to 100/CRITICAL as soon as one member event scored highly,
which destroyed priority as a triage signal. Signal points now add a
proportion of the remaining headroom instead.
"""
 
from __future__ import annotations
 
import itertools
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator
 
 
HIGH_TIERS = {"HIGH", "CRITICAL"}
 
# How long a case keeps accepting new member events after its last
# activity. Mirrors Sentinel's incident grouping window.
GROUPING_WINDOW = timedelta(minutes=15)
 
# How long a CLOSED case stays visible to the analyst. Ageing out of the
# detection window is not the same thing as being resolved.
RETENTION = timedelta(hours=24)
 
# Rolling buffer of events that detection runs over.
DETECTION_WINDOW = timedelta(minutes=30)
MAX_BUFFERED_EVENTS = 5000
 
PRIORITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
 
 
@dataclass
class EvidenceLine:
    """
    Structured evidence so the UI can render timestamps in the analyst's
    local timezone. The previous version emitted a preformatted UTC
    string into a card whose header used toLocaleString(), so one case
    showed two different clocks.
    """
    time: str          # ISO-8601, UTC, timezone-aware
    text: str
    event_id: str | None = None
 
 
@dataclass
class CorrelationSignal:
    signal_id: str
    title: str
    description: str
    points: int
    evidence: list[EvidenceLine] = field(default_factory=list)
 
 
@dataclass
class CorrelationCase:
    case_id: str
    user_id: str | None
    source_ip: str | None
    started_at: datetime
    ended_at: datetime
    event_count: int
    highest_event_score: int
    correlation_score: int
    priority: str
    signals: list[CorrelationSignal]
    event_ids: list[str]
    recommended_actions: list[str]
    # --- added for stable, incremental rendering and triage ---
    rev: int = 1                       # bumped on every real mutation
    status: str = "OPEN"               # OPEN | CLOSED | DISPOSITIONED
    disposition: str | None = None     # TRUE_POSITIVE | FALSE_POSITIVE | BENIGN_TRUE_POSITIVE
    created_at: datetime | None = None
    updated_at: datetime | None = None
    linked_case_ids: list[str] = field(default_factory=list)
 
 
# --------------------------------------------------------------- helpers
 
def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
 
 
def _get(event: Any, name: str, default: Any = None) -> Any:
    return event.get(name, default) if isinstance(event, dict) else getattr(event, name, default)
 
 
def _event_time(event: Any) -> datetime:
    return _utc(_get(event, "event_time"))
 
 
def _event_id(event: Any) -> str:
    value = _get(event, "id")
    if value is not None:
        return str(value)
    return f"{_get(event,'user_id','unknown')}:{_get(event,'source_ip','unknown')}:{_event_time(event).isoformat()}"
 
 
def _risk_tier(event: Any) -> str:
    return str(_get(event, "risk_tier", "LOW")).upper()
 
 
def _risk_score(event: Any) -> int:
    try:
        return int(_get(event, "risk_score", 0) or 0)
    except (TypeError, ValueError):
        return 0
 
 
def _outcome(event: Any) -> str:
    return str(_get(event, "outcome", "")).strip().lower()
 
 
def _is_success(event: Any) -> bool:
    return _outcome(event) in {"success", "successful", "succeeded", "allow", "allowed"}
 
 
def _is_failure(event: Any) -> bool:
    return _outcome(event) in {"failure", "failed", "fail", "deny", "denied"}
 
 
def _priority(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"
 
 
def _case_score(highest_event_score: int, signal_points: int) -> int:
    """
    Non-saturating combination. Signal points add a share of the score
    still available above the highest member event, so correlation always
    raises priority but never pins every case to 100.
 
        base 20, +55 points -> 20 + 55*0.80 = 64
        base 80, +55 points -> 80 + 55*0.20 = 91
    """
    base = max(0, min(100, int(highest_event_score)))
    headroom = (100 - base) / 100.0
    return int(round(min(100.0, base + signal_points * headroom)))
 
 
def _evidence(event: Any, text: str) -> EvidenceLine:
    return EvidenceLine(time=_event_time(event).isoformat(), text=text, event_id=_event_id(event))
 
 
# ------------------------------------------------------------- detection
 
@dataclass
class _Detection:
    """A raw detection, before it is reconciled into a persisted case."""
    entity_kind: str          # "user" | "ip"
    entity_value: str
    signal: CorrelationSignal
    events: list[Any]
 
 
def _detect(recent: list[Any]) -> list[_Detection]:
    """Run the three correlation rules over a window of events."""
    detections: list[_Detection] = []
 
    by_user: dict[str, list[Any]] = {}
    for e in recent:
        user_id = _get(e, "user_id")
        if user_id:
            by_user.setdefault(str(user_id), []).append(e)
 
    # 1) 3+ failures followed by success within 10 minutes
    for user_id, user_events in by_user.items():
        for idx, current in enumerate(user_events):
            if not _is_success(current):
                continue
            success_time = _event_time(current)
            previous = [
                e for e in user_events[:idx]
                if _event_time(e) >= success_time - timedelta(minutes=10) and _is_failure(e)
            ]
            if len(previous) >= 3:
                correlated = previous + [current]
                detections.append(_Detection(
                    "user", user_id,
                    CorrelationSignal(
                        "FAILURE_THEN_SUCCESS",
                        "Repeated failures followed by success",
                        f"{len(previous)} failed attempts for {user_id} were followed by a success within 10 minutes.",
                        25,
                        [_evidence(e, f"{_get(e,'source_ip','unknown')} | {_get(e,'outcome','')}") for e in correlated],
                    ),
                    correlated,
                ))
 
    # 2) Same IP touching 3+ users within 15 minutes
    by_ip: dict[str, list[Any]] = {}
    for e in recent:
        source_ip = _get(e, "source_ip")
        if source_ip:
            by_ip.setdefault(str(source_ip), []).append(e)
 
    for source_ip, ip_events in by_ip.items():
        ip_events.sort(key=_event_time)
        for i, anchor in enumerate(ip_events):
            end = _event_time(anchor) + timedelta(minutes=15)
            window = [e for e in ip_events[i:] if _event_time(e) <= end]
            users = sorted({str(_get(e, "user_id")) for e in window if _get(e, "user_id")})
            if len(users) >= 3:
                detections.append(_Detection(
                    "ip", source_ip,
                    CorrelationSignal(
                        "SAME_IP_MULTIPLE_USERS",
                        "One source IP targeted multiple users",
                        f"Source IP {source_ip} was associated with {len(users)} distinct users within 15 minutes.",
                        30,
                        [_evidence(e, f"{_get(e,'user_id','unknown')} | {_get(e,'outcome','')}") for e in window],
                    ),
                    window,
                ))
                break
 
    # 3) 2+ HIGH/CRITICAL events for one user within the detection window
    for user_id, user_events in by_user.items():
        risky = [e for e in user_events if _risk_tier(e) in HIGH_TIERS]
        if len(risky) >= 2:
            detections.append(_Detection(
                "user", user_id,
                CorrelationSignal(
                    "REPEATED_HIGH_RISK_USER",
                    "Repeated high-risk authentication activity",
                    f"{user_id} generated {len(risky)} HIGH/CRITICAL events within 30 minutes.",
                    20,
                    [_evidence(e, f"score {_risk_score(e)} | {_risk_tier(e)} | {_get(e,'source_ip','unknown')}") for e in risky],
                ),
                risky,
            ))
 
    return detections
 
 
def _recommended_actions(signals: list[CorrelationSignal]) -> list[str]:
    ids = {s.signal_id for s in signals}
    actions: list[str] = []
 
    if "FAILURE_THEN_SUCCESS" in ids:
        actions += [
            "Validate whether the successful authentication was initiated by the user.",
            "Review authentication activity immediately before and after the successful login.",
            "Review active sessions and revoke them if compromise is confirmed.",
        ]
 
    if "SAME_IP_MULTIPLE_USERS" in ids:
        actions += [
            "Review all authentication attempts from the source IP across affected identities.",
            "Check whether the pattern is consistent with password spraying or another credential attack.",
        ]
 
    if "REPEATED_HIGH_RISK_USER" in ids:
        actions += [
            "Prioritise the identity for analyst investigation and review the full event timeline.",
            "Compare device, location, MFA, and source-IP changes across the correlated events.",
        ]
 
    return list(dict.fromkeys(actions))
 
 
# ----------------------------------------------------------------- store
 
class CorrelationStore:
    """
    Holds correlation cases across calls. Cases are keyed by entity, so a
    user's ongoing incident keeps one immutable case_id no matter how its
    membership changes.
    """
 
    def __init__(
        self,
        grouping_window: timedelta = GROUPING_WINDOW,
        retention: timedelta = RETENTION,
        detection_window: timedelta = DETECTION_WINDOW,
    ) -> None:
        self.grouping_window = grouping_window
        self.retention = retention
        self.detection_window = detection_window
 
        self._cases: dict[str, CorrelationCase] = {}          # case_id -> case
        self._open_by_entity: dict[tuple[str, str], str] = {}  # entity -> open case_id
        self._buffer: dict[str, Any] = {}                      # event_id -> event
        self._seq: Iterator[int] = itertools.count(1)
 
    # -- public API ----------------------------------------------------
 
    def ingest(self, events: Iterable[Any], now: datetime | None = None) -> list[CorrelationCase]:
        """
        Add events to the rolling buffer, re-run detection, reconcile the
        results into persisted cases, and return the current case list.
 
        Safe to call repeatedly with overlapping batches: events are
        deduplicated by ID and signals are merged rather than appended.
        """
        for event in events:
            self._buffer.setdefault(_event_id(event), event)
 
        now = _utc(now) if now else datetime.now(timezone.utc)
        self._trim_buffer(now)
 
        recent = sorted(self._buffer.values(), key=_event_time)
        for detection in _detect(recent):
            self._reconcile(detection, now)
 
        self._age_cases(now)
        self._link_overlapping_cases()
        return self.cases()
 
    def cases(self) -> list[CorrelationCase]:
        return sorted(
            self._cases.values(),
            key=lambda c: (PRIORITY_RANK.get(c.priority, 0), c.correlation_score, c.ended_at),
            reverse=True,
        )
 
    def get(self, case_id: str) -> CorrelationCase | None:
        return self._cases.get(case_id)
 
    def set_disposition(self, case_id: str, disposition: str) -> CorrelationCase | None:
        """
        Analyst verdict. Kept here rather than in the UI so the evaluation
        chapter has a real precision denominator instead of synthetic
        labels, and so a future supervised arm has something to train on.
        """
        allowed = {"TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_TRUE_POSITIVE"}
        if disposition not in allowed:
            raise ValueError(f"disposition must be one of {sorted(allowed)}")
        case = self._cases.get(case_id)
        if case is None:
            return None
        case.disposition = disposition
        case.status = "DISPOSITIONED"
        case.updated_at = datetime.now(timezone.utc)
        case.rev += 1
        # A dispositioned case stops collecting new members.
        self._open_by_entity.pop(self._entity_of(case), None)
        return case
 
    def reset(self) -> None:
        self._cases.clear()
        self._open_by_entity.clear()
        self._buffer.clear()
 
    # -- internals -----------------------------------------------------
 
    @staticmethod
    def _entity_of(case: CorrelationCase) -> tuple[str, str]:
        if case.user_id:
            return ("user", str(case.user_id))
        return ("ip", str(case.source_ip))
 
    def _trim_buffer(self, now: datetime) -> None:
        cutoff = now - self.detection_window
        self._buffer = {
            eid: e for eid, e in self._buffer.items() if _event_time(e) >= cutoff
        }
        if len(self._buffer) > MAX_BUFFERED_EVENTS:
            keep = sorted(self._buffer.items(), key=lambda kv: _event_time(kv[1]), reverse=True)
            self._buffer = dict(keep[:MAX_BUFFERED_EVENTS])
 
    def _reconcile(self, detection: _Detection, now: datetime) -> None:
        key = (detection.entity_kind, detection.entity_value)
        times = [_event_time(e) for e in detection.events]
        started, ended = min(times), max(times)
 
        case_id = self._open_by_entity.get(key)
        case = self._cases.get(case_id) if case_id else None
 
        if case is None or ended > case.ended_at + self.grouping_window:
            case = self._new_case(detection, started, ended, now)
            self._cases[case.case_id] = case
            self._open_by_entity[key] = case.case_id
 
        changed = self._merge_signal(case, detection)
        changed |= self._merge_events(case, detection.events, started, ended)
 
        if changed:
            self._rescore(case)
            case.updated_at = now
            case.rev += 1
 
    def _new_case(self, detection: _Detection, started: datetime, ended: datetime, now: datetime) -> CorrelationCase:
        # Immutable identity, assigned once. Deliberately NOT derived from
        # any event timestamp - that was the root cause of cards being
        # reborn under new IDs as their membership shifted.
        subject = "".join(ch for ch in detection.entity_value if ch.isalnum())[-12:] or "unknown"
        case_id = f"CASE-{next(self._seq):05d}-{subject}"
        return CorrelationCase(
            case_id=case_id,
            user_id=detection.entity_value if detection.entity_kind == "user" else None,
            source_ip=detection.entity_value if detection.entity_kind == "ip" else None,
            started_at=started,
            ended_at=ended,
            event_count=0,
            highest_event_score=0,
            correlation_score=0,
            priority="LOW",
            signals=[],
            event_ids=[],
            recommended_actions=[],
            rev=0,
            status="OPEN",
            created_at=now,
            updated_at=now,
        )
 
    @staticmethod
    def _merge_signal(case: CorrelationCase, detection: _Detection) -> bool:
        incoming = detection.signal
        for existing in case.signals:
            if existing.signal_id != incoming.signal_id:
                continue
            # Same signal firing again with more members: refresh the text
            # and evidence, but do not create a second copy.
            seen = {(ev.time, ev.text) for ev in existing.evidence}
            fresh = [ev for ev in incoming.evidence if (ev.time, ev.text) not in seen]
            if not fresh and existing.description == incoming.description:
                return False
            existing.description = incoming.description
            existing.evidence = sorted(existing.evidence + fresh, key=lambda ev: ev.time)[-50:]
            return True
 
        case.signals.append(incoming)
        case.recommended_actions = _recommended_actions(case.signals)
        return True
 
    @staticmethod
    def _merge_events(case: CorrelationCase, events: list[Any], started: datetime, ended: datetime) -> bool:
        before = len(case.event_ids)
        known = set(case.event_ids)
        highest = case.highest_event_score
 
        for e in events:
            eid = _event_id(e)
            if eid not in known:
                known.add(eid)
                case.event_ids.append(eid)
            highest = max(highest, _risk_score(e))
 
        changed = len(case.event_ids) != before or highest != case.highest_event_score
        case.event_count = len(case.event_ids)
        case.highest_event_score = highest
 
        if started < case.started_at:
            case.started_at, changed = started, True
        if ended > case.ended_at:
            case.ended_at, changed = ended, True
        return changed
 
    @staticmethod
    def _rescore(case: CorrelationCase) -> None:
        points = sum(s.points for s in case.signals)
        case.correlation_score = _case_score(case.highest_event_score, points)
        case.priority = _priority(case.correlation_score)
        case.recommended_actions = _recommended_actions(case.signals)
 
    def _age_cases(self, now: datetime) -> None:
        for key, case_id in list(self._open_by_entity.items()):
            case = self._cases.get(case_id)
            if case is None or now - case.ended_at > self.grouping_window:
                self._open_by_entity.pop(key, None)
                if case is not None and case.status == "OPEN":
                    case.status = "CLOSED"
                    case.updated_at = now
                    case.rev += 1
 
        for case_id, case in list(self._cases.items()):
            if now - case.ended_at > self.retention:
                self._cases.pop(case_id, None)
 
    def _link_overlapping_cases(self) -> None:
        """
        A password-spray burst produces one IP case and several user cases
        over the same events. Rather than merging entity types into one
        card, cross-reference them so the analyst can see they belong
        together.
        """
        cases = list(self._cases.values())
        members = {c.case_id: set(c.event_ids) for c in cases}
        for a, b in itertools.combinations(cases, 2):
            if not members[a.case_id] & members[b.case_id]:
                continue
            for src, dst in ((a, b), (b, a)):
                if dst.case_id not in src.linked_case_ids:
                    src.linked_case_ids.append(dst.case_id)
                    src.rev += 1
 
 
# --------------------------------------------------- module-level façade
 
_DEFAULT_STORE = CorrelationStore()
 
 
def correlate_events(events: Iterable[Any], now: datetime | None = None) -> list[CorrelationCase]:
    """
    Backwards-compatible entry point: same signature as before, so the
    API layer needs no change. Unlike the previous version this is
    stateful - repeated calls accumulate into persisted cases instead of
    rebuilding them, and calling it with an overlapping batch of events is
    idempotent.
    """
    return _DEFAULT_STORE.ingest(events, now=now)
 
 
def get_store() -> CorrelationStore:
    """Access the shared store, e.g. to record an analyst disposition."""
    return _DEFAULT_STORE
 
 
def reset_store() -> None:
    """Clear all state. Intended for tests and for LANL replay reruns."""
    _DEFAULT_STORE.reset()
 
