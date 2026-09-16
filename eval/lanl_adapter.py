"""
eval/lanl_adapter.py
=====================
Adapter for evaluating AADRS against the LANL Comprehensive
Cyber-Security Events authentication dataset.

LANL auth.txt.gz columns:
    time, source_user@domain, dest_user@domain, source_computer,
    dest_computer, auth_type, logon_type, auth_orientation, success/failure

LANL redteam.txt.gz columns:
    time, user@domain, source_computer, dest_computer

Dataset limitations:
    LANL does not provide geographic or MFA telemetry. Geographic fields are
    therefore left empty and MFA is neutralised during this evaluation rather
    than interpreted as observed MFA use.
"""

from __future__ import annotations

import csv
import gzip
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Iterator, NamedTuple

from engine.models import AuthEvent, UserBaseline, DeviceProfile


FAILURE_WINDOW_SECONDS = 15 * 60


class LabelledEvent(NamedTuple):
    event: AuthEvent
    is_real_attack: bool
    device: DeviceProfile | None


# ---------------------------------------------------------------------------
# Step 1: Load LANL red-team ground truth
# ---------------------------------------------------------------------------

def load_redteam_labels(
    redteam_path: str,
) -> set[tuple[str, str, str, str]]:
    """
    Return exact:
        (time, user, source_computer, destination_computer)
    tuples for confirmed LANL red-team events.
    """
    labels: set[tuple[str, str, str, str]] = set()

    with gzip.open(redteam_path, "rt") as f:
        reader = csv.reader(f)

        for row in reader:
            if len(row) != 4:
                continue

            time_str, user, src_computer, dst_computer = row
            labels.add(
                (time_str, user, src_computer, dst_computer)
            )

    return labels


# ---------------------------------------------------------------------------
# Step 2: Build behavioural baselines
# ---------------------------------------------------------------------------

def build_baselines(
    auth_path: str,
    training_window_events: int,
) -> dict[str, UserBaseline]:
    """
    Use the first N events per user as the training period.

    All events count toward the size of the training period, but only
    successful authentications are used to learn usual login hours and
    known source computers.
    """

    user_event_counts: dict[str, int] = defaultdict(int)
    user_hours: dict[str, set[int]] = defaultdict(set)
    user_computers: dict[str, set[str]] = defaultdict(set)

    with gzip.open(auth_path, "rt") as f:
        reader = csv.reader(f)

        for row in reader:
            if len(row) != 9:
                continue

            (
                time_str,
                src_user,
                dst_user,
                src_computer,
                dst_computer,
                auth_type,
                logon_type,
                orientation,
                outcome,
            ) = row

            if user_event_counts[src_user] >= training_window_events:
                continue

            user_event_counts[src_user] += 1

            # Failed authentication attempts should not become normal behaviour.
            if outcome.strip().lower() != "success":
                continue

            # LANL timestamps are seconds from the start of capture rather than
            # real UTC timestamps. The hour below is therefore a relative
            # capture hour used consistently for baselining and evaluation.
            relative_hour = (int(time_str) // 3600) % 24

            user_hours[src_user].add(relative_hour)
            user_computers[src_user].add(src_computer)

    baselines: dict[str, UserBaseline] = {}

    for user in user_event_counts:
        baselines[user] = UserBaseline(
            user_id=user,
            usual_countries=[],
            usual_hours_utc=sorted(user_hours[user]),
            usual_devices=sorted(user_computers[user]),
        )

    return baselines


# ---------------------------------------------------------------------------
# Step 3: Stream labelled evaluation events
# ---------------------------------------------------------------------------

def stream_labelled_events(
    auth_path: str,
    baselines: dict[str, UserBaseline],
    redteam_labels: set[tuple[str, str, str, str]],
    skip_events_per_user: int,
) -> Iterator[LabelledEvent]:
    """
    Stream events occurring after each user's training window.

    recent_failure_count contains failures for the same user during the
    preceding 15-minute window. The current event itself is not included.
    """

    user_seen_count: dict[str, int] = defaultdict(int)

    recent_failures: dict[str, deque[int]] = defaultdict(deque)

    with gzip.open(auth_path, "rt") as f:
        reader = csv.reader(f)

        for row in reader:
            if len(row) != 9:
                continue

            (
                time_str,
                src_user,
                dst_user,
                src_computer,
                dst_computer,
                auth_type,
                logon_type,
                orientation,
                outcome,
            ) = row

            event_seconds = int(time_str)
            is_failure = outcome.strip().lower() != "success"

            # Remove failures outside the preceding 15-minute window.
            failures = recent_failures[src_user]

            while (
                failures
                and event_seconds - failures[0] > FAILURE_WINDOW_SECONDS
            ):
                failures.popleft()

            # Count failures BEFORE the current authentication.
            prior_failure_count = len(failures)

            user_seen_count[src_user] += 1

            # Training-period events are not evaluated, but failures occurring
            # near the end of training still provide context for later events.
            if user_seen_count[src_user] <= skip_events_per_user:
                if is_failure:
                    failures.append(event_seconds)
                continue

            baseline = baselines.get(src_user)

            # A computer observed during successful baseline activity is treated
            # as an established device. The fixed profile values are neutral
            # evaluation values; LANL itself does not provide trust/login-count
            # attributes.
            device = None

            if (
                baseline is not None
                and src_computer in baseline.usual_devices
            ):
                device = DeviceProfile(
                    device_id=src_computer,
                    user_id=src_user,
                    device_fingerprint=src_computer,
                    is_trusted=True,
                    total_logins=50,
                )

            # Arbitrary midnight epoch used only to expose LANL's relative
            # hour-of-day to the existing AuthEvent interface.
            event_time = (
                datetime(2025, 1, 1)
                + timedelta(seconds=event_seconds)
            )

            event = AuthEvent(
                user_id=src_user,
                event_time=event_time,
                source_ip="",
                provider="lanl_internal",
                country_code="",
                outcome="failure" if is_failure else "success",

                # LANL contains no MFA field. True is used here solely as a
                # neutral placeholder so R009 is not triggered by unavailable
                # telemetry. It must not be interpreted as observed MFA use.
                mfa_used=True,

                recent_failure_count=prior_failure_count,
                device_fingerprint=src_computer,
            )

            is_attack = (
                time_str,
                src_user,
                src_computer,
                dst_computer,
            ) in redteam_labels

            # Add current failure only AFTER calculating the event's preceding
            # failure count.
            if is_failure:
                failures.append(event_seconds)

            yield LabelledEvent(
                event=event,
                is_real_attack=is_attack,
                device=device,
            )