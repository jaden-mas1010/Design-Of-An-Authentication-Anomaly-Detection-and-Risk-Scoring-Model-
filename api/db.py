"""
api.db
======
SQLite-backed persistence for user baselines and device profiles,
replacing the in-memory store so data survives an API restart.

Uses the stdlib sqlite3 module - no extra dependency, and the file-based
DB is trivial to inspect/reset during development (just delete aadrs.db).
Schema uses JSON columns for list fields (usual_countries, usual_hours_utc)
since SQLite has no native array type - this is a pragmatic prototyping
choice; a Postgres deployment (per the proposal's Section 4.1) would use
proper array or normalised child-table columns instead.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional

from engine.models import UserBaseline, DeviceProfile

DB_PATH = Path(__file__).parent.parent / "aadrs.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS baselines (
    user_id TEXT PRIMARY KEY,
    usual_countries TEXT NOT NULL,   -- JSON list
    usual_hours_utc TEXT NOT NULL,   -- JSON list
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
    device_fingerprint TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    is_trusted INTEGER NOT NULL,
    total_logins INTEGER NOT NULL,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they don't exist yet. Safe to call on every startup."""
    conn = get_connection()
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def set_baseline(user_id: str, baseline: UserBaseline) -> None:
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO baselines (user_id, usual_countries, usual_hours_utc, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                usual_countries = excluded.usual_countries,
                usual_hours_utc = excluded.usual_hours_utc,
                updated_at = CURRENT_TIMESTAMP
            """,
            (user_id, json.dumps(baseline.usual_countries), json.dumps(baseline.usual_hours_utc)),
        )
        conn.commit()
    finally:
        conn.close()


def get_baseline(user_id: str) -> Optional[UserBaseline]:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM baselines WHERE user_id = ?", (user_id,)
        ).fetchone()
        if row is None:
            return None
        return UserBaseline(
            user_id=user_id,
            usual_countries=json.loads(row["usual_countries"]),
            usual_hours_utc=json.loads(row["usual_hours_utc"]),
        )
    finally:
        conn.close()


def set_device(device_fingerprint: str, device: DeviceProfile) -> None:
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO devices (device_fingerprint, device_id, is_trusted, total_logins, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(device_fingerprint) DO UPDATE SET
                is_trusted = excluded.is_trusted,
                total_logins = excluded.total_logins,
                updated_at = CURRENT_TIMESTAMP
            """,
            (device_fingerprint, device.device_id, int(device.is_trusted), device.total_logins),
        )
        conn.commit()
    finally:
        conn.close()


def get_device(device_fingerprint: Optional[str]) -> Optional[DeviceProfile]:
    if device_fingerprint is None:
        return None
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM devices WHERE device_fingerprint = ?", (device_fingerprint,)
        ).fetchone()
        if row is None:
            return None
        return DeviceProfile(
            device_id=row["device_id"],
            user_id="",
            device_fingerprint=device_fingerprint,
            is_trusted=bool(row["is_trusted"]),
            total_logins=row["total_logins"],
        )
    finally:
        conn.close()
