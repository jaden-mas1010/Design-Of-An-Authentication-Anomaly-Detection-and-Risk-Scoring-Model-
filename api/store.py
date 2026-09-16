"""
api.store
=========
Thin facade over the persistence layer, so api/app.py doesn't need to
know or care whether storage is in-memory, SQLite, or eventually
Postgres - only this module's function signatures matter to callers.

Currently backed by SQLite (api/db.py). Swapping to Postgres later is a
matter of rewriting db.py's internals; this facade and app.py stay
untouched.
"""

from __future__ import annotations

from typing import Optional

from engine.models import UserBaseline, DeviceProfile
from api import db


def set_baseline(user_id: str, baseline: UserBaseline) -> None:
    db.set_baseline(user_id, baseline)


def get_baseline(user_id: str) -> Optional[UserBaseline]:
    return db.get_baseline(user_id)


def set_device(device_fingerprint: str, device: DeviceProfile) -> None:
    db.set_device(device_fingerprint, device)


def get_device(device_fingerprint: Optional[str]) -> Optional[DeviceProfile]:
    return db.get_device(device_fingerprint)
