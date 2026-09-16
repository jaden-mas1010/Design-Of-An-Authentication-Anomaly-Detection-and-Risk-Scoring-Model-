"""
event_simulator.py
===================
Generates a continuous stream of synthetic authentication events and
posts them to the live /score endpoint, so the dashboard at
http://127.0.0.1:8000/dashboard has something real to display.

Not a substitute for real log data (see docs/realtime_dashboard.md for
what a genuine production feed would look like) - this exists purely to
demonstrate the real-time pipeline working end-to-end.

Usage:
    1. In one terminal: uvicorn api.app:app --reload --port 8000
    2. In another:       python3 event_simulator.py
    3. Open http://127.0.0.1:8000/dashboard in a browser and watch events
       appear live as this script generates them.

    Ctrl+C to stop.
"""

import random
import time
from datetime import datetime, timedelta

import httpx

BASE_URL = "http://127.0.0.1:8001"

USERS = ["u001", "u002", "u003"]
NORMAL_COUNTRY = "GB"
SUSPICIOUS_COUNTRIES = ["RU", "KP", "IR", "NL", "CN", "FR"]
TRUSTED_DEVICE_FP = "fp_alice_laptop"


def ensure_baselines_and_devices(client: httpx.Client) -> None:
    """Register a baseline + trusted device for each simulated user, once, at startup."""
    for user_id in USERS:
        client.post(f"/baselines/{user_id}", json={
            "usual_countries": [NORMAL_COUNTRY],
            "usual_hours_utc": list(range(8, 18)),
        })
        client.post(f"/devices/{TRUSTED_DEVICE_FP}_{user_id}", json={
            "device_fingerprint": f"{TRUSTED_DEVICE_FP}_{user_id}",
            "is_trusted": True,
            "total_logins": 50,
        })


def generate_event() -> dict:
    """
    Generate one synthetic event. Mostly normal traffic (~75%), with a
    mix of moderately and highly suspicious events mixed in, so the
    dashboard shows a realistic distribution rather than an unbroken
    wall of either all-LOW or all-CRITICAL results.
    """
    user_id = random.choice(USERS)
    roll = random.random()

    if roll < 0.75:
        # Normal login: usual country, usual hours, known trusted device
        hour = random.randint(8, 17)
        return {
            "user_id": user_id,
            "event_time": datetime.now().replace(hour=hour, minute=random.randint(0, 59)).isoformat(),
            "source_ip": "82.132.200.10",
            "provider": "azure_ad",
            "country_code": NORMAL_COUNTRY,
            "outcome": "success",
            "mfa_used": True,
            "recent_failure_count": 0,
            "device_fingerprint": f"{TRUSTED_DEVICE_FP}_{user_id}",
        }

    elif roll < 0.90:
        # Moderately suspicious: off-hours or unknown device, but not an attack
        return {
            "user_id": user_id,
            "event_time": (datetime.now().replace(hour=random.choice([5, 6, 19, 20]))).isoformat(),
            "source_ip": f"51.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "provider": "azure_ad",
            "country_code": random.choice([NORMAL_COUNTRY, "IE", "DE"]),
            "outcome": "success",
            "mfa_used": random.choice([True, False]),
            "recent_failure_count": random.choice([0, 1, 2]),
        }

    else:
        # High-risk: high-risk country, off-hours, unknown device, no MFA,
        # sometimes layered with a brute-force failure count too
        return {
            "user_id": user_id,
            "event_time": (datetime.now().replace(hour=random.choice([1, 2, 3, 4]))).isoformat(),
            "source_ip": f"185.220.{random.randint(1,254)}.{random.randint(1,254)}",
            "provider": "azure_ad",
            "country_code": random.choice(SUSPICIOUS_COUNTRIES),
            "outcome": "success",
            "mfa_used": False,
            "recent_failure_count": random.choice([0, 6, 12, 60]),
        }


def main():
    client = httpx.Client(base_url=BASE_URL, timeout=5.0)

    print("Registering baselines/devices for simulated users...")
    ensure_baselines_and_devices(client)

    print(f"Streaming synthetic events to {BASE_URL}/score")
    print(f"Open {BASE_URL}/dashboard in a browser to watch them arrive live.")
    print("Ctrl+C to stop.\n")

    try:
        while True:
            event = generate_event()
            try:
                r = client.post("/score", json=event)
                r.raise_for_status()
                data = r.json()
                print(f"  {event['user_id']:5s} {event['country_code']:3s} "
                      f"score={data['risk_score']:>3} tier={data['risk_tier']}")
            except httpx.HTTPError as e:
                print(f"  request failed: {e}")

            time.sleep(random.uniform(0.5, 2.5))
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
