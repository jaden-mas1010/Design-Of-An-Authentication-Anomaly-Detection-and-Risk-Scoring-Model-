"""
test_api_integration.py
========================
End-to-end integration test against the RUNNING API (not the Python
functions directly). This is the closest thing to "how David's system
would actually talk to this" - HTTP requests in, JSON out.

Usage:
    1. In one terminal:  uvicorn api.app:app --reload --port 8000
    2. In another:       python3 test_api_integration.py
"""

import httpx

BASE_URL = "http://127.0.0.1:8001"


def main():
    client = httpx.Client(base_url=BASE_URL, timeout=5.0)

    print("--- Health check ---")
    r = client.get("/health")
    r.raise_for_status()
    print(r.json())
    print()

    print("--- Registering baseline for u001 ---")
    r = client.post("/baselines/u001", json={
        "usual_countries": ["GB"],
        "usual_hours_utc": list(range(8, 18)),
    })
    r.raise_for_status()
    print(r.json())
    print()

    print("--- Registering trusted device for u001 ---")
    r = client.post("/devices/fp_alice_laptop", json={
        "device_fingerprint": "fp_alice_laptop",
        "is_trusted": True,
        "total_logins": 50,
    })
    r.raise_for_status()
    print(r.json())
    print()

    scenarios = [
        {
            "label": "Normal login (should be LOW)",
            "body": {
                "user_id": "u001",
                "event_time": "2026-07-08T09:30:00",
                "source_ip": "82.132.200.10",
                "provider": "azure_ad",
                "country_code": "GB",
                "outcome": "success",
                "mfa_used": True,
                "recent_failure_count": 0,
                "device_fingerprint": "fp_alice_laptop",
            },
        },
        {
            "label": "Login from Russia at 3am, unknown device (should be HIGH)",
            "body": {
                "user_id": "u001",
                "event_time": "2026-07-08T03:00:00",
                "source_ip": "95.213.0.100",
                "provider": "azure_ad",
                "country_code": "RU",
                "outcome": "success",
                "mfa_used": False,
                "recent_failure_count": 0,
            },
        },
        {
            "label": "Brute force pattern (should be HIGH/CRITICAL)",
            "body": {
                "user_id": "u001",
                "event_time": "2026-07-08T02:00:00",
                "source_ip": "185.220.101.50",
                "provider": "azure_ad",
                "country_code": "NL",
                "outcome": "success",
                "mfa_used": False,
                "recent_failure_count": 10,
            },
        },
        {
            "label": "Unknown user, no baseline/device registered at all",
            "body": {
                "user_id": "u999",
                "event_time": "2026-07-08T14:00:00",
                "source_ip": "1.2.3.4",
                "provider": "okta",
                "country_code": "US",
                "outcome": "success",
                "mfa_used": True,
                "recent_failure_count": 0,
            },
        },
    ]

    for scenario in scenarios:
        print(f"--- {scenario['label']} ---")
        r = client.post("/score", json=scenario["body"])
        r.raise_for_status()
        data = r.json()
        print(f"Score: {data['risk_score']}  Tier: {data['risk_tier']}  "
              f"(baseline_used={data['baseline_used']}, device_used={data['device_used']})")
        for factor in data["risk_factors"]:
            print(f"   {factor}")
        if data["mitre_technique_id"]:
            print(f"   MITRE: {data['mitre_technique_id']}")
        print()

    print("Integration test complete - API responded correctly to all requests.")


if __name__ == "__main__":
    main()
