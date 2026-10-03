"""Exercise the CyberGuard account-takeover pipeline exactly like the frontend does."""
import json
import sys

sys.path.insert(0, ".")

from fastapi.testclient import TestClient  # noqa: E402

from api.account_takeover import app  # noqa: E402

# Exact demo payload from script.js -> loadAccountTakeoverDemo()
DEMO_EVENTS = [
    {"timestamp": "2026-10-03T10:00:00", "user_id": "user001", "login_status": "failed", "ip_address": "203.0.113.10", "location": "Unknown City", "device": "Chrome-Windows", "session_action": "login_failed"},
    {"timestamp": "2026-10-03T10:01:00", "user_id": "user001", "login_status": "failed", "ip_address": "203.0.113.10", "location": "Unknown City", "device": "Chrome-Windows", "session_action": "login_failed"},
    {"timestamp": "2026-10-03T10:02:00", "user_id": "user001", "login_status": "failed", "ip_address": "203.0.113.10", "location": "Unknown City", "device": "Chrome-Windows", "session_action": "login_failed"},
    {"timestamp": "2026-10-03T10:03:00", "user_id": "user001", "login_status": "failed", "ip_address": "203.0.113.10", "location": "Unknown City", "device": "Chrome-Windows", "session_action": "login_failed"},
    {"timestamp": "2026-10-03T10:04:00", "user_id": "user001", "login_status": "failed", "ip_address": "203.0.113.10", "location": "Unknown City", "device": "Chrome-Windows", "session_action": "login_failed"},
    {"timestamp": "2026-10-03T10:05:00", "user_id": "user002", "login_status": "failed", "ip_address": "203.0.113.10", "location": "Unknown City", "device": "Firefox-Linux", "session_action": "login_failed"},
    {"timestamp": "2026-10-03T10:06:00", "user_id": "user003", "login_status": "failed", "ip_address": "203.0.113.10", "location": "Unknown City", "device": "Firefox-Linux", "session_action": "login_failed"},
    {"timestamp": "2026-10-03T10:07:00", "user_id": "user004", "login_status": "failed", "ip_address": "203.0.113.10", "location": "Unknown City", "device": "Firefox-Linux", "session_action": "login_failed"},
    {"timestamp": "2026-10-03T10:08:00", "user_id": "user005", "login_status": "failed", "ip_address": "203.0.113.10", "location": "Unknown City", "device": "Firefox-Linux", "session_action": "login_failed"},
    {"timestamp": "2026-10-03T10:09:00", "user_id": "user006", "login_status": "success", "ip_address": "203.0.113.10", "location": "Unknown City", "device": "Unknown-Mobile", "session_action": "privileged_action"},
]
DEMO_PROFILES = [
    {"user_id": "user001", "normal_locations": "Bhubaneswar", "known_devices": "Edge-Windows"},
    {"user_id": "user002", "normal_locations": "Bhubaneswar", "known_devices": "Chrome-Windows"},
    {"user_id": "user003", "normal_locations": "Cuttack", "known_devices": "Chrome-Windows"},
    {"user_id": "user004", "normal_locations": "Bhubaneswar", "known_devices": "Safari-Mac"},
    {"user_id": "user005", "normal_locations": "Puri", "known_devices": "Chrome-Windows"},
    {"user_id": "user006", "normal_locations": "Bhubaneswar", "known_devices": "Chrome-Windows"},
]

client = TestClient(app)

print("== health ==")
r = client.get("/")
print(r.status_code, json.dumps(r.json())[:120])

print("\n== demo analysis (frontend demo payload) ==")
r = client.post("/", json={"events": DEMO_EVENTS, "profiles": DEMO_PROFILES})
print("status:", r.status_code)
if r.status_code != 200:
    print(r.text[:2000])
else:
    body = r.json()
    print("summary:", json.dumps(body["result"]["summary"]))
    for acct in body["result"]["accounts"]:
        print("  account:", acct["user_id"], acct["risk_level"], acct["risk_score"], acct["detectors_triggered"])

print("\n== edge case: no session_id / session_action columns ==")
ev2 = [
    {"timestamp": "2026-10-03T11:00:00", "user_id": "u1", "login_status": "failed", "ip_address": "1.2.3.4", "location": "X", "device": "D1"},
    {"timestamp": "2026-10-03T11:01:00", "user_id": "u1", "login_status": "success", "ip_address": "1.2.3.4", "location": "X", "device": "D1"},
]
r = client.post("/", json={"events": ev2, "profiles": None})
print("status:", r.status_code)
if r.status_code != 200:
    print(r.text[:2000])
else:
    print("summary:", json.dumps(r.json()["result"]["summary"]))

print("\n== edge case: NO login_status column (detector 6 guard) ==")
ev3 = [
    {"timestamp": "2026-10-03T12:00:00", "user_id": "u9", "ip_address": "9.9.9.9", "location": "L1", "device": "D1"},
    {"timestamp": "2026-10-03T12:05:00", "user_id": "u9", "ip_address": "9.9.9.9", "location": "L1", "device": "D1"},
    {"timestamp": "2026-10-03T12:10:00", "user_id": "u9", "ip_address": "9.9.9.8", "location": "L2", "device": "D2"},
    {"timestamp": "2026-10-03T12:15:00", "user_id": "u9", "ip_address": "9.9.9.7", "location": "L3", "device": "D3"},
    {"timestamp": "2026-10-03T12:20:00", "user_id": "u9", "ip_address": "9.9.9.6", "location": "L4", "device": "D4"},
    {"timestamp": "2026-10-03T12:25:00", "user_id": "u9", "ip_address": "9.9.9.5", "location": "L5", "device": "D5"},
    {"timestamp": "2026-10-03T12:30:00", "user_id": "u9", "ip_address": "9.9.9.4", "location": "L6", "device": "D6"},
]
r = client.post("/", json={"events": ev3, "profiles": None})
print("status:", r.status_code)
if r.status_code != 200:
    print(r.text[:2000])
else:
    print("summary:", json.dumps(r.json()["result"]["summary"]))

print("\n== edge case: empty events ==")
r = client.post("/", json={"events": [], "profiles": None})
print("status:", r.status_code, r.json().get("detail", "<ok>"))

print("\n== path alias: POST /api/account_takeover ==")
r = client.post("/api/account_takeover", json={"events": DEMO_EVENTS, "profiles": DEMO_PROFILES})
print("status:", r.status_code, "flagged:", r.json()["result"]["summary"]["accounts_flagged"] if r.status_code == 200 else r.text[:300])

print("\n== path alias: GET /api/account_takeover ==")
r = client.get("/api/account_takeover")
print("status:", r.status_code, r.json().get("status"))

print("\n== edge case: profiles without expected columns ==")
r = client.post("/", json={"events": ev2, "profiles": [{"user_id": "u1"}]})
print("status:", r.status_code)
if r.status_code != 200:
    print(r.text[:2000])
else:
    print("summary:", json.dumps(r.json()["result"]["summary"]))
