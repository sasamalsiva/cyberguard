# CyberGuard 🛡️

**AI-powered cyber threat intelligence dashboard** — phishing message / website / QR analysis plus a full **Account Takeover (ATO)** detection engine with per-user risk scoring.

Built as a zero-backend-cost, single-domain web app: a static frontend plus two serverless functions on Vercel.

---

## Live Demo

**https://cyberguard-sigma-woad.vercel.app**

Frontend, the Account Takeover API and the phishing proxy are all served from that single domain, so the dashboard works on a judge's phone with no setup.

---

## Features

### 1. Phishing Analysis (message / URL / QR)
- **Message analysis** — paste any SMS, email or chat text and get a phishing verdict.
- **Website analysis** — submit a URL for reputation and phishing checks.
- **QR code analysis** — upload a QR image and decode it to check the embedded link.
- Powered by the Gradio inference Space [`saswatpatra/cyberguard_phishing`](https://huggingface.co/spaces/saswatpatra/cyberguard_phishing), called client-side from the browser through `@gradio/client`.

### 2. Account Takeover Detection Engine
Six behavioural detectors run over login telemetry, fused by a weighted risk engine into a single score and a `LOW` / `MEDIUM` / `HIGH` verdict per user.

| # | Detector | What it catches |
|---|----------|-----------------|
| 1 | Multiple Failed Login Attempts | Password guessing / brute force from a single source |
| 2 | Password Spraying | One password tried against many accounts from one IP |
| 3 | Unusual Login Location | Login from a location outside the user's normal baseline |
| 4 | Unknown / New Device | First-seen device, or a device outside the user's known set |
| 5 | Suspicious Session Activity | Session actions inconsistent with a normal login flow |
| 6 | Sudden Account Behaviour Change | Abrupt shift in a user's usual location, device or login pattern |

**Risk engine**
- Weighted detector contributions, plus bonuses for **evidence volume**, **repetition** and **cross-detector correlation**.
- Thresholds: `LOW < 30 ≤ MEDIUM < 70 ≤ HIGH`.
- Every flagged user is returned with the exact detectors that fired, the raw evidence, and a human-readable risk summary.

---

## Tech Stack

| Layer | Choice |
|-------|--------|
| Frontend | Vanilla HTML / CSS / JS (no build step) |
| ATO engine | Python 3, pandas, custom risk scoring |
| API (ATO) | FastAPI, deployed as a Vercel Python serverless function |
| API (proxy) | Node.js serverless function wrapping `@gradio/client` |
| Hosting | Vercel (static + serverless, one domain) |

---

## Project Structure

```
.
├── index.html                     # Static dashboard shell
├── style.css                      # Dashboard styling
├── script.js                      # Frontend logic + Gradio client
├── vercel.json                    # Serverless function config (framework preset disabled)
├── requirements.txt               # Python deps for the ATO function
├── package.json                   # Node deps for the phishing proxy
│
├── api/
│   ├── account_takeover.py        # FastAPI app (POST /api/account_takeover)
│   └── analyze.js                 # Node serverless proxy to the HF Space
│
├── account_takeover/
│   ├── account_takeover_engine.py # The six detectors
│   ├── account_takeover_service.py# Pipeline: DataFrames -> JSON report
│   └── risk_engine.py             # Scoring, bonuses, thresholds
│
├── cyberguard_login_events.csv        # Sample telemetry
├── cyberguard_organisation_profiles.csv # Sample user baselines
└── test_api_local.py              # Local API regression harness
```

---

## API

### `POST /api/account_takeover`

```jsonc
{
  "events": [
    {
      "timestamp": "2026-10-03T10:00:00",
      "user_id": "user001",
      "login_status": "failed",
      "ip_address": "203.0.113.10",
      "location": "Unknown City",
      "device": "Chrome-Windows",
      "session_action": "login_failed"
    }
  ],
  "profiles": [
    {
      "user_id": "user001",
      "normal_locations": "Bhubaneswar",
      "known_devices": "Edge-Windows"
    }
  ]
}
```

`profiles` is optional. Response:

```jsonc
{
  "success": true,
  "type": "account_takeover",
  "result": {
    "summary": { "users_analyzed": 6, "accounts_flagged": 6, "high_risk": 2, "medium_risk": 4, "detection_events": 15 },
    "users": [ /* per-user risk, verdict, detectors, evidence */ ]
  }
}
```

`GET /api/account_takeover` returns a health check. Empty `events` returns `400`.

### CSV columns

**Events** — `timestamp` *(required)*, `user_id` *(required)*, `login_status`, `ip_address`, `location`, `device`, `session_action`. Optional `event_id` / `session_id` are synthesised when absent.

**Profiles** — `user_id`, `normal_locations`, `known_devices`.

---

## Running Locally

### ATO engine only (CLI)

```bash
cd CyberGuard-main
python -m account_takeover.account_takeover_engine
```

Reads the two sample CSVs from the project root and prints every detector's output.

### ATO API

```bash
cd CyberGuard-main
pip install -r requirements.txt
python -m uvicorn api.account_takeover:app --port 8000
```

### Static frontend

```bash
cd CyberGuard-main
python -m http.server 5173
```

Open `http://localhost:5173`. The dashboard calls `/api/account_takeover` on its own origin, so serve the frontend and the API from the same origin (or use the CORS-enabled API on `http://localhost:8000`).

### Regression harness

```bash
cd CyberGuard-main
python test_api_local.py
```

Exits `0` when every case passes (demo scenario, missing optional columns, empty payload, both path aliases, CORS preflight).

---

## Deploying to Vercel

1. From the project folder, authenticate the CLI once: `npx vercel login`.
2. Deploy: `npx vercel deploy --prod --yes` (or `vercel --prod` against a linked GitHub repo).
3. No environment variables are required — the Hugging Face Space is public. If you ever make it private or gated, add an `HF_TOKEN` variable (a read token for that Space); the serverless proxy connects anonymously until then.
4. In the Vercel dashboard turn **off Deployment Protection** (Settings → Deployment Protection) so the URL is open to anyone — otherwise visitors hit a Vercel login wall.

`vercel.json` pins `"framework": null` so Vercel treats the repo as a plain static + serverless project: `index.html`, `script.js` and `style.css` are served statically, and anything under `api/` becomes a serverless function. That means `/api/account_takeover` and `/api/analyze` resolve with no rewrite rules.

Both endpoints live on the same domain as the frontend, so no CORS configuration or client-side URL change is needed in production.