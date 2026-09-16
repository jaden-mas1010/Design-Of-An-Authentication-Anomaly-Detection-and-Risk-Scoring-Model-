# AADRS User Manual

## 1. Introduction

AADRS stands for **Authentication Anomaly Detection and Risk Scoring**.

The system analyses authentication events, checks them against behavioural and security rules, and assigns a risk score between 0 and 100.

The main purpose of the system is to help an analyst quickly identify suspicious authentication activity and understand why an event received a particular risk score.

The system includes:

- Authentication event scoring
- Behavioural baselines
- Device context
- Rule-based detection
- Risk scoring
- Explainable rule contributions
- Real-time dashboard
- Investigation cases
- Ask AI feature
- Isolation Forest comparison

---

## 2. System Requirements

Before running the system, make sure the following are installed:

- Python 3.12 or later
- pip
- A web browser
- Groq API key for the Ask AI feature

Install the required Python libraries using:

```powershell
pip install -r requirements.txt
```

---

## 3. Project Setup

Open PowerShell and go to the project directory:

```powershell
cd C:\Users\user\Desktop\anomaly-detection
```

If the virtual environment already exists, activate it using:

```powershell
.\.venv\Scripts\Activate.ps1
```

Alternatively, commands can be run directly using the Python executable inside the virtual environment.

---

## 4. Configure the Groq API Key

The Ask AI feature uses the Groq API.

Set the API key in PowerShell:

```powershell
$env:GROQ_API_KEY="YOUR_GROQ_API_KEY"
```

The API key should never be uploaded to GitHub or stored directly inside the source code.

The application reads the key from the `GROQ_API_KEY` environment variable.

---

## 5. Start the AADRS API Server

From the project directory, run:

```powershell
.\.venv\Scripts\python.exe -m uvicorn api.app:app --host 127.0.0.1 --port 8001
```

If the server starts successfully, Uvicorn will show that the application is running on:

```text
http://127.0.0.1:8001
```

Keep this PowerShell window open while using AADRS.

---

## 6. Check the System Health

Open another PowerShell window and run:

```powershell
Invoke-RestMethod http://127.0.0.1:8001/health
```

A successful response confirms that the AADRS backend is running.

---

## 7. Open the Dashboard

Open the following address in a web browser:

```text
http://127.0.0.1:8001/dashboard
```

The dashboard displays authentication events and their calculated risk scores.

It can be used to view:

- User activity
- Country
- Risk score
- Risk tier
- Triggered detection rules
- Authentication behaviour
- Investigation information

---

## 8. Generate Test Authentication Events

AADRS includes an event simulator that can generate authentication events for demonstration and testing.

Open a second PowerShell window:

```powershell
cd C:\Users\user\Desktop\anomaly-detection
```

Then run:

```powershell
.\.venv\Scripts\python.exe .\event_simulator.py
```

The simulator will send authentication events to the AADRS API.

Example output:

```text
u001  GB  score=0   tier=LOW
u002  DE  score=40  tier=MEDIUM
u003  RU  score=95  tier=CRITICAL
```

Keep the dashboard open while the simulator is running to see events appear in real time.

Press:

```text
Ctrl + C
```

to stop the simulator.

---

## 9. Understanding the Risk Score

Each authentication event receives a score between:

```text
0 - 100
```

The score is calculated using triggered detection rules.

AADRS uses the following risk tiers:

| Risk Score | Risk Tier |
|---|---|
| 0 - 29 | LOW |
| 30 - 59 | MEDIUM |
| 60 - 84 | HIGH |
| 85 - 100 | CRITICAL |

Higher scores indicate that more suspicious authentication indicators were detected.

---

## 10. Detection Rules

AADRS uses explainable rules to calculate the authentication risk score.

| Rule | Description |
|---|---|
| R001 | Login from an unusual country |
| R002 | Login from a configured high-risk country |
| R003 | Authentication outside the user's usual hours |
| R004 | Login from an unknown device |
| R005 | Login from an untrusted device |
| R006 | Device has limited login history |
| R007 | Five or more recent authentication failures |
| R008 | Eight or more recent authentication failures |
| R009 | MFA not used when other suspicious indicators already exist |
| R010 | Authentication attempt failed |
| R012 | Fifty or more recent authentication failures |

R011 is currently inactive.

The final score is capped at 100.

---

## 11. Viewing Rule Explanations

AADRS does not only show the final risk score.

It also shows the rules that contributed to the score.

Example:

```text
Risk Score: 100
Risk Tier: CRITICAL

Triggered Rules:
R002 +25
R004 +15
R007 +20
R008 +15
R009 +10
R010 +5
R012 +20
```

This allows the analyst to understand why the authentication event was considered suspicious.

---

## 12. Ask AI

The dashboard contains an Ask AI feature.

It allows the analyst to ask questions about the authentication information currently available on the dashboard.

Example questions:

```text
Which alerts require immediate attention?
```

```text
Why is this authentication event high risk?
```

```text
Which user currently has the highest risk activity?
```

```text
What triggered this critical alert?
```

The AI receives only the dashboard context supplied by AADRS.

It does not have direct access to the database and should not invent information that is not available in the supplied context.

---

## 13. Groq API Errors

If the Ask AI feature shows an error such as:

```text
Groq HTTP 429
```

this normally means that the Groq API rate or token limit has been reached.

The main AADRS detection system will still continue working.

Only the AI-generated assistance may temporarily become unavailable.

---

## 14. Investigation Cases

AADRS can correlate authentication events into investigation cases.

Examples include:

- Failure followed by successful authentication
- Same source used across multiple users
- Repeated high-risk activity for one user

These cases can help an analyst review groups of related authentication events instead of looking at each event individually.

---

## 15. API Endpoints

AADRS provides several API endpoints.

| Endpoint | Purpose |
|---|---|
| `/health` | Check whether the API is running |
| `/dashboard` | Open the analyst dashboard |
| `/score` | Score an authentication event |
| `/score/compare` | Compare rule scoring with Isolation Forest |
| `/baselines/{user_id}` | Manage user behavioural baseline |
| `/devices/{device_fingerprint}` | Manage device information |
| `/investigations` | View investigation cases |
| `/ask` | Ask questions about current dashboard context |
| `/ws` | Real-time WebSocket communication |

---

## 16. Manual Authentication Test

A suspicious authentication event can also be submitted manually.

Example PowerShell request:

```powershell
$body = @{
    user_id = "demo-user"
    event_time = "2026-09-16T03:15:00"
    source_ip = "203.0.113.50"
    provider = "azure_ad"
    country_code = "RU"
    outcome = "failure"
    mfa_used = $false
    recent_failure_count = 50
    device_fingerprint = "new-device-demo"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "http://127.0.0.1:8001/score" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body
```

This type of event should generate a high or critical risk score because several suspicious indicators are present.

---

## 17. Isolation Forest Comparison

AADRS also includes an Isolation Forest component.

This component is used as a separate comparison against the rule-based risk scoring approach.

It does not change or contribute to the main AADRS rule-based score.

The comparison endpoint is:

```text
/score/compare
```

---

## 18. Stopping the System

To stop the event simulator:

```text
Ctrl + C
```

To stop the FastAPI server:

```text
Ctrl + C
```

Run this inside the PowerShell window where each process is running.

---

## 19. Troubleshooting

### Dashboard does not open

Check that the FastAPI server is running.

Run:

```powershell
Invoke-RestMethod http://127.0.0.1:8001/health
```

### Connection refused error

If you see:

```text
WinError 10061
```

the event simulator cannot connect to the API.

Start the FastAPI server first:

```powershell
.\.venv\Scripts\python.exe -m uvicorn api.app:app --host 127.0.0.1 --port 8001
```

Then run the simulator.

### Port 8001 is already in use

Run:

```powershell
netstat -ano | findstr :8001
```

Find the PID using the port and stop it using:

```powershell
taskkill /PID YOUR_PID /F
```

Then restart the AADRS server.

### Ask AI is unavailable

Check that the Groq environment variable exists:

```powershell
[bool]$env:GROQ_API_KEY
```

It should return:

```text
True
```

Restart the FastAPI server after changing the API key.

---

## 20. Demo Video

A short silent demonstration of AADRS is available here:

https://youtu.be/dde5IiLehew

The video demonstrates the system running and shows the dashboard and authentication security workflow.

---

## 21. Security Notes

- Never commit API keys to GitHub.
- Do not upload `.env` files containing secrets.
- Do not upload local databases containing sensitive information.
- Do not upload large authentication datasets.
- Use only authorised authentication data for testing.
- The current system is a research prototype and is not intended to replace a production SIEM or identity security platform.

---

## 22. Project Purpose

AADRS was developed as a cybersecurity research prototype for authentication security monitoring.

The project demonstrates how authentication events can be prioritised using an explainable risk-scoring approach while giving analysts visibility into the factors that caused an alert.
