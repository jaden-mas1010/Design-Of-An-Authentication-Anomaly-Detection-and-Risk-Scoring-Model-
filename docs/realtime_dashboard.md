# AADRS — Real-Time Monitoring Dashboard

Live view of every event scored by the API, added so the tool can be
demonstrated (to David/PMS or in a viva) as something that tracks
authentication risk as it happens, not just as a request/response API.

## How it works

```
event_simulator.py  --POST /score-->  api/app.py  --broadcast-->  api/ws_manager.py  --WebSocket-->  static/dashboard.html
```

- Every call to `POST /score` (and `/score/compare`, via its internal call
  to `/score`) now also broadcasts the result to any connected WebSocket
  clients via `api/ws_manager.py`'s `ConnectionManager`.
- `static/dashboard.html` is a single self-contained page (no build step,
  no extra dependencies) that opens a WebSocket connection to `/ws` and
  appends each incoming event to a live-updating table, colour-coded by
  risk tier, with running totals per tier at the top.
- `event_simulator.py` is a standalone script that generates a continuous
  stream of synthetic login events (~75% normal, ~15% moderately
  suspicious, ~10% high-risk) and posts them to `/score`, purely to give
  the dashboard something to display without needing real log data yet.

## Running it

**Terminal 1** — the API (now also serves the dashboard and the WebSocket):
```bash
uvicorn api.app:app --reload --port 8000
```

**Browser** — open the dashboard:
```
http://127.0.0.1:8000/dashboard
```
It will show "Connected" and sit waiting for events.

**Terminal 2** — generate live traffic:
```bash
python3 event_simulator.py
```

Watch the dashboard fill up in real time as the simulator runs. Ctrl+C
the simulator to stop generating traffic; the dashboard stays open and
simply stops receiving new rows.

## What this demonstrates vs what it doesn't

**Demonstrates:** the full pipeline — event in, scored, broadcast,
rendered live — works end-to-end, and that both the rule-based engine
and (via `/score/compare`, if wired into the simulator later) the
Isolation Forest layer could feed a real-time monitoring view.

**Does not yet demonstrate:** ingestion from a real authentication log
source. `event_simulator.py` generates synthetic events on a timer, not
a genuine SIEM/IdP event stream. Swapping the simulator for a real
ingestion adapter (e.g. polling Azure AD sign-in logs, or subscribing to
an event stream) is the natural next step if this needs to look at real
traffic rather than synthetic demonstration data.

## Known limitations

- **Single-process only.** The `ConnectionManager` in `api/ws_manager.py`
  keeps connected clients in an in-process Python list. If the API were
  ever run as multiple worker processes (e.g. `uvicorn --workers 4`) or
  scaled horizontally, a broadcast from one worker would not reach
  clients connected to a different worker. A production version would
  need a shared pub/sub layer (e.g. Redis) instead.
- **No historical replay.** The dashboard only shows events from the
  moment a browser tab connects onward — closing and reopening the tab
  does not show earlier events. Worth adding a "load last N events from
  the database" step on connect if this needs to survive page refreshes.
- **No authentication on the dashboard or the WebSocket.** Same caveat as
  the rest of the API — fine for local demoing, not for anything exposed
  beyond your own machine.
