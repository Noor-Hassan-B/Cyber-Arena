# 🔗 ThreatLens SOC — End-to-End Connections & Data Flow Report

> **Comprehensive Integration Walkthrough**: How Frontend, Backend, Database, WebSockets, and ML Models connect.

---

## 🔁 Complete Connection Lifecycle

```
[ User Login ] ──► POST /api/auth/login ──► FastAPI validates Bcrypt ──► Sets JWT Cookie
       │
       ▼
[ WebSocket Connect ] ──► ws://localhost:8000/api/ws?token=<JWT> ──► Hub registers client connection
       │
       ▼
[ Launch Scenario ] ──► User clicks "Launch Selected Attack"
       │
       ▼
[ Attack Execution ] ──► Backend triggers asyncio simulation task
       │
       ├─► 1. Streams command lines to terminal over WebSocket: hub.broadcast({"type":"attacker_cmd"})
       ├─► 2. Injects event stream logs over WebSocket: hub.broadcast({"type":"event"})
       ├─► 3. Evaluates event across 4 ML models (EWMA, Isolation Forest, DBSCAN, Heuristic)
       └─► 4. Creates correlated alert in MongoDB & broadcasts: hub.broadcast({"type":"alert_created"})
       │
       ▼
[ Analyst Triage ] ──► User clicks alert row ──► Drawer opens ──► Displays ML Votes & MITRE Details
       │
       ├─► Save Note: POST /api/alerts/{id}/note ──► Persisted in MongoDB
       ├─► Containment: POST /api/alerts/{id}/containment ──► Toggles SDN isolation
       └─► Export Report: GET /api/export/incident-report.md ──► Downloads Markdown Case File
```

---

## 🔍 Detailed Data Flow Scenarios

### Scenario A: Analyst Logging In
1. User enters `analyst@threatlens.io` / `threatlens2026` in `Login.jsx`.
2. Frontend sends `POST /api/auth/login` to FastAPI backend.
3. Backend looks up user in MongoDB, verifies password hash using `bcrypt.checkpw()`, generates JWT token signed with `JWT_SECRET`, and sets `threatlens_session` HTTP-Only cookie.
4. Frontend redirects to `/` (`Dashboard.jsx`).

### Scenario B: Launching an Attack Playbook (e.g., Hydra Password Spray)
1. Analyst selects `Brute Force` playbook and clicks **Launch Selected Attack**.
2. Frontend calls `api.startSim("brute_force", "normal")` (`POST /api/sim/start`).
3. Backend creates an asynchronous `asyncio` task executing the `brute_force` scenario.
4. Backend streams terminal logs line-by-line via WebSockets to `KaliConsole.jsx`.
5. Backend streams generated telemetry events to `EventStream.jsx`.
6. ML Detector Ensemble evaluates telemetry features:
   - EWMA Baseline: `ALERT` (78% confidence)
   - DBSCAN Outlier: `ALERT` (84% confidence)
   - Heuristic Correlation: `ALERT` (93% confidence)
7. Consensus threshold is met -> Backend inserts new correlated alert into MongoDB `alerts` collection and sends `alert_created` message via WebSockets.
8. Frontend receives `alert_created` event and triggers a Sonner toast notification + updates `AlertFeed.jsx`.

### Scenario C: Interactive Kali CLI Command Execution
1. Analyst types `nmap -sS -p 22,80,443,5432 -sV 10.42.0.10` in `KaliConsole.jsx`.
2. Frontend calls `api.attackerCmd(line)` (`POST /api/attacker/cmd`).
3. Backend parses the command string, identifies the tool (`nmap`), generates realistic terminal output lines, and triggers the `port_scan` simulation playbook.
4. Output lines are broadcast over WebSocket to `KaliConsole.jsx`.

### Scenario D: Analyst Triage & Incident Report Export
1. Analyst clicks an alert row in `AlertFeed.jsx`.
2. `AlertDrilldown.jsx` opens as a slide-over drawer showing ML consensus votes, MITRE ATT&CK codes, and recommended mitigations.
3. Analyst enters an investigation note and clicks **Save Note** (`POST /api/alerts/{id}/note`).
4. Analyst clicks **Trigger Host Enclave Isolation** (`POST /api/alerts/{id}/containment`).
5. Analyst clicks **Export Triage Report** -> Backend streams custom Markdown incident report file (`threatlens_incident_triage_report.md`).
