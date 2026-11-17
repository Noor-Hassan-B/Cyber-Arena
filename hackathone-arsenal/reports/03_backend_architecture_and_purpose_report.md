# ⚙️ ThreatLens SOC — Backend Architecture & Purpose Report

> **Location**: `app/backend/server.py`  
> **Framework**: Python 3.11+ · FastAPI · Motor / Mongomock · PyJWT · Bcrypt · Uvicorn

---

## 🎯 What Is the Use of the Backend?

The ThreatLens backend acts as the **central intelligence unit and simulation engine** of the SOC system. It performs four essential duties:

1. **Autonomous Anomaly Detection**: Evaluates every telemetry event using a multi-modal machine learning consensus model to detect complex attacks.
2. **Red-Team Attack Orchestration**: Simulates realistic cyber-attacks (password spraying, SQL injections, credential stuffing, latency spikes) against target microservices (`10.42.0.10`).
3. **Interactive Terminal Command Execution**: Emulates a Kali Linux attack environment, parsing terminal commands and returning realistic command outputs.
4. **Real-Time Data Streaming**: Broadcasts live telemetry logs, alerts, and system stats via WebSockets to all connected analyst dashboards.

---

## 🔬 Multi-Model Machine Learning Ensemble

To catch low-and-slow threats without overwhelming analysts with false positives, ThreatLens combines 4 detection algorithms:

```
Telemetry Event ──► [ EWMA Baseline ] ───────► Vote + Confidence % ──┐
                 ──► [ Isolation Forest ] ────► Vote + Confidence % ──┼─► Consensus Engine ──► Correlated Alert
                 ──► [ DBSCAN Clustering ] ───► Vote + Confidence % ──┤
                 ──► [ Heuristic Rules ] ─────► Vote + Confidence % ──┘
```

1. **EWMA Baseline (Exponentially Weighted Moving Average)**: Tracks exponential moving baseline request rates to detect volume anomalies.
2. **Isolation Forest**: Unsupervised tree algorithm isolating anomalous data points in high-dimensional feature space.
3. **DBSCAN Density Clustering**: Identifies spatial and IP density outliers, isolating suspicious proxy clusters.
4. **Heuristic Correlation**: Deterministic pattern matcher linking payloads to MITRE ATT&CK technique IDs.

---

## ⚔️ Red-Team Simulation Engine & Playbooks

The backend provides 5 pre-configured attack playbooks executed asynchronously via background asyncio tasks:

```python
SCENARIOS = {
    "brute_force": {
        "title": "Low-and-slow brute force detected",
        "mitre": {"id": "T1110.003", "name": "Password Spraying"},
        "risk": 82, "severity": "high",
        "source_ip": "185.220.101.44", "geo": "Frankfurt, DE",
        "commands": ["sudo hydra -L users.lst -P rockyou.txt -t 4 -W 90 auth-target-vm ssh", ...]
    },
    "credential_stuffing": {
        "title": "Distributed credential stuffing cluster",
        "mitre": {"id": "T1110.004", "name": "Credential Stuffing"},
        "risk": 91, "severity": "critical",
        "source_ip": "45.141.84.17", "geo": "Berlin, DE",
    },
    "port_scan": { ... },
    "ghost_tx": { ... },
    "sql_injection": { ... }
}
```

---

## 📡 REST API & WebSocket Endpoint Reference

### Authentication Endpoints
- `POST /api/auth/login`: Validates analyst credentials and sets `threatlens_session` JWT cookie.
- `POST /api/auth/logout`: Clears session cookie.
- `GET /api/auth/me`: Returns current analyst identity.

### SOC Data & Analytics Endpoints
- `GET /api/summary`: Returns total events ingested, live throughput rate, active threats, and peak risk score.
- `GET /api/events`: Returns 40 most recent raw telemetry events.
- `GET /api/alerts`: Returns correlated security alerts filtered by severity.
- `POST /api/alerts/{id}/status`: Updates alert status (`open`, `acknowledged`, `resolved`).
- `POST /api/alerts/{id}/note`: Saves analyst investigation notes.
- `POST /api/alerts/{id}/containment`: Toggles SDN hypervisor host containment.

### Attack Simulator & Terminal Endpoints
- `POST /api/sim/start`: Launches specified attack playbook (`brute_force`, `sql_injection`, etc.).
- `POST /api/sim/reset`: Purges telemetry buffers and flushes alert state.
- `POST /api/attacker/cmd`: Parses interactive Kali terminal command (`nmap`, `hydra`, `sqlmap`, `cat`, `ls`).

### Export Endpoints
- `GET /api/export/alerts.csv`: Downloads CSV report of all security alerts.
- `GET /api/export/incident-report.md`: Downloads executive SecOps Incident Triage Report in Markdown format.

### Real-Time WebSocket Endpoint
- `WS /api/ws`: Bi-directional WebSocket streaming live telemetry events, command output lines, and alert notifications.
