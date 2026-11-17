# 🛡️ ThreatLens SOC — Project Overview & Master Working Guide

> **Target Repository**: `https://github.com/Noor-Hassan-B/hackathone`  
> **System Architecture**: Autonomous Multi-Detector Anomaly Detection & Red-Team Simulation Engine

---

## 🎯 What Is ThreatLens? (Elevator Pitch)

**ThreatLens SOC** is an **Autonomous AI-Driven Cybersecurity Incident Response Platform** engineered for high-throughput enterprise infrastructure (e.g., digital neo-banks processing 65,000+ transactions/second).

Legacy SIEM (Security Information and Event Management) tools rely on static rule thresholds that generate high false-positive noise and fail to catch **low-and-slow** or **distributed proxy attacks**. ThreatLens replaces static alert thresholds with a **4-Model Machine Learning Anomaly Detection Ensemble** (`EWMA Baseline`, `Isolation Forest`, `DBSCAN Density Clustering`, and `Deterministic MITRE ATT&CK Heuristic Correlation`).

---

## 🏗️ Master System Architecture

```
                                  ┌──────────────────────────────────────────────┐
                                  │           React / Vite Web UI                │
                                  │      (Dark Cyber Command Center)             │
                                  └───────────────┬───────────────▲──────────────┘
                                                  │               │
                                   HTTP REST APIs │               │ WebSockets
                                  (Auth, Control) │               │ (Live Telemetry & CLI)
                                                  ▼               │
┌─────────────────────────────────────────────────────────────────┴──────────────────────────────────────────┐
│                                     Python FastAPI Backend Engine                                          │
├──────────────────────────┬─────────────────────────────┬──────────────────────────┬────────────────────────┤
│  Authentication Module   │  Red-Team Attack Simulator  │  Interactive Kali CLI    │  4-Model ML Anomaly    │
│  (PyJWT + Bcrypt)        │  (5 Scenario Playbooks)     │  (Command Parser & ZSH)  │  Consensus Engine      │
└────────────┬─────────────┴──────────────┬──────────────┴────────────┬─────────────┴───────────┬────────────┘
             │                            │                           │                         │
             ▼                            ▼                           ▼                         ▼
   ┌───────────────────┐    ┌───────────────────────────┐   ┌──────────────────┐    ┌──────────────────────┐
   │ MongoDB / Mock    │    │ WebSocket Broadcast Hub   │   │ Target Enclave   │    │ Ambient Telemetry    │
   │ (Alerts & Users)  │    │ (hub.broadcast)           │   │ (10.42.0.0/24)   │    │ (65k tx/s Generator) │
   └───────────────────┘    └───────────────────────────┘   └──────────────────┘    └──────────────────────┘
```

---

## ⚡ Key Features & Innovations

1. **4-Model Machine Learning Consensus Engine**:
   - Compares real-time audit logs across 4 independent anomaly models.
   - Eliminates alert fatigue by requiring consensus voting before firing high-priority alerts.

2. **Interactive Red-Team Kali Linux Console**:
   - Embedded interactive ZSH CLI in browser with auto-complete and command support (`nmap`, `hydra`, `sqlmap`, `curl`, `whoami`, `cat`, `ls`, `ping`).

3. **5 Pre-Built Offensive Attack Playbooks**:
   - **Brute Force** (`T1110.003`): Hydra password spraying with 90s throttle.
   - **Cred Stuffing** (`T1110.004`): Distributed proxy cluster across 19 residential IPs.
   - **Port Recon** (`T1595.001`): Nmap TCP SYN stealth scan.
   - **Ghost TX** (`T1078`): API replay attacks causing p99 latency spikes.
   - **SQL Injection** (`T1190`): SQLMap boolean blind schema extraction.

4. **Dynamic Risk Sensitivity Slider**:
   - Allows SOC analysts to set alerting thresholds (`50+ All`, `70+ Balanced`, `85+ Strict`) dynamically.

5. **Automated Incident Response & Containment**:
   - One-click SDN Hypervisor Host Isolation to lock down compromised nodes.
   - Export downloadable formatted **Incident Response Triage Reports (`.md`)** and **Alert CSVs**.

---

## 🚀 How to Run the Project Locally

### 1. Prerequisites
- Python 3.11+
- Node.js 18+ & npm

### 2. Launch Backend (Port 8000)
```powershell
cd app/backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Launch Frontend (Port 3000)
```powershell
cd app/frontend
npm install
npm run dev
```

### 4. Access URLs
- **Web UI**: `http://localhost:3000`
- **Swagger API Docs**: `http://localhost:8000/docs`
- **Default Credentials**: `analyst@threatlens.io` / `threatlens2026`
