# Sh4d0w_Br0k3rs: AI-Assisted Cyber Threat Hunting & Attack Path Visualization Platform

[![Frontend: React](https://img.shields.io/badge/Frontend-React_18-blue.svg)](https://react.dev/)
[![Backend: PHP](https://img.shields.io/badge/Backend-PHP_8_PDO-777BB4.svg)](https://www.php.net/)
[![Database: MySQL](https://img.shields.io/badge/Database-MySQL_8.0-4479A1.svg)](https://www.mysql.com/)
[![Containers: Docker](https://img.shields.io/badge/Container-Docker_Compose-2496ED.svg)](https://www.docker.com/)
[![Orchestration: Kubernetes](https://img.shields.io/badge/Orchestration-Kubernetes_K8s-326CE5.svg)](https://kubernetes.io/)
[![Framework: MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE_ATT%26CK_v14-red.svg)](https://attack.mitre.org/)

A comprehensive cyber threat hunting platform that ingests multi-source security telemetry, normalizes events across orthogonal domains, correlates suspicious sequences across entities and time, reconstructs potential attack paths with evidence-linked graphs, and presents SOC analysts with actionable, AI-assisted investigation leads.

---

## Project Objectives & Deliverables Fulfillment

| Objective / Deliverable | Status | Platform Implementation |
|---|---|---|
| **1. Multi-Source Ingestion** | **100% Complete** | Ingests Endpoint (Sysmon/EDR), Identity/Auth (AD/Kerberos/VPN), Network (Zeek/Netflow), and Cloud (AWS CloudTrail/S3) telemetry. Includes live Ingestion Workbench. |
| **2. Cross-Domain Correlation** | **100% Complete** | Sliding time-window correlation engine pivots across users, workstations, domain controllers, cloud roles, and external C2 IPs. |
| **3. MITRE ATT&CK Mapping** | **100% Complete** | Full 12-tactic enterprise matrix heatmap with active technique detection, hit frequency, and direct event linkages. |
| **4. Attack Path Visualization** | **100% Complete** | Directed SVG canvas graph with animated kill-chain playback, node blast-radius metrics, and clickable evidence tags. |
| **5. AI-Assisted Hunting & Linkage** | **100% Complete** | Generates executive threat hypotheses and SIEM queries (SPL/SQL) with deterministic `[EVT-...]` evidence citations. |
| **6. Incident Timeline & Reports** | **100% Complete** | Interactive chronological event stream and one-click exportable forensic reports (Markdown / Printable PDF). |
| **7. Multi-Source Synthetic Scenarios** | **100% Complete** | Documented scenarios: APT29 "GhostToken", BlackCat Ransomware, and Cloud IAM Cryptomining fleet. |
| **8. Architecture & AI Limitations** | **100% Complete** | Forensic governance report explaining Hallucination risks, Base-Rate Fallacy, and Human-in-the-Loop constraints. |

---

## Directory Layout

```
threat-hunter/
├── backend-php/                  # PHP REST API & MySQL Layer
│   ├── config/
│   │   └── db.php                # PDO database connection & CORS handling
│   ├── sql/
│   │   ├── schema.sql            # MySQL schema (tables, foreign keys, indexes)
│   │   └── seed_data.sql         # Multi-source synthetic datasets (APT29, Ransomware, Cloud)
│   ├── api/
│   │   ├── events.php            # Ingest, query, and filter security events
│   │   ├── correlate.php         # Cross-domain temporal & entity correlation
│   │   ├── attack_path.php       # Directed graph nodes, edges, and critical path
│   │   ├── mitre.php             # MITRE ATT&CK matrix heatmap and tactic distribution
│   │   ├── ai_assist.php         # Threat hunting query suggestions, hypotheses, & AI limitations
│   │   ├── scenarios.php         # Documented attack scenarios catalog
│   │   └── report.php            # Incident timeline & forensic investigation report
│   ├── seed.php                  # Automated CLI/web installer to setup & seed MySQL
│   ├── router.php                # Built-in PHP server router (php -S localhost:8000 router.php)
│   └── README.md                 # Backend documentation & XAMPP guide
├── frontend-react/               # Modern React 18 + Tailwind CSS Dashboard
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.jsx        # SOC header, scenario switcher, backend health monitor
│   │   │   ├── OverviewStats.jsx # KPI metric cards, confidence score, blast radius
│   │   │   ├── AttackPathGraph.jsx # Interactive directed graph & attack playback
│   │   │   ├── TimelineView.jsx  # Chronological event stream with domain filters
│   │   │   ├── MitreMatrixView.jsx # 12-tactic MITRE ATT&CK heatmap
│   │   │   ├── AIAssistantPanel.jsx # AI Threat Copilot & evidence-linked hypotheses
│   │   │   ├── EvidenceDrawer.jsx # Slide-out forensic telemetry raw inspector
│   │   │   ├── ReportModal.jsx   # Forensic incident report with export (PDF/MD)
│   │   │   ├── AiLimitationsModal.jsx # Formal AI limitations & SOC risk analysis
│   │   │   └── IngestionPanel.jsx # Multi-source live telemetry ingestion workbench
│   │   ├── constants/
│   │   │   ├── mitreMatrix.js    # MITRE ATT&CK 12-tactic reference catalog
│   │   │   └── attackScenarios.js# Synthetic attack datasets & scenarios
│   │   ├── services/
│   │   │   └── api.js            # Unified API client (PHP API + Local resilient engine)
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   ├── vite.config.js
│   └── tailwind.config.js
├── docs/
│   ├── ARCHITECTURE.md           # System architecture, data flow, correlation pipeline
│   ├── SCENARIOS.md              # Detailed walkthrough of synthetic attack scenarios
│   ├── AI_LIMITATIONS.md         # In-depth analysis of AI limitations in SOC / threat hunting
│   └── EVALUATION.md             # Quantitative benchmarks & evaluation results
└── README.md                     # Platform overview & quick start
```

---

## Quick Start Guide

### Option A: Cloud-Native Docker Compose (Recommended for Full Stack)
Run the entire 3-tier architecture (React + PHP + MySQL) in isolated containers with one command:
```bash
# Using PowerShell
.\deploy-docker.ps1

# Or using Bash
./deploy-docker.sh

# Or directly with Docker Compose
docker compose up -d --build
```
- **React Frontend:** `http://localhost:3000`
- **PHP REST API:** `http://localhost:8000`
- **MySQL Datastore:** `localhost:3306`

---

### Option B: Kubernetes (K8s) Cluster Deployment
Deploy the complete production stack to Kubernetes with persistent storage, ingress, and auto-scaling (HPA):
```bash
# Using PowerShell
.\deploy-k8s.ps1

# Or using Bash
./deploy-k8s.sh

# Or directly with Kustomize
kubectl apply -k ./k8s
```
See the comprehensive [docs/CONTAINERIZATION_AND_KUBERNETES.md](docs/CONTAINERIZATION_AND_KUBERNETES.md) guide for Ingress host setup and autoscaling tests.

---

### Option C: Local Development Mode (Frontend & Backend)

#### 1. Run the React Frontend
```bash
cd frontend-react
npm run dev
```
The dashboard will launch at `http://localhost:3000`.

> **Note on Dual-Mode Operation:**  
> The React dashboard includes an embedded in-memory correlation engine. It is **immediately functional out-of-the-box** even before you boot your MySQL/PHP server, allowing instant testing and review.

#### 2. Run the PHP & MySQL Backend (Native CLI / XAMPP)
- **With XAMPP / WAMP:** Copy `backend-php` to `htdocs` and import `sql/schema.sql` and `sql/seed_data.sql`.
- **With Standalone PHP CLI:**
  ```bash
  cd backend-php
  php seed.php                      # Creates & seeds MySQL
  php -S localhost:8000 router.php   # Launches API on port 8000
  ```

---

## Key Feature Demonstrations

### 1. Animated Attack Path Reconstruction
- Toggle the **Play Attack Sequence** button in the Attack Path Graph.
- Watch the platform sequentially light up nodes and directed edges across the cyber kill chain (from Spearphish attachment $\rightarrow$ In-memory PowerShell $\rightarrow$ LSASS dump $\rightarrow$ Remote WMI pivot $\rightarrow$ AWS S3 exfiltration).
- Click any edge badge to inspect the exact underlying raw event payload.

### 2. Evidence-Linked AI Copilot
- Review the AI investigation narrative in the AI Copilot tab.
- Click any `[EVT-...]` citation badge (e.g. `[EVT-APT-004]`).
- The **Evidence Drawer** slides out instantly, showing verified timestamps, process names, command-line arguments, cryptographic hashes, and raw JSON logs.

### 3. MITRE ATT&CK Enterprise Heatmap
- Inspect the 12-tactic matrix. Lit tiles indicate active adversarial techniques observed in the environment.
- Click any technique (e.g. `T1047 Windows Management Instrumentation` or `T1530 Cloud Data`) to highlight the correlated events.

### 4. Live Ingestion Workbench
- Click **Ingest Event** in the navbar.
- Select an attack template (e.g., Certutil Download Cradle, VPN Spray, DNS Tunneling, or AWS Firewall tampering).
- Click **Ingest Event Now** to trigger the correlation engine and update attack paths in real time.

### 5. Forensic Investigation Report Generator
- Click **Generate Report** to produce an executive incident summary, forensic timeline, evidence custody chain, and containment playbook.
- One-click export to Markdown (`.md`) or printable PDF.

---

## Explanation of AI Limitations in Threat Hunting

See [docs/AI_LIMITATIONS.md](file:///C:/Users/nh219/.gemini/antigravity/scratch/threat-hunter/docs/AI_LIMITATIONS.md) and the in-app **AI Limitations** dialog for an in-depth analysis of:
1. **Hallucination of Threat Indicators (IoCs):** Prevented via strict deterministic event UUID mapping.
2. **Base-Rate Fallacy:** Mitigated by requiring multi-domain orthogonal correlation before alert escalation.
3. **Adversarial Telemetry Poisoning:** Countered by mapping behavioral MITRE tactics rather than static string signatures.
4. **Context Window Constraints:** Solved through hierarchical graph abstraction.
5. **Human-in-the-Loop (HITL) Imperative:** AI suggests hypotheses, but human analysts retain exclusive authority over containment actions.
