# System Architecture & Technical Specifications

**Platform:** AegisHunt — AI-Assisted Cyber Threat Hunting & Attack Path Visualization  
**Stack:** React.js (Frontend), PHP PDO (REST API Backend), MySQL (Relational Telemetry Datastore)

---

## 1. High-Level Architectural Diagram

```
+-----------------------------------------------------------------------------------+
|                              PRESENTATION LAYER (React 18)                        |
|                                                                                   |
|  +--------------------+  +----------------------+  +---------------------------+  |
|  | Attack Path Graph  |  |  Timeline Stream     |  | MITRE ATT&CK Heatmap      |  |
|  | (SVG Canvas Nodes) |  | (Causality Sequence) |  | (12-Tactic Enterprise)    |  |
|  +--------------------+  +----------------------+  +---------------------------+  |
|             \                       |                       /                     |
|  +-----------------------------------------------------------------------------+  |
|  |                 AI Threat Copilot & Query Generator (Evidence-Linked)       |  |
|  +-----------------------------------------------------------------------------+  |
+------------------------------------------^----------------------------------------+
                                           | HTTP / REST (JSON)
+------------------------------------------v----------------------------------------+
|                                API ROUTING & CORRELATION LAYER (PHP)              |
|                                                                                   |
|  +--------------------+  +----------------------+  +---------------------------+  |
|  |  api/events.php    |  | api/correlate.php    |  | api/attack_path.php       |  |
|  |  (Ingest & Query)  |  | (Temporal Sliding)   |  | (Directed Topology)       |  |
|  +--------------------+  +----------------------+  +---------------------------+  |
|  +--------------------+  +----------------------+  +---------------------------+  |
|  |  api/mitre.php     |  | api/ai_assist.php    |  | api/report.php            |  |
|  |  (Matrix Mapping)  |  | (Hypothesis Engine)  |  | (Forensic IR Generator)   |  |
|  +--------------------+  +----------------------+  +---------------------------+  |
+------------------------------------------^----------------------------------------+
                                           | PDO Prepared Statements
+------------------------------------------v----------------------------------------+
|                                PERSISTENCE LAYER (MySQL 8 / MariaDB)              |
|                                                                                   |
|  [events]               [attack_scenarios]        [correlation_rules]             |
|  - event_uuid           - scenario_id             - rule_id                       |
|  - domain (EP/Auth/Net) - threat_actor            - sliding_window_minutes        |
|  - timestamp / host     - attack_vector           - condition_logic               |
|                                                                                   |
|  [incidents]            [incident_events]         [mitre_attack_matrix]           |
|  - confidence_score     - evidence chain link     - 12 tactics & techniques       |
+-----------------------------------------------------------------------------------+
```

---

## 2. Multi-Source Ingestion & Normalization Pipeline

The platform ingests events across four critical enterprise domains:

1. **Endpoint Telemetry (EDR / Sysmon / Auditd):**
   - Captures process spawns (`winword.exe` spawning `powershell.exe`), command-line parameters (`-Enc`, `-NoP`), memory injection (`rundll32.exe comsvcs.dll MiniDump`), and local file access (`.aws/credentials`).
2. **Identity & Authentication Telemetry (Active Directory / Kerberos / VPN):**
   - Tracks authentication results, failed attempt spikes, Kerberos ticket requests (Event ID 4769 with RC4 encryption type `0x17`), and RDP lateral movement (Logon Type 10).
3. **Network Telemetry (Zeek / Suricata / Flow Logs):**
   - Analyzes persistent C2 TLS beaconing, JA3 cryptographic fingerprints, jitter calculations, DNS query entropy, port sweeps, and egress bandwidth surges.
4. **Cloud Infrastructure Telemetry (AWS CloudTrail / GuardDuty):**
   - Records STS `AssumeRole` API calls, IAM policy attachment (`AdministratorAccess`), logging sabotage (`StopLogging`), S3 bulk `GetObject` operations, and compute instantiation (`RunInstances`).

### Normalization Schema Standard:
All events are normalized into a unified relational structure:
- `event_uuid`: Globally unique identifier (e.g. `EVT-APT-001`).
- `timestamp`: UTC ISO datetime.
- `domain`: `endpoint` | `auth` | `network` | `cloud`.
- `severity`: `informational` | `low` | `medium` | `high` | `critical`.
- `source_host`, `dest_host`, `source_ip`, `dest_ip`, `user_id`.
- `mitre_tactic`, `mitre_technique_id`, `mitre_technique_name`.
- `raw_payload`: Unaltered source telemetry in JSON format.

---

## 3. Correlation Engine Algorithm

The correlation pipeline executes the following stages:

1. **Sliding Time-Window Clustering:**
   Groups telemetry events occurring within configurable intervals (e.g., 30 to 120 minutes).
2. **Entity Graph Linkage:**
   Traces entity continuity across boundaries:
   $$\text{Workstation}(W_1) \xrightarrow{\text{User}(U_1)} \text{Kerberos Ticket} \xrightarrow{\text{Service Account}(U_2)} \text{Domain Controller}(DC_1)$$
3. **Kill-Chain Stage Progression:**
   Validates whether events follow an adversarial sequence:
   $$\text{Initial Access} \rightarrow \text{Execution} \rightarrow \text{Credential Access} \rightarrow \text{Lateral Movement} \rightarrow \text{Exfiltration / Impact}$$
4. **Confidence Scoring Formula:**
   $$C = \min\left(0.99, \, w_d \cdot N_d + w_t \cdot N_t + w_s \cdot S_{\text{max}}\right)$$
   where $N_d$ is the number of distinct telemetry domains (weight $w_d = 0.09$), $N_t$ is the number of observed MITRE tactics (weight $w_t = 0.08$), and $S_{\text{max}}$ is the severity baseline ($0.20$).

---

## 4. Directed Attack Path Graph Generation

- **Nodes:** Classified as `c2_server`, `endpoint`, `server`, or `cloud_resource`.
- **Edges:** Directed causality transitions carrying MITRE ATT&CK labels, execution timestamps, and direct foreign key links to `event_uuid`.
- **Blast Radius Analysis:** Computes the total set of compromised physical assets and user identities.
