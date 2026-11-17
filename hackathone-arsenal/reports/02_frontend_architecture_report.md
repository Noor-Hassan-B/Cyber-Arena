# 💻 ThreatLens SOC — Frontend Architecture & Component Report

> **Location**: `app/frontend/`  
> **Framework**: React 18 · Vite · TailwindCSS · Lucide Icons · Sonner Toasts

---

## 🏛️ Frontend Directory Structure

```
app/frontend/src/
├── components/
│   ├── AlertDrilldown.jsx   # Slide-over Incident Triage Workbench drawer
│   ├── AlertFeed.jsx        # Correlated Security Alerts Feed & Search bar
│   ├── EventStream.jsx      # Live Raw Telemetry Stream table & Tail viewer
│   ├── KaliConsole.jsx      # Interactive Kali Linux Attacker CLI window
│   ├── KpiTile.jsx          # Metric cards with tone glows & pulse indicators
│   ├── Leaderboard.jsx      # High-Risk Attacked Target Entities leaderboard
│   ├── ScenarioCard.jsx     # Offensive Playbook launcher selection cards
│   └── ThreatOrigins.jsx    # Geo-location IP threat map visualization
├── context/
│   └── AuthContext.jsx      # Session state & authentication provider
├── lib/
│   └── api.js               # Axios REST API client & WS URL builder
├── pages/
│   ├── Dashboard.jsx        # Main SOC Command Center layout & view modes
│   └── Login.jsx            # Dark cyber-security authentication page
├── App.js / App.css
├── index.css                # Glassmorphism tokens, custom scrollbars, badges
└── main.jsx
```

---

## 🎨 Design System & Visual Aesthetic

- **Theme Palette**: Deep Void (`#06090E`), Glass Surface (`#0B0F17`), Electric Cyan (`#38BDF8`), Phosphor Emerald (`#10B981`), Threat Red (`#EF4444`), Warm Amber (`#F59E0B`).
- **Typography**: Google Inter (Body & Headers) + JetBrains Mono (Telemetry & Metrics) + Space Mono (Terminal).
- **Glassmorphism Density**: `.tl-card` with `backdrop-filter: blur(12px)`, 10px rounded corners, and glowing borders on hover.

---

## 🔍 Core Component Breakdown

### 1. `Dashboard.jsx` (Main Command Center)
- **Top Navigation Bar**: Brand identity (`ThreatLens SOC Enterprise v2.4`), UTC Clock, WebSocket status (`HEALTHY` / `CONNECTING`), Analyst profile, and Logout.
- **View Mode Switcher**:
  - `Full Dashboard`: Single-page layout with KPIs, Playbook Launcher, Live Telemetry Stream, Alert Feed, Leaderboard, and Threat Map.
  - `Split Screen`: Side-by-side mode (left: SOC Alerts & Telemetry, right: Embedded Kali Linux Attacker VM).
- **MITRE ATT&CK Matrix Strip**: Highlights active attack tactics (`T1595.001`, `T1190`, `T1110.003`, `T1110.004`, `T1078`).

### 2. `AlertFeed.jsx` & `AlertDrilldown.jsx` (Incident Response)
- **Search & Filter**: Filter alerts by keyword, source IP, indicator, or severity tab (`ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **Triage Workbench Drawer**: Slide-over panel presenting:
  - 4-Model ML Consensus voting breakdown with confidence scores.
  - MITRE ATT&CK technique breakdown and anomaly features.
  - Recommended SecOps mitigation steps.
  - Analyst investigation note editor (`Save Note`).
  - SDN Hypervisor Host Isolation toggle button.
  - One-click Incident Case Report exporter (`.md`).

### 3. `KaliConsole.jsx` (Red-Team Attacker VM)
- **Interactive ZSH Prompt**: Allows typing real offensive commands (`nmap`, `hydra`, `sqlmap`, `curl`, `whoami`, `cat`, `ls`).
- **Command Auto-Completion**: Tab auto-completes available commands.
- **Quick Action Chips**: Instant shortcuts for launching common offensive payloads.

### 4. `EventStream.jsx` (Raw Telemetry Tail)
- **Live Stream**: Streams real-time network, authentication, exploit, and transaction events over WebSocket.
- **Category Tabs**: Filter by `ALL`, `AUTH`, `NETWORK`, `EXPLOIT`, `TRANSACTION`.
- **Controls**: Pause/Live tail toggle, search filter, and copy event JSON shortcut.
