# Threat Hunting Platform - Backend (PHP & MySQL)

This directory contains the complete PHP REST API and MySQL database for the **AI-Assisted Cyber Threat Hunting & Attack Path Visualization Platform**.

---

## Architecture Overview

- **Language & Runtime:** PHP 7.4+ / 8.0+ / 8.2+ (Uses standard PDO extension).
- **Database:** MySQL 5.7+ / 8.0+ or MariaDB 10.3+.
- **Endpoints:** RESTful JSON endpoints supporting CORS for the React frontend.
- **Capabilities:**
  - Multi-source ingestion (Endpoint/Sysmon, Identity/Active Directory, Network/Zeek, Cloud/AWS CloudTrail).
  - Cross-domain entity correlation engine (sliding time window + user + host pivot).
  - Directed attack path graph builder with blast-radius computation.
  - MITRE ATT&CK Enterprise Matrix mapper.
  - AI-assisted hypothesis generation with strictly cited `[EVT-...]` evidence links.
  - Forensic incident timeline and exportable investigation reports.

---

## Directory Structure

```
backend-php/
├── config/
│   └── db.php           # PDO MySQL connection settings & CORS headers
├── sql/
│   ├── schema.sql       # MySQL schema (tables, foreign keys, indexes)
│   └── seed_data.sql    # Multi-source synthetic datasets (APT29, Ransomware, Cryptomining)
├── api/
│   ├── events.php       # GET (query/filter) & POST (ingest new events)
│   ├── correlate.php    # Cross-domain temporal & entity correlation
│   ├── attack_path.php  # Directed graph nodes, edges, and critical path
│   ├── mitre.php        # MITRE ATT&CK technique mapping & tactic distribution
│   ├── ai_assist.php    # Threat hunting query suggestions, hypotheses, & AI limitations
│   ├── scenarios.php    # Documented attack scenarios catalog
│   └── report.php       # Incident timeline & forensic investigation report
├── seed.php             # Automated CLI/web installer to setup & seed MySQL
└── router.php           # Local PHP development server router
```

---

## Quick Setup Instructions

### Option 1: Using XAMPP / WAMP / Laragon
1. Start **Apache** and **MySQL** in your XAMPP Control Panel.
2. Open **phpMyAdmin** (`http://localhost/phpmyadmin`).
3. Click on the **SQL** tab and execute:
   - First, the contents of `sql/schema.sql`
   - Second, the contents of `sql/seed_data.sql`
4. Copy the `backend-php` folder into your web root (e.g., `C:\xampp\htdocs\threat-hunter-api`).
5. Verify database credentials in `backend-php/config/db.php`:
   ```php
   $db_host = '127.0.0.1';
   $db_name = 'threat_hunter';
   $db_user = 'root';
   $db_pass = ''; // Leave empty for default XAMPP root
   ```

### Option 2: Using Built-in PHP Development Server
If you have PHP installed on your terminal:
```bash
cd backend-php

# Seed the MySQL database
php seed.php

# Start the PHP server on port 8000
php -S localhost:8000 router.php
```

The API will now be live at `http://localhost:8000/api/...`.

---

## Available API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/scenarios` | Lists documented attack scenarios |
| `GET` | `/api/events?scenario_id=...` | Retrieves normalized security events |
| `POST` | `/api/events` | Ingests new endpoint/auth/network/cloud event |
| `GET` | `/api/correlate?scenario_id=...` | Runs temporal correlation & causality chain |
| `GET` | `/api/attack_path?scenario_id=...` | Reconstructs directed attack graph topology |
| `GET` | `/api/mitre?scenario_id=...` | MITRE ATT&CK matrix heatmap and tactic breakdown |
| `GET/POST` | `/api/ai_assist?action=summary` | AI threat summary with evidence citations |
| `GET` | `/api/ai_assist?action=query_suggestions` | AI hunting query recommendations (SPL/SQL) |
| `GET` | `/api/ai_assist?action=ai_limitations` | Comprehensive analysis of AI limitations in SOC |
| `GET` | `/api/report?scenario_id=...` | Forensic incident timeline & investigation report |
