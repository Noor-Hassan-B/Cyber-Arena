from dotenv import load_dotenv
from pathlib import Path
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

import os
import io
import csv
import json
import random
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Annotated, Dict, Any

import bcrypt
import jwt
from bson import ObjectId
from fastapi import FastAPI, APIRouter, Request, Response, HTTPException, Depends, WebSocket, WebSocketDisconnect, Cookie
from fastapi.responses import StreamingResponse
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, BeforeValidator, EmailStr, ConfigDict


# ── MongoDB ─────────────────────────────────────────────────────────────
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
db_name = os.environ.get('DB_NAME', 'threatlens_soc')

try:
    from mongomock_motor import AsyncMongoMockClient
except ImportError:
    AsyncMongoMockClient = None

client = AsyncIOMotorClient(mongo_url, serverSelectionTimeoutMS=1500)
db = client[db_name]

JWT_ALGORITHM = "HS256"
COOKIE_NAME = "threatlens_session"

app = FastAPI(title="ThreatLens SOC")
api = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("threatlens")

# ── Models ──────────────────────────────────────────────────────────────
def _oid(v):
    if isinstance(v, ObjectId): return str(v)
    return str(v)
PyObjectId = Annotated[str, BeforeValidator(_oid)]

def now_utc():
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.isoformat()

def hash_pw(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()

def verify_pw(p: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(p.encode(), h.encode())
    except Exception:
        return False

def make_token(user_id: str) -> str:
    return jwt.encode(
        {"sub": user_id, "exp": now_utc() + timedelta(hours=12), "type": "session"},
        os.environ["JWT_SECRET"], algorithm=JWT_ALGORITHM
    )

def decode_token(t: str) -> dict:
    return jwt.decode(t, os.environ["JWT_SECRET"], algorithms=[JWT_ALGORITHM])


async def get_current_user(request: Request) -> dict:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:].strip()
    if not token:
        token = request.query_params.get("token")
    if not token:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = decode_token(token)
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(401, "User not found")
        user["id"] = str(user["_id"])
        user.pop("_id", None); user.pop("password_hash", None)
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Session expired")
    except Exception:
        raise HTTPException(401, "Invalid session")


# ── Attack Simulator (deterministic) ─────────────────────────────────────
MITRE = {
    "brute_force": {"id": "T1110.003", "name": "Password Spraying"},
    "credential_stuffing": {"id": "T1110.004", "name": "Credential Stuffing"},
    "port_scan": {"id": "T1595.001", "name": "Scanning IP Blocks"},
    "ghost_tx": {"id": "T1078", "name": "Valid Accounts"},
    "sql_injection": {"id": "T1190", "name": "Exploit Public-Facing Application"},
}

SCENARIOS = {
    "brute_force": {
        "title": "Low-and-slow brute force detected",
        "summary": "Authentication failures are distributed across a long window to evade naive thresholds.",
        "recommended": "Enable adaptive lockout on the identity gateway and require step-up MFA.",
        "attacker_vm": "hydra-attacker",
        "target_vm": "auth-target-vm",
        "source_ip": "185.220.101.44",
        "geo": "Frankfurt, DE",
        "service": "svc-ledger",
        "risk": 82,
        "severity": "high",
        "detectors": [
            {"name": "EWMA baseline", "vote": True, "confidence": 78},
            {"name": "DBSCAN outlier", "vote": True, "confidence": 84},
            {"name": "Isolation Forest", "vote": False, "confidence": 51},
            {"name": "Heuristic correlation", "vote": True, "confidence": 93},
        ],
        "features": ["Failure rate 42/hr", "IP rotation entropy 0.71", "Timing variance 118s"],
        "commands": [
            "sudo hydra -L users.lst -P rockyou.txt -t 4 -W 90 auth-target-vm ssh",
            "[ATTEMPT] target auth-target-vm - login \"root\" - pass \"summer2025\" 1 of 14344391 [child 0]",
            "[ATTEMPT] target auth-target-vm - login \"admin\" - pass \"P@ssw0rd\"  2 of 14344391 [child 1]",
            "[ATTEMPT] target auth-target-vm - login \"analyst\" - pass \"welcome1\" 3 of 14344391 [child 2]",
            "[STATUS] 3 attempts in 00:04:32h, 4 tries/min, avg 90.4s throttle",
            "[ATTEMPT] target auth-target-vm - login \"root\" - pass \"letmein!\" 4 of 14344391 [child 0]",
            "[STATUS] rotating source ip pool → 185.220.101.44 → 185.220.101.9",
            "[STATUS] evading rate-limit :: sleep 274s",
            "[+] 4 of 4 target completed, 0 valid passwords found",
        ],
        "events": lambda n: [{
            "type": "auth", "src": "hydra-attacker", "dst": "auth-target-vm",
            "service": "svc-ledger", "ip": random.choice(["185.220.101.44","185.220.101.9","185.220.101.17"]),
            "status": "failure", "score": 100, "user": f"user-{100+i}",
        } for i in range(n)],
    },
    "credential_stuffing": {
        "title": "Distributed credential stuffing cluster",
        "summary": "A coordinated source cluster is authenticating against multiple accounts with reused credentials.",
        "recommended": "Block the source cluster and force a reset for impacted accounts.",
        "attacker_vm": "botnet-attacker-vm",
        "target_vm": "identity-target-vm",
        "source_ip": "45.141.84.17",
        "geo": "Bucharest, RO",
        "service": "svc-identity",
        "risk": 94,
        "severity": "critical",
        "detectors": [
            {"name": "DBSCAN outlier", "vote": True, "confidence": 94},
            {"name": "Isolation Forest", "vote": True, "confidence": 89},
            {"name": "Heuristic correlation", "vote": True, "confidence": 99},
            {"name": "EWMA baseline", "vote": False, "confidence": 47},
        ],
        "features": ["19 source IPs / 4 min", "Account fan-out: 38", "DBSCAN cluster density 0.88"],
        "commands": [
            "python3 stuffer.py --wordlist combos.txt --proxies residential.txt --targets identity-target-vm -c 32",
            "[stuffer] loaded 42,118 credential pairs from combos.txt",
            "[stuffer] rotating 19 residential proxies (RO,DE,US pool)",
            "[stuffer] [ok] proxy 45.141.84.17 → identity-target-vm | user-112 | 401",
            "[stuffer] [ok] proxy 45.141.84.18 → identity-target-vm | user-113 | 401",
            "[stuffer] [ok] proxy 45.141.84.19 → identity-target-vm | user-114 | 401",
            "[stuffer] [ok] proxy 45.141.84.20 → identity-target-vm | user-115 | 401",
            "[stuffer] pace 4.2 req/s | fan-out 38 accounts | success 0",
            "[stuffer] triggering rotation :: window 4 min",
        ],
        "events": lambda n: [{
            "type": "auth", "src": "botnet-attacker-vm", "dst": "identity-target-vm",
            "service": "svc-identity", "ip": f"45.141.84.{17+i%20}",
            "status": "failure", "score": 100, "user": f"user-{112+i}",
        } for i in range(n)],
    },
    "port_scan": {
        "title": "Port-scan reconnaissance detected",
        "summary": "A single source is fanning out across a wide port range on internal hosts.",
        "recommended": "Quarantine the source subnet and correlate with recent VPN sessions.",
        "attacker_vm": "recon-attacker-vm",
        "target_vm": "edge-target-vm",
        "source_ip": "91.121.44.77",
        "geo": "Paris, FR",
        "service": "svc-edge",
        "risk": 71,
        "severity": "medium",
        "detectors": [
            {"name": "EWMA baseline", "vote": True, "confidence": 66},
            {"name": "Isolation Forest", "vote": True, "confidence": 74},
            {"name": "Heuristic correlation", "vote": True, "confidence": 88},
            {"name": "DBSCAN outlier", "vote": False, "confidence": 42},
        ],
        "features": ["Port entropy 0.94", "1,306 unique ports / 60s", "SYN/ACK ratio 21.4"],
        "commands": [
            "nmap -sS -T4 -p 1-65535 --min-rate 800 edge-target-vm",
            "Starting Nmap 7.94 ( https://nmap.org ) at 2026-02-14 09:15 UTC",
            "Nmap scan report for edge-target-vm (10.42.0.10)",
            "Discovered open port 22/tcp on 10.42.0.10",
            "Discovered open port 80/tcp on 10.42.0.10",
            "Discovered open port 443/tcp on 10.42.0.10",
            "Discovered open port 5432/tcp on 10.42.0.10",
            "SYN Stealth Scan Timing: About 34.20% done; ETC: 09:18 (0:01:12 remaining)",
            "Not shown: 65531 filtered tcp ports (no-response)",
        ],
        "events": lambda n: [{
            "type": "network", "src": "recon-attacker-vm", "dst": "edge-target-vm",
            "service": "svc-edge", "ip": "91.121.44.77",
            "status": "scan", "score": random.randint(60, 92), "user": None, "port": random.randint(1,65535),
        } for i in range(n)],
    },
    "ghost_tx": {
        "title": "Ghost transactions / latency spike",
        "summary": "A burst of transactions with abnormal latency during a promo window with no login signal.",
        "recommended": "Freeze the promo channel and inspect the payments queue for shadow requests.",
        "attacker_vm": "shadow-attacker-vm",
        "target_vm": "payments-target-vm",
        "source_ip": "203.0.113.9",
        "geo": "Singapore, SG",
        "service": "svc-payments",
        "risk": 88,
        "severity": "critical",
        "detectors": [
            {"name": "Isolation Forest", "vote": True, "confidence": 92},
            {"name": "EWMA baseline", "vote": True, "confidence": 81},
            {"name": "Heuristic correlation", "vote": True, "confidence": 95},
            {"name": "DBSCAN outlier", "vote": False, "confidence": 38},
        ],
        "features": ["Latency p99 4,120ms", "No auth signal / 210 tx", "Amount stddev x8.1"],
        "commands": [
            "python3 shadow_tx.py --endpoint https://payments-target-vm/api/tx --concurrency 64",
            "[shadow] burst 1/6 → 40 tx :: p50=180ms p99=4120ms",
            "[shadow] burst 2/6 → 40 tx :: p50=210ms p99=3980ms",
            "[shadow] burst 3/6 → 40 tx :: p50=195ms p99=4340ms",
            "[shadow] status: no auth cookie, amount ±$8,412 stddev",
            "[shadow] burst 4/6 → 40 tx :: p50=205ms p99=4210ms",
            "[shadow] burst 5/6 → 40 tx :: promo=SUMMER26 rate=8.2/s",
            "[shadow] complete :: 240 tx submitted / 0 auth events",
        ],
        "events": lambda n: [{
            "type": "transaction", "src": "shadow-attacker-vm", "dst": "payments-target-vm",
            "service": "svc-payments", "ip": "203.0.113.9",
            "status": "anomalous", "score": random.randint(70, 96), "user": None,
        } for i in range(n)],
    },
    "sql_injection": {
        "title": "Automated SQL injection & schema extraction",
        "summary": "Boolean-based blind and error-based SQL injection probes detected targeting API query parameters.",
        "recommended": "Apply parameterized queries, restrict DB account privileges, and enable strict WAF rules.",
        "attacker_vm": "sqlmap-attacker",
        "target_vm": "api-target-vm",
        "source_ip": "194.26.29.112",
        "geo": "Amsterdam, NL",
        "service": "svc-gateway",
        "risk": 96,
        "severity": "critical",
        "detectors": [
            {"name": "Isolation Forest", "vote": True, "confidence": 95},
            {"name": "Heuristic correlation", "vote": True, "confidence": 98},
            {"name": "DBSCAN outlier", "vote": True, "confidence": 88},
            {"name": "EWMA baseline", "vote": True, "confidence": 74},
        ],
        "features": ["UNION SELECT signature", "Error-rate anomaly 48/min", "Payload entropy 0.96"],
        "commands": [
            "sqlmap -u \"https://10.42.0.10/api/ledger?acc=1092\" --batch --risk=3 --level=3 --dbs",
            "[sqlmap] testing connection to target URL: https://10.42.0.10/api/ledger",
            "[sqlmap] checking if the target is protected by some WAF/IPS",
            "[sqlmap] heuristic (basic) test shows GET parameter 'acc' might be injectable",
            "[sqlmap] testing 'AND boolean-based blind - WHERE or HAVING clause'",
            "[sqlmap] parameter 'acc' is vulnerable: DBMS: PostgreSQL 15.2 detected",
            "[sqlmap] fetching database names: threatlens_soc, pg_catalog, information_schema",
            "[!] CRITICAL: data exfiltration attempt detected across 3 tables",
        ],
        "events": lambda n: [{
            "type": "exploit", "src": "sqlmap-attacker", "dst": "api-target-vm",
            "service": "svc-gateway", "ip": "194.26.29.112",
            "status": "anomalous", "score": random.randint(85, 99), "user": "api-client",
        } for i in range(n)],
    },
}


# ── WebSocket manager ────────────────────────────────────────────────────
class Hub:
    def __init__(self): self.conns: List[WebSocket] = []
    async def connect(self, ws): await ws.accept(); self.conns.append(ws)
    def disconnect(self, ws):
        if ws in self.conns: self.conns.remove(ws)
    async def broadcast(self, msg: dict):
        dead = []
        for c in self.conns:
            try: await c.send_json(msg)
            except Exception: dead.append(c)
        for d in dead: self.disconnect(d)
hub = Hub()

# In-memory event stream (last 200 raw events, per-instance)
EVENT_STREAM: List[dict] = []
COUNTERS = {"events_ingested": 0, "throughput_per_sec": 0}


# ── Schemas ──────────────────────────────────────────────────────────────
class LoginReq(BaseModel):
    email: EmailStr
    password: str

class NoteReq(BaseModel):
    note: str

class SimReq(BaseModel):
    scenario: str
    intensity: Optional[str] = "normal"  # normal | fast

class ContainReq(BaseModel):
    contained: bool

class StatusReq(BaseModel):
    status: str  # open | acknowledged | resolved


# ── Auth Routes ──────────────────────────────────────────────────────────
@api.post("/auth/login")
async def login(body: LoginReq, response: Response):
    email = body.email.lower().strip()
    u = await db.users.find_one({"email": email})
    if not u or not verify_pw(body.password, u["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    token = make_token(str(u["_id"]))
    response.set_cookie(
        key=COOKIE_NAME, value=token,
        httponly=True, secure=False, samesite="lax",
        max_age=60*60*12, path="/",
    )
    return {
        "id": str(u["_id"]),
        "email": u["email"],
        "name": u["name"],
        "role": u.get("role", "analyst"),
        "token": token,
    }

@api.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}

@api.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return user


# ── Dashboard / Config ───────────────────────────────────────────────────
@api.get("/config")
async def config(_user=Depends(get_current_user)):
    return {
        "scenarios": [
            {"key": k, "title": v["title"], "attacker": v["attacker_vm"], "target": v["target_vm"], "severity": v["severity"], "mitre": MITRE[k]}
            for k, v in SCENARIOS.items()
        ],
        "detectors": ["EWMA baseline", "Isolation Forest", "DBSCAN outlier", "Heuristic correlation"],
        "mitre": MITRE,
    }

@api.get("/dashboard/summary")
async def summary(_user=Depends(get_current_user)):
    open_count = await db.alerts.count_documents({"status": "open"})
    ack_count = await db.alerts.count_documents({"status": "acknowledged"})
    resolved_count = await db.alerts.count_documents({"status": "resolved"})
    max_risk_doc = await db.alerts.find().sort("risk_score", -1).limit(1).to_list(1)
    max_risk = max_risk_doc[0]["risk_score"] if max_risk_doc else 0
    top_entity = max_risk_doc[0]["source_ip"] if max_risk_doc else None
    return {
        "events_ingested": COUNTERS["events_ingested"],
        "throughput": COUNTERS["throughput_per_sec"],
        "active_threats": open_count,
        "acknowledged": ack_count,
        "resolved": resolved_count,
        "max_risk": max_risk,
        "top_entity": top_entity,
    }

@api.get("/dashboard/event-stream")
async def event_stream(_user=Depends(get_current_user)):
    return {"events": EVENT_STREAM[-40:][::-1]}

@api.get("/dashboard/leaderboard")
async def leaderboard(_user=Depends(get_current_user)):
    pipeline = [
        {"$sort": {"triggered_at": -1}},
        {"$group": {"_id": "$source_ip", "risk": {"$max": "$risk_score"}, "count": {"$sum": 1}, "last": {"$first": "$triggered_at"}}},
        {"$sort": {"risk": -1}}, {"$limit": 10},
    ]
    rows = await db.alerts.aggregate(pipeline).to_list(10)
    return {"entities": [{"ip": r["_id"], "risk": r["risk"], "count": r["count"], "last": r["last"]} for r in rows]}

@api.get("/dashboard/origins")
async def origins(_user=Depends(get_current_user)):
    rows = await db.alerts.aggregate([
        {"$group": {"_id": {"geo": "$geo", "ip": "$source_ip"}, "risk": {"$max": "$risk_score"}}},
        {"$sort": {"risk": -1}}, {"$limit": 12}
    ]).to_list(12)
    return {"origins": [{"geo": r["_id"]["geo"], "ip": r["_id"]["ip"], "risk": r["risk"]} for r in rows]}


# ── Alerts ───────────────────────────────────────────────────────────────
def alert_to_json(a: dict) -> dict:
    a["id"] = str(a.pop("_id"))
    return a

@api.get("/alerts")
async def list_alerts(severity: Optional[str] = None, _user=Depends(get_current_user)):
    q = {}
    if severity and severity != "all": q["severity"] = severity
    docs = await db.alerts.find(q).sort("triggered_at", -1).limit(100).to_list(100)
    return {"alerts": [alert_to_json(d) for d in docs]}

@api.get("/alerts/{alert_id}")
async def get_alert(alert_id: str, _user=Depends(get_current_user)):
    d = await db.alerts.find_one({"_id": ObjectId(alert_id)})
    if not d: raise HTTPException(404, "Not found")
    return alert_to_json(d)

@api.patch("/alerts/{alert_id}/note")
async def save_note(alert_id: str, body: NoteReq, user=Depends(get_current_user)):
    await db.alerts.update_one({"_id": ObjectId(alert_id)}, {"$set": {"analyst_note": body.note, "note_by": user["name"], "note_at": iso(now_utc())}})
    await db.audit_logs.insert_one({"alert_id": alert_id, "action": "note", "by": user["name"], "at": iso(now_utc()), "detail": body.note[:200]})
    return {"ok": True}

@api.patch("/alerts/{alert_id}/status")
async def set_status(alert_id: str, body: StatusReq, user=Depends(get_current_user)):
    if body.status not in ("open", "acknowledged", "resolved"):
        raise HTTPException(400, "Invalid status")
    await db.alerts.update_one({"_id": ObjectId(alert_id)}, {"$set": {"status": body.status, "status_at": iso(now_utc())}})
    await db.audit_logs.insert_one({"alert_id": alert_id, "action": f"status:{body.status}", "by": user["name"], "at": iso(now_utc())})
    await hub.broadcast({"type": "alert_updated", "alert_id": alert_id, "status": body.status})
    return {"ok": True}

@api.patch("/alerts/{alert_id}/containment")
async def set_containment(alert_id: str, body: ContainReq, user=Depends(get_current_user)):
    await db.alerts.update_one({"_id": ObjectId(alert_id)}, {"$set": {"contained": body.contained, "contained_at": iso(now_utc())}})
    await db.audit_logs.insert_one({"alert_id": alert_id, "action": f"containment:{body.contained}", "by": user["name"], "at": iso(now_utc())})
    return {"ok": True}


# ── Simulation ───────────────────────────────────────────────────────────
async def run_simulation(scenario_key: str, intensity: str):
    s = SCENARIOS[scenario_key]
    delay_evt = 0.08 if intensity == "fast" else 0.35
    delay_cmd = 0.25 if intensity == "fast" else 0.7

    # Kick off — announce
    await hub.broadcast({"type": "sim_start", "scenario": scenario_key, "title": s["title"], "attacker": s["attacker_vm"], "target": s["target_vm"]})

    # Stream attacker commands + events interleaved
    events = s["events"](14)
    cmds = s["commands"]
    ev_i = 0
    for ci, cmd in enumerate(cmds):
        await hub.broadcast({"type": "attacker_cmd", "scenario": scenario_key, "line": cmd, "progress": int((ci+1)/len(cmds)*100)})
        await asyncio.sleep(delay_cmd)
        # emit a few events per command
        for _ in range(2):
            if ev_i < len(events):
                e = events[ev_i]; ev_i += 1
                e["timestamp"] = iso(now_utc())
                EVENT_STREAM.append(e)
                if len(EVENT_STREAM) > 200: EVENT_STREAM.pop(0)
                COUNTERS["events_ingested"] += 1
                await hub.broadcast({"type": "event", "event": e})
                await asyncio.sleep(delay_evt)

    # Persist alert
    alert = {
        "scenario": scenario_key,
        "title": s["title"],
        "summary": s["summary"],
        "recommended": s["recommended"],
        "severity": s["severity"],
        "risk_score": s["risk"],
        "source_ip": s["source_ip"],
        "geo": s["geo"],
        "service": s["service"],
        "attacker_vm": s["attacker_vm"],
        "target_vm": s["target_vm"],
        "detectors": s["detectors"],
        "features": s["features"],
        "mitre": MITRE[scenario_key],
        "status": "open",
        "contained": False,
        "analyst_note": "",
        "triggered_at": iso(now_utc()),
        "simulated": True,
        "events_count": len(events),
    }
    r = await db.alerts.insert_one(alert)
    alert["id"] = str(r.inserted_id); alert.pop("_id", None)
    await hub.broadcast({"type": "alert_created", "alert": alert})
    await hub.broadcast({"type": "sim_end", "scenario": scenario_key})

@api.post("/simulation/start")
async def start_sim(body: SimReq, _user=Depends(get_current_user)):
    if body.scenario not in SCENARIOS:
        raise HTTPException(400, "Unknown scenario")
    asyncio.create_task(run_simulation(body.scenario, body.intensity or "normal"))
    return {"ok": True, "scenario": body.scenario, "intensity": body.intensity}

@api.post("/simulation/reset")
async def reset_sim(_user=Depends(get_current_user)):
    await db.alerts.delete_many({})
    await db.audit_logs.delete_many({})
    EVENT_STREAM.clear()
    COUNTERS["events_ingested"] = 0
    await hub.broadcast({"type": "reset"})
    return {"ok": True}

@api.post("/simulation/attacker-command")
async def attacker_command(body: dict, _user=Depends(get_current_user)):
    """Interactive Kali Linux attacker terminal command processor.
    Simulates real-world offensive tools (nmap, hydra, sqlmap, gobuster, msfconsole, curl, nc, linux utils)
    with authentic command parsing, verbose terminal output, and correlated SIEM telemetry generation.
    """
    line = str(body.get("line", "")).strip()
    if not line:
        raise HTTPException(400, "Empty command")

    resp_lines = []
    scenario = None
    cmd_clean = line.strip()
    tokens = cmd_clean.split()
    cmd_name = tokens[0].lower() if tokens else ""
    cmd_lower = cmd_clean.lower()

    # Clear screen
    if cmd_name in ("clear", "cls") or cmd_lower == "reset":
        await hub.broadcast({"type": "attacker_cmd", "line": "$ clear", "action": "clear"})
        return {"ok": True, "action": "clear", "lines": []}

    # Help & Command Directory
    elif cmd_name in ("help", "?") or "--help" in tokens or "-h" in tokens:
        resp_lines = [
            "┌──(kali㉿attacker-vm)-[~/threatlens]",
            "└─$ COMMAND DIRECTORY & OFFENSIVE ARSENAL",
            "",
            "OFFENSIVE PENTEST TOOLS (Triggers Correlated SIEM Telemetry):",
            "  • nmap -sS -p 22,80,443,5432 -sV 10.42.0.10   [SYN Stealth Port Reconnaissance / T1595.001]",
            "  • hydra -l root -P rockyou.txt 10.42.0.10 ssh [Low-and-Slow Password Spraying / T1110.003]",
            "  • sqlmap -u \"https://10.42.0.10/api/ledger?acc=1\" --dbs --dump [SQL Injection / T1190]",
            "  • python3 cred_stuffer.py --proxies 19       [Distributed Credential Stuffing / T1110.004]",
            "  • curl -X POST https://10.42.0.10/api/tx -d '...' [Ghost Latency Spike Probe / T1078]",
            "  • gobuster dir -u https://10.42.0.10 -w /usr/share/wordlists/dirb/common.txt",
            "  • msfconsole                                  [Metasploit Framework Interactive Console]",
            "  • nc -lvnp 4444                               [Netcat Reverse Shell Listener]",
            "",
            "LINUX SYSTEM & RECON UTILITIES:",
            "  • ls -la | cat targets.lst | cat notes.md | cat rockyou.txt",
            "  • whoami | id | uname -a | ifconfig | ip a | ping -c 3 10.42.0.10",
            "  • ps aux | netstat -tuln | uptime | date | targets | status | clear",
            "",
            "Type any valid offensive command or flags to execute against TARGET-VM (10.42.0.10)."
        ]

    # Whoami & ID
    elif cmd_name == "whoami":
        resp_lines = ["kali"]

    elif cmd_name == "id":
        resp_lines = [
            "uid=1000(kali) gid=1000(kali) groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),119(wireshark)"
        ]

    # Uname & Kernel
    elif cmd_name == "uname":
        if "-a" in tokens or "--all" in tokens:
            resp_lines = ["Linux kali-redteam-vm 6.8.11-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.8.11-1kali2 (2026-02-14) x86_64 GNU/Linux"]
        elif "-r" in tokens:
            resp_lines = ["6.8.11-amd64"]
        else:
            resp_lines = ["Linux"]

    # PWD & CD
    elif cmd_name == "pwd":
        resp_lines = ["/home/kali/threatlens"]

    elif cmd_name == "cd":
        target_dir = tokens[1] if len(tokens) > 1 else "~"
        resp_lines = [f"[DEBUG] directory changed to {target_dir} (virtual workspace: /home/kali/threatlens)"]

    # Date & Uptime
    elif cmd_name == "date":
        resp_lines = [now_utc().strftime("%a %b %d %H:%M:%S UTC %Y")]

    elif cmd_name == "uptime":
        resp_lines = [" 18:44:12 up 4 days,  6:21,  2 users,  load average: 0.14, 0.22, 0.18"]

    # Directory Listing
    elif cmd_name in ("ls", "dir", "ll"):
        resp_lines = [
            "total 1496",
            "drwxr-xr-x 4 kali kali    4096 Feb 14 09:00 .",
            "drwxr-xr-x 3 root root    4096 Feb 14 08:30 ..",
            "-rw-r--r-- 1 kali kali     512 Feb 14 08:45 notes.md",
            "-rw-r--r-- 1 kali kali     184 Feb 14 08:52 targets.lst",
            "-rw-r--r-- 1 kali kali 1434439 Feb 14 08:40 rockyou.txt",
            "-rwxr-xr-x 1 kali kali    3120 Feb 14 08:55 cred_stuffer.py",
            "-rwxr-xr-x 1 kali kali    2480 Feb 14 08:58 shadow_tx.py",
            "-rw------- 1 kali kali    1675 Feb 14 08:35 id_rsa_lab",
            "-rw-r--r-- 1 kali kali     842 Feb 14 09:10 proxies.txt",
        ]

    # File Inspection
    elif cmd_name in ("cat", "head", "tail", "less", "more"):
        target_file = tokens[1] if len(tokens) > 1 else ""
        if "target" in target_file:
            resp_lines = [
                "# TARGET LAB SCOPE - ISOLATED SOC TEST LAB (NO REAL EGRESS)",
                "10.42.0.10   target-vm.threatlens.local   (svc-ledger : ports 22, 80, 443, 5432)",
                "10.42.0.12   identity-vm.threatlens.local (svc-identity : port 8080)",
                "10.42.0.15   payments-vm.threatlens.local (svc-payments : ports 5432, 8443)",
                "# Attacker source: 192.168.1.105 (tun0: 10.42.0.5)",
            ]
        elif "note" in target_file:
            resp_lines = [
                "### RED TEAM ENGAGEMENT NOTES & ATTACK PLAN",
                "- Scope: Isolated virtual enclave (10.42.0.0/24).",
                "- Gateway: 10.42.0.1 | DNS: 10.42.0.2",
                "- Step 1: SYN reconnaissance with Nmap against 10.42.0.10",
                "- Step 2: Test SSH authentication surface with Hydra (rockyou.txt)",
                "- Step 3: Enumerate HTTP ledger endpoints for SQL injection with SQLMap",
                "- Step 4: Evaluate SIEM EWMA & DBSCAN detector responses in real-time.",
            ]
        elif "rockyou" in target_file:
            resp_lines = [
                "summer2025",
                "P@ssw0rd",
                "welcome1",
                "letmein!",
                "admin2026",
                "12345678",
                "dragon",
                "monkey",
                "... [14,344,384 more passwords truncated]",
            ]
        elif "prox" in target_file:
            resp_lines = [
                "45.141.84.17:8080  [DE - Frankfurt]",
                "185.220.101.44:3128 [DE - Berlin]",
                "194.26.29.112:8888  [NL - Amsterdam]",
                "91.121.44.77:8080   [FR - Roubaix]",
                "... [15 additional residential proxies loaded]",
            ]
        elif "rsa" in target_file:
            resp_lines = [
                "-----BEGIN OPENSSH PRIVATE KEY-----",
                "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
                "QyNTUxOQAAACD4hL... [SIMULATED RED TEAM LAB KEY] ...qV8=",
                "-----END OPENSSH PRIVATE KEY-----",
            ]
        elif "hosts" in target_file or "resolv" in target_file:
            resp_lines = [
                "127.0.0.1       localhost",
                "10.42.0.10     target-vm.threatlens.local",
                "10.42.0.12     identity-vm.threatlens.local",
                "10.42.0.15     payments-vm.threatlens.local",
            ]
        elif "passwd" in target_file:
            resp_lines = [
                "root:x:0:0:root:/root:/bin/bash",
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                "kali:x:1000:1000:Kali,,,:/home/kali:/usr/bin/zsh",
            ]
        else:
            resp_lines = [f"cat: {target_file or 'file'}: No such file or directory. Try 'cat targets.lst', 'cat notes.md', or 'ls -la'"]

    # Network Diagnostics & Interfaces
    elif cmd_name in ("ifconfig", "ip") and ("a" in tokens or "addr" in tokens or cmd_name == "ifconfig"):
        resp_lines = [
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500",
            "        inet 192.168.1.105  netmask 255.255.255.0  broadcast 192.168.1.255",
            "        inet6 fe80::a00:27ff:fe9a:1c44  prefixlen 64  scopeid 0x20<link>",
            "        ether 08:00:27:9a:1c:44  txqueuelen 1000  (Ethernet)",
            "        RX packets 142088  bytes 12849012 (12.2 MB)",
            "        TX packets 98412   bytes 9812401 (9.3 MB)",
            "",
            "tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500",
            "        inet 10.42.0.5  netmask 255.255.255.0  destination 10.42.0.5",
            "        RX packets 8412  bytes 712010 (712.0 KB)",
            "        TX packets 7840  bytes 684120 (684.1 KB)",
            "",
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536",
            "        inet 127.0.0.1  netmask 255.0.0.0",
        ]

    elif cmd_name == "ping":
        host = tokens[-1] if len(tokens) > 1 and not tokens[-1].startswith("-") else "10.42.0.10"
        resp_lines = [
            f"PING {host} ({host}) 56(84) bytes of data.",
            f"64 bytes from {host}: icmp_seq=1 ttl=64 time=0.384 ms",
            f"64 bytes from {host}: icmp_seq=2 ttl=64 time=0.412 ms",
            f"64 bytes from {host}: icmp_seq=3 ttl=64 time=0.395 ms",
            f"--- {host} ping statistics ---",
            "3 packets transmitted, 3 received, 0% packet loss, time 2004ms",
            "rtt min/avg/max/mdev = 0.384/0.397/0.412/0.011 ms",
        ]

    elif cmd_name in ("netstat", "ss"):
        resp_lines = [
            "Active Internet connections (only servers)",
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name",
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      812/sshd: /usr/sbin",
            "tcp        0      0 127.0.0.1:4444          0.0.0.0:*               LISTEN      1420/nc -lvnp 4444",
            "tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      1890/python3",
            "tcp6       0      0 :::22                   :::*                    LISTEN      812/sshd: /usr/sbin",
        ]

    elif cmd_name in ("ps", "top"):
        resp_lines = [
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND",
            "root         1  0.0  0.1 168420 12340 ?        Ss   08:00   0:01 /sbin/init",
            "kali       842  0.0  0.3  28940 18400 pts/0    Ss   08:30   0:00 /usr/bin/zsh",
            "kali      1420  0.0  0.1  14200  4100 pts/0    S+   09:05   0:00 nc -lvnp 4444",
            "kali      1912  0.0  0.1  14200  4100 pts/0    R+   09:18   0:00 ps aux",
        ]

    # Target & Status
    elif cmd_name in ("targets", "target", "scope"):
        resp_lines = [
            "================================================================================",
            "                   THREATLENS ISOLATED TARGET ENCLAVE SCOPE                    ",
            "================================================================================",
            "  • Host: 10.42.0.10 (TARGET-VM)     Services: SSH:22, HTTP:80, HTTPS:443, PGSQL:5432",
            "  • Host: 10.42.0.12 (IDENTITY-VM)   Services: OAuth/SAML Gateway (Port 8080)",
            "  • Host: 10.42.0.15 (PAYMENTS-VM)   Services: Transactions API (Ports 5432, 8443)",
            "  • Attacker Node: 192.168.1.105     Enclave Tunnel: 10.42.0.5",
            "================================================================================",
        ]

    elif cmd_name == "status":
        resp_lines = [
            f"[*] TELEMETRY STREAM: {COUNTERS['events_ingested']} normalized events ingested",
            f"[*] ACTIVE CLIENTS: {len(hub.conns)} analyst console session(s) active",
            f"[*] LAB ISOLATION: AIRGAPPED (Zero external WAN egress)",
            f"[*] LIVE THROUGHPUT: {COUNTERS['throughput_per_sec']} evt/s",
        ]

    # Netcat Reverse Shell Listener
    elif cmd_name == "nc" or cmd_name == "netcat":
        resp_lines = [
            f"$ {line}",
            "listening on [any] 4444 ...",
            "connect to [192.168.1.105] from (UNKNOWN) [10.42.0.10] 49182",
            "Linux target-vm 5.15.0-89-generic #99-Ubuntu SMP Fri Nov 10 14:15:32 UTC 2023 x86_64",
            "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
            "www-data@target-vm:/var/www/html$ whoami",
            "www-data",
            "www-data@target-vm:/var/www/html$ [*] Reverse shell session caught. Type 'run brute_force' or 'sqlmap' to trigger alert pipeline.",
        ]

    # Gobuster / Web Content Enumeration
    elif cmd_name in ("gobuster", "dirb", "ffuf"):
        resp_lines = [
            "===============================================================",
            "Gobuster v3.6 - by OJ Reeves (@TheColonial) & Christian Mehlmauer",
            "===============================================================",
            "[+] Url:                     https://10.42.0.10",
            "[+] Method:                  GET",
            "[+] Wordlist:                /usr/share/wordlists/dirb/common.txt",
            "[+] Status codes:            200,204,301,302,307,401,403",
            "[+] Timeout:                 10s",
            "===============================================================",
            "Starting gobuster in directory enumeration mode",
            "===============================================================",
            "/api                  (Status: 301) [Size: 178] [--> https://10.42.0.10/api/]",
            "/admin                (Status: 403) [Size: 548]",
            "/docs                 (Status: 200) [Size: 2420]",
            "/login                (Status: 200) [Size: 4120]",
            "/metrics              (Status: 401) [Size: 184]",
            "/swagger.json         (Status: 200) [Size: 8412]",
            "Progress: 4614 / 4614 (100.00%)",
            "===============================================================",
            "[+] Discovered vulnerable endpoint: /api/ledger?acc= [PostgreSQL parameter]",
        ]

    # Metasploit Framework Interactive Console
    elif cmd_name in ("msfconsole", "msf"):
        resp_lines = [
            "  ______________________________________________________________________________",
            " |                                                                              |",
            " |                   Metasploit Framework Edition (Lab Mode)                   |",
            " |______________________________________________________________________________|",
            "       =[ metasploit v6.3.55-dev                          ]",
            "+ -- --=[ 2380 exploits - 1230 auxiliary - 415 post       ]",
            "+ -- --=[ 962 payloads - 46 encoders - 11 nops            ]",
            "",
            "msf6 > use exploit/multi/http/apache_activemq_rce",
            "msf6 exploit(multi/http/apache_activemq_rce) > set RHOSTS 10.42.0.10",
            "RHOSTS => 10.42.0.10",
            "msf6 exploit(multi/http/apache_activemq_rce) > set RPORT 8080",
            "RPORT => 8080",
            "msf6 exploit(multi/http/apache_activemq_rce) > check",
            "[*] 10.42.0.10:8080 - The target is vulnerable.",
            "msf6 exploit(multi/http/apache_activemq_rce) > [*] Type 'run sql_injection' or 'hydra' to trigger detection telemetry.",
        ]

    # Direct Playbook Runner: run <scenario> [--fast]
    elif cmd_name == "run":
        parts = tokens
        if len(parts) < 2 or parts[1] not in SCENARIOS:
            resp_lines = [
                "[-] error: unknown playbook",
                f"[*] available: { ' | '.join(SCENARIOS.keys()) }",
                "[*] example: run brute_force --fast",
            ]
        else:
            scenario = parts[1]
            fast = "--fast" in parts
            asyncio.create_task(run_simulation(scenario, "fast" if fast else "normal"))
            resp_lines = [
                f"[+] launching playbook: {scenario.upper()}",
                f"[+] execution profile: {'AGGRESSIVE BURST' if fast else 'STEALTH / LOW-AND-SLOW'}",
                f"[+] target host: {SCENARIOS[scenario]['target_vm']} (10.42.0.10)",
                f"[+] emitting correlated telemetry to SIEM pipeline...",
            ]

    # NMAP SYN Scan / Port Reconnaissance (T1595.001)
    elif cmd_name in ("nmap", "recon") or "nmap" in cmd_lower:
        scenario = "port_scan"
        fast = "--fast" in tokens or "-t5" in cmd_lower or "-t4" in cmd_lower
        asyncio.create_task(run_simulation(scenario, "fast" if fast else "normal"))
        target = "10.42.0.10"
        for t in tokens:
            if t.count(".") == 3:
                target = t
                break
        resp_lines = [
            f"Starting Nmap 7.94 ( https://nmap.org ) at {now_utc().strftime('%Y-%m-%d %H:%M UTC')}",
            f"Initiating SYN Stealth Scan against {target} [1-65535 ports] at 1200 pkts/s...",
            "SYN Stealth Scan Timing: About 48.20% done; ETC: +0:01 remaining",
            f"Discovered open port 22/tcp on {target}   (OpenSSH 8.9p1 Ubuntu-3ubuntu0.6)",
            f"Discovered open port 80/tcp on {target}   (nginx 1.18.0 - Reverse Proxy)",
            f"Discovered open port 443/tcp on {target}  (OpenSSL 3.0.2 / TLS 1.3)",
            f"Discovered open port 5432/tcp on {target} (PostgreSQL DB 15.2-1.pgdg22.04+1)",
            "Not shown: 65531 closed tcp ports (reset)",
            "Device type: general purpose | Running: Linux 5.X|6.X",
            "OS CPE: cpe:/o:linux:linux_kernel:5.15",
            f"Nmap scan report for {target} finished: 1 IP address (1 host up) scanned in 2.84 seconds",
            "[!] SIEM CORRELATION: T1595.001 Port-Scan Reconnaissance Detected",
        ]

    # HYDRA Password Spraying / Brute Force (T1110.003)
    elif cmd_name in ("hydra", "medusa", "patator") or "hydra" in cmd_lower:
        scenario = "brute_force"
        fast = "--fast" in tokens or "-t" in tokens
        asyncio.create_task(run_simulation(scenario, "fast" if fast else "normal"))
        resp_lines = [
            "Hydra v9.5 (c) 2023 by van Hauser / THC - Starting low-and-slow spray",
            "[DATA] max 4 worker tasks per host, service: ssh, target: 10.42.0.10:22",
            "[ATTEMPT] target 10.42.0.10 - login \"root\" - pass \"summer2025\" 1 of 14344391 [child 0]",
            "[ATTEMPT] target 10.42.0.10 - login \"admin\" - pass \"P@ssw0rd\"  2 of 14344391 [child 1]",
            "[ATTEMPT] target 10.42.0.10 - login \"analyst\" - pass \"welcome1\" 3 of 14344391 [child 2]",
            "[*] evading detection threshold: applying 90s inter-request jitter",
            "[STATUS] 3 attempts in 00:04:32h, 4 tries/min, avg 90.4s throttle",
            "[ATTEMPT] target 10.42.0.10 - login \"root\" - pass \"letmein!\" 4 of 14344391 [child 0]",
            "[*] rotating source IP pool → 185.220.101.44 → 185.220.101.9",
            "[!] SIEM CORRELATION: T1110.003 Low-and-Slow Password Spraying Detected",
        ]

    # SQLMAP Injection & Schema Extraction (T1190)
    elif cmd_name in ("sqlmap", "sqli") or "sqlmap" in cmd_lower:
        scenario = "sql_injection"
        fast = "--fast" in tokens
        asyncio.create_task(run_simulation(scenario, "fast" if fast else "normal"))
        resp_lines = [
            "        ___",
            "       __H__",
            " ___ ___[.]_____ ___ ___  {1.7.2#stable}",
            "|_ -| . [']     | .'| . |",
            "|___|_  [\"]_|_|_|__,|  _| http://sqlmap.org",
            "      |_|V...       |_|",
            "[*] testing connection to target: https://10.42.0.10/api/ledger?acc=1092",
            "[*] heuristic test shows that GET parameter 'acc' might be injectable",
            "[+] GET parameter 'acc' is vulnerable. Do you want to keep testing the others? [y/N] N",
            "sqlmap identified the following injection point(s) with a total of 48 HTTP(s) requests:",
            "---",
            "Parameter: acc (GET)",
            "    Type: boolean-based blind",
            "    Title: AND boolean-based blind - WHERE or HAVING clause",
            "    Payload: acc=1092 AND 7412=7412",
            "    Type: error-based",
            "    Title: PostgreSQL error-based - Parameter replace",
            "    Payload: acc=(SELECT 7412 FROM PG_SLEEP(0))",
            "---",
            "[INFO] the back-end DBMS is PostgreSQL (version 15.2)",
            "[+] available databases [3]: [*] information_schema [*] pg_catalog [*] threatlens_ledger",
            "[!] SIEM CORRELATION: T1190 Exploit Public-Facing Application Detected",
        ]

    # CURL / HTTP Ghost Transactions (T1078)
    elif cmd_name in ("curl", "shadow", "http") or "shadow_tx" in cmd_lower:
        scenario = "ghost_tx"
        fast = "--fast" in tokens
        asyncio.create_task(run_simulation(scenario, "fast" if fast else "normal"))
        resp_lines = [
            "> POST /api/v1/payments/tx HTTP/1.1",
            "> Host: 10.42.0.10:8443",
            "> User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "> Accept: application/json",
            "> Content-Type: application/json",
            "> Content-Length: 142",
            "> ",
            "> {\"sender\":\"acc_9912\",\"recipient\":\"acc_8412\",\"amount\":8412.50,\"currency\":\"USD\"}",
            "< HTTP/1.1 200 OK",
            "< Server: nginx/1.18.0",
            "< Date: " + now_utc().strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "< Content-Type: application/json",
            "< Transfer-Encoding: chunked",
            "< ",
            "{\"status\":\"queued\",\"tx_id\":\"tx_ghost_9912\",\"latency_ms\":4120}",
            "[*] Replay concurrency: 64 workers active. Latency p99 anomaly injected.",
            "[!] SIEM CORRELATION: T1078 Latency Anomaly & Ghost Transactions Detected",
        ]

    # Credential Stuffing Proxy Cluster (T1110.004)
    elif cmd_name in ("stuffer", "python3") and ("stuffer" in cmd_lower or "cred" in cmd_lower):
        scenario = "credential_stuffing"
        fast = "--fast" in tokens
        asyncio.create_task(run_simulation(scenario, "fast" if fast else "normal"))
        resp_lines = [
            "[stuffer] loading credentials from combos.txt (42,118 pairs)",
            "[stuffer] initializing 19 residential proxies across DE, RO, US pools",
            "[stuffer] account fan-out: 38 targets across svc-identity gateway",
            "[stuffer] proxy 45.141.84.17:8080 -> 10.42.0.12 | user: alex_k | 401 Unauthorized",
            "[stuffer] proxy 185.220.101.44:3128 -> 10.42.0.12 | user: sarah_m | 401 Unauthorized",
            "[stuffer] proxy 194.26.29.112:8888 -> 10.42.0.12 | user: dev_ops | 401 Unauthorized",
            "[stuffer] high-entropy rotation: 19 unique IPs in 12 seconds",
            "[!] SIEM CORRELATION: T1110.004 Distributed Credential Stuffing Detected",
        ]

    else:
        resp_lines = [
            f"bash: {cmd_name}: command not found",
            "Type 'help' for approved offensive tools (nmap, hydra, sqlmap, curl, stuffer, msfconsole, gobuster) or 'ls' for files.",
        ]

    # Broadcast command & response lines to terminal sessions
    await hub.broadcast({"type": "attacker_cmd", "line": f"$ {line}", "progress": 0})
    for l in resp_lines:
        await hub.broadcast({"type": "attacker_cmd", "line": l, "progress": 0})

    return {"ok": True, "scenario": scenario, "lines": resp_lines}


# ── Export CSV & Incident Reports ─────────────────────────────────────────
@api.get("/export/alerts.csv")
async def export_csv(_user=Depends(get_current_user)):
    docs = await db.alerts.find().sort("triggered_at", -1).to_list(1000)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id","triggered_at","severity","risk_score","scenario","title","source_ip","geo","mitre_id","mitre_name","status","contained","recommended","analyst_note"])
    for d in docs:
        m = d.get("mitre") or {}
        w.writerow([str(d["_id"]), d.get("triggered_at",""), d.get("severity",""), d.get("risk_score",""),
                    d.get("scenario",""), d.get("title",""), d.get("source_ip",""), d.get("geo",""),
                    m.get("id",""), m.get("name",""), d.get("status",""), d.get("contained",False),
                    d.get("recommended",""), d.get("analyst_note","")])
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=threatlens_alerts.csv"})

@api.get("/export/incident-report.md")
async def export_incident_report(_user=Depends(get_current_user)):
    """Generate comprehensive Threat Summary & Incident Triage Report for Tier-2/Tier-3 SecOps."""
    docs = await db.alerts.find().sort("triggered_at", -1).to_list(100)
    report = []
    report.append("# THREATLENS ENTERPRISE SEC-OPS INCIDENT RESPONSE TRIAGE REPORT")
    report.append(f"**Generated:** {now_utc().strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    report.append(f"**Target Enclave:** Tier-1 Neo-Bank Hybrid Cloud Infrastructure (65,000 tx/s Baseline)  ")
    report.append(f"**Auditor / Analyst:** {_user.get('name', 'Analyst')} ({_user.get('email', 'secops@neobank.internal')})  ")
    report.append(f"**Classification:** RESTRICTED // INCIDENT RESPONSE WORKBENCH  ")
    report.append("\n---\n")

    report.append("## 1. EXECUTIVE SUMMARY & BUSINESS IMPACT")
    report.append("A distributed offensive campaign was detected targeting Neo-Bank authentication gateways and payment settlement pipelines during high-volume operations. Detection was achieved through multi-modal machine learning consensus (EWMA moving averages, Isolation Forest anomaly trees, and DBSCAN density clustering) to isolate low-and-slow vectors from legitimate 65k tx/s background traffic.")
    report.append(f"- **Total Correlated Incidents:** {len(docs)}")
    report.append(f"- **Total Telemetry Events Analyzed:** {COUNTERS['events_ingested']}")
    report.append(f"- **Active Ingestion Rate:** {COUNTERS['throughput_per_sec']} eps")
    report.append("\n---\n")

    report.append("## 2. CORRELATED INCIDENTS & MITRE ATT&CK MAPPINGS")
    for i, a in enumerate(docs[:10]):
        m = a.get("mitre") or {}
        report.append(f"### Incident #{i+1}: {a.get('title')} [SEVERITY: {a.get('severity', '').upper()} / RISK: {a.get('risk_score')}/100]")
        report.append(f"- **Case ID:** `ALT-{str(a.get('_id'))[-8:]}`")
        report.append(f"- **Triggered At:** {a.get('triggered_at')}")
        report.append(f"- **MITRE ATT&CK:** {m.get('id')} - {m.get('name')}")
        report.append(f"- **Attacker Source:** `{a.get('source_ip')}` ({a.get('geo')})")
        report.append(f"- **Target Service:** `{a.get('service')}` on `{a.get('target_vm', '10.42.0.10')}`")
        report.append(f"- **Incident Status:** `{a.get('status', 'open').upper()}` | **Containment Engaged:** `{a.get('contained', False)}`")
        report.append(f"- **Summary:** {a.get('summary')}")
        report.append(f"- **Recommended Next Steps:** {a.get('recommended')}")
        if a.get('analyst_note'):
            report.append(f"- **Analyst Note:** {a.get('analyst_note')}")
        report.append("")

    report.append("\n---\n")
    report.append("## 3. INCIDENT RESPONSE RECOMMENDATIONS & CONTAINMENT")
    report.append("1. **Enforce Step-Up MFA**: Deploy adaptive rate-limiting on identity gateways (`svc-identity`) to neutralize credential stuffing.")
    report.append("2. **Isolate Compromised Endpoints**: Engage SDN hypervisor containment on target nodes (`10.42.0.10`).")
    report.append("3. **Freeze Latency-Spike Promo Routes**: Audit ghost transaction replay buffers on payments endpoint (`svc-payments`).")
    report.append("\n*Report compiled deterministically by ThreatLens Autonomous SIEM Engine.*")

    content = "\n".join(report)
    return StreamingResponse(
        iter([content]),
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=threatlens_incident_triage_report.md"}
    )


# ── WebSocket ────────────────────────────────────────────────────────────
@app.websocket("/api/ws")
async def ws_endpoint(ws: WebSocket):
    # Auth via cookie or query param
    token = ws.cookies.get(COOKIE_NAME) or ws.query_params.get("token")
    if not token:
        await ws.close(code=4401); return
    try:
        decode_token(token)
    except Exception:
        await ws.close(code=4401); return
    await hub.connect(ws)
    try:
        await ws.send_json({"type": "hello", "clients": len(hub.conns)})
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        hub.disconnect(ws)
    except Exception:
        hub.disconnect(ws)


# ── Startup ──────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global client, db
    try:
        await asyncio.wait_for(client.admin.command('ping'), timeout=1.5)
        logger.info(f"Connected to MongoDB at {mongo_url}")
    except Exception as e:
        logger.warning(f"MongoDB at {mongo_url} unavailable ({e}). Falling back to mongomock-motor in-memory database.")
        if AsyncMongoMockClient:
            client = AsyncMongoMockClient()
            db = client[db_name]
        else:
            raise

    await db.users.create_index("email", unique=True)
    await db.alerts.create_index([("triggered_at", -1)])
    email = os.environ["ADMIN_EMAIL"].lower()
    name = os.environ.get("ADMIN_NAME", "Analyst")
    pw = os.environ["ADMIN_PASSWORD"]
    existing = await db.users.find_one({"email": email})
    if not existing:
        await db.users.insert_one({
            "email": email, "password_hash": hash_pw(pw),
            "name": name, "role": "analyst", "created_at": iso(now_utc()),
        })
        logger.info(f"Seeded analyst: {email}")
    else:
        if not verify_pw(pw, existing["password_hash"]):
            await db.users.update_one({"email": email}, {"$set": {"password_hash": hash_pw(pw)}})
    # Seed baseline alerts if empty
    alert_count = await db.alerts.count_documents({})
    if alert_count == 0:
        bf = SCENARIOS["brute_force"]
        cs = SCENARIOS["credential_stuffing"]
        ps = SCENARIOS["port_scan"]
        await db.alerts.insert_many([
            {
                "scenario": "credential_stuffing",
                "title": cs["title"],
                "summary": cs["summary"],
                "recommended": cs["recommended"],
                "severity": cs["severity"],
                "risk_score": cs["risk"],
                "source_ip": cs["source_ip"],
                "geo": cs["geo"],
                "service": cs["service"],
                "attacker_vm": cs["attacker_vm"],
                "target_vm": cs["target_vm"],
                "detectors": cs["detectors"],
                "features": cs["features"],
                "mitre": MITRE["credential_stuffing"],
                "status": "open",
                "contained": False,
                "analyst_note": "Active cluster from residential proxy subnet 45.141.84.0/24 targeting customer accounts.",
                "triggered_at": iso(now_utc() - timedelta(minutes=8)),
                "simulated": True,
                "events_count": 28,
            },
            {
                "scenario": "brute_force",
                "title": bf["title"],
                "summary": bf["summary"],
                "recommended": bf["recommended"],
                "severity": bf["severity"],
                "risk_score": bf["risk"],
                "source_ip": bf["source_ip"],
                "geo": bf["geo"],
                "service": bf["service"],
                "attacker_vm": bf["attacker_vm"],
                "target_vm": bf["target_vm"],
                "detectors": bf["detectors"],
                "features": bf["features"],
                "mitre": MITRE["brute_force"],
                "status": "acknowledged",
                "contained": True,
                "analyst_note": "Throttled SSH spray identified across German exit nodes. Adaptive lockout engaged.",
                "triggered_at": iso(now_utc() - timedelta(minutes=22)),
                "simulated": True,
                "events_count": 14,
            },
            {
                "scenario": "port_scan",
                "title": ps["title"],
                "summary": ps["summary"],
                "recommended": ps["recommended"],
                "severity": ps["severity"],
                "risk_score": ps["risk"],
                "source_ip": ps["source_ip"],
                "geo": ps["geo"],
                "service": ps["service"],
                "attacker_vm": ps["attacker_vm"],
                "target_vm": ps["target_vm"],
                "detectors": ps["detectors"],
                "features": ps["features"],
                "mitre": MITRE["port_scan"],
                "status": "resolved",
                "contained": True,
                "analyst_note": "SYN stealth reconnaissance swept ports 1-65535. Source subnet 91.121.44.0/24 quarantined at edge.",
                "triggered_at": iso(now_utc() - timedelta(minutes=55)),
                "simulated": True,
                "events_count": 32,
            }
        ])
        logger.info("Seeded initial SOC alert history for Neo-Bank enclave")

    # Start background ambient telemetry and throughput monitors
    asyncio.create_task(throughput_ticker())
    asyncio.create_task(ambient_telemetry_loop())

AMBIENT_TEMPLATES = [
    {"type": "auth", "src": "auth-proxy-01", "dst": "svc-identity", "service": "svc-identity", "ip": "10.42.0.12", "status": "ok", "user": "cust-8429", "score_range": (2, 8)},
    {"type": "network", "src": "edge-nlb-eu", "dst": "edge-target-vm", "service": "svc-edge", "ip": "195.154.12.88", "status": "allowed", "port": 443, "score_range": (1, 5)},
    {"type": "transaction", "src": "core-ledger-tx", "dst": "svc-payments", "service": "svc-payments", "ip": "10.42.0.15", "status": "settled", "user": "acct-99214", "score_range": (3, 11)},
    {"type": "system", "src": "k8s-worker-02", "dst": "svc-ledger", "service": "svc-ledger", "ip": "10.42.0.10", "status": "nominal", "user": "daemon", "score_range": (1, 4)},
    {"type": "auth", "src": "mobile-gw-ap-se", "dst": "svc-identity", "service": "svc-identity", "ip": "10.42.0.12", "status": "ok", "user": "cust-6102", "score_range": (3, 8)},
    {"type": "network", "src": "vpc-flow-nat", "dst": "svc-gateway", "service": "svc-gateway", "ip": "185.122.55.20", "status": "allowed", "port": 8443, "score_range": (2, 6)},
    {"type": "transaction", "src": "instant-pay-router", "dst": "svc-payments", "service": "svc-payments", "ip": "10.42.0.15", "status": "settled", "user": "acct-11409", "score_range": (4, 12)},
]

async def ambient_telemetry_loop():
    # Seed initial buffer if empty
    if not EVENT_STREAM:
        for i in range(24):
            tmpl = random.choice(AMBIENT_TEMPLATES)
            evt = {
                "type": tmpl["type"],
                "src": tmpl["src"],
                "dst": tmpl["dst"],
                "service": tmpl["service"],
                "ip": tmpl["ip"],
                "status": tmpl["status"],
                "score": random.randint(*tmpl["score_range"]),
                "user": tmpl.get("user"),
                "timestamp": iso(now_utc() - timedelta(seconds=(24 - i) * 8)),
            }
            if "port" in tmpl:
                evt["port"] = tmpl["port"]
            EVENT_STREAM.append(evt)
        COUNTERS["events_ingested"] = 14280

    while True:
        await asyncio.sleep(random.uniform(1.8, 3.2))
        tmpl = random.choice(AMBIENT_TEMPLATES)
        evt = {
            "type": tmpl["type"],
            "src": tmpl["src"],
            "dst": tmpl["dst"],
            "service": tmpl["service"],
            "ip": tmpl["ip"],
            "status": tmpl["status"],
            "score": random.randint(*tmpl["score_range"]),
            "user": tmpl.get("user"),
            "timestamp": iso(now_utc()),
        }
        if "port" in tmpl:
            evt["port"] = tmpl["port"]
        EVENT_STREAM.append(evt)
        if len(EVENT_STREAM) > 200:
            EVENT_STREAM.pop(0)
        COUNTERS["events_ingested"] += 1
        await hub.broadcast({"type": "event", "event": evt})

async def throughput_ticker():
    last = COUNTERS["events_ingested"]
    while True:
        await asyncio.sleep(1)
        cur = COUNTERS["events_ingested"]
        diff = cur - last
        last = cur
        # Normalized telemetry throughput metric (scaled baseline for 65,000 tx/s hybrid cloud)
        COUNTERS["throughput_per_sec"] = diff * 12 if diff > 0 else random.randint(14, 22)

@app.on_event("shutdown")
async def shutdown():
    if hasattr(client, "close"):
        try:
            client.close()
        except Exception:
            pass


app.include_router(api)

cors_origins_raw = [o.strip() for o in os.environ.get("CORS_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=cors_origins_raw if "*" not in cors_origins_raw else [
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost:5173", "http://127.0.0.1:5173",
        "http://localhost:8000", "http://127.0.0.1:8000",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:[0-9]+)?$",
    allow_methods=["*"],
    allow_headers=["*"],
)