"""
visual_simulator.py
Real-time Visual Simulation Server & Interactive SOC Operations Dashboard
for FCGD-AH (Feedback-Controlled Generative Deception in Adaptive Honeypots).

Runs an HTTP & WebSocket server (zero external web dependencies, pure standard library)
that serves a high-fidelity visual dashboard visualizing:
1. Live Network Attack Graph (Attacker -> Honeypot SSH -> Virtual FS -> Deception Engine)
2. Interactive Fake Environment & Database Viewer (PostgreSQL tables, S3 manifests, Decoy FS)
3. Deception Engine Pipeline & Validator Feedback Loop (Attempts, criteria checks, pass/fail retry)
4. Attack Pattern Analytics (Top targeted artifacts, retry distributions, latency heatmaps)
5. Live Attack Simulator Controls (Trigger automated reconnaissance, AWS key hunt, credential theft)
"""

import http.server
import json
import os
import secrets
import socket
import sys
import threading
import time
import urllib.parse
from datetime import datetime

# Setup project imports
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fcgd_ah.taxonomy import ArtifactCategory
from fcgd_ah.schemas import SessionState, EnvironmentFacts, MalwareInterestProfile
from fcgd_ah import retry_loop
from fcgd_ah.config import LOG_FILE

# Global in-memory simulation telemetry
EVENTS_LOG = []
ACTIVE_SESSIONS = []
VIRTUAL_DB = {
    "users": [
        {"id": 1, "username": "admin", "role": "superadmin", "last_login": "2026-10-26 14:12:00", "auth_type": "2FA_TOTP"},
        {"id": 2, "username": "deploy", "role": "ci_pipeline", "last_login": "2026-10-26 16:45:22", "auth_type": "SSH_KEY"},
        {"id": 3, "username": "ubuntu", "role": "system_maintenance", "last_login": "2026-10-25 09:30:10", "auth_type": "PASSWORD"},
        {"id": 4, "username": "appuser", "role": "db_service", "last_login": "2026-10-26 17:00:01", "auth_type": "APP_TOKEN"}
    ],
    "sessions": [
        {"session_id": "sess_918231", "user_id": 2, "ip": "192.168.1.15", "status": "ACTIVE", "token_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"session_id": "sess_412399", "user_id": 4, "ip": "10.20.34.110", "status": "VERIFIED", "token_hash": "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"}
    ],
    "audit_logs": [
        {"id": 101, "timestamp": "2026-10-26 16:50:01", "event": "DB_CONNECTION_ESTABLISHED", "source": "10.20.34.110"},
        {"id": 102, "timestamp": "2026-10-26 17:02:14", "event": "S3_SNAPSHOT_BACKUP_COMPLETED", "source": "s3://internal-backups/prod-server-01/"},
        {"id": 103, "timestamp": "2026-10-26 17:28:44", "event": "HONEYTOKEN_GENERATION_RECORDED", "source": "FCGD_DECEPTION_ENGINE"}
    ]
}

def load_attempt_history():
    history = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        history.append(json.loads(line))
        except Exception:
            pass
    return history[-30:]

def run_deception_simulation(category_name: str, attacker_cmd: str):
    try:
        category = ArtifactCategory(category_name)
    except Exception:
        category = ArtifactCategory.AWS_CREDENTIALS

    facts = EnvironmentFacts(
        hostname="prod-server-01",
        org_name="DemoCorp",
        existing_users=["deploy", "ubuntu", "root", "attacker"],
        previously_generated_artifacts=[]
    )
    malware_profile = MalwareInterestProfile(
        file_type_interests=[".env", ".pem", ".key", ".conf"],
        credential_patterns=["aws", "pass", "token", "secret"],
        network_destinations=["10.0.0.0/8"]
    )
    session = SessionState(
        session_id=f"sim_{int(time.time()*1000)%1000000}",
        commands_run=[attacker_cmd],
        files_touched=[],
        duration_s=12.4,
        env_facts=facts,
        malware_profile=malware_profile
    )

    t0 = time.perf_counter()
    result = retry_loop.run(session, category)
    latency = (time.perf_counter() - t0) * 1000

    event = {
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "session_id": session.session_id,
        "attacker_cmd": attacker_cmd,
        "category": category.value,
        "suggested_path": result.suggested_path,
        "deployed": result.deployed,
        "attempts": result.attempts_consumed,
        "latency_ms": round(latency, 2),
        "artifact_preview": result.artifact_content if result.artifact_content else "",
        "issues": [issue.criterion for issue in result.all_issues]
    }
    EVENTS_LOG.insert(0, event)
    if len(EVENTS_LOG) > 50:
        EVENTS_LOG.pop()
    return event


class SimulationAPIHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            self.serve_dashboard()
        elif path == "/api/status":
            self.send_json({
                "status": "ONLINE",
                "honeypot_host": "prod-server-01",
                "honeypot_ip": "127.0.0.1:2222",
                "org": "DemoCorp",
                "events": EVENTS_LOG[:15],
                "history": load_attempt_history(),
                "db": VIRTUAL_DB
            })
        elif path == "/api/database":
            self.send_json(VIRTUAL_DB)
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/simulate_attack":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body) if body else {}
            cat = data.get("category", "aws_credentials")
            cmd = data.get("command", "cat ~/.aws/credentials")
            event = run_deception_simulation(cat, cmd)
            self.send_json(event)
        elif path == "/api/record_event":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body) if body else {}
            EVENTS_LOG.insert(0, data)
            if len(EVENTS_LOG) > 50:
                EVENTS_LOG.pop()
            self.send_json({"status": "OK"})
        else:
            self.send_error(404, "Not Found")

    def send_json(self, data):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def serve_dashboard(self):
        html_content = DASHBOARD_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html_content)))
        self.end_headers()
        self.wfile.write(html_content)

    def log_message(self, format, *args):
        # Silence default standard HTTP logging for cleaner terminal
        pass


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FCGD-AH: Real-Time Honeypot Visual Simulation & SOC Operations</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Outfit:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg-dark: #0a0e17;
    --card-bg: rgba(16, 24, 39, 0.75);
    --card-border: rgba(56, 189, 248, 0.15);
    --accent-cyan: #06b6d4;
    --accent-red: #f43f5e;
    --accent-green: #10b981;
    --accent-purple: #8b5cf6;
    --accent-amber: #f59e0b;
    --text-main: #f1f5f9;
    --text-muted: #94a3b8;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background-color: var(--bg-dark);
    color: var(--text-main);
    font-family: 'Outfit', sans-serif;
    min-height: 100vh;
    overflow-x: hidden;
    background-image: 
      radial-gradient(circle at 10% 15%, rgba(6, 182, 212, 0.08) 0%, transparent 40%),
      radial-gradient(circle at 90% 85%, rgba(244, 63, 94, 0.08) 0%, transparent 40%),
      radial-gradient(circle at 50% 50%, rgba(139, 92, 246, 0.05) 0%, transparent 60%);
  }

  /* Header */
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.25rem 2rem;
    border-bottom: 1px solid var(--card-border);
    background: rgba(10, 14, 23, 0.85);
    backdrop-filter: blur(12px);
    position: sticky;
    top: 0;
    z-index: 50;
  }
  .brand { display: flex; align-items: center; gap: 1rem; }
  .brand-badge {
    background: linear-gradient(135deg, #f43f5e, #8b5cf6);
    padding: 0.4rem 0.8rem;
    border-radius: 8px;
    font-weight: 800;
    letter-spacing: 1px;
    font-size: 0.85rem;
    box-shadow: 0 0 15px rgba(244, 63, 94, 0.4);
  }
  .brand h1 { font-size: 1.25rem; font-weight: 700; color: #fff; }
  .brand p { font-size: 0.8rem; color: var(--text-muted); }

  .status-cluster { display: flex; gap: 1.5rem; align-items: center; }
  .status-pill {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    background: rgba(16, 185, 129, 0.1);
    border: 1px solid rgba(16, 185, 129, 0.3);
    padding: 0.35rem 0.9rem;
    border-radius: 9999px;
    font-size: 0.8rem;
    color: var(--accent-green);
    font-weight: 600;
  }
  .pulse-dot {
    width: 8px; height: 8px; border-radius: 50%; background: var(--accent-green);
    box-shadow: 0 0 8px var(--accent-green);
    animation: pulse 1.5s infinite;
  }
  @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.85); } }

  /* Grid Layout */
  .grid-container {
    display: grid;
    grid-template-columns: 340px 1fr 380px;
    gap: 1.25rem;
    padding: 1.5rem 2rem;
    max-width: 1800px;
    margin: 0 auto;
  }

  /* Card Component */
  .card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 14px;
    padding: 1.25rem;
    backdrop-filter: blur(10px);
    display: flex;
    flex-direction: column;
    gap: 1rem;
    box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
    position: relative;
    overflow: hidden;
  }
  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent);
    opacity: 0.4;
  }
  .card-title {
    font-size: 0.95rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    color: var(--accent-cyan);
  }

  /* Node Graph Visualization */
  .topology-canvas-container {
    position: relative;
    height: 380px;
    border: 1px solid rgba(255, 255, 255, 0.05);
    border-radius: 10px;
    background: radial-gradient(circle at center, #111827 0%, #070a10 100%);
    overflow: hidden;
  }
  canvas#topologyCanvas { width: 100%; height: 100%; display: block; }

  /* Control Buttons */
  .btn-attack {
    background: linear-gradient(135deg, rgba(244, 63, 94, 0.2), rgba(244, 63, 94, 0.05));
    border: 1px solid var(--accent-red);
    color: #ff8597;
    padding: 0.75rem 1rem;
    border-radius: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    cursor: pointer;
    font-weight: 600;
    transition: all 0.2s ease;
    display: flex;
    align-items: center;
    justify-content: space-between;
    text-align: left;
  }
  .btn-attack:hover {
    background: var(--accent-red);
    color: #fff;
    box-shadow: 0 0 15px rgba(244, 63, 94, 0.5);
    transform: translateY(-2px);
  }
  .btn-attack span.sub { font-size: 0.7rem; opacity: 0.75; display: block; }

  /* Terminal Preview */
  .terminal-box {
    background: #05070c;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 8px;
    padding: 0.85rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: #38bdf8;
    height: 260px;
    overflow-y: auto;
    white-space: pre-wrap;
    line-height: 1.45;
  }

  /* Live Stream Feeds */
  .feed-list {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
    max-height: 480px;
    overflow-y: auto;
  }
  .feed-item {
    background: rgba(255, 255, 255, 0.02);
    border-left: 3px solid var(--accent-cyan);
    padding: 0.65rem 0.85rem;
    border-radius: 4px;
    font-size: 0.82rem;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    transition: background 0.2s;
  }
  .feed-item.pass { border-left-color: var(--accent-green); }
  .feed-item.retry { border-left-color: var(--accent-amber); }
  .feed-item.recon { border-left-color: #3b82f6; }
  .feed-item:hover { background: rgba(255, 255, 255, 0.05); }
  .feed-meta { display: flex; justify-content: space-between; font-size: 0.72rem; color: var(--text-muted); }
  .badge {
    padding: 0.15rem 0.45rem; border-radius: 4px; font-weight: 700; font-size: 0.7rem; text-transform: uppercase;
  }
  .badge-green { background: rgba(16, 185, 129, 0.2); color: var(--accent-green); }
  .badge-amber { background: rgba(245, 158, 11, 0.2); color: var(--accent-amber); }
  .badge-red { background: rgba(244, 63, 94, 0.2); color: var(--accent-red); }
  .badge-blue { background: rgba(59, 130, 246, 0.2); color: #60a5fa; }

  /* Database Table Preview */
  .db-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.78rem;
    font-family: 'JetBrains Mono', monospace;
  }
  .db-table th {
    text-align: left;
    padding: 0.5rem;
    border-bottom: 1px solid var(--card-border);
    color: var(--accent-cyan);
    font-weight: 600;
  }
  .db-table td {
    padding: 0.5rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    color: #cbd5e1;
  }
  .db-table tr:hover { background: rgba(56, 189, 248, 0.04); }

  /* Metrics Bar */
  .metric-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.8rem; }
  .metric-box {
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 8px;
    padding: 0.75rem;
    text-align: center;
  }
  .metric-box .val { font-size: 1.5rem; font-weight: 800; color: #fff; font-family: 'JetBrains Mono', monospace; }
  .metric-box .lbl { font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.2rem; }

  /* Scrollbars */
  ::-webkit-scrollbar { width: 5px; height: 5px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.15); border-radius: 4px; }
</style>
</head>
<body>

<header>
  <div class="brand">
    <div class="brand-badge">FCGD-AH</div>
    <div>
      <h1>Adaptive Honeypot Visual Operations Console</h1>
      <p>Closed-Loop Generative Deception Architecture Simulation</p>
    </div>
  </div>
  <div class="status-cluster">
    <div class="status-pill" style="border-color: rgba(16, 185, 129, 0.4); color: #10b981; background: rgba(16, 185, 129, 0.08);">
      <div class="pulse-dot" style="background: #10b981; box-shadow: 0 0 8px #10b981;"></div>
      Original Node: 2200 (Protected)
    </div>
    <div class="status-pill">
      <div class="pulse-dot"></div>
      Honeypot Trap: 2222 (Deceptive)
    </div>
    <div class="status-pill" style="border-color: rgba(6, 182, 212, 0.3); color: var(--accent-cyan); background: rgba(6, 182, 212, 0.08);">
      Target Node: prod-server-01
    </div>
  </div>
</header>

<main class="grid-container">

  <!-- LEFT: ATTACK SIMULATOR CONTROLS & DATABASE VIEWER -->
  <div style="display: flex; flex-direction: column; gap: 1.25rem;">
    
    <div class="card">
      <div class="card-title">
        <span style="display: flex; align-items: center; gap: 0.5rem;">
          <span class="pulse-dot" style="background:#f43f5e; box-shadow: 0 0 10px #f43f5e;"></span>
          <span>Live Attacker Monitoring</span>
        </span>
        <span class="badge badge-red" id="attackerThreatBadge">LIVE SESSION</span>
      </div>
      <p style="font-size: 0.78rem; color: var(--text-muted);">
        Real-time telemetry and reconnaissance feed from remote attacker shell.
      </p>

      <div style="background: rgba(0,0,0,0.35); border: 1px solid rgba(244,63,94,0.3); border-radius: 8px; padding: 0.85rem; font-family: 'JetBrains Mono', monospace; font-size: 0.76rem; display: flex; flex-direction: column; gap: 0.5rem;">
        <div style="display: flex; justify-content: space-between;">
          <span style="color: var(--text-muted);">Attacker IP:</span>
          <span style="color: #f43f5e; font-weight: 700;" id="attackerIp">10.186.112.16</span>
        </div>
        <div style="display: flex; justify-content: space-between;">
          <span style="color: var(--text-muted);">Authenticated:</span>
          <span style="color: #fff; font-weight: 600;" id="attackerUser">attacker (uid=1002)</span>
        </div>
        <div style="display: flex; justify-content: space-between;">
          <span style="color: var(--text-muted);">Session ID:</span>
          <span style="color: var(--accent-cyan); word-break: break-all;" id="attackerSession">sess_active_ssh</span>
        </div>
        <div style="display: flex; justify-content: space-between;">
          <span style="color: var(--text-muted);">SSH Client:</span>
          <span style="color: #cbd5e1;">OpenSSH_Windows / 2.0</span>
        </div>
        <div style="display: flex; justify-content: space-between;">
          <span style="color: var(--text-muted);">Last Command:</span>
          <span style="color: #38bdf8; font-weight: 700; word-break: break-all;" id="attackerLastCmd">Waiting for input...</span>
        </div>
        <div style="display: flex; justify-content: space-between;">
          <span style="color: var(--text-muted);">Observed Intent:</span>
          <span style="color: var(--accent-amber); font-weight: 700;" id="attackerIntent">Credential Hunting</span>
        </div>
        <div style="display: flex; justify-content: space-between;">
          <span style="color: var(--text-muted);">MITRE ATT&CK:</span>
          <span style="color: #a78bfa; font-weight: 600;" id="attackerMitre">T1552 (Unsecured Creds)</span>
        </div>
      </div>

      <div style="font-size: 0.72rem; color: var(--text-muted); line-height: 1.4; background: rgba(16,185,129,0.06); border: 1px solid rgba(16,185,129,0.2); padding: 0.6rem; border-radius: 6px;">
        <strong style="color: #10b981;">🛡️ Isolation Status:</strong> Adversary is fully confined inside virtual filesystem. Zero host exposure.
      </div>
    </div>

    <!-- ATTACKER EXPLOITATION ARSENAL & VECTORS TRACKER -->
    <div class="card">
      <div class="card-title">
        <span>🎯 Target Honeytoken Matrix</span>
        <span class="badge badge-cyan" id="matrixCoverage">0 / 6 BREACHED</span>
      </div>
      <p style="font-size: 0.75rem; color: var(--text-muted);">
        Tracks which high-value assets Laptop 2 has compromised vs. untouched bait.
      </p>

      <div style="display: flex; flex-direction: column; gap: 0.45rem; font-family: 'JetBrains Mono', monospace; font-size: 0.74rem;" id="vectorTrackerList">
        <div class="vector-item" id="vec_aws" style="display:flex; justify-content:space-between; align-items:center; background:rgba(255,255,255,0.02); padding:0.4rem 0.6rem; border-radius:4px; border-left:3px solid #64748b;">
          <span>☁️ AWS Cloud Keys</span>
          <span class="badge" style="background:rgba(255,255,255,0.06); color:#94a3b8;">SAFE</span>
        </div>
        <div class="vector-item" id="vec_env" style="display:flex; justify-content:space-between; align-items:center; background:rgba(255,255,255,0.02); padding:0.4rem 0.6rem; border-radius:4px; border-left:3px solid #64748b;">
          <span>⚙️ App .env Secrets</span>
          <span class="badge" style="background:rgba(255,255,255,0.06); color:#94a3b8;">SAFE</span>
        </div>
        <div class="vector-item" id="vec_ssh" style="display:flex; justify-content:space-between; align-items:center; background:rgba(255,255,255,0.02); padding:0.4rem 0.6rem; border-radius:4px; border-left:3px solid #64748b;">
          <span>🔐 SSH Private RSA Key</span>
          <span class="badge" style="background:rgba(255,255,255,0.06); color:#94a3b8;">SAFE</span>
        </div>
        <div class="vector-item" id="vec_db" style="display:flex; justify-content:space-between; align-items:center; background:rgba(255,255,255,0.02); padding:0.4rem 0.6rem; border-radius:4px; border-left:3px solid #64748b;">
          <span>🗄️ Database db.conf</span>
          <span class="badge" style="background:rgba(255,255,255,0.06); color:#94a3b8;">SAFE</span>
        </div>
        <div class="vector-item" id="vec_dir" style="display:flex; justify-content:space-between; align-items:center; background:rgba(255,255,255,0.02); padding:0.4rem 0.6rem; border-radius:4px; border-left:3px solid #64748b;">
          <span>📁 Backup Decoy Dirs</span>
          <span class="badge" style="background:rgba(255,255,255,0.06); color:#94a3b8;">SAFE</span>
        </div>
        <div class="vector-item" id="vec_c2" style="display:flex; justify-content:space-between; align-items:center; background:rgba(255,255,255,0.02); padding:0.4rem 0.6rem; border-radius:4px; border-left:3px solid #64748b;">
          <span>🌐 Malware C2 Beacon</span>
          <span class="badge" style="background:rgba(255,255,255,0.06); color:#94a3b8;">SAFE</span>
        </div>
      </div>
    </div>

    <!-- ORIGINAL PRODUCTION ASSETS (PROFESSOR COMPARISON CARD) -->
    <div class="card" style="border: 1px solid rgba(16, 185, 129, 0.3); background: rgba(16, 185, 129, 0.02);">
      <div class="card-title">
        <span style="color: #10b981;">🏛️ Original Enterprise Node (Port 2200)</span>
        <span class="badge" style="background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.4);">AUTHENTIC</span>
      </div>
      <p style="font-size: 0.74rem; color: var(--text-muted); margin-bottom: 0.6rem;">
        Genuine corporate infrastructure holding the authentic database, real secrets, and strict authentication.
      </p>

      <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; display: flex; flex-direction: column; gap: 0.45rem;">
        <div style="background: rgba(0,0,0,0.3); padding: 0.45rem 0.6rem; border-radius: 4px; border-left: 3px solid #10b981;">
          <div style="color: #94a3b8; font-size: 0.68rem;">AUTHENTIC DATABASE:</div>
          <div style="color: #e2e8f0; font-weight: 600;">PostgreSQL 15 / SQLite (democorp_production.db)</div>
          <div style="color: #64748b; font-size: 0.68rem;">Tables: corporate_users, customer_accounts, service_credentials</div>
        </div>

        <div style="background: rgba(0,0,0,0.3); padding: 0.45rem 0.6rem; border-radius: 4px; border-left: 3px solid #10b981;">
          <div style="color: #94a3b8; font-size: 0.68rem;">PRODUCTION SECRETS:</div>
          <div style="color: #e2e8f0; font-weight: 600;">original_secrets/prod.env, aws_credentials</div>
          <div style="color: #64748b; font-size: 0.68rem;">Master RSA: company_master_rsa (2048-bit)</div>
        </div>

        <div style="background: rgba(0,0,0,0.3); padding: 0.45rem 0.6rem; border-radius: 4px; border-left: 3px solid #10b981;">
          <div style="color: #94a3b8; font-size: 0.68rem;">AUTHENTICATION GATEWAY:</div>
          <div style="color: #10b981; font-weight: 600;">ssh admin@&lt;HOST_IP&gt; -p 2200</div>
          <div style="color: #94a3b8; font-size: 0.68rem;">Pass: DemoCorp2026!Secure (Rejects intruders)</div>
        </div>
      </div>
    </div>

  </div>

  <!-- CENTER: 2D ATTACK TOPOLOGY GRAPH & REAL-TIME GENERATOR TRACE -->
  <div style="display: flex; flex-direction: column; gap: 1.25rem;">
    
    <!-- TOPOLOGY CANVAS -->
    <div class="card">
      <div class="card-title">
        <span>🌐 Real-Time Infiltration & Deception Topology Graph</span>
        <span style="font-size: 0.75rem; color: var(--accent-green);">Animated Data Flows</span>
      </div>
      <div class="topology-canvas-container">
        <canvas id="topologyCanvas"></canvas>
      </div>
      <div class="metric-row">
        <div class="metric-box">
          <div class="val" id="totalInterceptions">0</div>
          <div class="lbl">Honeytoken Traps</div>
        </div>
        <div class="metric-box">
          <div class="val" id="avgLatency">0.42 ms</div>
          <div class="lbl">Avg Synthesis Speed</div>
        </div>
        <div class="metric-box">
          <div class="val" id="passRate">100%</div>
          <div class="lbl">Validator Pass Rate</div>
        </div>
      </div>
    </div>

    <!-- TERMINAL INSPECTION PANEL -->
    <div class="card">
      <div class="card-title">
        <span>💻 Deception Engine Artifact Live Inspector</span>
        <span id="activeArtifactPath" style="font-size: 0.75rem; color: var(--accent-amber); font-family: 'JetBrains Mono';">Waiting for trigger...</span>
      </div>
      <div class="terminal-box" id="artifactTerminal">
# Select an attack from the left panel to watch the closed-loop generator
# synthesize and validate an artifact in sub-millisecond response time...
      </div>
    </div>

  </div>

  <!-- RIGHT: VALIDATOR FEEDBACK STREAM & RECENT INCIDENTS -->
  <div style="display: flex; flex-direction: column; gap: 1.25rem;">
    
    <div class="card" style="flex: 1;">
      <div class="card-title">
        <span>🛡️ Validator Feedback & Retry Stream</span>
        <span class="badge badge-amber">4-Rule Check</span>
      </div>
      <p style="font-size: 0.75rem; color: var(--text-muted);">
        Closed-loop discriminator validating syntax, regex, entropy, and consistency before deploying.
      </p>

      <div class="feed-list" id="eventFeed">
        <!-- Live events injected here -->
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        <span>📊 Architecture Verification</span>
      </div>
      <div style="font-size: 0.8rem; line-height: 1.6; color: var(--text-muted);">
        <div><strong style="color: #fff;">1. Attacker Action:</strong> Intercepted via SSH shell</div>
        <div><strong style="color: #fff;">2. Policy Engine:</strong> Classifies command -> ArtifactCategory</div>
        <div><strong style="color: #fff;">3. Generator:</strong> Fills template with session facts</div>
        <div><strong style="color: #fff;">4. Validator:</strong> 4 independent checks (Retry if failed)</div>
        <div><strong style="color: #fff;">5. VFS Deploy:</strong> Injects into fake filesystem instantly</div>
      </div>
    </div>

  </div>

</main>

<script>
// Canvas Topology Visualization
const canvas = document.getElementById('topologyCanvas');
const ctx = canvas.getContext('2d');
let width, height;

function resizeCanvas() {
  width = canvas.parentElement.clientWidth;
  height = canvas.parentElement.clientHeight;
  canvas.width = width;
  canvas.height = height;
}
window.addEventListener('resize', resizeCanvas);
resizeCanvas();

const nodes = [
  { id: 'attacker', name: 'Attacker Machine', sub: '127.0.0.1 (Exploit Shell)', x: 0.15, y: 0.5, color: '#f43f5e', icon: '💀' },
  { id: 'honeypot', name: 'Honeypot SSH Server', sub: 'Port 2222 (VFS Shell)', x: 0.45, y: 0.28, color: '#06b6d4', icon: '🛡️' },
  { id: 'database', name: 'Decoy PostgreSQL', sub: '10.20.34.110 (Fake DB)', x: 0.45, y: 0.75, color: '#10b981', icon: '🗄️' },
  { id: 'engine', name: 'FCGD-AH Engine', sub: 'Templates & Feedback Loop', x: 0.82, y: 0.5, color: '#8b5cf6', icon: '⚡' }
];

let particles = [];
function spawnParticle(fromNode, toNode, color = '#f43f5e') {
  particles.push({
    from: fromNode,
    to: toNode,
    progress: 0,
    speed: 0.02 + Math.random() * 0.015,
    color: color
  });
}

function drawTopology() {
  ctx.clearRect(0, 0, width, height);

  // Draw Links
  const links = [
    { from: 0, to: 1, label: 'SSH Infiltration' },
    { from: 1, to: 2, label: 'Virtual DB Query' },
    { from: 1, to: 3, label: 'Honeytoken Trigger' },
    { from: 3, to: 1, label: 'Validated Decoy Injection' }
  ];

  links.forEach(link => {
    const n1 = nodes[link.from];
    const n2 = nodes[link.to];
    const x1 = n1.x * width;
    const y1 = n1.y * height;
    const x2 = n2.x * width;
    const y2 = n2.y * height;

    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.lineTo(x2, y2);
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
    ctx.lineWidth = 2;
    ctx.setLineDash([4, 4]);
    ctx.stroke();
    ctx.setLineDash([]);
  });

  // Update & Draw Particles
  for (let i = particles.length - 1; i >= 0; i--) {
    let p = particles[i];
    p.progress += p.speed;
    const n1 = nodes[p.from];
    const n2 = nodes[p.to];
    const x = (n1.x + (n2.x - n1.x) * p.progress) * width;
    const y = (n1.y + (n2.y - n1.y) * p.progress) * height;

    ctx.beginPath();
    ctx.arc(x, y, 4, 0, Math.PI * 2);
    ctx.fillStyle = p.color;
    ctx.shadowColor = p.color;
    ctx.shadowBlur = 10;
    ctx.fill();
    ctx.shadowBlur = 0;

    if (p.progress >= 1) particles.splice(i, 1);
  }

  // Draw Nodes
  nodes.forEach((n, idx) => {
    const x = n.x * width;
    const y = n.y * height;

    // Outer glow
    ctx.beginPath();
    ctx.arc(x, y, 26, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(16, 24, 39, 0.9)';
    ctx.strokeStyle = n.color;
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.fill();

    // Node icon
    ctx.font = '16px Outfit';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(n.icon, x, y);

    // Labels
    ctx.font = '600 12px Outfit';
    ctx.fillStyle = '#fff';
    ctx.fillText(n.name, x, y + 36);

    ctx.font = '10px JetBrains Mono';
    ctx.fillStyle = '#94a3b8';
    ctx.fillText(n.sub, x, y + 50);
  });

  requestAnimationFrame(drawTopology);
}
drawTopology();

// Remove ambient packet pulses so graph is 100% static when idle
let lastKnownEventCount = -1;

function animateAttackFlow() {
  // Attacker (0) -> Honeypot (1)
  spawnParticle(0, 1, '#f43f5e');
  // Honeypot (1) -> Deception Engine (3)
  setTimeout(() => spawnParticle(1, 3, '#8b5cf6'), 250);
  // Deception Engine (3) -> Honeypot (1) -> Attacker (0)
  setTimeout(() => spawnParticle(3, 1, '#10b981'), 550);
  setTimeout(() => spawnParticle(1, 0, '#06b6d4'), 850);
}

// Attack Trigger Function
async function triggerAttack(category, command) {
  animateAttackFlow();

  try {
    const res = await fetch('/api/simulate_attack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ category: category, command: command })
    });
    const data = await res.json();

    document.getElementById('activeArtifactPath').innerText = data.suggested_path || 'Synthetic Honeytoken';
    document.getElementById('artifactTerminal').innerText = data.artifact_preview || 'No content preview';

    refreshDashboard();
  } catch (err) {
    console.error('Simulation error:', err);
  }
}

// Polling Dashboard Data
async function refreshDashboard() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();

    // Trigger visual particles if a new attack event was received from the live Honeypot SSH!
    if (data.events) {
      if (lastKnownEventCount >= 0 && data.events.length > lastKnownEventCount) {
        animateAttackFlow();
        const latest = data.events[0];
        if (latest) {
          document.getElementById('activeArtifactPath').innerText = latest.suggested_path || 'Synthetic Honeytoken';
          document.getElementById('artifactTerminal').innerText = latest.artifact_preview || 'No content preview';
          
          // Dynamically extract remote attacker IP from command string e.g. [10.186.112.16]
          if (latest.attacker_cmd && latest.attacker_cmd.includes('[')) {
            const extractedIp = latest.attacker_cmd.substring(latest.attacker_cmd.indexOf('[') + 1, latest.attacker_cmd.indexOf(']'));
            if (extractedIp) document.getElementById('attackerIp').innerText = extractedIp;
            const cleanCmd = latest.attacker_cmd.substring(latest.attacker_cmd.indexOf(']') + 1).trim();
            document.getElementById('attackerLastCmd').innerText = cleanCmd || latest.attacker_cmd;
          } else {
            document.getElementById('attackerLastCmd').innerText = latest.attacker_cmd || 'Active';
          }
          if (latest.session_id) document.getElementById('attackerSession').innerText = latest.session_id;

          // Dynamically update observed intent and MITRE ATT&CK technique
          if (latest.category === 'aws_credentials') {
            document.getElementById('attackerIntent').innerText = 'Cloud Account Takeover';
            document.getElementById('attackerMitre').innerText = 'T1552.001 (Cloud Credentials)';
          } else if (latest.category === 'ssh_private_key') {
            document.getElementById('attackerIntent').innerText = 'Lateral Movement / Bastion Pivot';
            document.getElementById('attackerMitre').innerText = 'T1552.004 (Private Keys)';
          } else if (latest.category === 'app_config_file') {
            document.getElementById('attackerIntent').innerText = 'App Secrets Exfiltration';
            document.getElementById('attackerMitre').innerText = 'T1552 (Configuration Files)';
          } else if (latest.category === 'database_credentials') {
            document.getElementById('attackerIntent').innerText = 'Production DB Breach';
            document.getElementById('attackerMitre').innerText = 'T1005 (Data from Local System)';
          } else {
            document.getElementById('attackerIntent').innerText = 'Host & User Reconnaissance';
            document.getElementById('attackerMitre').innerText = 'T1082 / T1033 (Discovery)';
          }
        }
      }
      lastKnownEventCount = data.events.length;
    }

    // Update Counter Metrics
    document.getElementById('totalInterceptions').innerText = data.events.length;
    if (data.events.length > 0) {
      const avg = data.events.reduce((sum, e) => sum + e.latency_ms, 0) / data.events.length;
      document.getElementById('avgLatency').innerText = `${avg.toFixed(2)} ms`;
    }

    // Update Target Honeytoken Matrix
    if (data.events) {
      const breachedCats = new Set(data.events.filter(e => e.category !== 'reconnaissance').map(e => e.category));
      
      const updateRow = (id, catKey) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (breachedCats.has(catKey)) {
          el.style.borderLeftColor = '#f43f5e';
          el.style.background = 'rgba(244,63,94,0.08)';
          el.querySelector('.badge').className = 'badge badge-red';
          el.querySelector('.badge').innerText = 'BREACHED';
        }
      };

      updateRow('vec_aws', 'aws_credentials');
      updateRow('vec_env', 'app_config_file');
      updateRow('vec_ssh', 'ssh_private_key');
      updateRow('vec_db', 'database_credentials');
      updateRow('vec_dir', 'decoy_directory');
      updateRow('vec_c2', 'malware_c2_infrastructure');

      const count = Math.min(6, breachedCats.size);
      const covEl = document.getElementById('matrixCoverage');
      if (covEl) {
        covEl.innerText = `${count} / 6 BREACHED`;
        covEl.className = count > 0 ? 'badge badge-red' : 'badge badge-cyan';
      }
    }

    // Populate Feed List
    const feed = document.getElementById('eventFeed');
    feed.innerHTML = data.events.map(ev => {
      const isRecon = ev.category === 'reconnaissance';
      const isPass = ev.attempts === 1;
      const borderClass = isRecon ? 'recon' : (isPass ? 'pass' : 'retry');
      const badgeCls = isRecon ? 'badge-blue' : (isPass ? 'badge-green' : 'badge-amber');
      const catColor = isRecon ? '#94a3b8' : '#38bdf8';
      const badgeLabel = isRecon ? 'REAL SHELL' : `${ev.attempts} attempt(s)`;
      return `
        <div class="feed-item ${borderClass}">
          <div class="feed-meta">
            <span style="color:#fff; font-family:'JetBrains Mono';"><strong>${ev.attacker_cmd}</strong></span>
            <span>${ev.timestamp}</span>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:center; margin-top:3px;">
            <span style="font-family:'JetBrains Mono'; font-weight:600; color:${catColor};">${ev.category.toUpperCase()}</span>
            <div>
              <span class="badge ${badgeCls}">${badgeLabel}</span>
              <span style="font-size:0.7rem; color:#94a3b8; margin-left:4px;">${ev.latency_ms}ms</span>
            </div>
          </div>
          ${ev.issues && ev.issues.length ? `<div style="font-size:0.7rem; color:#f59e0b;">⚠️ Resolved: ${ev.issues.join(', ')}</div>` : ''}
        </div>
      `;
    }).join('');

  } catch (e) {
    console.error(e);
  }
}

// Initial pull & recurring refresh (1 second interval for instant response)
refreshDashboard();
setInterval(refreshDashboard, 1000);
</script>

</body>
</html>
"""

def run_server(port=8080):
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), SimulationAPIHandler)
    print(f"\n[+] Visual Simulation Server started successfully!")
    print(f"    URL: http://localhost:{port} (or http://127.0.0.1:{port})")
    print(f"    Press Ctrl+C to stop.\n")
    server.serve_forever()

if __name__ == "__main__":
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port)
