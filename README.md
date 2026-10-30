<div align="center">

# 🛡️ FCGD-AH
### Feedback-Controlled Generative Deception in Adaptive Honeypots

*Next-Generation Active Cyber Defense Architecture with Deterministic Syntactic Validation & Sub-Millisecond Deception Synthesis*

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python Version" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License: MIT" /></a>
  <a href="#-closed-loop-validation-pipeline"><img src="https://img.shields.io/badge/Deception%20Latency-%3C%201.5%20ms-brightgreen?style=for-the-badge&logo=speedtest&logoColor=white" alt="Latency" /></a>
  <a href="#-system-architecture"><img src="https://img.shields.io/badge/Architecture-Closed--Loop%20Discriminator-blueviolet?style=for-the-badge" alt="Architecture" /></a>
  <a href="#-testing--verification"><img src="https://img.shields.io/badge/Tests-19%2F19%20Passing-success?style=for-the-badge&logo=pytest&logoColor=white" alt="Pytest" /></a>
</p>

[Key Features](#-key-features) •
[System Architecture](#-system-architecture) •
[Honeytoken Taxonomy](#-honeytoken-taxonomy) •
[Quick Start](#-quick-start) •
[SOC Dashboard](#-real-time-soc-visual-operations-dashboard) •
[Presentation Guide](#-enterprise-vs-honeypot-contrast) •
[Documentation](#-academic-thesis--documentation)

</div>

---

## 📌 Executive Summary

Traditional honeypots (e.g., standard low-interaction SSH daemons) rely on **static decoy files and fixed credentials**. Modern automated scanners, malware droppers, and human adversaries easily detect these static patterns through syntax discrepancies, entropy anomalies, or missing cryptographic headers—terminating reconnaissance before actionable threat intelligence is gathered.

Conversely, integrating **Cloud Large Language Models (LLMs)** introduces critical vulnerabilities:
1. **Unacceptable Latency**: 800 ms to 3,000 ms response times that immediately tip off attackers on interactive shells.
2. **Hallucination & Leaks**: Risk of leaking real host metadata or producing syntactically invalid credentials.
3. **Cloud Dependency**: Inability to run in air-gapped, isolated enclave environments.

**FCGD-AH (Feedback-Controlled Generative Deception in Adaptive Honeypots)** solves this paradigm. By coupling an interactive Paramiko-based SSH daemon with a **closed-loop syntactic generator-discriminator pair**, FCGD-AH dynamically synthesizes, validates, and deploys high-fidelity synthetic honeytokens with **deterministic sub-millisecond (< 1.5 ms) latency** and **0% syntactic failure**.

---

## ⚡ Key Features

- **⚡ Sub-Millisecond Synthesis Latency**: Template state-machines synthesize and validate complex decoy artifacts in **$0.3\text{ ms} - 1.5\text{ ms}$**, preserving genuine interactive command typing responsiveness.
- **🔄 Closed-Loop Discriminator with Self-Correcting Retry Loop**: Bounded 3-attempt feedback mechanism enforcing temperature-backoff scheduling ($\tau \in [0.9 \rightarrow 0.6 \rightarrow 0.3]$). If a syntactic or entropy anomaly is caught, the discriminator auto-corrects before deployment.
- **🛡️ 4-Tier Independent Algorithmic Discriminator**:
  - `Rule 1`: Structural Regex standard compliance (`AKIA...`, PEM boundaries, valid URI schemes).
  - `Rule 2`: Envelope integrity (RFC-compliant headers, footers, boundary markers).
  - `Rule 3`: Format credibility & Shannon entropy analysis (realistic high-entropy cryptographic strings).
  - `Rule 4`: Provenance and session environmental consistency (system users, network subnets, hostnames).
- **📴 100% Offline & Air-Gapped Autonomy**: Operates entirely with pure Python and local dependencies—zero external cloud APIs, zero GPU dependencies, and zero outbound network exposure.
- **📊 Real-Time SOC Visual Operations Console**: Built-in HTTP web dashboard serving interactive attack flow animations, dynamic in-memory database exploration, and deception telemetry feeds.
- **🏛️ Dual-Surface Architecture**: Includes both a protected enterprise server (Port `2200`) and the deceptive honeypot server (Port `2222`) to demonstrate defense-in-depth and live contrast analysis.

---

## 🏛 System Architecture

```text
                                  [ Adversary / Port Scanner ]
                                               │
                                               ▼  TCP Port 2222
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   FCGD-AH SSH HONEYPOT                                      │
│                                                                                             │
│   ┌────────────────────────┐      ┌─────────────────────────┐      ┌────────────────────┐   │
│   │  Paramiko SSH Daemon   │ ───► │  Virtual File System    │ ───► │   Policy Engine    │   │
│   │  (Ubuntu 22.04 Decoy)  │      │  (Stateful In-Memory)   │      │ (Command Classifier│   │
│   └────────────────────────┘      └─────────────────────────┘      └─────────┬──────────┘   │
└───────────────────────────────────────────────────┬──────────────────────────┼──────────────┘
                                                    │                          │
                        ┌───────────────────────────┘                          │
                        ▼ (Benign Command: ls, pwd, whoami)                    ▼ (Exploit / Key Harvest Attempt)
             ┌─────────────────────────┐                     ┌────────────────────────────────────────────────┐
             │ Standard VFS Execution  │                     │            FCGD-AH DECEPTION ENGINE            │
             │ Return File / Directory │                     │                                                │
             └─────────────────────────┘                     │  1. Context-Aware Synthesis Engine             │
                                                             │     • Target Host & Subnet Adaptation          │
                                                             │     • Role & Privilege Calibration             │
                                                             │                                                │
                                                             │  2. 4-Tier Algorithmic Discriminator           │
                                                             │     • Regex • Headers • Entropy • Provenance   │
                                                             │                                                │
                                                             │  3. Bounded Feedback Retry Loop                │
                                                             │     • Self-correction with temperature scaling │
                                                             └───────────────────────┬────────────────────────┘
                                                                                     │
                                                                                     ▼ (100% Validated Honeytoken)
                                                             ┌────────────────────────────────────────────────┐
                                                             │       Virtual Filesystem Dynamic Injection     │
                                                             │  (~/.aws/credentials, /var/www/.env, etc.)     │
                                                             └───────────────────────┬────────────────────────┘
                                                                                     │
                                                                                     ▼
                                                             ┌────────────────────────────────────────────────┐
                                                             │            SOC Operations Dashboard            │
                                                             │      (Live Attack Graphs & Telemetry)          │
                                                             └────────────────────────────────────────────────┘
```

---

## 🎯 Honeytoken Taxonomy

FCGD-AH dynamically recognizes attacker intent and synthesizes 7 distinct honeytoken profiles:

| # | Artifact Taxonomy Profile | Target File Path | Generated Artifact Characteristics |
| :-: | :--- | :--- | :--- |
| **1** | **`AWS_CREDENTIALS`** | `~/.aws/credentials` | Structurally valid `AKIA[0-9A-Z]{16}` access keys, high-entropy Base64 secret keys, multi-profile region configurations. |
| **2** | **`SSH_PRIVATE_KEY`** | `~/.ssh/<host>_rsa` | Strict 2048-bit OpenSSL PEM RSA boundaries (`BEGIN/END RSA PRIVATE KEY`), valid modulus padding, contextual file permissions (`0600`). |
| **3** | **`APP_CONFIG_FILE`** | `/var/www/app/.env` | Environment configs matching session context (`DB_HOST`, `REDIS_URL`, JWT signing secrets, high-entropy production tokens). |
| **4** | **`DATABASE_CREDENTIALS`** | `/etc/app/db.conf` | Multi-environment database configuration stanzas (PostgreSQL / MySQL) with ports, credentials, and connection pools. |
| **5** | **`DECOY_DIRECTORY`** | `/home/<user>/sensitive/` | Synthetic file hierarchies populated with decoy documentation, financial manifests, and internal audit logs reflecting real VFS usernames. |
| **6** | **`VULNERABLE_SERVICE_BANNER`**| `/etc/banner_<svc>.txt` | Authentic service identification banners (OpenSSH 8.2p1, Apache 2.4.41, vsftpd 3.0.3) designed to lure automated exploit frameworks. |
| **7** | **`MALWARE_C2_INFRASTRUCTURE`**| `/tmp/.c2config` | Adversary tracking beacons, decoy reverse-proxy domains, and synthetic command-and-control callback configurations. |

---

## 🔄 Closed-Loop Validation Pipeline

Every synthesized decoy artifact is evaluated before transmission:

```
[Attacker Request] ──► [Generator (τ=0.9)] ──► [Validator (4 Criteria)]
                             ▲                             │
                             │ FAIL                        │ PASS
                             └── [Adaptive Retry Loop] ◄───┴──► [Deploy to VFS]
                                  (Temp scaled to 0.6 -> 0.3)
```

1. **Structural Regex Test**: Verifies compliance with strict vendor syntax (e.g. AWS Key ID standards).
2. **Cryptographic Header Test**: Asserts start/end delimiter integrity and multiline envelope standards.
3. **Format Credibility & Entropy Check**: Computes Shannon entropy ($\approx 4.2 - 5.8\text{ bits/char}$) ensuring that tokens are not predictable low-entropy dummy strings.
4. **Provenance Consistency**: Enforces that internal IP addresses, ports, usernames, and hostnames match the active session facts.

---

## 🚀 Quick Start

### 1. Prerequisites

- **Python**: 3.10, 3.11, 3.12, or 3.14
- **Git**

### 2. Installation

```bash
# Clone the repository
git clone https://github.com/RamXCat/adaptive-honeypot.git
cd adaptive-honeypot

# Create and activate a virtual environment
python -m venv venv

# Windows:
venv\Scripts\activate
# Linux / macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Running the System

### Step 1: Launch the SOC Visual Operations Dashboard

Run the standalone HTTP visual operations dashboard:

```bash
python visual_simulator.py
```
* **URL:** Navigate to **`http://localhost:8080`** in your browser.
* **Features:** Live interactive attack graph, PostgreSQL virtual table inspector, real-time retry latency heatmaps, and telemetry feeds.

---

### Step 2: Start the Adaptive SSH Honeypot

Start the deceptive honeypot server in a separate terminal:

```bash
python honeypot/honeypot_server.py
```

* Listens on **`0.0.0.0:2222`** by default.
* Emulates an authentic **Ubuntu 22.04.3 LTS (Jammy Jellyfish)** environment.

---

### Step 3: Connect via Standard SSH Client

Simulate an intruder session using your preferred OpenSSH terminal:

```bash
ssh attacker@127.0.0.1 -p 2222
```
*Any password is accepted by default to trap the attacker.*

#### Try Reconnaissance & Honeytoken Exploitation Commands:

```bash
# 1. Benign reconnaissance (VFS response)
whoami
pwd
uname -a
ls -la /etc/

# 2. AWS Credential Hunt (Triggers sub-millisecond FCGD-AH generation)
cat ~/.aws/credentials

# 3. Application Secret Harvesting
cat /var/www/app/.env

# 4. Keyword Searching across files
grep -r "password" /var/www/
```

Watch the **Honeypot Terminal** and the **SOC Visual Dashboard** display the sub-millisecond generation and validation sequence in real time!

---

## 🏛 Enterprise vs Honeypot Contrast

To demonstrate active cyber defense in action (e.g. for academic juries, presentations, or executive briefings), this repository includes both the protected corporate bastion and the decoy honeypot:

| Metric | 🏛️ Genuine Enterprise Server | 🪤 Adaptive Honeypot Server |
| :--- | :--- | :--- |
| **Port** | **Port `2200`** | **Port `2222`** |
| **Role** | Core Bastion (`prod-corp-bastion-01`) | Deceptive Trap (`prod-server-01`) |
| **Authentication** | Strict enterprise credentials | Open / Permissive (Session Tracker) |
| **Database** | Authentic Relational DB (`democorp_production.db`) | Virtual in-memory table views |
| **Secrets** | Protected corporate assets | Dynamically synthesized Honeytokens |

To run the genuine enterprise server:
```bash
python original_server/server.py
```
Connect via SSH:
```bash
ssh admin@127.0.0.1 -p 2200
# Password: DemoCorp2026!Secure
```
*For detailed presentation talking points and live demonstration commands, see [ORIGINAL_VS_HONEYPOT_GUIDE.md](ORIGINAL_VS_HONEYPOT_GUIDE.md).*

---

## 🧪 Testing & Verification

The framework includes a comprehensive adversarial test suite to validate the discriminator against malformed tokens:

```bash
# Run the 19-test validator adversarial test suite
python -m pytest fcgd_ah/tests -v
```

Execute the automated end-to-end integration test:

```bash
python honeypot/test_honeypot.py
```

Run batch generation benchmarks across all 7 taxonomies:

```bash
python fcgd_ah/batch_run.py
python fcgd_ah/analyze_log.py
```

---

## 📊 Telemetry & Structured Logging

Telemetry is recorded into structured JSON Lines (`attempt_log.jsonl`):

```json
{
  "timestamp": "2026-10-30T16:38:45.102Z",
  "session_id": "sess_1793358544_61793",
  "category": "aws_credentials",
  "attempt_index": 1,
  "status": "PASS",
  "latency_ms": 1.28,
  "validation_details": {
    "regex_check": true,
    "header_check": true,
    "entropy_check": true,
    "provenance_check": true
  }
}
```

---

## 📁 Repository Structure

```text
adaptive-honeypot/
│
├── fcgd_ah/                         # Core FCGD-AH Generative Deception Engine
│   ├── taxonomy.py                  # 7 Honeytoken taxonomy category definitions
│   ├── schemas.py                   # SessionState, EnvironmentFacts, and telemetry schemas
│   ├── config.py                    # Retry limits, temperature scheduling & paths
│   ├── templates.py                 # Deterministic synthetic generators
│   ├── generator.py                 # Context-aware artifact generation
│   ├── validator.py                 # 4-tier algorithmic syntactic discriminator
│   ├── retry_loop.py                # Feedback retry loop orchestrator
│   ├── deployer.py                  # Virtual filesystem injection adapter
│   ├── logger.py                    # Structured JSONL telemetry recorder
│   ├── demo.py                      # Single-session CLI demonstration
│   ├── batch_run.py                 # Multi-category benchmark runner
│   ├── analyze_log.py               # Latency and telemetry log analyzer
│   └── tests/                       # Adversarial test suite
│       └── test_validator.py        # 19 comprehensive discriminator test cases
│
├── honeypot/                        # Interactive SSH Honeypot
│   ├── honeypot_server.py           # Paramiko SSH server entrypoint
│   ├── virtual_fs.py                # In-memory virtual Linux filesystem
│   ├── policy_engine.py             # Benign vs exploit command classifier
│   ├── session_state.py             # Real-time session and credential tracker
│   ├── test_honeypot.py             # End-to-end honeypot integration test
│   └── requirements.txt
│
├── original_server/                 # Enterprise Server (Contrast Baseline)
│   ├── server.py                    # Authenticated SSH server on Port 2200
│   ├── original_database.py         # Relational database interface & query engine
│   ├── democorp_production.db       # Production SQLite database
│   └── original_secrets/            # Protected mock enterprise secrets
│
├── visual_simulator.py              # Real-Time SOC Visual Dashboard Server
├── requirements.txt                 # Unified project dependencies
├── ORIGINAL_VS_HONEYPOT_GUIDE.md    # Dual-server demonstration guide
├── PROJECT_REPORT_DOCUMENTATION.md  # Comprehensive academic project report
└── LICENSE                          # MIT License
```

---

## 📚 Academic Thesis & Documentation

Comprehensive documentation, literature review, and mathematical foundations are available in:
* **[PROJECT_REPORT_DOCUMENTATION.md](PROJECT_REPORT_DOCUMENTATION.md)**: Full academic project report with problem domain analysis, literature review, functional requirements, and architecture specifications.
* **[ORIGINAL_VS_HONEYPOT_GUIDE.md](ORIGINAL_VS_HONEYPOT_GUIDE.md)**: Step-by-step walkthrough script for presenting to professors, evaluators, and security teams.

---

## 📜 License

This project is licensed under the terms of the [MIT License](LICENSE).
