# FCGD-AH: Feedback-Controlled Generative Deception in Adaptive Honeypots

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Architecture: Pure--Python](https://img.shields.io/badge/architecture-pure--python%20%7C%20offline-success.svg)]()
[![Deception Latency](https://img.shields.io/badge/latency-%3C1.5ms-brightgreen.svg)]()

> **FCGD-AH** is an adaptive cyber-deception framework that integrates a high-interaction SSH honeypot with a closed-loop generative deception module. Instead of serving static, predictable decoy tokens or incurring the severe latency and hallucination risks of cloud LLMs, FCGD-AH dynamically synthesizes, validates, and deploys high-fidelity synthetic honeytokens with sub-millisecond response latency.

---

## 📑 Table of Contents

- [Key Highlights](#-key-highlights)
- [System Architecture](#-system-architecture)
- [Directory Structure](#-directory-structure)
- [Honeytoken Taxonomy](#-honeytoken-taxonomy)
- [Closed-Loop Validation Pipeline](#-closed-loop-validation-pipeline)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Running the System](#-running-the-system)
  - [1. Real-Time SOC Visual Dashboard](#1-real-time-soc-visual-dashboard)
  - [2. Honeypot Server](#2-honeypot-server)
  - [3. Attacker Terminal & Reconnaissance](#3-attacker-terminal--reconnaissance)
  - [4. Protected Original Server (Contrast Demo)](#4-protected-original-server-contrast-demo)
- [Testing & Verification](#-testing--verification)
- [Telemetry & Logs](#-telemetry--logs)
- [License](#-license)

---

## ⚡ Key Highlights

- **Sub-Millisecond Generative Latency**: Template state-machines yield honeytoken generation and validation in **$0.3\text{ ms} - 1.5\text{ ms}$**, eliminating terminal typing lag.
- **Closed-Loop Discriminator & Bounded Retries**: Multi-rule offline validator verifies structural regex, headers/footers, entropy, and provenance consistency with bounded temperature-fallback retry (`[0.9 -> 0.6 -> 0.3]`). Guaranteed **0% syntactic malformations** delivered to adversaries.
- **Zero Cloud / GPU Dependencies**: Completely air-gapped and self-contained; zero external API keys or heavy GPU runtimes required.
- **Dual-Surface Infrastructure**: Includes both a protected authentic enterprise server (Port `2200`) and the deceptive honeypot server (Port `2222`) to demonstrate defense-in-depth and contrast analysis.
- **Interactive SOC Telemetry Dashboard**: Built-in HTTP dashboard visualizing live network attack graphs, in-memory PostgreSQL tables, and deception engine pipelines in real-time.

---

## 🏛 System Architecture

```text
[ Attacker / Reconnaissance Scanner ]
                 │
                 ▼  (SSH Port 2222)
┌───────────────────────────────────────────────┐
│              Honeypot Server                  │
│   • Multi-session SSH Daemon (Paramiko)       │
│   • Virtual In-Memory File System (VFS)       │
│   • Real-Time Policy Classification Engine    │
└───────────────────────┬───────────────────────┘
                        │
            Benign? ────┴──── Exploit / Target Key?
            │                              │
            ▼                              ▼
 ┌──────────────────────┐   ┌──────────────────────────────────────────┐
 │ Standard VFS Shell   │   │         FCGD-AH Deception Engine         │
 │ (ls, pwd, whoami,    │   │  1. Dynamic Context-Aware Synthesis      │
 │  cat /etc/passwd)    │   │  2. 4-Tier Algorithmic Discriminator     │
 └──────────────────────┘   │  3. Adaptive Retry Loop (Self-Correcting)│
                            └──────────────────┬───────────────────────┘
                                               │ (Valid Honeytoken)
                                               ▼
                                    ┌──────────────────────┐
                                    │ Virtual File System  │
                                    │ Live Injection       │
                                    └──────────┬───────────┘
                                               │
                                               ▼
                             ┌───────────────────────────────────┐
                             │    SOC Operations Dashboard       │
                             │   (HTTP Real-Time Visualizer)     │
                             └───────────────────────────────────┘
```

---

## 📁 Directory Structure

```text
.
├── fcgd_ah/                        # FCGD-AH Core Generative Deception Package
│   ├── taxonomy.py                 # 7 Honeytoken taxonomy categories
│   ├── schemas.py                  # Telemetry dataclasses & session state
│   ├── config.py                   # Generation loop parameters & retry settings
│   ├── templates.py                # Deterministic synthetic generators
│   ├── generator.py                # Context-aware artifact generator
│   ├── validator.py                # 4-tier syntactic & semantic discriminator
│   ├── retry_loop.py               # Closed-loop validation retry controller
│   ├── deployer.py                 # Virtual filesystem & SFTP deployment adapter
│   ├── logger.py                   # Structured JSONL telemetry recorder
│   ├── demo.py                     # Single-session CLI demonstration
│   ├── batch_run.py                # Batch generation benchmark across categories
│   ├── analyze_log.py              # Statistical log analyzer & latency calculator
│   └── tests/                      # Automated test suite
│       └── test_validator.py       # Unit tests for discriminator validation rules
├── honeypot/                       # SSH Honeypot Server & Virtual Environment
│   ├── honeypot_server.py          # Paramiko SSH server entrypoint
│   ├── virtual_fs.py               # In-memory virtual Linux filesystem
│   ├── policy_engine.py            # Command classification (Benign vs Exploit)
│   ├── session_state.py            # Session state and credential tracker
│   ├── test_honeypot.py            # End-to-end honeypot integration test
│   └── requirements.txt
├── original_server/                # Genuine Enterprise Target (For Contrast Demo)
│   ├── server.py                   # Strict authenticated SSH bastion on Port 2200
│   ├── original_database.py        # Real enterprise relational database interface
│   ├── democorp_production.db      # SQLite production database
│   └── original_secrets/           # Authentic enterprise keys and secrets
├── visual_simulator.py             # Pure-Python SOC Visualizer Web Server
├── requirements.txt                # Unified project dependencies
├── ORIGINAL_VS_HONEYPOT_GUIDE.md   # Side-by-side presentation guide
└── PROJECT_REPORT_DOCUMENTATION.md # Academic thesis & system specifications
```

---

## 🎯 Honeytoken Taxonomy

The deception engine categorizes attacker requests into 7 distinct honeytoken profiles:

| Category | Typical Injected Path | Synthesized Content Highlights |
| :--- | :--- | :--- |
| **`AWS_CREDENTIALS`** | `~/.aws/credentials` | Structurally valid `AKIA...` keys, high-entropy secret hashes, regions |
| **`SSH_PRIVATE_KEY`** | `~/.ssh/<host>_rsa` | Valid 2048-bit PEM RSA format headers and synthetic key body |
| **`APP_CONFIG_FILE`** | `/var/www/app/.env` | Database hostnames, JWT tokens, Redis ports matching session context |
| **`DATABASE_CREDENTIALS`**| `/etc/app/db.conf` | PostgreSQL/MySQL connection URIs, roles, passwords |
| **`DECOY_DIRECTORY`** | `/home/<user>/sensitive/`| Context-consistent filenames referencing discovered environment users |
| **`VULNERABLE_SERVICE_BANNER`** | `/etc/banner_<svc>.txt`| Authentic OpenSSH, Apache, vsftpd version banners |
| **`MALWARE_C2_INFRASTRUCTURE`** | `/tmp/.c2config` | Synthetic C2 callback endpoints, beacon frequencies, and payload seeds |

---

## 🔄 Closed-Loop Validation Pipeline

Every synthesized decoy token passes through 4 algorithmic checks before presentation:
1. **Structural Regex Verification**: Enforces pattern standards (e.g., AWS Key format `^AKIA[0-9A-Z]{16}$`).
2. **Header/Footer Completeness**: Validates block envelope formatting (e.g., `-----BEGIN RSA PRIVATE KEY-----`).
3. **Format Credibility & Shannon Entropy**: Ensures tokens contain high entropy and realistic noise.
4. **Provenance & Environment Consistency**: Enforces that usernames, hosts, and subnets mirror the active session environment facts.

If any check fails, the feedback loop triggers an adaptive retry with temperature scaling:
$$\tau \in \{0.9 \rightarrow 0.6 \rightarrow 0.3\}$$

---

## 🚀 Getting Started

### Prerequisites

- **Python**: Version `3.10` or higher (`3.10` - `3.14` supported)
- **Git**
- Optional: Modern web browser (Chrome, Firefox, Edge, Safari) for the visual dashboard.

### Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/<YOUR_USERNAME>/fcgd-ah.git
cd fcgd-ah

# (Optional but recommended) Create and activate a virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

---

## 💻 Running the System

### 1. Real-Time SOC Visual Dashboard
Launch the visual web operations dashboard:
```bash
python visual_simulator.py
```
Open your browser at **`http://localhost:8080`** to view real-time attack flows, virtual database viewers, and generative deception pipelines.

### 2. Honeypot Server
Start the deceptive SSH honeypot daemon:
```bash
python honeypot/honeypot_server.py
```
*Listens on port `2222` (or configured port) emulating an Ubuntu 22.04 LTS host.*

### 3. SSH Client Connection & Reconnaissance
Connect using any standard SSH client:
```bash
ssh attacker@127.0.0.1 -p 2222
# Password: any password accepted (e.g., password)
```
Try running reconnaissance commands:
```bash
whoami
pwd
cat ~/.aws/credentials
cat /var/www/app/.env
```

### 4. Protected Original Server (Contrast Demo)
To demonstrate the contrast between genuine assets and honeypot decoys:
```bash
python original_server/server.py
```
Connect via strict SSH:
```bash
ssh admin@127.0.0.1 -p 2200
# Password: DemoCorp2026!Secure
```
*Refer to [ORIGINAL_VS_HONEYPOT_GUIDE.md](ORIGINAL_VS_HONEYPOT_GUIDE.md) for full demo talking points.*

---

## 🧪 Testing & Verification

Run the comprehensive pytest suite to verify discriminator rules and validation logic:

```bash
python -m pytest fcgd_ah/tests -v
```

Execute the automated end-to-end honeypot integration test:

```bash
python honeypot/test_honeypot.py
```

Run the multi-category batch generation benchmark:

```bash
python fcgd_ah/batch_run.py
python fcgd_ah/analyze_log.py
```

---

## 📊 Telemetry & Logs

All generation and validation attempts are logged into structured JSONL format (`attempt_log.jsonl`):
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

## 📜 License

This project is open-source software licensed under the [MIT License](LICENSE).
