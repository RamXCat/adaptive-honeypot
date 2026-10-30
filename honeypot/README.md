# FCGD-AH Interactive SSH Honeypot Server

**Adaptive High-Interaction SSH Honeypot with Sub-Millisecond Generative Deception**

---

## Overview

The Honeypot server acts as the target system (Computer 2) in the FCGD-AH architecture. It listens for incoming SSH connections, accepts attacker logins, tracks reconnaissance commands, and dynamically generates credible synthetic honeytokens in real-time when the attacker attempts credential exfiltration.

### Core Features
- **Paramiko-Powered SSH Service**: Listens on port `2222` and handles both automated tool execution (`exec_command`) and interactive PTY shells.
- **Dynamic Policy Engine**: Categorizes commands into `ACTION_REAL` (benign system discovery) and `ACTION_FAKE` (honeytoken triggers).
- **Sub-Millisecond Feedback Loop**: Automatically triggers `fcgd_ah.retry_loop.run()` to validate and refine artifacts before returning them to the attacker.
- **In-Memory Virtual Linux Filesystem**: Simulates Ubuntu 22.04 LTS directory structures and caches generated honeytokens so subsequent read commands return consistent artifacts.
- **Simultaneous Visual Monitoring**: Displays real-time detection, policy decisions, and validation telemetry directly on the honeypot operator's terminal.

---

## Directory Structure

```text
honeypot/
├── __init__.py           # Package marker
├── config.py             # Port, host, credentials, host key location
├── session_state.py      # Telemetry tracking and FCGD-AH state adaptation
├── policy_engine.py      # Command classification (ACTION_REAL vs ACTION_FAKE)
├── virtual_fs.py         # Virtual Linux filesystem and shell execution engine
├── ssh_server.py         # Paramiko ServerInterface implementation
├── honeypot_server.py    # Main server daemon and live monitoring display
├── requirements.txt      # Dependencies (paramiko, colorama)
└── README.md             # Documentation
```

---

## Supported Attacker Triggers

| Attacker Command Example | Policy Decision | Generated Deception Category |
|---|---|---|
| `whoami`, `pwd`, `ls -la` | `ACTION_REAL` | Benign virtual Linux responses |
| `cat ~/.aws/credentials` | `ACTION_FAKE` | `ArtifactCategory.AWS_CREDENTIALS` |
| `cat .env` or `cat /var/www/app/.env` | `ACTION_FAKE` | `ArtifactCategory.APP_CONFIG_FILE` |
| `grep password /var/www/*` | `ACTION_FAKE` | `ArtifactCategory.APP_CONFIG_FILE` / `DATABASE_CREDENTIALS` |
| `cat /etc/app/db.conf` | `ACTION_FAKE` | `ArtifactCategory.DATABASE_CREDENTIALS` |
| `find / -name "*.pem"` or `id_rsa` | `ACTION_FAKE` | `ArtifactCategory.SSH_PRIVATE_KEY` |
| `ls /home/deploy/sensitive/` | `ACTION_FAKE` | `ArtifactCategory.DECOY_DIRECTORY` |
| `cat /tmp/.c2config` | `ACTION_FAKE` | `ArtifactCategory.MALWARE_C2_INFRASTRUCTURE` |

---

## How to Run the Honeypot

### 1. Start the Honeypot Server

From the project root:

```bash
python -m honeypot.honeypot_server
```

Options:
- `--host 0.0.0.0`: Interface to bind (default: `0.0.0.0`)
- `--port 2222`: Port to listen on (default: `2222`)

### 2. Connect from the Attacker Console

From another terminal (or another computer):

```bash
python attacker/attacker_console.py
```

Defaults when prompted:
- Target IP: `127.0.0.1` (or honeypot LAN IP)
- Port: `2222`
- Username: `attacker`
- Password: `password`

### 3. Connect via Standard SSH

You can also connect using any standard SSH client:

```bash
ssh attacker@127.0.0.1 -p 2222
```
(Password: `password`)
