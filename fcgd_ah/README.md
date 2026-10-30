# FCGD-AH: Generative Deception Module

**Fast Context-Aware Generative Deception for Adaptive Honeypots (FCGD-AH)**  
*Mode: Fully Offline | Template-Based | Deterministic Feedback Loop | Instant Response*

---

## Overview

The FCGD-AH Deception Module generates dynamic, highly credible honeytokens and deception artifacts tailored to attacker session telemetry without requiring external network calls or heavyweight LLMs.

### Key Capabilities
- **Sub-millisecond Latency**: Pure Python template and regex generation engine yielding attempt latencies of **< 0.5 ms** (well under 100 ms).
- **Multi-Attempt Feedback Loop**: Bounded retry loop (max 3 attempts) that dynamically adjusts the artifact template variant and repairs detected flaws based on validation feedback.
- **Strict 4-Tier Validation**: Independent verification for referential consistency, provenance consistency, format credibility, and non-functionality (synthetic-only credentials).
- **Deliberate Canary Failure for Live Demos**: Built-in demonstration modes (`APP_CONFIG_FILE` and `DECOY_DIRECTORY`) that intentionally fail Attempt 1 to showcase the corrective feedback mechanism before succeeding on Attempt 2.
- **Air-Gapped & Offline Ready**: Operates completely offline with zero model downloads or API token requirements.

---

## Directory Structure

```text
fcgd_ah/
│
├── __init__.py               # Package marker
├── taxonomy.py               # ArtifactCategory enum (7 categories)
├── schemas.py                # Dataclasses: SessionState, EnvironmentFacts, ValidationIssue, etc.
├── config.py                 # Loop config (MAX_ATTEMPTS=3, temperature schedule, log paths)
├── templates.py              # Template generators & synthetic value generators
├── generator.py              # Context-aware artifact generator with feedback branching
├── validator.py              # 4 independent rule-based checks (regex & string matching)
├── retry_loop.py             # Orchestrates generation → validation → feedback retry loop
├── logger.py                 # Structured JSONL logging to attempt_log.jsonl
├── deployer.py               # SFTP deployment helper (Paramiko) with env-var credential isolation
│
├── demo.py                   # Single end-to-end attacker session simulation
├── batch_run.py              # Multi-session simulation across all 7 categories
├── analyze_log.py            # Reads attempt_log.jsonl and displays performance analytics
│
├── tests/
│   └── test_validator.py     # Comprehensive adversarial pytest suite
│
├── attempt_log.jsonl         # Auto-generated attempt telemetry
├── requirements.txt          # Paramiko (for SFTP deployment)
└── README.md                 # Project documentation
```

---

## Taxonomy (7 Artifact Categories)

1. `aws_credentials` (`~/.aws/credentials`): Synthetic AWS access keys (`AKIA...`), secret keys, and regions.
2. `ssh_private_key` (`~/.ssh/<host>_rsa`): Realistic PEM RSA private key bodies with synthetically generated content.
3. `app_config_file` (`/var/www/app/.env`): Environment configs incorporating target hostnames, internal DB endpoints, and high-entropy secrets.
4. `database_credentials` (`/etc/app/db.conf`): Database configuration blocks with ports, DB names, and strong passwords.
5. `decoy_directory` (`/home/<user>/sensitive/`): Directory structures referencing real verified users present in `EnvironmentFacts`.
6. `vulnerable_service_banner` (`/etc/banner_<svc>.txt`): Authentic server banners for OpenSSH, Apache, vsftpd.
7. `malware_c2_infrastructure` (`/tmp/.c2config`): Synthetic C2 domain beacon configurations and internal callback channels.

---

## 4-Tier Independent Validation Engine

Every artifact must pass 4 rule-based checks before deployment:

| Criterion | Inspection Logic |
|---|---|
| **Referential Consistency** | Matches system configuration values (e.g., `HOST=`) strictly against `session.env_facts.hostname`. |
| **Provenance Consistency** | Asserts file ownership paths (`/home/<user>/`) only utilize users from `env_facts.existing_users`. Flags any synthetic canary names (e.g., `ghost_`). |
| **Format Credibility** | Validates structural integrity: AWS key format (`^AKIA[0-9A-Z]{16}$`), 40-char secret keys, PEM header/footers, and password length thresholds (≥ 16 chars). |
| **Non-Functionality** | Confirms credentials are fully synthetic and prevents leakage of public documentation examples (e.g., `AKIAIOSFODNN7EXAMPLE`). |

---

## Getting Started

### 1. Requirements

- Python 3.10+
- Optional: `paramiko` (only required if deploying over SFTP)
- `pytest` (for running test suites)

Install optional dependencies:
```bash
pip install -r fcgd_ah/requirements.txt
```

### 2. Run the Single Session Demo

Simulates an attacker inspecting an environment and requesting an application config file. Notice how Attempt 1 deliberately fails due to password length and Attempt 2 automatically corrects it:

```bash
python -m fcgd_ah.demo
```

### 3. Run the Batch Simulation

Executes 21 diverse attacker sessions across all 7 artifact categories and logs results to `attempt_log.jsonl`:

```bash
python -m fcgd_ah.batch_run
```

### 4. Analyze Attempt Telemetry

Parses `attempt_log.jsonl` and generates an ASCII summary report with success rates, retry distributions, and latency metrics:

```bash
python -m fcgd_ah.analyze_log
```

### 5. Run Adversarial Tests

Run the full pytest suite testing adversarial inputs, boundary conditions, and consistency checks:

```bash
pytest fcgd_ah/tests/test_validator.py -v
```

---

## Live SFTP Deployment (Optional)

To deploy generated artifacts directly to a honeypot target, configure the target environment variables:

```bash
export TARGET_HOST="192.168.1.100"
export TARGET_SSH_USER="ubuntu"
export TARGET_SSH_PASSWORD="secure_password"
```

Then invoke `deploy_to_target(artifact_content, remote_path)` from `fcgd_ah.deployer`.
Credentials are never hardcoded and will raise an `EnvironmentError` if unset.
