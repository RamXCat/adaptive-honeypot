"""
templates.py
Fake value generators and per-category artifact template variants.
ALL generation is local — no network, no LLM.
"""

import secrets
import random
import string
import base64
import textwrap
from typing import Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Low-level fake value generators
# ─────────────────────────────────────────────────────────────────────────────

def fake_aws_access_key() -> str:
    """AKIA + 16 random uppercase alphanumeric chars → matches ^AKIA[0-9A-Z]{16}$"""
    chars = string.ascii_uppercase + string.digits
    return "AKIA" + "".join(secrets.choice(chars) for _ in range(16))


def fake_aws_secret_key() -> str:
    """40-char base64-safe string (real AWS secrets are 40 chars)."""
    alphabet = string.ascii_letters + string.digits + "+/"
    return "".join(secrets.choice(alphabet) for _ in range(40))


def fake_pem_ssh_private_key() -> str:
    """PEM-formatted RSA private key with a random garbage base64 body."""
    body_bytes = secrets.token_bytes(1700)           # ~1700 bytes → realistic key body
    b64 = base64.b64encode(body_bytes).decode()
    wrapped = textwrap.fill(b64, width=64)
    return f"-----BEGIN RSA PRIVATE KEY-----\n{wrapped}\n-----END RSA PRIVATE KEY-----"


def fake_db_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def fake_internal_ip() -> str:
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def fake_c2_domain() -> str:
    words = ["update", "cdn", "metrics", "api", "telemetry", "sync", "relay"]
    tlds  = ["net", "org", "io", "co"]
    base  = "".join(random.choices(string.ascii_lowercase, k=random.randint(5, 9)))
    return f"{random.choice(words)}.{base}.{random.choice(tlds)}"


def fake_token(length: int = 32) -> str:
    return secrets.token_hex(length // 2)


def fake_port() -> int:
    return random.choice([3306, 5432, 6379, 27017, 9200, 5984])


# ─────────────────────────────────────────────────────────────────────────────
# Per-category template builders
# Returns: (artifact_content: str, suggested_path: str)
# temperature: 0.9 = variant 0 (creative/risky), 0.6 = variant 1, 0.3 = variant 2
# ─────────────────────────────────────────────────────────────────────────────

def _variant_index(temperature: float) -> int:
    if temperature >= 0.8:
        return 0
    elif temperature >= 0.5:
        return 1
    else:
        return 2


def build_aws_credentials(hostname: str, org: str, temperature: float) -> Tuple[str, str]:
    ak = fake_aws_access_key()
    sk = fake_aws_secret_key()
    region = random.choice(["us-east-1", "eu-west-1", "ap-south-1"])
    content = (
        f"[default]\n"
        f"aws_access_key_id={ak}\n"
        f"aws_secret_access_key={sk}\n"
        f"region={region}\n"
        f"# {org} production credentials — do not share\n"
    )
    return content, "~/.aws/credentials"


def build_ssh_private_key(hostname: str, org: str, temperature: float) -> Tuple[str, str]:
    content = fake_pem_ssh_private_key()
    return content, f"/home/deploy/.ssh/{hostname}_rsa"


def build_app_config_file(
    hostname: str, org: str, temperature: float,
    prior_issue_criteria: list[str] | None = None
) -> Tuple[str, str]:
    """
    DELIBERATE FAILURE on variant 0:
    Variant 0 (temp=0.9): generates a DB_PASS that is only 8 chars → fails format_credibility.
    Variant 1+ (temp≤0.6): generates a correct 20-char password.
    """
    idx = _variant_index(temperature)
    db_host = fake_internal_ip()
    db_user = "appuser"
    db_name = f"{org.lower().replace(' ', '_')}_prod"

    if idx == 0:
        db_pass = secrets.token_hex(4)      # Only 8 chars → intentionally too short
    else:
        db_pass = fake_db_password(20)      # 20 chars → passes format check

    token = fake_token(32)
    content = (
        f"# {org} application configuration\n"
        f"APP_ENV=production\n"
        f"HOST={hostname}\n"
        f"DB_HOST={db_host}\n"
        f"DB_USER={db_user}\n"
        f"DB_NAME={db_name}\n"
        f"DB_PASS={db_pass}\n"
        f"SECRET_KEY={token}\n"
        f"DEBUG=false\n"
    )
    return content, "/var/www/app/.env"


def build_database_credentials(hostname: str, org: str, temperature: float) -> Tuple[str, str]:
    port = fake_port()
    db_ip = fake_internal_ip()
    passwd = fake_db_password(22)
    content = (
        f"[database]\n"
        f"db_host = {db_ip}\n"
        f"port = {port}\n"
        f"user = db_admin\n"
        f"password = {passwd}\n"
        f"dbname = {org.lower().replace(' ', '_')}_core\n"
        f"# Generated for {hostname}\n"
    )
    return content, "/etc/app/db.conf"


def build_decoy_directory(
    hostname: str, org: str, temperature: float,
    existing_users: list[str] | None = None,
    prior_issue_criteria: list[str] | None = None
) -> Tuple[str, str]:
    """
    DELIBERATE FAILURE on variant 0:
    Variant 0 (temp=0.9): references a random invented username → fails provenance_consistency.
    Variant 1+ (temp≤0.6): strictly uses a user from existing_users.
    """
    idx = _variant_index(temperature)
    users = existing_users or ["deploy"]

    if idx == 0:
        # Use an invented name not in existing_users
        invented_user = "ghost_" + secrets.token_hex(3)
        owner = invented_user
    else:
        # Use a verified existing user
        owner = random.choice(users)

    dirs = ["backup_2024", "archive", "snapshots", "credentials_old", "keys"]
    selected = random.sample(dirs, k=min(3, len(dirs)))
    listing = "\n".join(f"drwxr-x--- 2 {owner} {owner} 4096 Sep {random.randint(1,30):02d} {d}/" for d in selected)
    content = (
        f"# Decoy directory listing on {hostname}\n"
        f"total {random.randint(12, 48)}\n"
        f"{listing}\n"
    )
    return content, f"/home/{owner}/sensitive/"


def build_vulnerable_service_banner(hostname: str, org: str, temperature: float) -> Tuple[str, str]:
    versions = [
        ("OpenSSH", "7.2p2 Ubuntu 4ubuntu2.8"),
        ("Apache", "2.4.29 (Ubuntu)"),
        ("vsftpd", "2.3.4"),
    ]
    svc, ver = random.choice(versions)
    port = {"OpenSSH": 22, "Apache": 80, "vsftpd": 21}[svc]
    content = (
        f"SSH-2.0-{svc}_{ver}\n"
        f"# Banner for {hostname} ({org})\n"
        f"# Service: {svc} on port {port}\n"
    )
    return content, f"/etc/banner_{svc.lower()}.txt"


def build_malware_c2_infrastructure(hostname: str, org: str, temperature: float) -> Tuple[str, str]:
    c2 = fake_c2_domain()
    ip  = fake_internal_ip()
    token = fake_token(24)
    content = (
        f"# C2 configuration (simulated)\n"
        f"C2_HOST={c2}\n"
        f"C2_IP={ip}\n"
        f"C2_PORT={random.randint(1024, 65535)}\n"
        f"AUTH_TOKEN={token}\n"
        f"BEACON_INTERVAL=60\n"
        f"# Do not distribute — internal use only ({org})\n"
    )
    return content, "/tmp/.c2config"
