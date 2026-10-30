"""
config.py
Configuration parameters for the FCGD-AH SSH Honeypot server.
"""

import os

# Server Network Settings
BIND_HOST: str = "0.0.0.0"
BIND_PORT: int = 2222

# Authentication Settings
DEFAULT_USER: str = "ubuntu"
DEFAULT_PASSWORD: str = "password"
ACCEPT_ANY_AUTH: bool = True  # Allows demo access with any credentials (ubuntu, deploy, root, etc.)

# RSA Host Key location
HOST_KEY_FILE: str = os.path.join(os.path.dirname(__file__), "host_rsa.key")

# Honeypot Identity Facts (fed directly to FCGD-AH environment context)
TARGET_HOSTNAME: str = "prod-server-01"
TARGET_ORG: str = "DemoCorp"
TARGET_USERS: list[str] = ["deploy", "ubuntu", "root", "attacker"]

# Default fake files and paths
INITIAL_DIR: str = "/home/ubuntu"
BANNER_TEXT: str = "Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-101-generic x86_64)\n"
