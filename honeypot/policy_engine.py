"""
policy_engine.py
Classifies attacker commands into policy actions (ACTION_REAL, ACTION_FAKE, ACTION_ERROR)
and maps suspicious targets to the appropriate FCGD-AH ArtifactCategory.
"""

from typing import Tuple, Optional
from fcgd_ah.taxonomy import ArtifactCategory

# Actions defined by the FCGD-AH architecture
ACTION_REAL: str = "ACTION_REAL"
ACTION_FAKE: str = "ACTION_FAKE"
ACTION_ERROR: str = "ACTION_ERROR"

def classify_command(command: str) -> Tuple[str, Optional[ArtifactCategory]]:
    """
    Evaluates an attacker command string.
    Returns: (action, target_category)
    """
    cmd = command.strip().lower()
    
    # Safe system reconnaissance commands (allow directory listing of directories like .aws, .ssh)
    if cmd.startswith("ls") or cmd.startswith("dir") or cmd in ["whoami", "pwd", "id", "uname", "hostname", "date", "uptime", "ps", "top", "free", "df"]:
        # Only treat as fake if it is explicitly cat/grep/reading content, not directory listing
        return ACTION_REAL, None

    # 1. AWS Credentials
    if "aws" in cmd or "credentials" in cmd:
        return ACTION_FAKE, ArtifactCategory.AWS_CREDENTIALS
        
    # 2. SSH Private Keys
    if "id_rsa" in cmd or ".pem" in cmd or "ssh_private" in cmd or ("find" in cmd and "pem" in cmd):
        return ACTION_FAKE, ArtifactCategory.SSH_PRIVATE_KEY
        
    # 3. Application Configuration (.env files)
    if ".env" in cmd or ("/var/www" in cmd and "cat" in cmd):
        return ACTION_FAKE, ArtifactCategory.APP_CONFIG_FILE
        
    # 4. Database Credentials / Password Search
    if "db.conf" in cmd or "database" in cmd or ("grep" in cmd and "password" in cmd):
        if "grep" in cmd and "password" in cmd and "var/www" in cmd:
            return ACTION_FAKE, ArtifactCategory.APP_CONFIG_FILE
        return ACTION_FAKE, ArtifactCategory.DATABASE_CREDENTIALS
        
    # 5. Decoy Directory Listing
    if "sensitive" in cmd or "backup_2024" in cmd or "archive" in cmd:
        return ACTION_FAKE, ArtifactCategory.DECOY_DIRECTORY
        
    # 6. Service Banners
    if "banner" in cmd or ("version" in cmd and any(s in cmd for s in ["ssh", "apache", "ftp"])):
        return ACTION_FAKE, ArtifactCategory.VULNERABLE_SERVICE_BANNER
        
    # 7. Malware C2 Configuration
    if "c2" in cmd or "beacon" in cmd or ".c2config" in cmd:
        return ACTION_FAKE, ArtifactCategory.MALWARE_C2_INFRASTRUCTURE

    real_commands = [
        "cat /etc/passwd", "cat /etc/issue", "cat /etc/os-release",
        "echo", "history"
    ]
    for r in real_commands:
        if cmd == r or cmd.startswith(f"{r} ") or cmd.startswith(f"{r};"):
            return ACTION_REAL, None
            
    # Default fallback
    return ACTION_REAL, None
