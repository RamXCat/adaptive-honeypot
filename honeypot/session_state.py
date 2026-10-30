"""
session_state.py
Tracks attacker telemetry and bridges SSH sessions to FCGD-AH SessionState.
"""

import time
import re
from typing import Optional
from fcgd_ah.schemas import SessionState, EnvironmentFacts, MalwareInterestProfile
from . import config

class HoneypotSessionTracker:
    def __init__(self, session_id: str, client_ip: str, username: str):
        self.session_id: str = session_id
        self.client_ip: str = client_ip
        self.username: str = username
        self.start_time: float = time.time()
        self.commands_run: list[str] = []
        self.files_touched: list[str] = []
        
        # Honeypot environment facts
        self.env_facts: EnvironmentFacts = EnvironmentFacts(
            hostname=config.TARGET_HOSTNAME,
            org_name=config.TARGET_ORG,
            existing_users=list(config.TARGET_USERS),
            previously_generated_artifacts=[]
        )
        
        # Dynamic attacker interest profile
        self.file_interests: set[str] = set()
        self.credential_interests: set[str] = set()
        self.network_interests: set[str] = set()

    def record_command(self, cmd: str) -> None:
        """Records a command executed by the attacker and updates the interest profile."""
        clean_cmd = cmd.strip()
        if not clean_cmd:
            return
            
        self.commands_run.append(clean_cmd)
        
        # Detect file extension interests
        for ext in [".env", ".pem", ".json", ".conf", ".key", ".yml", ".yaml", ".txt"]:
            if ext in clean_cmd.lower():
                self.file_interests.add(ext)
                
        # Detect credential keywords
        for cred in ["aws", "password", "token", "secret", "api_key", "credentials", "id_rsa"]:
            if cred in clean_cmd.lower():
                self.credential_interests.add(cred.upper())
                
        # Extract potential touched paths
        paths = re.findall(r"(?:/[\w\-.]+)+|(?:\~/[.\w\-]+)", clean_cmd)
        for p in paths:
            if p not in self.files_touched:
                self.files_touched.append(p)

    def to_fcgd_session_state(self) -> SessionState:
        """Constructs an FCGD-AH compatible SessionState object."""
        duration = time.time() - self.start_time
        profile = MalwareInterestProfile(
            file_type_interests=sorted(list(self.file_interests)),
            credential_patterns=sorted(list(self.credential_interests)),
            network_destinations=sorted(list(self.network_interests))
        )
        return SessionState(
            session_id=self.session_id,
            commands_run=list(self.commands_run),
            files_touched=list(self.files_touched),
            duration_s=round(duration, 2),
            env_facts=self.env_facts,
            malware_profile=profile
        )
