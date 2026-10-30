"""
ssh_server.py
Paramiko ServerInterface implementation for the FCGD-AH SSH Honeypot.
Handles authentication, PTY allocation, exec requests, and shell requests.
"""

import os
import threading
import paramiko
from typing import Optional, Callable
from . import config

def get_or_create_host_key() -> paramiko.RSAKey:
    """Loads existing host key or generates a fresh 2048-bit RSA key."""
    if os.path.exists(config.HOST_KEY_FILE):
        try:
            return paramiko.RSAKey.from_private_key_file(config.HOST_KEY_FILE)
        except Exception:
            pass
            
    # Generate new RSA host key
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(config.HOST_KEY_FILE)
    return key


class HoneypotSSHInterface(paramiko.ServerInterface):
    def __init__(self, client_ip: str, on_auth_success: Optional[Callable[[str], None]] = None):
        self.client_ip: str = client_ip
        self.username: str = config.DEFAULT_USER
        self.on_auth_success = on_auth_success
        self.channels: dict[int, dict] = {}
        self.lock = threading.Lock()

    def get_channel_info(self, chan_id: int) -> dict:
        with self.lock:
            if chan_id not in self.channels:
                self.channels[chan_id] = {
                    "event": threading.Event(),
                    "cmd": None,
                    "shell": False,
                }
            return self.channels[chan_id]

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            self.get_channel_info(chanid)
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        if config.ACCEPT_ANY_AUTH:
            if self.on_auth_success:
                self.on_auth_success(username)
            return paramiko.AUTH_SUCCESSFUL
        elif username == config.DEFAULT_USER and password == config.DEFAULT_PASSWORD:
            if self.on_auth_success:
                self.on_auth_success(username)
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        info = self.get_channel_info(channel.get_id())
        info["shell"] = True
        info["event"].set()
        return True

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        info = self.get_channel_info(channel.get_id())
        info["cmd"] = command.decode("utf-8", errors="replace")
        info["event"].set()
        return True
