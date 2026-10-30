"""
Original Enterprise Production SSH Server (DemoCorp Internal Gateway).
Port: 2200 (Default)
Host: 0.0.0.0

This server emulates the authentic, uncompromised internal bastion host of DemoCorp.
Unlike the deceptive honeypot (which grants access to any intruder and serves dynamic bait),
this server enforces STRICT enterprise authentication, realistic production shell sessions,
and hosts the genuine database and secrets.
"""

import os
import sys
import socket
import threading
import paramiko
import time
from original_database import query_db_cli, init_original_database

# Ensure database is present
init_original_database()

# Server Configuration
SSH_HOST = "0.0.0.0"
SSH_PORT = 2200

# Legitimate Corporate Credentials
AUTHORIZED_CREDENTIALS = {
    "sec_admin": "VaultK3y_Master2026!",
    "lead_dev": "Rivera_Arch#992",
    "db_admin": "Postgres_Cluster_Root#",
    "auditor": "PCI_DSS_Compliant_2026",
    "admin": "DemoCorp2026!Secure"
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HOST_KEY_FILE = os.path.join(BASE_DIR, "original_secrets", "company_master_rsa")

if not os.path.exists(HOST_KEY_FILE):
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_FILE)

HOST_KEY = paramiko.RSAKey(filename=HOST_KEY_FILE)


class ProductionServerInterface(paramiko.ServerInterface):
    """Strict Paramiko SSH Interface for the Genuine Server."""

    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.authenticated_user = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Strict credential verification
        if username in AUTHORIZED_CREDENTIALS and AUTHORIZED_CREDENTIALS[username] == password:
            print(f"[\033[92mORIGINAL-SSH\033[0m] Authorized login SUCCESS from {self.client_ip} as user '{username}'")
            self.authenticated_user = username
            return paramiko.AUTH_SUCCESSFUL
        else:
            print(f"[\033[91mORIGINAL-SSH\033[0m] Authentication FAILED from {self.client_ip} for user '{username}'")
            return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True


def handle_production_shell(channel, username, client_ip):
    """Provides a realistic Linux production bash terminal to authorized operators."""
    channel.send("\r\n\033[1;34m========================================================================\033[0m\r\n")
    channel.send("\033[1;37m   DemoCorp Inc. Production Gateway (INTERNAL INFRASTRUCTURE NODE)    \033[0m\r\n")
    channel.send("   Node: prod-corp-bastion-01.internal.democorp.local | Ubuntu 22.04 LTS\r\n")
    channel.send("   Security Policy: STRICT PCI-DSS & SOC-2 AUDITED ENVIRONMENT\r\n")
    channel.send("\033[1;34m========================================================================\033[0m\r\n")
    channel.send(f"\033[0;32m[*] Authenticated as: {username} (Access Level: PRIVILEGED)\033[0m\r\n")
    channel.send("\033[0;33m[*] Type 'help' for enterprise management commands.\033[0m\r\n\r\n")

    current_dir = "/srv/enterprise/production"
    prompt = f"\033[1;32m{username}@prod-corp-bastion\033[0m:\033[1;34m{current_dir}\033[0m$ "
    channel.send(prompt)

    cmd_buffer = ""

    while True:
        try:
            data = channel.recv(1024)
            if not data:
                break

            for char in data.decode("utf-8", errors="ignore"):
                if char in ("\r", "\n"):
                    channel.send("\r\n")
                    cmd = cmd_buffer.strip()
                    cmd_buffer = ""

                    if cmd in ("exit", "logout", "quit"):
                        channel.send("Closing secure enterprise session. Goodbye.\r\n")
                        channel.close()
                        return

                    elif cmd == "help":
                        channel.send(
                            "Available Enterprise Management Commands:\r\n"
                            "  db-query <SQL>      - Execute query against original relational database\r\n"
                            "  db-status           - Display production database schemas and health\r\n"
                            "  cat <file>          - View production secret files (.env, aws_credentials, rsa)\r\n"
                            "  ls -la              - List current secure directory contents\r\n"
                            "  whoami              - Display current user identity & role\r\n"
                            "  uname -a            - Display production kernel architecture\r\n"
                            "  exit                - Terminate privileged connection\r\n\r\n"
                        )

                    elif cmd == "whoami":
                        channel.send(f"{username}\r\n")

                    elif cmd == "uname -a":
                        channel.send("Linux prod-corp-bastion 5.15.0-101-generic #111-Ubuntu SMP x86_64 GNU/Linux\r\n")

                    elif cmd in ("ls", "ls -la", "ls -l"):
                        channel.send(
                            "total 36\r\n"
                            "drwxr-x--- 3 root     secops 4096 Oct 26 14:00 .\r\n"
                            "drwxr-xr-x 8 root     root   4096 Oct 20 09:12 ..\r\n"
                            "-rw-r----- 1 sec_admin secops 1240 Oct 26 14:02 prod.env\r\n"
                            "-rw-r----- 1 sec_admin secops  430 Oct 26 14:05 aws_credentials\r\n"
                            "-rw------- 1 sec_admin secops 2602 Oct 26 14:06 company_master_rsa\r\n"
                            "-rw-r----- 1 db_admin  secops 16384 Oct 26 14:10 democorp_production.db\r\n"
                            "-rwxr-x--- 1 sec_admin secops 3120 Oct 26 14:15 sync_secrets.sh\r\n\r\n"
                        )

                    elif cmd.startswith("cat "):
                        target = cmd[4:].strip()
                        if target in ("prod.env", ".env", "/srv/enterprise/production/prod.env"):
                            with open(os.path.join(BASE_DIR, "original_secrets", "prod.env"), "r") as f:
                                channel.send(f.read().replace("\n", "\r\n") + "\r\n")
                        elif target in ("aws_credentials", "credentials", "~/.aws/credentials"):
                            with open(os.path.join(BASE_DIR, "original_secrets", "aws_credentials"), "r") as f:
                                channel.send(f.read().replace("\n", "\r\n") + "\r\n")
                        elif target in ("company_master_rsa", "id_rsa", "~/.ssh/id_rsa"):
                            with open(os.path.join(BASE_DIR, "original_secrets", "company_master_rsa"), "r") as f:
                                channel.send(f.read().replace("\n", "\r\n") + "\r\n")
                        else:
                            channel.send(f"cat: {target}: Permission denied or file not found\r\n")

                    elif cmd == "db-status":
                        channel.send(
                            "[+] PostgreSQL Production Cluster: ONLINE (Primary at 10.0.4.15:5432)\r\n"
                            "[+] Active Schema Tables: corporate_users, customer_accounts, service_credentials\r\n"
                            "[+] Connection Pool: 24 active / 100 max\r\n"
                            "[+] Replication Delay: 0.12ms (Synchronous to Standby Node)\r\n\r\n"
                        )

                    elif cmd.startswith("db-query "):
                        sql = cmd[9:].strip()
                        res = query_db_cli(sql)
                        channel.send(res.replace("\n", "\r\n") + "\r\n")

                    elif cmd == "":
                        pass
                    else:
                        channel.send(f"bash: {cmd}: command not found (strict production whitelist enforced)\r\n")

                    channel.send(prompt)

                elif char == "\x08" or char == "\x7f":  # Backspace
                    if len(cmd_buffer) > 0:
                        cmd_buffer = cmd_buffer[:-1]
                        channel.send("\x08 \x08")
                elif char == "\x03":  # Ctrl+C
                    channel.send("^C\r\n" + prompt)
                    cmd_buffer = ""
                else:
                    cmd_buffer += char
                    channel.send(char)

        except Exception as e:
            break

    channel.close()


def start_original_ssh_server():
    """Starts the authentic SSH Server listening on port 2200."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SSH_HOST, SSH_PORT))
    sock.listen(10)

    print("\n" + "=" * 75)
    print(f"[*] DEMOCORP ORIGINAL ENTERPRISE SSH SERVER STARTED")
    print(f"[*] Listening on: {SSH_HOST}:{SSH_PORT}")
    print(f"[*] Authorized User: admin | Pass: DemoCorp2026!Secure")
    print(f"[*] Authorized User: sec_admin | Pass: VaultK3y_Master2026!")
    print(f"[*] Authentic Database: {os.path.join(BASE_DIR, 'democorp_production.db')}")
    print(f"[*] Authentic Secrets: {os.path.join(BASE_DIR, 'original_secrets')}")
    print("=" * 75 + "\n")

    while True:
        try:
            client, addr = sock.accept()
            client_ip = addr[0]

            transport = paramiko.Transport(client)
            transport.add_server_key(HOST_KEY)

            server_iface = ProductionServerInterface(client_ip)

            try:
                transport.start_server(server=server_iface)
            except Exception as e:
                transport.close()
                continue

            chan = transport.accept(20)
            if chan is None:
                transport.close()
                continue

            server_iface.event.wait(10)
            if not server_iface.event.is_set():
                chan.close()
                transport.close()
                continue

            shell_thread = threading.Thread(
                target=handle_production_shell,
                args=(chan, server_iface.authenticated_user or "unknown", client_ip),
                daemon=True
            )
            shell_thread.start()

        except Exception as e:
            time.sleep(0.5)


if __name__ == "__main__":
    start_original_ssh_server()
