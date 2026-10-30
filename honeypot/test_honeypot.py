"""
test_honeypot.py
Automated end-to-end test verifying the Honeypot SSH server interacts seamlessly
with Paramiko SSH clients and invokes FCGD-AH dynamic deception correctly.
"""

import threading
import time
import sys
import os
import paramiko

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from honeypot import config
from honeypot.honeypot_server import start_honeypot

TEST_PORT = 2223  # Use test port to avoid collision

def run_server_in_background():
    th = threading.Thread(target=start_honeypot, kwargs={"host": "127.0.0.1", "port": TEST_PORT}, daemon=True)
    th.start()
    time.sleep(1.5)  # Wait for socket to bind

def test_honeypot_end_to_end():
    print("[*] Starting honeypot background service on port", TEST_PORT)
    run_server_in_background()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print("[*] Connecting client to 127.0.0.1:", TEST_PORT)
    client.connect(
        hostname="127.0.0.1",
        port=TEST_PORT,
        username="attacker",
        password="password",
        timeout=5
    )
    print("[+] SSH Connection successful!")

    # 1. Test benign reconnaissance
    stdin, stdout, stderr = client.exec_command("whoami")
    out = stdout.read().decode().strip()
    assert out == "attacker", f"Expected 'attacker', got '{out}'"
    print(f"  [PASS] whoami -> {out}")

    stdin, stdout, stderr = client.exec_command("pwd")
    out = stdout.read().decode().strip()
    assert "/home/attacker" in out, f"Expected /home/attacker, got '{out}'"
    print(f"  [PASS] pwd -> {out}")

    # 2. Test honeytoken trigger: AWS credentials
    stdin, stdout, stderr = client.exec_command("cat ~/.aws/credentials")
    out = stdout.read().decode().strip()
    assert "aws_access_key_id=AKIA" in out, f"Expected AKIA key in AWS output, got: {out[:100]}"
    print(f"  [PASS] cat ~/.aws/credentials -> Generated AKIA Honeytoken verified!")

    # 3. Test honeytoken trigger: Application Config .env
    stdin, stdout, stderr = client.exec_command("cat .env")
    out = stdout.read().decode().strip()
    assert "DB_PASS=" in out and "HOST=prod-server-01" in out, f"Expected DB_PASS and HOST in .env, got: {out[:100]}"
    print(f"  [PASS] cat .env -> Generated .env config Honeytoken verified!")

    # 4. Test honeytoken trigger: Password grep
    stdin, stdout, stderr = client.exec_command("grep password /var/www/*")
    out = stdout.read().decode().strip()
    assert "DB_PASS=" in out or "password" in out.lower(), f"Expected password match in grep, got: {out[:100]}"
    print(f"  [PASS] grep password /var/www/* -> Triggered Honeytoken search verified!")

    client.close()
    print("\n[+] ALL HONEYPOT INTEGRATION TESTS PASSED SUCCESSFULLY!")
    time.sleep(0.5)
    os._exit(0)

if __name__ == "__main__":
    test_honeypot_end_to_end()
