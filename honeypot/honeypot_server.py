"""
honeypot_server.py
Main SSH Honeypot Server powered by the FCGD-AH Generative Deception Module.
Accepts attacker connections on port 2222, classifies commands with the policy engine,
dynamically generates honeytokens using FCGD-AH, and logs all telemetry.
"""

import socket
import sys
import os
import threading
import time
import json
from datetime import datetime
import argparse
from colorama import init, Fore, Back, Style

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import paramiko
from fcgd_ah import retry_loop
from fcgd_ah.taxonomy import ArtifactCategory
from honeypot import config
from honeypot.session_state import HoneypotSessionTracker
from honeypot.policy_engine import classify_command, ACTION_FAKE, ACTION_REAL
from honeypot.virtual_fs import VirtualFileSystem
from honeypot.ssh_server import HoneypotSSHInterface, get_or_create_host_key

init(autoreset=True)

def print_honeypot_banner(host: str = config.BIND_HOST, port: int = config.BIND_PORT):
    banner = f"""{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════════════╗
║               FCGD-AH ADAPTIVE HONEYPOT SERVER                       ║
║           Generative Deception & Automated Validation Engine         ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
  {Fore.GREEN}● Listening on{Style.RESET_ALL}      : {host}:{port}
  {Fore.GREEN}● Honeypot Node{Style.RESET_ALL}     : {config.TARGET_HOSTNAME} ({config.TARGET_ORG})
  {Fore.GREEN}● Deception Mode{Style.RESET_ALL}    : Sub-millisecond Template Feedback Loop (Offline)
  {Fore.GREEN}● Default Creds{Style.RESET_ALL}     : {config.DEFAULT_USER} / {config.DEFAULT_PASSWORD}
"""
    print(banner)


def handle_attacker_command(
    cmd: str,
    tracker: HoneypotSessionTracker,
    vfs: VirtualFileSystem,
) -> tuple[str, str]:
    """
    Evaluates a command, invoking FCGD-AH for ACTION_FAKE triggers,
    or executing against the virtual filesystem for ACTION_REAL.
    """
    tracker.record_command(cmd)
    action, category = classify_command(cmd)

    if action == ACTION_FAKE and category is not None:
        print(f"\n{Back.RED}{Fore.WHITE}{Style.BRIGHT} [!] HONEYTOKEN TRIGGER DETECTED {Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Attacker IP{Style.RESET_ALL}   : {tracker.client_ip} ({tracker.username})")
        print(f"  {Fore.YELLOW}Command{Style.RESET_ALL}       : {Fore.WHITE}{cmd}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Policy Engine{Style.RESET_ALL} : {Fore.MAGENTA}{action}{Style.RESET_ALL} -> {Fore.CYAN}{category.value}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Action{Style.RESET_ALL}        : Generating synthetic honeytoken via FCGD-AH...")

        t_start = time.perf_counter()
        session_state = tracker.to_fcgd_session_state()
        result = retry_loop.run(session_state, category)
        latency_ms = (time.perf_counter() - t_start) * 1000

        if result.deployed and result.artifact_content:
            status_text = f"{Fore.GREEN}SUCCESS (Deployed){Style.RESET_ALL}"
            print(f"  {Fore.YELLOW}Status{Style.RESET_ALL}        : {status_text} in {latency_ms:.3f} ms")
            print(f"  {Fore.YELLOW}Attempts used{Style.RESET_ALL} : {result.attempts_consumed} of 3")
            if result.suggested_path:
                print(f"  {Fore.YELLOW}VFS Mapping{Style.RESET_ALL}   : {result.suggested_path}")
                vfs.set_artifact(result.suggested_path, result.artifact_content)
                # If attacker searched for .env locally, also make it available in current directory & /home/attacker/app/
                if ".env" in result.suggested_path:
                    vfs.set_artifact(os.path.join(vfs.cwd, ".env"), result.artifact_content)
                    vfs.set_artifact(f"/home/{tracker.username}/app/.env", result.artifact_content)
                elif "credentials" in result.suggested_path:
                    vfs.set_artifact(f"/home/{tracker.username}/.aws/credentials", result.artifact_content)

            # Asynchronously notify visual dashboard of live attacker event
            def _notify_dashboard():
                try:
                    import urllib.request
                    evt = {
                        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                        "session_id": tracker.session_id,
                        "attacker_cmd": f"[{tracker.client_ip}] {cmd}",
                        "category": category.value,
                        "suggested_path": result.suggested_path,
                        "deployed": result.deployed,
                        "attempts": result.attempts_consumed,
                        "latency_ms": round(latency_ms, 2),
                        "artifact_preview": result.artifact_content if result.artifact_content else "",
                        "issues": [issue.criterion for issue in result.all_issues]
                    }
                    req = urllib.request.Request(
                        "http://127.0.0.1:8080/api/record_event",
                        data=json.dumps(evt).encode("utf-8"),
                        headers={"Content-Type": "application/json"}
                    )
                    urllib.request.urlopen(req, timeout=1)
                except Exception:
                    pass
            threading.Thread(target=_notify_dashboard, daemon=True).start()
            
            # Format grep responses appropriately
            if "grep" in cmd:
                lines = [line for line in result.artifact_content.splitlines() if "password" in line.lower() or "pass" in line.lower()]
                if lines:
                    output = "\n".join(f"/var/www/app/.env:{l}" for l in lines) + "\n"
                else:
                    output = result.artifact_content
            else:
                output = result.artifact_content
                
            return output, ""
        else:
            print(f"  {Fore.RED}Generation Failed — Safe null response returned.{Style.RESET_ALL}")
            return "", "Permission denied\n"

    else:
        # Benign command
        print(f"  {Fore.BLUE}[*]{Style.RESET_ALL} [{tracker.client_ip}] {Fore.WHITE}{cmd}{Style.RESET_ALL} -> {Fore.GREEN}ACTION_REAL{Style.RESET_ALL}")
        stdout_text, stderr_text = vfs.execute_benign_command(cmd)

        # Asynchronously broadcast benign command to visual dashboard
        def _notify_benign():
            try:
                import urllib.request
                evt = {
                    "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    "session_id": tracker.session_id,
                    "attacker_cmd": f"[{tracker.client_ip}] {cmd}",
                    "category": "reconnaissance",
                    "suggested_path": vfs.cwd,
                    "deployed": True,
                    "attempts": 1,
                    "latency_ms": 0.15,
                    "artifact_preview": stdout_text[:300] if stdout_text else (stderr_text[:300] if stderr_text else "(executed)"),
                    "issues": []
                }
                req = urllib.request.Request(
                    "http://127.0.0.1:8080/api/record_event",
                    data=json.dumps(evt).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req, timeout=1)
            except Exception:
                pass
        threading.Thread(target=_notify_benign, daemon=True).start()

        return stdout_text, stderr_text


def handle_single_channel(
    channel: paramiko.Channel,
    server: HoneypotSSHInterface,
    tracker: HoneypotSessionTracker,
    vfs: VirtualFileSystem,
):
    try:
        info = server.get_channel_info(channel.get_id())
        info["event"].wait(10)
        
        # 1. Exec command mode (single command execution)
        if info["cmd"] is not None:
            cmd = info["cmd"]
            stdout_out, stderr_out = handle_attacker_command(cmd, tracker, vfs)
            if stdout_out:
                channel.send(stdout_out.encode("utf-8"))
            if stderr_out:
                channel.send_stderr(stderr_out.encode("utf-8"))
            channel.send_exit_status(0)
            channel.close()
            return

        # 2. Interactive shell mode
        if info["shell"]:
            channel.send(config.BANNER_TEXT.encode("utf-8"))
            prompt = f"{tracker.username}@{config.TARGET_HOSTNAME}:{vfs.cwd}$ "
            channel.send(prompt.encode("utf-8"))
            
            buffer = ""
            while True:
                data = channel.recv(1024)
                if not data:
                    break
                text = data.decode("utf-8", errors="replace")
                
                # Echo characters for interactive shell
                channel.send(text.encode("utf-8"))
                
                for char in text:
                    if char in ("\r", "\n"):
                        channel.send(b"\r\n")
                        cmd_to_run = buffer.strip()
                        buffer = ""
                        
                        if cmd_to_run.lower() in ("exit", "quit", "logout"):
                            channel.send(b"Connection closed.\r\n")
                            channel.close()
                            return
                            
                        if cmd_to_run:
                            out, err = handle_attacker_command(cmd_to_run, tracker, vfs)
                            if out:
                                # Replace newlines with CRLF for terminals
                                channel.send(out.replace("\n", "\r\n").encode("utf-8"))
                            if err:
                                channel.send_stderr(err.replace("\n", "\r\n").encode("utf-8"))
                                
                        prompt = f"{tracker.username}@{config.TARGET_HOSTNAME}:{vfs.cwd}$ "
                        channel.send(prompt.encode("utf-8"))
                    elif char == "\x08" or char == "\x7f":  # Backspace
                        if buffer:
                            buffer = buffer[:-1]
                            channel.send(b"\b \b")
                    else:
                        buffer += char
                        
    except Exception as e:
        print(f"  {Fore.RED}[-] Channel Error: {e}{Style.RESET_ALL}")
    finally:
        try:
            channel.close()
        except Exception:
            pass


def client_thread(client_sock: socket.socket, client_addr: tuple):
    client_ip = client_addr[0]
    session_id = f"sess_{int(time.time())}_{client_addr[1]}"
    tracker = HoneypotSessionTracker(session_id=session_id, client_ip=client_ip, username=config.DEFAULT_USER)
    vfs = VirtualFileSystem(username=tracker.username, hostname=config.TARGET_HOSTNAME)

    print(f"\n{Fore.GREEN}[+] INCOMING CONNECTION{Style.RESET_ALL} from {client_ip}:{client_addr[1]} (Session: {session_id})")

    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        host_key = get_or_create_host_key()
        transport.add_server_key(host_key)

        def on_auth(user):
            tracker.username = user
            vfs.username = user
            vfs.cwd = f"/home/{user}"
            print(f"  {Fore.GREEN}[+] AUTHENTICATION ACCEPTED{Style.RESET_ALL} for user: {Fore.YELLOW}{user}{Style.RESET_ALL}")

        server = HoneypotSSHInterface(client_ip=client_ip, on_auth_success=on_auth)
        transport.start_server(server=server)

        # Handle multiple channels over the same transport connection
        while transport.is_active():
            channel = transport.accept(1.0)
            if channel is not None:
                ch_thread = threading.Thread(
                    target=handle_single_channel,
                    args=(channel, server, tracker, vfs),
                    daemon=True
                )
                ch_thread.start()

    except Exception as e:
        print(f"  {Fore.RED}[-] Connection exception: {e}{Style.RESET_ALL}")
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        print(f"{Fore.YELLOW}[*] Connection terminated{Style.RESET_ALL} for {client_ip}:{client_addr[1]}")


def start_honeypot(host: str = config.BIND_HOST, port: int = config.BIND_PORT):
    print_honeypot_banner(host, port)
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind((host, port))
        server_sock.listen(100)
        print(f"{Fore.CYAN}[*] Honeypot Server is ready and waiting for attacker connections...{Style.RESET_ALL}\n")
        
        while True:
            client_sock, client_addr = server_sock.accept()
            th = threading.Thread(target=client_thread, args=(client_sock, client_addr), daemon=True)
            th.start()
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Shutting down Honeypot Server...{Style.RESET_ALL}")
    finally:
        server_sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FCGD-AH SSH Honeypot Server")
    parser.add_argument("--host", default=config.BIND_HOST, help="Host address to bind to")
    parser.add_argument("--port", type=int, default=config.BIND_PORT, help="Port to bind to")
    args = parser.parse_args()

    start_honeypot(host=args.host, port=args.port)
