import paramiko
import time
import sys
from colorama import init, Fore, Back, Style

# Initialize colorama for Windows terminal colors
init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.RED}{Style.BRIGHT}
    ___   ___________ ___   ________ __ ___________ 
   /   | /_  __/_  __/   | / ____/ //_// ____/ __ \\
  / /| |  / /   / / / /| |/ /   / ,<  / __/ / /_/ /
 / ___ | / /   / / / ___ / /___/ /| |/ /___/ _, _/ 
/_/  |_|/_/   /_/ /_/  |_\\____/_/ |_/_____/_/ |_|  
                                                   
{Fore.WHITE}{Back.RED} [ FCGD-AH Network Exploitation Framework v1.0 ] {Style.RESET_ALL}
"""
    print(banner)

def slow_print(text, delay=0.01, color=Fore.GREEN, end="\n"):
    for char in text:
        sys.stdout.write(f"{color}{char}")
        sys.stdout.flush()
        time.sleep(delay)
    print(Style.RESET_ALL, end=end)

def execute_command(client, cmd, silent=False):
    if not silent:
        slow_print(f"\n{Fore.RED}root@target:~# {Fore.WHITE}{cmd}", delay=0.03)
        time.sleep(0.5)
    
    stdin, stdout, stderr = client.exec_command(cmd)
    output = stdout.read().decode('utf-8')
    errors = stderr.read().decode('utf-8')
    
    if not silent:
        if output:
            print(f"{Fore.LIGHTCYAN_EX}{output}", end="")
        if errors:
            print(f"{Fore.LIGHTRED_EX}{errors}", end="")
    return output, errors

def interactive_shell(client, target_ip):
    print(f"\n{Fore.YELLOW}[*] Entering manual exploitation mode. Type 'exit' to return to menu.{Style.RESET_ALL}\n")
    while True:
        try:
            cmd = input(f"{Fore.RED}root@{target_ip}{Style.RESET_ALL}:~# ")
            if cmd.lower() in ['exit', 'quit']:
                break
            if not cmd.strip():
                continue
            
            # Use the helper without the fake typing effect
            stdin, stdout, stderr = client.exec_command(cmd)
            output = stdout.read().decode('utf-8')
            errors = stderr.read().decode('utf-8')
            
            if output:
                print(f"{Fore.LIGHTCYAN_EX}{output}", end="")
            if errors:
                print(f"{Fore.LIGHTRED_EX}{errors}", end="")
                
        except KeyboardInterrupt:
            print()
            break
        except Exception as e:
            print(f"{Fore.RED}[-] Error executing command: {e}{Style.RESET_ALL}")

def show_menu(client, target_ip):
    while True:
        print(f"\n{Fore.CYAN}==================================================")
        print(f"{Fore.WHITE}{Style.BRIGHT}TARGET: {Fore.GREEN}{target_ip} {Fore.WHITE}| STATUS: {Fore.RED}COMPROMISED")
        print(f"{Fore.CYAN}==================================================")
        print(f"{Fore.YELLOW}[1] {Fore.WHITE}Manual Interactive Shell")
        print(f"{Fore.YELLOW}[2] {Fore.WHITE}Reconnaissance (whoami, pwd, ls)")
        print(f"{Fore.YELLOW}[3] {Fore.WHITE}Extract AWS Credentials (cat ~/.aws/credentials)")
        print(f"{Fore.YELLOW}[4] {Fore.WHITE}Search for Passwords (grep password /var/www/*)")
        print(f"{Fore.YELLOW}[5] {Fore.WHITE}Full Automated Attack (Panel Demo)")
        print(f"{Fore.YELLOW}[99] {Fore.WHITE}Disconnect & Exit")
        print(f"{Fore.CYAN}=================================================={Style.RESET_ALL}")
        
        choice = input(f"{Fore.CYAN}Select attack vector > {Style.RESET_ALL}").strip()
        
        if choice == '1':
            interactive_shell(client, target_ip)
        elif choice == '2':
            slow_print(f"\n{Fore.YELLOW}[*] Launching system reconnaissance module...")
            execute_command(client, "whoami")
            execute_command(client, "pwd")
            execute_command(client, "ls -la")
        elif choice == '3':
            slow_print(f"\n{Fore.YELLOW}[*] Attempting to extract AWS credentials from known paths...")
            execute_command(client, "cat ~/.aws/credentials")
        elif choice == '4':
            slow_print(f"\n{Fore.YELLOW}[*] Scanning web directories for exposed secrets...")
            execute_command(client, "grep password /var/www/*")
        elif choice == '5':
            slow_print(f"\n{Fore.YELLOW}[*] INITATING AUTOMATED EXPLOITATION SEQUENCE...{Style.RESET_ALL}")
            time.sleep(1)
            execute_command(client, "whoami")
            execute_command(client, "pwd")
            execute_command(client, "ls")
            time.sleep(2)
            slow_print(f"\n{Fore.MAGENTA}[!] Suspicious directory structure detected. Scanning for secrets...{Style.RESET_ALL}")
            execute_command(client, "cat ~/.aws/credentials")
            time.sleep(2)
            execute_command(client, "cat .env")
            time.sleep(2)
            execute_command(client, "grep password /var/www/*")
            slow_print(f"\n{Fore.GREEN}[+] Attack sequence complete. Waiting for exfiltration.{Style.RESET_ALL}")
        elif choice == '99':
            print(f"{Fore.RED}[*] Terminating connection...{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}[-] Invalid selection.{Style.RESET_ALL}")

def main():
    print_banner()
    slow_print("[*] Initializing Attacker Console...", color=Fore.YELLOW)
    
    # Get connection details
    target_ip = input(f"{Fore.CYAN}[?] Enter Target Honeypot IP (e.g., 192.168.x.x): {Style.RESET_ALL}").strip()
    target_port = input(f"{Fore.CYAN}[?] Enter Target Port (default: 2222): {Style.RESET_ALL}").strip()
    username = input(f"{Fore.CYAN}[?] Enter Username (default: attacker): {Style.RESET_ALL}").strip()
    password = input(f"{Fore.CYAN}[?] Enter Password (default: password): {Style.RESET_ALL}").strip()

    # Defaults
    if not target_ip: target_ip = "127.0.0.1"
    if not target_port: target_port = 2222
    else: target_port = int(target_port)
    if not username: username = "attacker"
    if not password: password = "password"

    slow_print(f"[*] Establishing secure connection to {target_ip}:{target_port} as '{username}'...", color=Fore.YELLOW)
    
    # Initialize SSH Client
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Connect to the honeypot
        client.connect(hostname=target_ip, port=target_port, username=username, password=password, timeout=10)
        slow_print("[+] CONNECTION SUCCESSFUL! Target compromised.\n", color=Fore.GREEN)
        
        # Open the TUI Menu
        show_menu(client, target_ip)
                
    except Exception as e:
        slow_print(f"[-] CONNECTION FAILED: {e}", color=Fore.RED)
    finally:
        client.close()
        slow_print("[*] Session closed. Traces wiped.", color=Fore.YELLOW)

if __name__ == "__main__":
    main()
