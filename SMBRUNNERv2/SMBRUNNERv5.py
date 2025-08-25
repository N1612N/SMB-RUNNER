#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SMBRUNNERv2
A cross-platform (Windows/Linux) SMB auto-enumeration and loot analyzer.
- Minimal deps: pysmb (required for SMB), python-dotenv (optional for env loading)
- Credentials via environment (PowerShell/CMD/Bash) or local config file.
- Caches ping/port results for 7 days to speed up repeat scans.
- Menu-driven with auto-run option 0 if no input within 5 seconds.

Author: Sanalnadh M Kattungal
Envestnet - Offensive Security [RED TEAM]
Maintainer (script revamp): SMBRUNNERv2 generator
"""

import os
import sys
import re
import json
import time
import socket
import platform
import threading
import datetime
from ipaddress import ip_network, IPv4Address, IPv4Network
from html import escape
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# ------------------------------
# ASCII Art (reused from SMBRUNNER)
# ------------------------------
ASCII_ART = r"""

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
"""

# ------------------------------
# Regex patterns (reused from SMBRUNNER)
# ------------------------------
REGEX_PATTERNS = {
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

# ------------------------------
# Globals & Paths
# ------------------------------
BASE_DIR = Path(__file__).resolve().parent
CACHE_FILE = BASE_DIR / ".smbrunner_cache.json"
CONFIG_FILE = BASE_DIR / "smbrunner_config.json"
TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOOT_DIR = BASE_DIR / f"smb_loot - {TIMESTAMP}"
CACHE_TTL = 7 * 24 * 60 * 60  # 1 week seconds

alive_hosts: List[str] = []
open_ports: Dict[str, List[int]] = {}
sensitive_info: List[Tuple[str, str, str]] = []  # (path, label, data)
summary_info: Dict[str, List[str]] = {}  # host -> list(shares)

# ------------------------------
# Utility: Timed Input
# ------------------------------
class TimedInput:
    def __init__(self):
        self.value = None

    def _thread_input(self, prompt: str):
        try:
            self.value = input(prompt)
        except Exception:
            self.value = None

    def get(self, prompt: str, timeout: int) -> Optional[str]:
        t = threading.Thread(target=self._thread_input, args=(prompt,))
        t.daemon = True
        t.start()
        t.join(timeout)
        return self.value

# ------------------------------
# Dependency checks (lazy imports)
# ------------------------------

def check_dependencies() -> Dict[str, bool]:
    status = {"pysmb": False, "dotenv": False}
    try:
        import smb  # noqa: F401
        from smb.SMBConnection import SMBConnection  # noqa: F401
        status["pysmb"] = True
    except Exception:
        status["pysmb"] = False
    try:
        import dotenv  # noqa: F401
        status["dotenv"] = True
    except Exception:
        status["dotenv"] = False
    return status

# ------------------------------
# Credentials
# ------------------------------

def load_credentials() -> Tuple[str, str, str, str]:
    """Return (user, password, domain, source). Source is 'env', 'config', or 'anonymous'."""
    user = os.getenv("SMB_USER", "")
    pwd = os.getenv("SMB_PASS", "")
    dom = os.getenv("SMB_DOMAIN", "")

    if user and (pwd or dom is not None):
        return user, pwd, dom, "env"

    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            user = data.get("SMB_USER", "")
            pwd = data.get("SMB_PASS", "")
            dom = data.get("SMB_DOMAIN", "")
            if user:
                return user, pwd, dom, "config"
        except Exception:
            pass

    return "", "", "", "anonymous"

# ------------------------------
# Cache helpers
# ------------------------------

def _load_cache() -> Dict[str, dict]:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _save_cache(cache: Dict[str, dict]) -> None:
    try:
        CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except Exception:
        pass


def _cache_key_for_target(target: str) -> str:
    return target.strip()


def get_cached_scan(target: str) -> Optional[dict]:
    cache = _load_cache()
    key = _cache_key_for_target(target)
    entry = cache.get(key)
    if not entry:
        return None
    if time.time() - entry.get("timestamp", 0) > CACHE_TTL:
        return None
    return entry


def set_cached_scan(target: str, alive: List[str], ports: Dict[str, List[int]]):
    cache = _load_cache()
    cache[_cache_key_for_target(target)] = {
        "timestamp": time.time(),
        "alive_hosts": alive,
        "open_ports": ports,
    }
    _save_cache(cache)


def clear_cache():
    global alive_hosts, open_ports
    alive_hosts = []
    open_ports = {}
    if CACHE_FILE.exists():
        try:
            CACHE_FILE.unlink()
        except Exception:
            pass

# ------------------------------
# Network helpers (ping & ports)
# ------------------------------

def is_host_alive(ip: str) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = f"ping -n 1 -w 1000 {ip} > nul 2>&1"
    else:
        cmd = f"ping -c 1 -W 1 {ip} > /dev/null 2>&1"
    return os.system(cmd) == 0


def ping_sweep(network: str) -> List[str]:
    print(f"\n[*] Scanning live hosts in: {network}")
    hosts = []
    for ip in ip_network(network, strict=False).hosts():
        sip = str(ip)
        if is_host_alive(sip):
            print(f"[+] Host alive: {sip}")
            hosts.append(sip)
    return hosts


def scan_ports(ip: str, ports: List[int] = [139, 445]) -> List[int]:
    openp: List[int] = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    openp.append(port)
        except Exception:
            pass
    if openp:
        print(f"[+] {ip} open ports: {openp}")
    return openp


def do_port_scan(ips: List[str]) -> Dict[str, List[int]]:
    results: Dict[str, List[int]] = {}
    for ip in ips:
        ports = scan_ports(ip)
        if ports:
            results[ip] = ports
    return results

# ------------------------------
# SMB enumeration & download
# ------------------------------

def smb_enum_and_loot(target_ips: List[str], creds: Tuple[str, str, str]) -> None:
    try:
        from smb.SMBConnection import SMBConnection
    except Exception:
        print("[-] pysmb module is not installed. Install with: pip install pysmb")
        return

    user, pwd, dom = creds

    for ip in target_ips:
        ports = open_ports.get(ip, [])
        if not ports:
            continue

        try:
            # Try both 445 then 139
            connected = False
            conn = SMBConnection(user or "", pwd or "", "smbrunner", "target", domain=dom or "", use_ntlm_v2=True)
            for p in [445, 139]:
                try:
                    if p in ports and conn.connect(ip, p, timeout=10):
                        connected = True
                        break
                except Exception:
                    pass

            if not connected:
                print(f"[!] Unable to connect SMB on {ip}")
                continue

            if user:
                print(f"[+] Authenticated login success on {ip} as {user}")
            else:
                print(f"[+] Anonymous login success: {ip}")

            shares = conn.listShares()
            for share in shares:
                if getattr(share, 'isSpecial', False) or share.name in ["ADMIN$", "C$", "IPC$"]:
                    continue
                print(f"[*] Accessing share: {share.name}")
                summary_info.setdefault(ip, []).append(share.name)
                download_share(conn, share.name, ip)

            conn.close()
        except Exception as e:
            print(f"[!] SMB error on {ip}: {e}")


def download_share(conn, share_name: str, ip: str, path: str = "") -> None:
    base = LOOT_DIR / f"{share_name}_{ip}"
    try:
        files = conn.listPath(share_name, (path + "/") if path else "/")
        for f in files:
            if f.filename in [".", ".."]:
                continue
            remote_path = f"{path}/{f.filename}" if path else f.filename
            if f.isDirectory:
                download_share(conn, share_name, ip, remote_path)
            else:
                dest = base / remote_path.replace('/', '_')
                dest.parent.mkdir(parents=True, exist_ok=True)
                with open(dest, 'wb') as h:
                    conn.retrieveFile(share_name, remote_path, h)
                print(f"[+] Downloaded: {share_name}:{remote_path}")
    except Exception as e:
        print(f"[!] Download error from {share_name} on {ip}: {e}")

# ------------------------------
# Sensitive data scan & reports
# ------------------------------

def scan_sensitive_data(base_path: Path) -> None:
    global sensitive_info
    sensitive_info.clear()
    for root, _, files in os.walk(base_path):
        for name in files:
            fp = Path(root) / name
            try:
                with open(fp, 'r', errors='ignore', encoding='utf-8', newline='') as f:
                    for line in f:
                        for label, pattern in REGEX_PATTERNS.items():
                            if re.search(pattern, line, re.DOTALL):
                                sensitive_info.append((str(fp), label, line.strip()))
            except Exception:
                # fallback binary read for some files
                try:
                    with open(fp, 'rb') as bf:
                        data = bf.read().decode('utf-8', errors='ignore')
                        for label, pattern in REGEX_PATTERNS.items():
                            if re.search(pattern, data, re.DOTALL):
                                sensitive_info.append((str(fp), label, '<binary-match>'))
                except Exception:
                    continue

def generate_report(data, formats=None):
    from datetime import datetime
    import os, json

    if not formats or len(formats) == 0:
        # If no format chosen, generate ALL
        formats = ["txt", "json", "html"]

    # Always a string path
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join("reports", timestamp)
    os.makedirs(report_dir, exist_ok=True)

    for fmt in formats:
        report_path = os.path.join(report_dir, f"report.{fmt}")

        if fmt == "txt":
            with open(report_path, "w") as f:
                f.write("=== SMBRUNNER Report ===\n")
                f.write(json.dumps(data, indent=2))
        
        elif fmt == "json":
            with open(report_path, "w") as f:
                json.dump(data, f, indent=2)
        
        elif fmt == "html":
            with open(report_path, "w") as f:
                f.write("<html><body><h1>SMBRUNNER Report</h1><pre>")
                f.write(json.dumps(data, indent=2))
                f.write("</pre></body></html>")

    print(f"[+] Report(s) saved in: {report_dir}")

# ------------------------------
# Summary
# ------------------------------

def print_summary():
    print("\n========== Summary ==========")
    if alive_hosts:
        print(f"Alive Hosts ({len(alive_hosts)}):")
        for h in alive_hosts:
            print(f"  - {h}")
    else:
        print("Alive Hosts: none")

    if open_ports:
        print("\nOpen SMB Ports:")
        for ip, ports in open_ports.items():
            print(f"  - {ip}: {ports}")
    else:
        print("\nOpen SMB Ports: none")

    if summary_info:
        print("\nShares:")
        for host, shares in summary_info.items():
            print(f"  - {host}:")
            for s in shares:
                print(f"      * {s}")
    else:
        print("\nShares: none")

    if sensitive_info:
        print("\nSensitive Findings (category -> sample lines):")
        by_cat: Dict[str, int] = {}
        for _, label, _ in sensitive_info:
            by_cat[label] = by_cat.get(label, 0) + 1
        for k, v in sorted(by_cat.items(), key=lambda x: (-x[1], x[0])):
            print(f"  - {k}: {v}")
    else:
        print("\nSensitive Findings: none")
    print("============================\n")

# ------------------------------
# Input validation
# ------------------------------

def validate_target_input(s: str) -> Tuple[Optional[str], Optional[str]]:
    s = (s or "").strip()
    # Single IP
    try:
        IPv4Address(s.split('/')[0])
        # IP or IP/CIDR
        if '/' in s:
            # Ensure valid network; allow host bits (strict=False)
            ip_network(s, strict=False)
            return s, 'subnet'
        else:
            return s, 'ip'
    except Exception:
        pass

    # Pure CIDR like 192.168.1.0/24
    try:
        ip_network(s, strict=False)
        return s, 'subnet'
    except Exception:
        return None, None

# ------------------------------
# High-level workflows
# ------------------------------

def do_automatic_scan(creds: Tuple[str, str, str]):
    # Determine current subnet
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        octets = local_ip.split('.')
        network = '.'.join(octets[:3]) + '.0/24'
    except Exception:
        print("[-] Could not determine local subnet. Please use option 1.")
        return

    do_target_scan(network, creds, skip_ping=False, exit_after=True)


def do_target_scan(target: str, creds: Tuple[str, str, str], skip_ping: bool, exit_after: bool):
    global alive_hosts, open_ports

    # Use cache if fresh
    cached = get_cached_scan(target)
    if cached:
        print(f"[*] Using cached discovery for {target} (<=7 days old)")
        alive_hosts = cached.get('alive_hosts', [])
        open_ports = cached.get('open_ports', {})
    else:
        if skip_ping:
            alive_hosts = [target] if validate_target_input(target)[1] == 'ip' else []
        else:
            if validate_target_input(target)[1] == 'ip':
                alive_hosts = [target] if is_host_alive(target) else []
            else:
                alive_hosts = ping_sweep(target)

        open_ports = do_port_scan(alive_hosts)
        set_cached_scan(target, alive_hosts, open_ports)

    if not open_ports:
        print("[!] No SMB ports open on discovered hosts.")
    else:
        smb_enum_and_loot(list(open_ports.keys()), creds)

    # Secret scan & report
    if LOOT_DIR.exists():
        scan_sensitive_data(LOOT_DIR)
        generate_report(LOOT_DIR, ['txt', 'json', 'html'])

    print_summary()

    if exit_after:
        sys.exit(0)

# ------------------------------
# Menus & options
# ------------------------------

def list_loot_folders() -> List[Path]:
    items = []
    for p in BASE_DIR.iterdir():
        if p.is_dir() and str(p.name).startswith("smb_loot - "):
            items.append(p)
    return sorted(items)


def option_sensitive_scan_existing():
    folders = list_loot_folders()
    if not folders:
        print("[-] No loot folders found in working directory.")
        return
    print("\nAvailable loot folders:")
    for idx, p in enumerate(folders, start=1):
        print(f"  {idx}. {p.name}")
    choice = input("Select folder number to scan: ").strip()
    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(folders):
            print("[-] Invalid selection.")
            return
    except Exception:
        print("[-] Invalid selection.")
        return

    folder = folders[idx]
    scan_sensitive_data(folder)
    print_summary()
    yn = input("Generate report? (y/N): ").strip().lower()
    if yn == 'y':
        fmts = input("Formats [txt,json,html] (comma-separated, default=txt,json,html): ").strip()
        formats = [x.strip().lower() for x in (fmts or 'txt,json,html').split(',') if x.strip()]
        generate_report(folder, formats)


def option_enumerate_live_hosts():
    target = input("Enter subnet or IP: ").strip()
    t, kind = validate_target_input(target)
    if not t:
        print("[-] Invalid input.")
        return
    if kind == 'ip':
        hosts = [t] if is_host_alive(t) else []
    else:
        hosts = ping_sweep(t)
    global alive_hosts
    alive_hosts = hosts
    set_cached_scan(t, alive_hosts, {})
    print_summary()


def option_enumerate_open_ports():
    target = input("Enter subnet or IP: ").strip()
    t, kind = validate_target_input(target)
    if not t:
        print("[-] Invalid input.")
        return
    if kind == 'ip':
        hosts = [t] if is_host_alive(t) else []
    else:
        hosts = ping_sweep(t)
    ports = do_port_scan(hosts)
    global alive_hosts, open_ports
    alive_hosts = hosts
    open_ports = ports
    set_cached_scan(t, alive_hosts, open_ports)
    print_summary()


def option_generate_report_for_current():
    if not LOOT_DIR.exists():
        print("[-] No current loot directory yet.")
    fmts = input("Report formats (txt,json,html) [default=txt,json,html]: ").strip()
    formats = [x.strip().lower() for x in (fmts or 'txt,json,html').split(',') if x.strip()]
    if not sensitive_info:
        if LOOT_DIR.exists():
            scan_sensitive_data(LOOT_DIR)
        else:
            print("[-] Nothing to report.")
            return
    generate_report(LOOT_DIR, formats)


# ------------------------------
# Banner & environment info
# ------------------------------

def print_banner_and_env():
    print(ASCII_ART)
    print(f"[*] Platform: {platform.system()}")
    deps = check_dependencies()
    ready = deps.get('pysmb', False)
    print(f"[*] Dependency check: pysmb={'OK' if deps['pysmb'] else 'MISSING'}, dotenv={'OK' if deps['dotenv'] else 'MISSING (optional)'}")
    print(f"[*] Script readiness: {'READY' if ready else 'NOT READY (pysmb required)'}")

    user, pwd, dom, src = load_credentials()
    if user:
        print(f"[+] Credentials source: {src} | Username: {user} | Domain: {dom or '(none)'}")
    else:
        print("[!] No credentials configured (env or config). Proceeding with ANONYMOUS access where possible.")


# ------------------------------
# Main
# ------------------------------

def main():
    print_banner_and_env()

    # Ensure loot dir exists early (some options may use it)
    LOOT_DIR.mkdir(parents=True, exist_ok=True)

    timed = TimedInput()
    print(
        """
================== MENU ==================
0: Automatic Scanning
1: Target Network or IP Address
2: Enumerate Live Hosts
3: Enumerate Open Ports
4: Sensitive Information Scan
5: Generate Report
6: Display Summary
7: Clear Cache
9: Exit
==========================================
"""
    )

    choice = timed.get("Select option [Default=0 in 5s]: ", 5)
    if not choice:
        choice = "0"
    choice = choice.strip()

    # Load credentials once for actions that need it
    user, pwd, dom, _src = load_credentials()
    creds = (user, pwd, dom)

    if choice == "9":
        print("Exiting...")
        sys.exit(0)

    elif choice == "7":
        clear_cache()
        print("[+] Cache cleared and in-memory data reset.")

    elif choice == "6":
        print_summary()

    elif choice == "5":
        option_generate_report_for_current()

    elif choice == "4":
        option_sensitive_scan_existing()

    elif choice == "3":
        option_enumerate_open_ports()

    elif choice == "2":
        option_enumerate_live_hosts()

    elif choice == "1":
        attempts = 0
        while attempts < 3:
            target = input("Enter subnet or IP (e.g., 10.152.10.15/24 or 10.152.10.15): ").strip()
            t, kind = validate_target_input(target)
            if not t:
                attempts += 1
                print(f"[-] Invalid input. Attempts: {attempts}/3")
                if attempts >= 3:
                    print("[-] Too many invalid attempts. Exiting.")
                    sys.exit(1)
                continue
            skip_ping = (kind == 'ip')
            do_target_scan(t, creds, skip_ping=skip_ping, exit_after=True)
            break

    elif choice == "0":
        do_automatic_scan(creds)

    else:
        print("[-] Invalid selection.")


if __name__ == '__main__':
    try:
        # Optional: auto-load .env if python-dotenv is present
        try:
            from dotenv import load_dotenv  # type: ignore
            load_dotenv()
        except Exception:
            pass
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.")
        sys.exit(130)
