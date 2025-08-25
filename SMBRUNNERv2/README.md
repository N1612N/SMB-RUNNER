SMBRUNNERv2

A lightweight cross-platform tool for SMB share enumeration, looting, and sensitive data extraction.
Works on Windows & Linux, no external dependencies required once packaged into an executable.

✨ Features

ASCII art banner (old-school touch).

Platform detection (Windows/Linux).

Self-check for environment and dependencies.

Credential handling:

Uses exported environment variables (SMB_USER, SMB_PASS, SMB_DOMAIN).

Or reads from smbrunner_config.json.

Falls back to anonymous access if none found.

Automatic and manual scanning modes.

Ping sweep & port scan (139, 445).

SMB share enumeration & file download (loot stored locally).

Regex-based sensitive information search.

Reporting in TXT, JSON, or HTML.

Built-in cache for ping/port scans (1 week).

Menu-driven interface with auto-run (Option 0 after 5 seconds).

📋 Menu Options
0: Automatic Scanning
1: Target Network or IP Address
2: Enumerate Live Hosts
3: Enumerate Open Ports
4: Sensitive Information Scan
5: Generate Report
6: Display Summary
7: Clear Saved Data
9: Exit

🔍 Option 0: Automatic Scanning

Detects current subnet automatically.

Performs ping scan → port scan → SMB authentication → share enumeration.

Downloads files to a unique loot folder.

Extracts secrets and generates a report.

Displays final summary.

🎯 Option 1: Target Network or IP

Accepts subnet (CIDR, e.g. 10.152.10.15/24) or single IP.

Validates input (3 invalid attempts = exit).

For subnet → ping + port scan.

For single IP → skips ping and goes straight to SMB.

Enumerates shares, downloads loot, scans for secrets, generates report, shows summary, then exits.

🌐 Option 2: Enumerate Live Hosts

Input subnet/IP.

Performs ping sweep.

Displays live hosts.

🔓 Option 3: Enumerate Open Ports

Input subnet/IP.

Performs ping + SMB port scan.

Displays results.

🕵️ Option 4: Sensitive Info Scan

Lists loot folders.

User selects one.

Regex patterns applied on downloaded files.

Displays matches.

Asks if report should be generated.

📑 Option 5: Generate Report

Prompts for format (txt, json, html).

Builds report from current scan data.

📊 Option 6: Display Summary

Shows results in a clean structured format:

Live hosts

Open ports

Secrets found

Secret categories

🔄 Option 7: Clear Saved Data

Wipes cached live hosts / open ports.

Useful if rescanning the same network.

🚪 Option 9: Exit

Clean exit from the program.

⚙️ Installation & Usage
1. Clone
git clone https://github.com/yourusername/SMBRUNNERv2.git
cd SMBRUNNERv2

2. Run with Python (if not using executable)
pip install pysmb python-dotenv
python SMBRUNNERv2.py

3. Build Executable (Optional)

With PyInstaller:

pip install pyinstaller
pyinstaller --onefile --clean SMBRUNNERv2.py


Output:

Windows → dist/SMBRUNNERv2.exe

Linux → dist/SMBRUNNERv2

4. Credentials

Either export to shell:

# Bash
export SMB_USER=username
export SMB_PASS=password
export SMB_DOMAIN=domain


or create a smbrunner_config.json next to the executable:

{
  "SMB_USER": "username",
  "SMB_PASS": "password",
  "SMB_DOMAIN": "domain"
}


If neither is found → runs as anonymous.

📂 Loot Storage

All downloaded SMB files stored in loot_<timestamp>/.

Each run creates a unique folder.

📝 Notes

Works on Windows & Linux.

ping must be available in $PATH. (Default on Windows; almost always installed on Linux).

If packaged into .exe / binary → no Python required on the target system.

AV false positives may occur on Windows (common with PyInstaller onefile binaries).

⚠️ Disclaimer

This tool is for authorized penetration testing and security research only.
Do not use against networks without proper permission.