<img width="650" height="442" alt="Screenshot 2026-07-25 140550" src="https://github.com/user-attachments/assets/906c32e6-51d1-4f0f-b236-d57fd83357cf" />
Python Vulnerability Scanner

A lightweight CLI tool that scans a target host for open ports and services using Nmap, then cross-references detected service versions against the National Vulnerability Database (NVD) to identify known CVEs.

Features
Port and service/version detection via Nmap (python-nmap)
Automated CVE lookup against the public NVD REST API
CVSS severity scoring for each matched vulnerability
Plain-text report generation with timestamps
Built-in authorization confirmation prompt before scanning
How it works
Discovery — runs an Nmap scan (-sV) against the target to find open ports and fingerprint running services.
Identification — extracts product name and version for each detected service.
Correlation — queries the NVD API using the identified product/version as keywords to find matching CVE records and CVSS scores.
Reporting — writes a timestamped report file summarizing all findings.
Requirements
Python 3.8+
Nmap installed on the system (sudo apt install nmap)
Python packages listed in requirements.txt
Installation
bash
git clone https://github.com/<your-username>/vuln-scanner-project.git
cd vuln-scanner-project
pip install -r requirements.txt --break-system-packages
Usage
bash
python3 vuln_scanner.py <target_ip_or_hostname>

Example:

bash
python3 vuln_scanner.py 192.168.56.101

You'll be prompted to confirm authorization before the scan begins.

⚠️ Authorized Use Only

This tool is intended strictly for scanning systems you own or have explicit written permission to test — for example, personal homelab VMs or deliberately vulnerable targets like Metasploitable2. Scanning systems without authorization is illegal in most jurisdictions. This project was built for personal cybersecurity learning and portfolio purposes.

Roadmap / Future Improvements
 CPE-based CVE matching (more precise than keyword search)
 JSON/CSV export alongside text reports
 Optional --ports flag for targeted port ranges
 NVD API key support for higher rate limits
 Simple web UI (FastAPI) wrapping the scan engine
Author

Built by Mohammed Sofiyan  as part of ongoing cybersecurity self-study (Google Cybersecurity Certificate, CompTIA Security+).
