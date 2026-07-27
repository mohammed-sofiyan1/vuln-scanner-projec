
+).
# Python Vulnerability Scanner

A command-line tool that scans a target host for open ports and services
using Nmap, identifies running software via CPE fingerprinting, and
cross-references findings against the National Vulnerability Database (NVD)
to surface known CVEs with CVSS-based severity scoring.

## Features
- Port and service/version detection via Nmap (`python-nmap`)
- Precise CVE matching using CPE (Common Platform Enumeration) strings,
  with automatic fallback to keyword search when a CPE can't be determined
- CVSS severity classification (Critical / High / Medium / Low)
- Multiple report formats: plain text, JSON, or CSV (or all three at once)
- Configurable port ranges, scan timeout, and output directory
- Optional NVD API key support for significantly faster scans
- Retry logic with backoff for NVD API rate limiting
- Adjustable log verbosity (quiet / normal / verbose)
- Built-in authorization confirmation prompt before scanning

## How it works
1. **Discovery** — runs an Nmap scan (`-sV`) against the target to find open
   ports and fingerprint running services.
2. **Identification** — extracts product name, version, and any CPE strings
   Nmap detected for each open port.
3. **Correlation** — queries the NVD API for matching CVEs, trying (in order
   of precision):
   1. Nmap's own detected CPE string
   2. A best-effort constructed CPE from the product/version
   3. A loose keyword search, as a last-resort fallback
4. **Reporting** — writes a timestamped report (text, JSON, and/or CSV)
   summarizing all findings, including CVSS scores and severity ratings.

## Requirements
- Python 3.9+
- Nmap installed on the system (`sudo apt install nmap`)
- Python packages listed in `requirements.txt`

## Installation
```
git clone https://github.com/mohammed-sofiyan1/vuln-scanner-projec.git
cd vuln-scanner-projec
pip install -r requirements.txt --break-system-packages
```

## Usage
```
python3 vuln_scanner.py <target> [options]
```

### Options
| Flag | Description | Default |
|---|---|---|
| `--ports` | Port range to scan, e.g. `1-1000` or `22,80,443` | Nmap's default range |
| `--format` | Report format: `txt`, `json`, `csv`, or `all` | `txt` |
| `--output-dir` | Directory to save reports in | current directory |
| `--api-key` | NVD API key for higher rate limits (or set `NVD_API_KEY` env var) | none |
| `--timeout` | Nmap scan timeout in seconds | `300` |
| `--no-confirm` | Skip the authorization confirmation prompt | off |
| `--quiet` / `--verbose` | Adjust log detail | normal |

### Examples
Basic scan:
```
python3 vuln_scanner.py 192.168.56.101
```

Scan a specific port range and export all report formats:
```
python3 vuln_scanner.py 192.168.56.101 --ports 1-1000 --format all --output-dir reports/
```

Faster scans using an NVD API key:
```
export NVD_API_KEY=your_key_here
python3 vuln_scanner.py 192.168.56.101 --verbose
```

You'll be prompted to confirm authorization before each scan begins
(unless `--no-confirm` is set).

## Example Output
<img width="650" height="442" alt="Screenshot 2026-07-25 140550" src="https://github.com/user-attachments/assets/906c32e6-51d1-4f0f-b236-d57fd83357cf" />

## Getting an NVD API Key (optional, recommended)
Without a key, NVD limits requests to ~5 per 30 seconds, so scans with many
open ports take a while. A free API key raises this to ~50 per 30 seconds.
Request one at: https://nvd.nist.gov/developers/request-an-api-key

## Authorized Use Only
This tool is intended strictly for scanning systems you own or have explicit
written permission to test — for example, personal homelab VMs or
deliberately vulnerable targets like **Metasploitable2**. Scanning systems
without authorization is illegal in most jurisdictions. This project was
built for personal cybersecurity learning and portfolio purposes.

## Roadmap / Future Improvements
- [ ] Web UI (FastAPI backend + simple frontend)
- [ ] Host discovery / subnet sweep mode (`-sn`)
- [ ] Config file support (`.env` / `config.yaml`)
- [ ] Unit tests with `pytest`
- [ ] Docker container for easy deployment

## Development Note
This project began as an AI-assisted first draft, which I then used as a
study reference — going through it function by function to understand
Nmap integration, CPE/CVE matching logic, the NVD API, and CLI design
patterns. I'm actively rewriting sections myself as I build a deeper
understanding of the codebase, and the commit history reflects that
progression.

## Author
Built by Ace as part of ongoing cybersecurity self-study
(Google Cybersecurity Certificate, CompTIA Security+ in progress).
