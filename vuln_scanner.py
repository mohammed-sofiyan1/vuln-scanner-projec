#!/usr/bin/env python3
"""
Simple Vulnerability Scanner.
----------------------------
Scans a target for open ports/services using nmap, then checks
detected service versions against the NVD (National Vulnerability
Database) API for known CVEs.

USAGE:
    python3 vuln_scanner.py <target_ip_or_host>

EXAMPLE:
    python3 vuln_scanner.py 192.168.1.10

IMPORTANT:
    Only scan systems you own or have explicit written permission to scan.
    Scanning systems without authorization is illegal in most jurisdictions.
"""

import sys
import json
import time
import requests
import nmap
from datetime import datetime

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def banner():
    print("=" * 60)
    print(" Simple Vulnerability Scanner")
    print(" For authorized use on your own systems/homelab only")
    print("=" * 60)


def scan_target(target):
    """Run an nmap scan with service/version detection."""
    print(f"\n[*] Starting scan on {target} ...")
    scanner = nmap.PortScanner()

    try:
        # -sV = service/version detection, -T4 = faster timing
        scanner.scan(target, arguments="-sV -T4")
    except Exception as e:
        print(f"[!] Scan failed: {e}")
        sys.exit(1)

    if target not in scanner.all_hosts():
        # nmap sometimes resolves hostnames differently; grab whatever host it found
        hosts = scanner.all_hosts()
        if not hosts:
            print("[!] No hosts found. Is the target reachable?")
            sys.exit(1)
        target = hosts[0]

    results = []
    for proto in scanner[target].all_protocols():
        ports = scanner[target][proto].keys()
        for port in sorted(ports):
            data = scanner[target][proto][port]
            results.append({
                "port": port,
                "protocol": proto,
                "state": data.get("state", ""),
                "service": data.get("name", ""),
                "product": data.get("product", ""),
                "version": data.get("version", ""),
            })

    return results


def query_nvd(product, version):
    """Query NVD API for CVEs matching a product/version keyword search."""
    if not product:
        return []

    keyword = f"{product} {version}".strip()
    params = {"keywordSearch": keyword, "resultsPerPage": 5}

    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=15)
        if resp.status_code != 200:
            return []
        data = resp.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve_id = item["cve"]["id"]
            descriptions = item["cve"].get("descriptions", [])
            desc_text = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
            # Try to grab a CVSS score if available
            metrics = item["cve"].get("metrics", {})
            score = "N/A"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    score = metrics[key][0]["cvssData"].get("baseScore", "N/A")
                    break
            cves.append({"id": cve_id, "score": score, "description": desc_text[:200]})
        return cves
    except requests.exceptions.RequestException:
        return []


def generate_report(target, results, filename):
    """Write a plain-text report to disk."""
    with open(filename, "w") as f:
        f.write("VULNERABILITY SCAN REPORT\n")
        f.write(f"Target: {target}\n")
        f.write(f"Date:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        if not results:
            f.write("No open ports found.\n")
            return

        for r in results:
            f.write(f"Port {r['port']}/{r['protocol']} - {r['state']}\n")
            f.write(f"  Service: {r['service']} | Product: {r['product']} | Version: {r['version']}\n")

            if r.get("cves"):
                f.write("  Potential CVEs:\n")
                for cve in r["cves"]:
                    f.write(f"    - {cve['id']} (CVSS: {cve['score']})\n")
                    f.write(f"      {cve['description']}\n")
            else:
                f.write("  No CVEs found (or product/version not identified).\n")
            f.write("\n")

    print(f"\n[+] Report saved to: {filename}")


def main():
    banner()

    if len(sys.argv) != 2:
        print("\nUsage: python3 vuln_scanner.py <target_ip_or_host>")
        sys.exit(1)

    target = sys.argv[1]

    print(f"\n[!] Reminder: only scan systems you own or are authorized to test.")
    confirm = input(f"Proceed with scanning '{target}'? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        sys.exit(0)

    results = scan_target(target)

    print(f"\n[+] Found {len(results)} open port(s). Checking for CVEs...\n")

    for r in results:
        print(f"  Port {r['port']}/{r['protocol']} - {r['service']} "
              f"{r['product']} {r['version']}".strip())

        cves = query_nvd(r["product"], r["version"])
        r["cves"] = cves

        if cves:
            for cve in cves:
                print(f"    -> {cve['id']} (CVSS: {cve['score']})")
        else:
            print("    -> No CVEs matched")

        # Be polite to the NVD API (rate limit: ~5 requests per 30s without a key)
        time.sleep(6)

    filename = f"scan_report_{target.replace('.', '_')}_{int(time.time())}.txt"
    generate_report(target, results, filename)


if __name__ == "__main__":
    main()
