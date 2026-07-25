#!/usr/bin/env python3
"""
Vulnerability Scanner
---------------------
Scans a target for open ports/services using Nmap, identifies running
software via CPE fingerprinting, and cross-references findings against the
National Vulnerability Database (NVD) to surface known CVEs with CVSS
severity scoring.

USAGE:
    python3 vuln_scanner.py <target> [options]

EXAMPLES:
    python3 vuln_scanner.py 192.168.56.101
    python3 vuln_scanner.py 192.168.56.101 --ports 1-1000 --format json
    python3 vuln_scanner.py 192.168.56.101 --format all --output-dir reports/
    python3 vuln_scanner.py 192.168.56.101 --no-confirm --quiet

AUTHORIZED USE ONLY:
    Only scan systems you own or have explicit written permission to test.
    Scanning systems without authorization is illegal in most jurisdictions.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests

try:
    import nmap
except ImportError:
    print("ERROR: python-nmap is not installed. Run: pip install python-nmap --break-system-packages")
    sys.exit(1)


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_API_RETRIES = 3
DEFAULT_RATE_LIMIT_SECONDS = 6      # safe default without an API key
API_KEY_RATE_LIMIT_SECONDS = 0.6    # NVD allows ~50 req/30s with a key

logger = logging.getLogger("vuln_scanner")


# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------

@dataclass
class CVEMatch:
    cve_id: str
    cvss_score: str
    severity: str
    description: str


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    cpe_list: list[str] = field(default_factory=list)
    cves: list[CVEMatch] = field(default_factory=list)
    match_method: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------
# Logging setup
# --------------------------------------------------------------------------

def setup_logging(verbosity: str) -> None:
    level = {"quiet": logging.WARNING, "normal": logging.INFO, "verbose": logging.DEBUG}[verbosity]
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


# --------------------------------------------------------------------------
# CVSS severity classification
# --------------------------------------------------------------------------

def classify_severity(score) -> str:
    """Map a CVSS base score to the standard severity band."""
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

def scan_target(target: str, port_range: Optional[str], timeout: int) -> tuple[str, list[PortResult]]:
    """Run an Nmap scan with service/version detection. Returns (resolved_target, results)."""
    logger.info(f"[*] Starting scan on {target} ...")
    scanner = nmap.PortScanner()

    args = "-sV -T4"
    if port_range:
        args += f" -p {port_range}"

    try:
        scanner.scan(target, arguments=args, timeout=timeout)
    except nmap.PortScannerError as e:
        logger.error(f"[!] Nmap error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"[!] Scan failed: {e}")
        sys.exit(1)

    hosts = scanner.all_hosts()
    if not hosts:
        logger.error("[!] No hosts found. Is the target reachable? "
                      "(Check firewall rules, VM networking mode, or permissions - "
                      "some scan types need sudo.)")
        sys.exit(1)

    resolved_target = target if target in hosts else hosts[0]

    results: list[PortResult] = []
    for proto in scanner[resolved_target].all_protocols():
        for port in sorted(scanner[resolved_target][proto].keys()):
            data = scanner[resolved_target][proto][port]

            raw_cpe = data.get("cpe", "")
            if isinstance(raw_cpe, list):
                cpe_list = [c for c in raw_cpe if c]
            elif raw_cpe:
                cpe_list = [raw_cpe]
            else:
                cpe_list = []

            results.append(PortResult(
                port=port,
                protocol=proto,
                state=data.get("state", ""),
                service=data.get("name", ""),
                product=data.get("product", ""),
                version=data.get("version", ""),
                cpe_list=cpe_list,
            ))

    return resolved_target, results


def build_cpe_string(product: str, version: str) -> Optional[str]:
    """Best-effort CPE 2.3 construction when nmap didn't provide one directly."""
    if not product:
        return None
    vendor_guess = product.lower().split()[0]
    product_guess = product.lower().replace(" ", "_")
    version_part = version if version else "*"
    return f"cpe:2.3:a:{vendor_guess}:{product_guess}:{version_part}:*:*:*:*:*:*:*"


# --------------------------------------------------------------------------
# NVD lookups
# --------------------------------------------------------------------------

class NVDClient:
    """Thin client around the NVD REST API with retry + rate-limit handling."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.rate_limit = API_KEY_RATE_LIMIT_SECONDS if api_key else DEFAULT_RATE_LIMIT_SECONDS
        self.headers = {"apiKey": api_key} if api_key else {}

    def _request(self, params: dict) -> Optional[dict]:
        for attempt in range(1, MAX_API_RETRIES + 1):
            try:
                resp = requests.get(NVD_API_URL, params=params, headers=self.headers, timeout=15)
                logger.debug(f"    [debug] NVD status: {resp.status_code} (attempt {attempt})")

                if resp.status_code == 200:
                    return resp.json()

                if resp.status_code == 429:
                    wait = 10 * attempt
                    logger.warning(f"    [!] Rate limited by NVD, waiting {wait}s before retry...")
                    time.sleep(wait)
                    continue

                logger.debug(f"    [debug] NVD non-200 body: {resp.text[:200]}")
                return None

            except requests.exceptions.Timeout:
                logger.warning(f"    [!] NVD request timed out (attempt {attempt}/{MAX_API_RETRIES})")
            except requests.exceptions.RequestException as e:
                logger.warning(f"    [!] NVD request failed: {e}")
                return None

        return None

    def _parse_matches(self, data: dict) -> list[CVEMatch]:
        matches = []
        for item in data.get("vulnerabilities", []):
            cve_id = item["cve"]["id"]
            descriptions = item["cve"].get("descriptions", [])
            desc_text = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

            metrics = item["cve"].get("metrics", {})
            score = "N/A"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    score = metrics[key][0]["cvssData"].get("baseScore", "N/A")
                    break

            matches.append(CVEMatch(
                cve_id=cve_id,
                cvss_score=str(score),
                severity=classify_severity(score),
                description=desc_text[:250],
            ))
        return matches

    def query_by_cpe(self, cpe_string: str) -> list[CVEMatch]:
        if not cpe_string:
            return []
        logger.debug(f"    [debug] Querying NVD by CPE: '{cpe_string}'")
        data = self._request({"virtualMatchString": cpe_string, "resultsPerPage": 10})
        time.sleep(self.rate_limit)
        return self._parse_matches(data) if data else []

    def query_by_keyword(self, product: str, version: str) -> list[CVEMatch]:
        if not product:
            return []
        keyword = f"{product} {version}".strip()
        logger.debug(f"    [debug] Querying NVD by keyword: '{keyword}'")
        data = self._request({"keywordSearch": keyword, "resultsPerPage": 10})
        time.sleep(self.rate_limit)
        return self._parse_matches(data) if data else []


def enrich_with_cves(results: list[PortResult], client: NVDClient) -> None:
    """Populate .cves and .match_method on each PortResult, trying the most
    precise method first and falling back progressively."""
    for r in results:
        logger.info(f"  Port {r.port}/{r.protocol} - {r.service} {r.product} {r.version}".rstrip())

        if not r.product:
            logger.info("    -> No product identified by Nmap; skipping CVE lookup")
            continue

        cves: list[CVEMatch] = []
        method = None

        for cpe in r.cpe_list:
            cves = client.query_by_cpe(cpe)
            if cves:
                method = f"nmap-detected CPE ({cpe})"
                break

        if not cves:
            guessed = build_cpe_string(r.product, r.version)
            if guessed:
                cves = client.query_by_cpe(guessed)
                if cves:
                    method = f"guessed CPE ({guessed})"

        if not cves:
            cves = client.query_by_keyword(r.product, r.version)
            if cves:
                method = "keyword search (fallback)"

        r.cves = cves
        r.match_method = method

        if cves:
            logger.info(f"    [match method: {method}]")
            for cve in sorted(cves, key=lambda c: c.cvss_score, reverse=True):
                logger.info(f"    -> {cve.cve_id} [{cve.severity}] (CVSS: {cve.cvss_score})")
        else:
            logger.info("    -> No CVEs matched (tried CPE and keyword search)")


# --------------------------------------------------------------------------
# Report generation
# --------------------------------------------------------------------------

def write_text_report(target: str, results: list[PortResult], path: Path) -> None:
    with open(path, "w") as f:
        f.write("VULNERABILITY SCAN REPORT\n")
        f.write(f"Target: {target}\n")
        f.write(f"Date:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        if not results:
            f.write("No open ports found.\n")
            return

        for r in results:
            f.write(f"Port {r.port}/{r.protocol} - {r.state}\n")
            f.write(f"  Service: {r.service} | Product: {r.product} | Version: {r.version}\n")
            if r.cves:
                f.write(f"  Match method: {r.match_method}\n")
                f.write("  Potential CVEs:\n")
                for cve in r.cves:
                    f.write(f"    - {cve.cve_id} [{cve.severity}] (CVSS: {cve.cvss_score})\n")
                    f.write(f"      {cve.description}\n")
            else:
                f.write("  No CVEs found (or product/version not identified).\n")
            f.write("\n")


def write_json_report(target: str, results: list[PortResult], path: Path) -> None:
    payload = {
        "target": target,
        "scan_date": datetime.now().isoformat(),
        "ports": [r.to_dict() for r in results],
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


def write_csv_report(target: str, results: list[PortResult], path: Path) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["port", "protocol", "service", "product", "version",
                          "cve_id", "severity", "cvss_score", "match_method"])
        for r in results:
            if r.cves:
                for cve in r.cves:
                    writer.writerow([r.port, r.protocol, r.service, r.product, r.version,
                                      cve.cve_id, cve.severity, cve.cvss_score, r.match_method])
            else:
                writer.writerow([r.port, r.protocol, r.service, r.product, r.version,
                                  "", "", "", ""])


def print_summary(results: list[PortResult]) -> None:
    total_cves = sum(len(r.cves) for r in results)
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    for r in results:
        for cve in r.cves:
            severity_counts[cve.severity] = severity_counts.get(cve.severity, 0) + 1

    logger.info("\n" + "=" * 60)
    logger.info(" SCAN SUMMARY")
    logger.info("=" * 60)
    logger.info(f" Open ports scanned : {len(results)}")
    logger.info(f" Total CVEs found   : {total_cves}")
    for sev in ("Critical", "High", "Medium", "Low"):
        if severity_counts.get(sev):
            logger.info(f"   {sev:<9}: {severity_counts[sev]}")
    logger.info("=" * 60)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan a target for open ports and known CVEs (Nmap + NVD).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--ports", default=None,
                         help="Port range to scan, e.g. 1-1000 or 22,80,443 (default: Nmap's default range)")
    parser.add_argument("--format", choices=["txt", "json", "csv", "all"], default="txt",
                         help="Report output format (default: txt)")
    parser.add_argument("--output-dir", default=".", help="Directory to save reports in (default: current dir)")
    parser.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"),
                         help="NVD API key for higher rate limits (or set NVD_API_KEY env var)")
    parser.add_argument("--timeout", type=int, default=300, help="Nmap scan timeout in seconds (default: 300)")
    parser.add_argument("--no-confirm", action="store_true",
                         help="Skip the authorization confirmation prompt (use with caution)")
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("--quiet", action="store_const", dest="verbosity", const="quiet")
    verbosity.add_argument("--verbose", action="store_const", dest="verbosity", const="verbose")
    parser.set_defaults(verbosity="normal")
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    setup_logging(args.verbosity)

    logger.info("=" * 60)
    logger.info(" Vulnerability Scanner")
    logger.info(" For authorized use on your own systems/homelab only")
    logger.info("=" * 60)

    if not args.no_confirm:
        logger.warning("\n[!] Reminder: only scan systems you own or are authorized to test.")
        confirm = input(f"Proceed with scanning '{args.target}'? (yes/no): ").strip().lower()
        if confirm != "yes":
            logger.info("Aborted.")
            sys.exit(0)

    if args.api_key:
        logger.info("[*] Using NVD API key (higher rate limit enabled)")
    else:
        logger.info("[*] No NVD API key set - using conservative rate limiting "
                     "(set NVD_API_KEY env var or --api-key to speed this up)")

    try:
        resolved_target, results = scan_target(args.target, args.ports, args.timeout)
        logger.info(f"\n[+] Found {len(results)} open port(s). Checking for CVEs...\n")

        client = NVDClient(api_key=args.api_key)
        enrich_with_cves(results, client)

        print_summary(results)

        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = int(time.time())
        safe_target = resolved_target.replace(".", "_").replace(":", "_")
        base = output_dir / f"scan_report_{safe_target}_{stamp}"

        formats = ["txt", "json", "csv"] if args.format == "all" else [args.format]
        for fmt in formats:
            path = base.with_suffix(f".{fmt}")
            if fmt == "txt":
                write_text_report(resolved_target, results, path)
            elif fmt == "json":
                write_json_report(resolved_target, results, path)
            elif fmt == "csv":
                write_csv_report(resolved_target, results, path)
            logger.info(f"[+] Report saved to: {path}")

    except KeyboardInterrupt:
        logger.warning("\n[!] Scan interrupted by user. Exiting.")
        sys.exit(130)


if __name__ == "__main__":
    main()

