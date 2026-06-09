#!/usr/bin/env python3
"""
EdgeReveal - Cloudflare Origin Revealer
Find real IP addresses behind Cloudflare protection by scanning subdomains.
"""

__version__ = "1.1.0"

import argparse
import csv
import json
import os
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    AddressValueError,
)
from pathlib import Path
from typing import Optional, TextIO

import dns.resolver
import pyfiglet
import requests
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)

# Resolve the directory where this script lives so the bundled wordlist can be found.
SCRIPT_DIR = Path(__file__).parent.resolve()


class Colors:
    """Terminal color constants."""
    RED = Fore.RED
    GREEN = Fore.GREEN
    BLUE = Fore.LIGHTBLUE_EX
    YELLOW = Fore.LIGHTYELLOW_EX
    WHITE = Fore.WHITE
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    RESET = Style.RESET_ALL


class OutputFormat(Enum):
    """Output format types."""
    NORMAL = "normal"
    JSON = "json"
    YAML = "yaml"
    CSV = "csv"


@dataclass
class ResolveResult:
    """Result of a DNS resolution attempt."""
    domain: str
    ipv4: list = field(default_factory=list)
    ipv6: list = field(default_factory=list)
    status: str = "unknown"
    ipv4_cloudflare: list = field(default_factory=list)
    ipv6_cloudflare: list = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ipv4_non_cf(self) -> list:
        return [ip for ip in self.ipv4 if ip not in self.ipv4_cloudflare]

    @property
    def ipv6_non_cf(self) -> list:
        return [ip for ip in self.ipv6 if ip not in self.ipv6_cloudflare]

    @property
    def has_non_cf_ip(self) -> bool:
        return bool(self.ipv4_non_cf or self.ipv6_non_cf)

    @property
    def all_cloudflare(self) -> bool:
        if not self.ipv4 and not self.ipv6:
            return False
        all_v4_cf = all(ip in self.ipv4_cloudflare for ip in self.ipv4) if self.ipv4 else True
        all_v6_cf = all(ip in self.ipv6_cloudflare for ip in self.ipv6) if self.ipv6 else True
        return all_v4_cf and all_v6_cf


@dataclass
class ScanReport:
    """Complete scan report."""
    target_domain: str
    scan_date: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_checked: int = 0
    found: list = field(default_factory=list)
    cloudflare: list = field(default_factory=list)
    not_found: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    @property
    def summary(self) -> dict:
        return {
            "found": len(self.found),
            "cloudflare": len(self.cloudflare),
            "not_found": len(self.not_found),
            "errors": len(self.errors),
        }

    def to_dict(self) -> dict:
        return {
            "target_domain": self.target_domain,
            "scan_date": self.scan_date,
            "total_checked": self.total_checked,
            "summary": self.summary,
            "results": {
                "found": [asdict(r) for r in self.found],
                "cloudflare": [asdict(r) for r in self.cloudflare],
                "not_found": [asdict(r) for r in self.not_found],
                "errors": [asdict(r) for r in self.errors],
            },
        }


class CloudflareIPRanges:
    """Manages Cloudflare IP ranges with dynamic fetching."""

    API_V4 = "https://www.cloudflare.com/ips-v4"
    API_V6 = "https://www.cloudflare.com/ips-v6"

    FALLBACK_V4 = [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    ]

    FALLBACK_V6 = [
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
        "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
        "2c0f:f248::/32",
    ]

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self._v4_ranges: Optional[list] = None
        self._v6_ranges: Optional[list] = None
        self._fetched_from_api = False

    def _fetch_from_api(self, url: str) -> list:
        try:
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            return [line.strip() for line in response.text.strip().split("\n") if line.strip()]
        except requests.RequestException:
            return []

    def _load_ranges(self) -> None:
        if self._v4_ranges is not None and self._v6_ranges is not None:
            return

        v4_cidrs = self._fetch_from_api(self.API_V4)
        v6_cidrs = self._fetch_from_api(self.API_V6)

        if v4_cidrs and v6_cidrs:
            self._fetched_from_api = True
        else:
            v4_cidrs = self.FALLBACK_V4
            v6_cidrs = self.FALLBACK_V6

        self._v4_ranges = []
        for cidr in v4_cidrs:
            try:
                self._v4_ranges.append(IPv4Network(cidr))
            except ValueError:
                pass

        self._v6_ranges = []
        for cidr in v6_cidrs:
            try:
                self._v6_ranges.append(IPv6Network(cidr))
            except ValueError:
                pass

    def is_cloudflare_ip(self, ip: str) -> bool:
        self._load_ranges()

        try:
            ip_obj = IPv4Address(ip)
            return any(ip_obj in network for network in self._v4_ranges)
        except AddressValueError:
            pass

        try:
            ip_obj = IPv6Address(ip)
            return any(ip_obj in network for network in self._v6_ranges)
        except AddressValueError:
            pass

        return False

    @property
    def fetched_from_api(self) -> bool:
        self._load_ranges()
        return self._fetched_from_api


class ReportWriter:
    """Handles writing reports in multiple formats."""

    @staticmethod
    def write(report: ScanReport, output_path: Path, fmt: OutputFormat, only_found: bool = False) -> None:
        with open(output_path, "w", encoding="utf-8") as f:
            if fmt == OutputFormat.JSON:
                ReportWriter._write_json(report, f, only_found)
            elif fmt == OutputFormat.YAML:
                ReportWriter._write_yaml(report, f, only_found)
            elif fmt == OutputFormat.CSV:
                ReportWriter._write_csv(report, f, only_found)
            else:
                ReportWriter._write_normal(report, f, only_found)

    @staticmethod
    def _write_normal(report: ScanReport, output: TextIO, only_found: bool = False) -> None:
        output.write("EdgeReveal Scan Report\n")
        output.write("=" * 60 + "\n")
        output.write(f"Target: {report.target_domain}\n")
        output.write(f"Date: {report.scan_date}\n")
        output.write(f"Total checked: {report.total_checked}\n\n")

        if report.found:
            output.write(f"[FOUND] Non-Cloudflare IPs ({len(report.found)}):\n")
            for r in report.found:
                output.write(f"  {r.domain}\n")
                output.write(f"    {ReportWriter._format_ips(r)}\n")
            output.write("\n")

        if not only_found:
            if report.cloudflare:
                output.write(f"[CLOUDFLARE] Behind Cloudflare ({len(report.cloudflare)}):\n")
                for r in report.cloudflare:
                    output.write(f"  {r.domain}\n")
                    output.write(f"    {ReportWriter._format_ips(r)}\n")
                output.write("\n")

            if report.not_found:
                output.write(f"[NOT FOUND] ({len(report.not_found)}):\n")
                for r in report.not_found:
                    output.write(f"  {r.domain}\n")
                output.write("\n")

            if report.errors:
                output.write(f"[ERRORS] ({len(report.errors)}):\n")
                for r in report.errors:
                    output.write(f"  {r.domain}: {r.error}\n")

    @staticmethod
    def _format_ips(result: ResolveResult) -> str:
        parts = []
        if result.ipv4:
            v4_formatted = []
            for ip in result.ipv4:
                cf_tag = " [CF]" if ip in result.ipv4_cloudflare else ""
                v4_formatted.append(f"{ip}{cf_tag}")
            parts.append(f"v4:[{', '.join(v4_formatted)}]")
        if result.ipv6:
            v6_formatted = []
            for ip in result.ipv6:
                cf_tag = " [CF]" if ip in result.ipv6_cloudflare else ""
                v6_formatted.append(f"{ip}{cf_tag}")
            parts.append(f"v6:[{', '.join(v6_formatted)}]")
        return " | ".join(parts) if parts else "N/A"

    @staticmethod
    def _write_json(report: ScanReport, output: TextIO, only_found: bool = False) -> None:
        data = report.to_dict()
        if only_found:
            data["results"] = {"found": data["results"]["found"]}
        json.dump(data, output, indent=2)

    @staticmethod
    def _write_yaml(report: ScanReport, output: TextIO, only_found: bool = False) -> None:
        data = report.to_dict()
        if only_found:
            data["results"] = {"found": data["results"]["found"]}
        ReportWriter._dict_to_yaml(data, output, indent=0)

    @staticmethod
    def _dict_to_yaml(data, output: TextIO, indent: int = 0) -> None:
        """Recursively write dict/list/scalar to YAML."""
        space = "  " * indent
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    output.write(f"{space}{key}:\n")
                    ReportWriter._dict_to_yaml(value, output, indent + 1)
                else:
                    safe_val = str(value).replace("'", "''")
                    output.write(f"{space}{key}: '{safe_val}'\n")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    # Write first key inline with dash, rest indented
                    items = list(item.items())
                    if items:
                        first_k, first_v = items[0]
                        if isinstance(first_v, (dict, list)):
                            output.write(f"{space}- {first_k}:\n")
                            ReportWriter._dict_to_yaml(first_v, output, indent + 2)
                        else:
                            safe_v = str(first_v).replace("'", "''")
                            output.write(f"{space}- {first_k}: '{safe_v}'\n")
                        for k, v in items[1:]:
                            if isinstance(v, (dict, list)):
                                output.write(f"{space}  {k}:\n")
                                ReportWriter._dict_to_yaml(v, output, indent + 2)
                            else:
                                safe_v = str(v).replace("'", "''")
                                output.write(f"{space}  {k}: '{safe_v}'\n")
                elif isinstance(item, list):
                    output.write(f"{space}-\n")
                    ReportWriter._dict_to_yaml(item, output, indent + 1)
                else:
                    safe_item = str(item).replace("'", "''")
                    output.write(f"{space}- '{safe_item}'\n")
        else:
            safe_val = str(data).replace("'", "''")
            output.write(f"{space}'{safe_val}'\n")

    @staticmethod
    def _write_csv(report: ScanReport, output: TextIO, only_found: bool = False) -> None:
        writer = csv.writer(output)
        writer.writerow(["domain", "ipv4", "ipv4_cloudflare", "ipv6", "ipv6_cloudflare", "status", "error"])

        results = report.found
        if not only_found:
            results = results + report.cloudflare + report.not_found + report.errors

        for r in results:
            writer.writerow([
                r.domain,
                ";".join(r.ipv4) if r.ipv4 else "",
                ";".join(r.ipv4_cloudflare) if r.ipv4_cloudflare else "",
                ";".join(r.ipv6) if r.ipv6 else "",
                ";".join(r.ipv6_cloudflare) if r.ipv6_cloudflare else "",
                r.status,
                r.error or "",
            ])


class EdgeReveal:
    """Main scanner class."""

    def __init__(
        self,
        domain: str,
        wordlists: list,
        threads: int = 10,
        output: Optional[str] = None,
        output_format: OutputFormat = OutputFormat.NORMAL,
        verbose: bool = False,
        quiet: bool = False,
        only_found: bool = False,
        dns_timeout: float = 5.0,
        dns_servers: Optional[list] = None,
        rate_limit: float = 0.0,
    ):
        self.domain = domain.lower().strip()
        # Default to bundled subdomains.txt if no wordlist is provided.
        self.wordlists = wordlists if wordlists else [str(SCRIPT_DIR / "subdomains.txt")]
        self.threads = max(1, threads)
        self.output = Path(output) if output else None
        self.output_format = output_format
        self.verbose = verbose
        self.quiet = quiet
        self.only_found = only_found
        self.dns_timeout = dns_timeout
        self.rate_limit = rate_limit
        self._custom_dns_servers = list(dns_servers) if dns_servers else []

        self.cf_ranges = CloudflareIPRanges()
        self.report = ScanReport(target_domain=self.domain)
        self.stop_requested = False

        # Configure DNS resolver
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = dns_timeout
        self._resolver.timeout = dns_timeout
        if self._custom_dns_servers:
            self._resolver.nameservers = self._custom_dns_servers

    def log(self, message: str, level: str = "info") -> None:
        if self.quiet and level != "error":
            return
        if level == "verbose" and not self.verbose:
            return
        tqdm.write(message)

    def display_banner(self) -> None:
        if self.quiet:
            return
        figlet_text = pyfiglet.Figlet(font="slant").renderText("EdgeReveal")
        tqdm.write(f"{Colors.BLUE}{figlet_text}{Colors.RESET}")
        tqdm.write(f"{Colors.RED}Cloudflare Origin Revealer - Find Real IP Addresses Behind Cloudflare{Colors.RESET}")
        tqdm.write(f'{Colors.YELLOW}"Revealing what sits behind the edge"{Colors.RESET}\n')

    def load_wordlists(self) -> list:
        subdomains = set()

        for wordlist in self.wordlists:
            wordlist_path = Path(wordlist)
            if not wordlist_path.exists():
                self.log(f"{Colors.RED}[ERROR] Wordlist not found: {wordlist}", "error")
                sys.exit(1)

            with open(wordlist_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        subdomains.add(stripped.lower())

            self.log(f"{Colors.YELLOW}[INFO] Loaded wordlist: {wordlist_path}")

        self.log(f"{Colors.YELLOW}[INFO] Total unique subdomains: {len(subdomains)}")
        return sorted(subdomains)

    def _resolve_record(self, domain: str, record_type: str) -> tuple:
        """
        Resolve a DNS record type.
        Returns (list_of_ips, error_string_or_None).
        """
        ips = []
        try:
            answers = self._resolver.resolve(domain, record_type)
            for rdata in answers:
                ips.append(rdata.address)
            return ips, None
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
        ):
            return [], None
        except dns.resolver.NoNameservers:
            return [], "no nameservers"
        except (dns.resolver.Timeout, dns.resolver.LifetimeTimeout):
            return [], "timeout"
        except Exception as e:
            return [], str(e)

    def resolve_domain(self, subdomain: Optional[str] = None) -> ResolveResult:
        """Resolve a domain or subdomain for both A and AAAA records."""
        full_domain = f"{subdomain}.{self.domain}" if subdomain else self.domain
        result = ResolveResult(domain=full_domain)

        if self.rate_limit > 0:
            time.sleep(self.rate_limit)

        ipv4_list, err4 = self._resolve_record(full_domain, "A")
        ipv6_list, err6 = self._resolve_record(full_domain, "AAAA")

        result.ipv4 = ipv4_list
        result.ipv4_cloudflare = [ip for ip in ipv4_list if self.cf_ranges.is_cloudflare_ip(ip)]

        result.ipv6 = ipv6_list
        result.ipv6_cloudflare = [ip for ip in ipv6_list if self.cf_ranges.is_cloudflare_ip(ip)]

        # Consolidate errors (prefer the more informative one)
        errors = [e for e in [err4, err6] if e and e not in ("timeout",)]
        timeout_errors = [e for e in [err4, err6] if e == "timeout"]

        if not result.ipv4 and not result.ipv6:
            if timeout_errors:
                result.status = "error"
                result.error = "timeout"
            elif errors:
                result.status = "error"
                result.error = errors[0]
            else:
                result.status = "not_found"
        elif result.has_non_cf_ip:
            result.status = "found"
        elif result.all_cloudflare:
            result.status = "cloudflare"
        else:
            result.status = "found"

        return result

    def _log_found(self, result: ResolveResult) -> None:
        parts = []
        if result.ipv4:
            v4_parts = []
            for ip in result.ipv4:
                if ip in result.ipv4_cloudflare:
                    v4_parts.append(f"{ip}{Colors.YELLOW}[CF]{Colors.WHITE}")
                else:
                    v4_parts.append(f"{Colors.GREEN}{ip}{Colors.WHITE}")
            parts.append(f"v4:[{', '.join(v4_parts)}]")
        if result.ipv6:
            v6_parts = []
            for ip in result.ipv6:
                if ip in result.ipv6_cloudflare:
                    v6_parts.append(f"{ip}{Colors.YELLOW}[CF]{Colors.WHITE}")
                else:
                    v6_parts.append(f"{Colors.GREEN}{ip}{Colors.WHITE}")
            parts.append(f"v6:[{', '.join(v6_parts)}]")

        ips_str = f"{Colors.WHITE} | ".join(parts)
        self.log(f"{Colors.GREEN}[FOUND]  {Colors.WHITE}{result.domain} {Colors.CYAN}->{Colors.RESET} {ips_str}")

    def _log_cloudflare(self, result: ResolveResult) -> None:
        parts = []
        if result.ipv4:
            parts.append(f"v4:[{', '.join(result.ipv4)}]")
        if result.ipv6:
            parts.append(f"v6:[{', '.join(result.ipv6)}]")
        ips_str = " | ".join(parts)
        self.log(f"{Colors.YELLOW}[CF]     {Colors.WHITE}{result.domain} {Colors.CYAN}->{Colors.RESET} {ips_str}", "verbose")

    def add_result(self, result: ResolveResult) -> None:
        if result.status == "found":
            self.report.found.append(result)
            self._log_found(result)
        elif result.status == "cloudflare":
            self.report.cloudflare.append(result)
            self._log_cloudflare(result)
        elif result.status == "not_found":
            self.report.not_found.append(result)
            self.log(f"{Colors.RED}[NX]     {result.domain}", "verbose")
        elif result.status == "error":
            self.report.errors.append(result)
            self.log(f"{Colors.MAGENTA}[ERR]    {result.domain}: {result.error}", "verbose")

    def save_report(self) -> None:
        if not self.output:
            return
        try:
            ReportWriter.write(self.report, self.output, self.output_format, self.only_found)
            self.log(f"{Colors.GREEN}[INFO] Results saved to {self.output}")
        except Exception as e:
            self.log(f"{Colors.RED}[ERROR] Failed to save report: {e}", "error")

    def handle_interrupt(self, signum: int, frame) -> None:
        """Handle Ctrl+C gracefully — no blocking input() inside tqdm."""
        if self.stop_requested:
            tqdm.write(f"\n{Colors.RED}[INFO] Force quitting...{Colors.RESET}")
            sys.exit(0)
        tqdm.write(f"\n{Colors.YELLOW}[INFO] Interrupt received. Press Ctrl+C again to quit, or wait to continue.{Colors.RESET}")
        self.stop_requested = True

    def run(self) -> ScanReport:
        signal.signal(signal.SIGINT, self.handle_interrupt)

        self.display_banner()

        # Pre-load CF ranges and report source
        if self.cf_ranges.fetched_from_api:
            self.log(f"{Colors.GREEN}[INFO] Cloudflare IP ranges loaded from API")
        else:
            self.log(f"{Colors.YELLOW}[INFO] Using fallback Cloudflare IP ranges (API unreachable)")

        if self.dns_servers:
            self.log(f"{Colors.CYAN}[INFO] Using custom DNS: {', '.join(self.dns_servers)}")

        # Load wordlists
        subdomains = self.load_wordlists()

        # Check root domain
        self.log(f"{Colors.YELLOW}[INFO] Checking root domain: {self.domain}")
        root_result = self.resolve_domain()
        self.add_result(root_result)
        self.report.total_checked += 1

        self.log(f"{Colors.YELLOW}[INFO] Starting subdomain scan ({self.threads} threads)...\n")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.resolve_domain, sub): sub for sub in subdomains}

            with tqdm(
                total=len(futures),
                desc=f"{Colors.CYAN}Scanning{Colors.RESET}",
                unit="sub",
                disable=self.quiet,
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}",
                ncols=80,
                leave=False,
            ) as pbar:
                for future in as_completed(futures):
                    if self.stop_requested:
                        self.log(f"{Colors.RED}[INFO] Scan interrupted — saving partial results...")
                        # Python 3.9+ supports cancel_futures; guard for older versions
                        try:
                            executor.shutdown(wait=False, cancel_futures=True)
                        except TypeError:
                            executor.shutdown(wait=False)
                        break

                    try:
                        result = future.result()
                    except Exception as e:
                        sub = futures[future]
                        result = ResolveResult(
                            domain=f"{sub}.{self.domain}",
                            status="error",
                            error=str(e),
                        )

                    self.add_result(result)
                    self.report.total_checked += 1
                    pbar.update(1)

                    found = len(self.report.found)
                    cf = len(self.report.cloudflare)
                    pbar.set_postfix_str(f"found:{found} cf:{cf}")

        # Summary
        self.log(f"\n{Colors.WHITE}{'=' * 60}")
        self.log(f"{Colors.CYAN}Scan Summary:")
        self.log(f"{Colors.GREEN}  Found (non-CF IPs) : {len(self.report.found)}")
        self.log(f"{Colors.YELLOW}  Behind Cloudflare  : {len(self.report.cloudflare)}")
        self.log(f"{Colors.RED}  Not found (NXDOMAIN): {len(self.report.not_found)}")
        if self.report.errors:
            self.log(f"{Colors.MAGENTA}  Errors             : {len(self.report.errors)}")
        self.log(f"{Colors.WHITE}  Total checked      : {self.report.total_checked}")
        self.log(f"{Colors.WHITE}{'=' * 60}\n")

        self.save_report()
        self.log(f"{Colors.WHITE}Scan complete.")
        return self.report

    # Expose only user-supplied DNS resolvers, not system defaults.
    @property
    def dns_servers(self):
        return self._custom_dns_servers


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="EdgeReveal - Cloudflare Origin Revealer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 EdgeReveal.py example.com
  python3 EdgeReveal.py example.com -w subs.txt -t 20 -o report.json -f json
  python3 EdgeReveal.py example.com -w list1.txt -w list2.txt -v
  python3 EdgeReveal.py example.com -q -o found.csv -f csv --only-found
  python3 EdgeReveal.py example.com --dns 8.8.8.8 --dns 1.1.1.1 --timeout 3
        """,
    )

    parser.add_argument("domain", help="Target domain (e.g., example.com)")

    parser.add_argument(
        "-w", "--wordlist",
        action="append",
        dest="wordlists",
        default=[],
        metavar="FILE",
        help="Wordlist file(s). Can be specified multiple times. Defaults to bundled subdomains.txt.",
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Concurrent threads (default: 10)",
    )

    parser.add_argument(
        "-o", "--output",
        help="Output file for report",
        metavar="FILE",
    )

    parser.add_argument(
        "-f", "--format",
        choices=["normal", "json", "yaml", "csv"],
        default="normal",
        help="Output format (default: normal)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show all results including NXDOMAIN and CF-only subdomains",
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress banner and progress bar (only print FOUND lines)",
    )

    parser.add_argument(
        "--only-found",
        action="store_true",
        dest="only_found",
        help="When saving a report, include only non-CF results",
    )

    parser.add_argument(
        "--dns",
        action="append",
        dest="dns_servers",
        default=[],
        metavar="IP",
        help="Custom DNS resolver IP(s). Can be specified multiple times. (e.g. --dns 8.8.8.8)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="SECS",
        help="DNS resolution timeout per query in seconds (default: 5.0)",
    )

    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        metavar="SECS",
        dest="rate_limit",
        help="Sleep between DNS queries per thread, e.g. 0.1 (default: 0 = no limit)",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"EdgeReveal {__version__}",
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    scanner = EdgeReveal(
        domain=args.domain,
        wordlists=args.wordlists,
        threads=args.threads,
        output=args.output,
        output_format=OutputFormat(args.format),
        verbose=args.verbose,
        quiet=args.quiet,
        only_found=args.only_found,
        dns_timeout=args.timeout,
        dns_servers=args.dns_servers if args.dns_servers else None,
        rate_limit=args.rate_limit,
    )

    scanner.run()


if __name__ == "__main__":
    main()
