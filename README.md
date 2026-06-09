# EdgeReveal

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
![Version](https://img.shields.io/badge/version-1.1.1-green.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)
![Tool Type](https://img.shields.io/badge/tool-recon-red.svg)

EdgeReveal is a Python reconnaissance tool for authorized security testing. It checks a target domain and its subdomains, resolves IPv4 and IPv6 records, filters known Cloudflare IP ranges, and reports hosts that may expose non-Cloudflare origin IPs.

Developed by [JOJIN JOHN](https://www.linkedin.com/in/jojin-john/).

> [!WARNING]
> Use EdgeReveal only on domains you own or have explicit permission to test.

## Features

- Resolves both `A` and `AAAA` DNS records.
- Detects multiple IPs per hostname.
- Filters Cloudflare IPv4 and IPv6 ranges.
- Fetches current Cloudflare ranges with built-in fallback ranges.
- Scans subdomains concurrently with configurable threads.
- Supports one or more custom wordlists.
- Includes a bundled default wordlist: `subdomains.txt`.
- Exports reports as normal text, JSON, YAML, or CSV.
- Supports quiet, verbose, timeout, DNS resolver, and rate-limit controls.
- Saves partial results if interrupted.

## Requirements

- Python 3.8 or newer
- `pip`

## Installation

Clone the repository:

```bash
git clone https://github.com/jojin1709/EdgeReveal.git
cd EdgeReveal
```

Create a virtual environment and install dependencies.

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Windows PowerShell:

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Quick Start

Linux/macOS:

```bash
python3 EdgeReveal.py example.com
```

Windows:

```powershell
python EdgeReveal.py example.com
```

Show help:

```bash
python3 EdgeReveal.py --help
```

Show version:

```bash
python3 EdgeReveal.py --version
```

## Usage

```bash
python3 EdgeReveal.py <domain> [options]
```

Windows users can replace `python3` with `python`.

## Options

| Option | Description |
| --- | --- |
| `<domain>` | Target domain, such as `example.com`. |
| `-w, --wordlist FILE` | Wordlist file. Can be used multiple times. Defaults to bundled `subdomains.txt`. |
| `-t, --threads N` | Number of concurrent scan threads. Default: `10`. |
| `-o, --output FILE` | Save the report to a file. |
| `-f, --format FORMAT` | Output format: `normal`, `json`, `yaml`, or `csv`. Default: `normal`. |
| `-v, --verbose` | Show NXDOMAIN, Cloudflare-only, and error entries. |
| `-q, --quiet` | Hide banner and progress bar. Prints only found results. |
| `--only-found` | When saving a report, include only non-Cloudflare results. |
| `--dns IP` | Custom DNS resolver. Can be used multiple times. |
| `--timeout SECS` | DNS timeout per query in seconds. Default: `5.0`. |
| `--rate-limit SECS` | Sleep between DNS queries per thread. Default: `0`. |
| `--version` | Print the current version and exit. |

## Examples

Basic scan:

```bash
python3 EdgeReveal.py example.com
```

Scan with the bundled wordlist and 50 threads:

```bash
python3 EdgeReveal.py example.com -t 50
```

Use a custom wordlist:

```bash
python3 EdgeReveal.py example.com -w my-subdomains.txt
```

Use multiple wordlists:

```bash
python3 EdgeReveal.py example.com -w common.txt -w extra.txt
```

Save a normal text report:

```bash
python3 EdgeReveal.py example.com -o report.txt
```

Save JSON output:

```bash
python3 EdgeReveal.py example.com -o report.json -f json
```

Save YAML output:

```bash
python3 EdgeReveal.py example.com -o report.yaml -f yaml
```

Save CSV output:

```bash
python3 EdgeReveal.py example.com -o report.csv -f csv
```

Save only non-Cloudflare findings:

```bash
python3 EdgeReveal.py example.com -q -o found.csv -f csv --only-found
```

Show verbose scan details:

```bash
python3 EdgeReveal.py example.com -v
```

Use custom DNS resolvers:

```bash
python3 EdgeReveal.py example.com --dns 8.8.8.8 --dns 1.1.1.1
```

Use a shorter DNS timeout:

```bash
python3 EdgeReveal.py example.com --timeout 3
```

Slow down per-thread DNS queries:

```bash
python3 EdgeReveal.py example.com --rate-limit 0.1
```

Combine common options:

```bash
python3 EdgeReveal.py example.com -w subs.txt -t 30 --dns 8.8.8.8 --timeout 3 -o report.json -f json
```

## Wordlists

The default scan uses `subdomains.txt` from this repository. You can add comments to wordlists with `#`; blank lines and comment lines are ignored.

Example:

```text
www
mail
admin
# staging hosts
dev
staging
```

## Output Formats

Normal text output:

```text
EdgeReveal Scan Report
============================================================
Target: example.com
Date: 2026-06-09T12:00:00+00:00
Total checked: 150

[FOUND] Non-Cloudflare IPs (2):
  mail.example.com
    v4:[192.0.2.10]

[CLOUDFLARE] Behind Cloudflare (5):
  www.example.com
    v4:[104.16.1.1 [CF]] | v6:[2606:4700::1 [CF]]
```

JSON output:

```json
{
  "target_domain": "example.com",
  "scan_date": "2026-06-09T12:00:00+00:00",
  "total_checked": 150,
  "summary": {
    "found": 2,
    "cloudflare": 5,
    "not_found": 143,
    "errors": 0
  },
  "results": {}
}
```

CSV output:

```csv
domain,ipv4,ipv4_cloudflare,ipv6,ipv6_cloudflare,status,error
mail.example.com,192.0.2.10,,,,found,
www.example.com,104.16.1.1,104.16.1.1,2606:4700::1,2606:4700::1,cloudflare,
```

## Troubleshooting

If dependencies are missing, reinstall them:

```bash
pip install -r requirements.txt
```

A scan that reports `Found (non-CF IPs) : 0` is not automatically a failure. It can mean the target is fully proxied, the tested names do not exist, or the target is intentionally configured to hide origin infrastructure.

If scans are slow or unreliable, try a public resolver and a shorter timeout:

```bash
python3 EdgeReveal.py example.com --dns 8.8.8.8 --timeout 3
```

If the target or resolver rate-limits DNS queries, lower the thread count or add a delay:

```bash
python3 EdgeReveal.py example.com -t 5 --rate-limit 0.2
```

## Version History

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Contributing

Pull requests are welcome. Keep changes focused, readable, and tested before opening a PR.

Basic contribution flow:

```bash
git checkout -b feature/your-feature
git add .
git commit -m "Describe your change"
git push origin feature/your-feature
```

## Legal Notice

EdgeReveal is intended for ethical security research, authorized penetration testing, and defensive assessment. Unauthorized scanning may be illegal. You are responsible for following applicable laws, program rules, and scope limits.

## License

MIT License. See [LICENSE](LICENSE) for details.
