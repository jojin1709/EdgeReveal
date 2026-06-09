# Changelog

## [1.1.0] - 2026-06-09

### Fixed
- **Wordlist path bug** — the bundled `subdomains.txt` wordlist is resolved relative to the script's own directory, not the current working directory. Running EdgeReveal from any directory no longer crashes with "Wordlist not found".
- **YAML output corruption** — the custom YAML serialiser was incorrectly indenting nested list-of-dicts. Rewritten to produce valid, readable YAML for all report structures.
- **`executor.shutdown` compatibility** — `cancel_futures=True` is only available on Python ≥ 3.9. Wrapped in a try/except so the tool works on 3.8 as well.
- **DNS errors swallowed silently** — `_resolve_record` previously caught `Exception` and returned an empty list with no error message. Now returns `(ips, error_string)` so timeouts and "no nameservers" conditions are surfaced in the report and verbose output.
- **Ctrl+C deadlock** — `handle_interrupt` called `input()` inside the tqdm/thread context which would deadlock. Replaced with a two-press pattern: first Ctrl+C marks stop requested and saves partial results; second Ctrl+C force-quits immediately.
- **Thread throttle** — `time.sleep(0.05)` was inside the `as_completed` loop, blocking the main thread after every future completion and negating most of the threading benefit. Removed from the loop (optional per-thread rate limiting is now a `--rate-limit` flag instead).
- **Colorama reset leak** — ANSI reset was missing after several log lines, causing color bleed into the progress bar on some terminals.
- **Future exception propagation** — unhandled exceptions raised inside a thread's `future.result()` call were crashing the scan silently. Now caught and stored as an error result.

### Added
- `--dns IP` — specify one or more custom DNS resolvers (e.g. `--dns 8.8.8.8 --dns 1.1.1.1`). Previously the system resolver was always used.
- `--timeout SECS` — per-query DNS timeout, default 5.0 s. Useful for fast scans (`--timeout 2`) or slow/unreliable resolvers.
- `--rate-limit SECS` — optional sleep between DNS queries per thread (e.g. `--rate-limit 0.1`) for targets where flooding DNS triggers rate-limiting or blackholing.
- `--only-found` — when writing a report file, include only the non-Cloudflare results. Combines well with `-q` for clean output pipelines.
- `--version` — print version string and exit.
- IPv4 addresses are now highlighted in green in `[FOUND]` lines so they stand out from the `[CF]` tagged IPs at a glance.
- `[CF]` lines are now `verbose` level (hidden unless `-v`) to reduce noise for the common case where most subdomains are behind Cloudflare.
- Errors are shown as `[ERR]` at verbose level; counted in the summary block.
- Summary block now includes total checked count.
- DNS resolver info line printed at startup when `--dns` is used.
- Wordlist lines are now lowercased and `errors='replace'` added to the file reader so non-UTF-8 wordlists don't crash on Linux/WSL.

## [1.0.0] - Initial release
- Subdomain scanning with concurrent threading
- Cloudflare IP detection (live API + fallback ranges)
- Output formats: normal text, JSON, YAML, CSV
- Progress bar with live found/cf counters
- Multiple wordlist support
