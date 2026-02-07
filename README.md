# traur

Heuristic security scanner for AUR packages. Analyzes PKGBUILDs, install scripts, source URLs, metadata, and git history pre-install.

ALPM hook integration for paru/yay.

## Install

```bash
cargo build --release
sudo install -Dm755 target/release/traur /usr/bin/traur
sudo install -Dm755 target/release/traur-hook /usr/bin/traur-hook
sudo install -Dm644 hook/traur.hook /usr/share/libalpm/hooks/traur.hook
```

## Usage

```bash
traur scan <package>      # scan a package
traur report <package>    # detailed signal breakdown
traur allow <package>     # whitelist a package
traur bench               # benchmark 1000 latest AUR packages
```

## How it works

8 independent features emit scored signals per package:

| Feature | What it checks |
|---------|---------------|
| PKGBUILD analysis | 52 regex patterns for dangerous shell code |
| Install script analysis | 19 patterns for suspicious .install hooks |
| Source URL analysis | 11 patterns for untrusted source domains |
| Checksum analysis | Missing, skipped, or weak checksums |
| Metadata analysis | AUR votes, popularity, maintainer status |
| Name analysis | Typosquatting and brand impersonation |
| Maintainer analysis | New accounts, batch uploads |
| Git history analysis | New network code, author changes |

Composite score 0-100, 5 tiers:

```
LOW (0-19) → MEDIUM (20-39) → HIGH (40-59) → CRITICAL (60-79) → MALICIOUS (80-100)
```

Override gates (curl|bash, reverse shells, Python RCE) escalate to MALICIOUS regardless of score.

## Detection coverage

Patterns derived from real AUR malware incidents:
- **CHAOS RAT (2025)** — browser impersonation packages, RAT distribution
- **Google Chrome RAT (2025)** — .install script, Python download+execute
- **Acroread (2018)** — orphan takeover, curl from paste service, systemd persistence

Categories: download-and-execute, reverse shells, credential theft, persistence mechanisms, privilege escalation, C2/exfiltration, cryptocurrency mining, code obfuscation, kernel module loading, environment variable theft, system reconnaissance.

## Benchmark

```bash
traur bench [--count N] [--jobs J]
```

Scans the N most recently modified AUR packages in parallel. Prints detailed signals for HIGH+ packages.

Analysis: **~0.5ms per package** (8 features, 82 regex patterns). Bottleneck is AUR git I/O.

## Adding patterns

Edit `data/patterns.toml`:

```toml
[[pkgbuild_analysis]]
id = "P-MY-PATTERN"
pattern = 'regex_here'
points = 70
description = "What this detects"
override_gate = false
```

## License

GPL-3.0
