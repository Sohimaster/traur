# traur

Heuristic security scanner for AUR packages. Analyzes PKGBUILDs, install scripts, source URLs, metadata, and git history pre-install.
integrates into paru/yay as a hook and displays risk analysis

<img width="942" height="453" alt="image" src="https://github.com/user-attachments/assets/f9b375a3-d9f9-412c-af73-f80ba86472e8" />


## Installation

```bash
paru -S traur
```

## Usage

```bash
traur scan                # scan all installed aur packages
traur scan <package>      # scan a package
traur report <package>    # detailed signal breakdown
traur allow <package>     # whitelist a package
traur bench               # benchmark 1000 latest AUR packages
```

## How it works

10 independent features emit scored signals per package:

| Feature | What it checks |
|---------|---------------|
| PKGBUILD analysis | Dangerous shell code |
| Install script analysis | Suspicious .install hooks |
| Source URL analysis | Untrusted source domains |
| Checksum analysis | Missing, skipped, or weak checksums |
| Metadata analysis | AUR votes, popularity, maintainer status |
| Name analysis | Typosquatting and brand impersonation |
| Maintainer analysis | New accounts, batch uploads |
| Git history analysis | New network code, author changes |
| Shell analysis | Beyond-regex obfuscation (var concat, indirect exec, data blobs) |
| GTFOBins analysis | Legitimate binary abuse |

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

Analysis: **~0.5ms per package** (10 features, 239 regex patterns). Bottleneck is AUR git I/O.

## License

MIT
