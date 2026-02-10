# traur

Trust scoring for AUR packages, written in Rust. Analyzes PKGBUILDs, install scripts, source URLs, metadata, and git history to score how much you should trust a package before installing it. Includes an ALPM hook that automatically scans packages before any install or upgrade transaction.

<img width="859" height="640" alt="image" src="https://github.com/user-attachments/assets/768915bd-4aa2-4450-96c7-408e73e0d103" />




## Installation

```bash
paru -S traur
```

## Usage

```bash
traur scan                # scan all installed aur packages
traur scan <package>      # scan a package
traur allow <package>     # whitelist a package
```

## How it works

12 independent features emit scored signals per package:

| Feature | What it checks |
|---------|---------------|
| PKGBUILD analysis | Dangerous shell code |
| Install script analysis | Suspicious .install hooks |
| Source URL analysis | Untrusted source domains |
| Checksum analysis | Missing, skipped, or weak checksums |
| Metadata analysis | AUR votes, popularity, maintainer status |
| Name analysis | Typosquatting and brand impersonation |
| Maintainer analysis | New accounts, batch uploads |
| Orphan takeover analysis | Submitter != maintainer, orphan takeover patterns |
| Git history analysis | New network code, author changes |
| Shell analysis | Beyond-regex obfuscation (var concat, indirect exec, data blobs) |
| GTFOBins analysis | Legitimate binary abuse |
| Bin source verification | -bin package source domain vs upstream URL mismatch |

## Detection coverage

Patterns derived from real AUR malware incidents:
- **CHAOS RAT (2025)** — browser impersonation packages, RAT distribution
- **Google Chrome RAT (2025)** — .install script, Python download+execute
- **Acroread (2018)** — orphan takeover, curl from paste service, systemd persistence

Categories: download-and-execute, reverse shells, credential theft, persistence mechanisms, privilege escalation, C2/exfiltration, cryptocurrency mining, code obfuscation, kernel module loading, environment variable theft, system reconnaissance.

## License

MIT
