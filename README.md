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
traur clean [package]     # remove cached git clones
```

The package ships a `traur-scan.timer` for unattended scanning:

```bash
systemctl enable --now traur-scan.timer   # daily, notifies when packages are flagged
```

Or run it yourself from cron with exit status as the signal (non-zero when a
SUSPICIOUS or MALICIOUS package is found):

```bash
traur scan --flagged-only --json
```

The ALPM hook runs at `PreTransaction`, which is **after** `makepkg` has executed
`build()`. For a payload in `build()`, the code has already run by then. To scan
before the build starts, install the wrapper from issue #19/#16:

```bash
sudo install -Dm755 /usr/share/traur/makepkg-wrapper.sh /usr/local/bin/makepkg
```

It only acts inside yay/paru build caches, passes `--printsrcinfo`,
`--packagelist` and other query invocations straight through, and leaves local
`makepkg` runs untouched. Trusted packages build without prompting; SUSPICIOUS
and MALICIOUS ones require an explicit `y`.

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
- **Atomic Arch (2026)** — orphan takeover, build-time `npm`/`bun` dependency injection (`atomic-lockfile`, `js-digest`), eBPF rootkit loading, cloud credential harvesting
- **CHAOS RAT (2025)** — browser impersonation packages, RAT distribution
- **Google Chrome RAT (2025)** — .install script, Python download+execute
- **Acroread (2018)** — orphan takeover, curl from paste service, systemd persistence

Categories: download-and-execute, reverse shells, credential theft, persistence mechanisms, privilege escalation, C2/exfiltration, cryptocurrency mining, code obfuscation, kernel module and eBPF loading, build-time package-manager installs, environment variable theft, system reconnaissance.

## License

MIT
