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
traur scan <pkg> [<pkg>...]  # scan one or more packages
traur allow <package>     # whitelist a package
```

## How it works

14 independent features emit scored signals per package, then a context-aware scoring
pipeline computes the final trust score.

| Feature | What it checks |
|---------|---------------|
| PKGBUILD analysis | Dangerous shell code, NPM obfuscated exec, atomic-lockfile |
| Install script analysis | Suspicious .install hooks |
| Source URL analysis | Untrusted source domains |
| Checksum analysis | Missing, skipped, or weak checksums |
| Metadata analysis | AUR votes, popularity, maintainer status |
| Name analysis | Typosquatting and brand impersonation |
| Maintainer analysis | New accounts, batch uploads |
| Orphan takeover analysis | Submitter != maintainer, orphan takeover patterns |
| Git history analysis | New network code, author changes |
| Shell analysis | Beyond-regex obfuscation |
| PKGBUILD diff analysis | Checksum changes, domain changes, major rewrites |
| GTFOBins analysis | Legitimate binary abuse |
| Bin source verification | -bin package source domain vs upstream URL mismatch |
| AUR comments analysis | Security keywords in AUR comments (time-aware) |

### Scoring pipeline

1. **Community gate** — time-aware AUR comment threat evaluation
2. **Critical gate** — signals that alone classify a package as Malicious
3. **Override gate** — high-severity signals (curl-pipe-bash, reverse shells, etc.)
4. **Weighted risk** — composite score from all signals (15% Metadata, 45% PKGBUILD, 25% Behavioral, 15% Temporal)
5. **Maintainer trust** — account age, package count, takeover recency multiplier
6. **Popularity penalty** — low votes/usage increases risk
7. **Orphan + malicious diff boost** — takeover combined with new suspicious diff → risk ≥ 95
8. **NPM risk** — suspicious install scripts, new maintainers, dead repos
9. **Clamp & tier** — 5 tiers: Trusted(81-100), OK(61-80), Sketchy(41-60), Suspicious(21-40), Malicious(0-20)

### Time-aware comment threat

AUR comments mentioning malware/backdoor/etc. are evaluated with time-awareness and
popularity context, preventing stale or mitigated warnings from falsely classifying
packages as Malicious.

High-popularity repos (≥3 votes or ≥0.01 popularity):
- < 7 days old → Malicious override
- 7–60 days → degraded signal
- > 60 days → ignored

Low-popularity repos:
- Degraded if mitigation/follow-up comments exist after the warning
- Always fires if no mitigation and the warning is > 60 days old (orphaned concern)

Mitigation phrases ("patched", "fixed", "not compromised", "different package", etc.)
in comments after a warning automatically downgrade the threat.

## Detection coverage

Patterns derived from real AUR malware incidents:
- **CHAOS RAT (2025)** — browser impersonation packages, RAT distribution
- **Google Chrome RAT (2025)** — .install script, Python download+execute
- **Acroread (2018)** — orphan takeover, curl from paste service, systemd persistence

Categories: download-and-execute, reverse shells, credential theft, persistence mechanisms, privilege escalation, C2/exfiltration, cryptocurrency mining, code obfuscation, kernel module loading, environment variable theft, system reconnaissance.

## License

MIT
