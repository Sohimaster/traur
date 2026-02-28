# traur-x (Experimental)

> [!WARNING]
> **EXPERIMENTAL PROJECT:** This project is currently undergoing a major architectural migration from simple point-based scoring to complex **rule-based multi-signal detection**. It is in an unstable state and **MUST NOT** be part of any production or security-critical workflow.

**traur-x** is an experimental engine for AUR package analysis. Instead of relying on individual point scores, it is moving toward a YARA-inspired model where rules evaluate multiple signals (Metadata, Pkgbuild, Behavioral, Temporal) in context to produce high-confidence security verdicts.

<img width="859" height="640" alt="image" src="https://github.com/user-attachments/assets/768915bd-4aa2-4450-96c7-408e73e0d103" />

## Current Status: Migration in Progress

We are currently migrating all legacy signals into a unified Rule Engine. This allows for coordinated detection (e.g., "Flag as Malicious only if *both* a download-and-execute pattern exists *and* the maintainer is new").

## Verdict Levels (Experimental)

| Verdict | Level | Action | Description |
|---------|-------|--------|-------------|
| **TRUSTED** | 0 | Allow | Explicitly whitelisted or high-reputation community package. |
| **OK** | 1 | Allow | No rules matched. |
| **SUSPICIOUS**| 2 | Prompt | Heuristics matched potential risk patterns. |
| **MALICIOUS** | 3 | Block | High-confidence match for known attack vectors. |

## Usage (Development Only)

```bash
# Scan a package using the experimental rule engine
traur scan <package>

# Benchmark against the latest AUR metadata dump
traur bench --count 100
```

## How it Works (New Architecture)

The engine now supports **Multi-Signal Rules** implemented in Rhai. A single rule can now inspect:
1. **Metadata:** Votes, popularity, out-of-date status, maintainer age.
2. **Pkgbuild:** Shell patterns, obfuscation, network calls.
3. **Behavioral:** Install script hooks, systemd persistence.
4. **Temporal:** Git history anomalies, sudden author changes.

### Example Rule Logic
```javascript
// Rules can now correlate different data points
if pkg.pkgbuild_content.contains("curl | bash") && pkg.metadata.num_votes < 5 {
    return [#{ verdict: "malicious", reason: "Unverified pipe-to-shell in low-reputation package" }];
}
```

## Detection Coverage

Currently focusing on patterns derived from real AUR incidents:
- **Coordinated Attacks:** Browser impersonation + RAT distribution.
- **Supply Chain:** Orphan takeover + suspicious source updates.
- **Obfuscation:** Complex shell redirects and dynamic code execution.

> PS: I'm noob in rust

## License

MIT
