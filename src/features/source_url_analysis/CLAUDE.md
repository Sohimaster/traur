# Source URL Analysis

Checks source URLs in PKGBUILDs for suspicious domains and patterns.

## What it detects

- **Raw IP URLs**: `http://1.2.3.4/...` — legitimate sources use domain names
- **URL shorteners**: bit.ly, tinyurl — hiding the real destination
- **Discord webhooks**: Data exfiltration channel
- **Paste services**: pastebin.com, paste.ee — mutable, untrusted content hosting
- **Dynamic DNS**: duckdns.org, no-ip.com — common in C2 infrastructure

## Signals emitted

All signals use `SignalCategory::Pkgbuild` (weight 0.45). See `data/patterns.toml` section `source_url_analysis`.

## Dependencies

- `shared/patterns.rs` — regex pattern matching
- `PackageContext.pkgbuild_content` — scans source=() array and full PKGBUILD content
