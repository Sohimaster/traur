# Source URL Analysis

Checks source URLs in the `source=()` array of PKGBUILDs for suspicious domains and patterns.

## What it detects

- **Raw IP URLs**: `http://1.2.3.4/...` — legitimate sources use domain names
- **URL shorteners**: bit.ly, tinyurl — hiding the real destination
- **Discord webhooks**: Data exfiltration channel
- **Paste services**: pastebin.com, paste.ee — mutable, untrusted content hosting
- **Dynamic DNS**: duckdns.org, no-ip.com — common in C2 infrastructure
- **Telegram bot API**: Data exfiltration via Telegram bots
- **Tunnel services**: ngrok, serveo, localtunnel — obfuscated endpoints
- **Plain HTTP**: Source URLs without TLS (MITM risk, low points)

## Scope

Only matches against the `source=()` array content, NOT the entire PKGBUILD. URLs in comments or code body are ignored by this feature (exfiltration URLs in code are caught by `pkgbuild_analysis` instead).

## Signals emitted

All signals use `SignalCategory::Pkgbuild` (weight 0.45). See `data/patterns.toml` section `source_url_analysis`.

## Dependencies

- `shared/patterns.rs` — regex pattern matching (cached via OnceLock in `patterns.rs`)
- `PackageContext.pkgbuild_content` — extracts source=() array from PKGBUILD content

## Performance

Patterns are compiled once via `OnceLock` and reused across invocations. Source array regex is cached via `LazyLock`.
