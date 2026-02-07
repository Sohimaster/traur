# PKGBUILD Analysis

Static analysis of PKGBUILD shell code for dangerous patterns.

## What it detects

- **Download-and-execute**: `curl|bash`, `wget|sh`, `source <(curl ...)` — override gates (-> MALICIOUS)
- **Reverse shells**: `/dev/tcp/`, `nc -e`, `socat TCP EXEC` — override gates
- **Obfuscation**: `base64 -d`, `eval $var`, `eval $(base64 ...)`, gzip+exec
- **Credential access**: SSH keys, browser profiles, GPG keyring, /etc/passwd
- **Persistence**: systemd service creation, cron jobs, shell profile modification, LD_PRELOAD

## Signals emitted

All signals use `SignalCategory::Pkgbuild` (weight 0.45). See `data/patterns.toml` section `pkgbuild_analysis` for full pattern list.

## Dependencies

- `shared/patterns.rs` — loads and compiles regex patterns from TOML
- `PackageContext.pkgbuild_content` — the PKGBUILD file content to analyze

## Known false positives

- `P-SYSTEMD-CREATE` (+35): Legitimate daemon packages create systemd services. Context matters — a browser extension creating a service is suspicious, a daemon is expected.
- `P-BASE64` (+60): Some packages use base64 for icon encoding in desktop files.
- `P-LD-PRELOAD` (+60): Some legitimate packages (like gamemode) use LD_PRELOAD.
