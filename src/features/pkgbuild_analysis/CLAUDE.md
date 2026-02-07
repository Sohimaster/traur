# PKGBUILD Analysis

Static analysis of PKGBUILD shell code for dangerous patterns.

## What it detects

- **Download-and-execute**: `curl|bash`, `curl|python`, `curl|perl`, `wget|sh`, `wget|python`, `source <(curl ...)` — override gates (-> MALICIOUS)
- **Reverse shells**: `/dev/tcp/`, `nc -e`, `socat TCP EXEC`, Python socket+subprocess — override gates
- **Obfuscation**: `base64 -d`, `eval $var`, `eval $(base64 ...)`, gzip+exec, `python -c`
- **Credential access**: SSH keys, browser profiles, GPG keyring, /etc/passwd, clipboard
- **Persistence**: systemd service creation, cron jobs, shell profile modification, LD_PRELOAD
- **Privilege escalation**: SUID/SGID bit setting, named pipes (mkfifo)
- **Exfiltration**: Discord webhooks, URL shorteners, OpenSSL client connections, direct disk read

## Signals emitted

All signals use `SignalCategory::Pkgbuild` (weight 0.45). See `data/patterns.toml` section `pkgbuild_analysis` for full pattern list.

## Dependencies

- `shared/patterns.rs` — loads and compiles regex patterns from TOML
- `PackageContext.pkgbuild_content` — the PKGBUILD file content to analyze

## Known false positives

- `P-SYSTEMD-CREATE` (+35): Legitimate daemon packages create systemd services.
- `P-BASE64` (+60): Some packages use base64 for icon encoding in desktop files.
- `P-LD-PRELOAD` (+60): Some legitimate packages (like gamemode) use LD_PRELOAD.
- `P-PYTHON-INLINE` (+45): Legitimate packages may use `python -c` for version checks or build logic.
- `P-CLIPBOARD-READ` (+50): Clipboard managers legitimately use xclip/xsel/wl-paste.
