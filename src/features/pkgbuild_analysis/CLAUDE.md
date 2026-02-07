# PKGBUILD Analysis

Static analysis of PKGBUILD shell code for dangerous patterns.

## What it detects

- **Download-and-execute**: `curl|bash`, `curl|python`, `curl|perl`, `wget|sh`, `wget|python`, `source <(curl ...)`, process substitution, decompression pipes, Ruby/Perl fetch-exec — override gates (-> MALICIOUS)
- **Reverse shells**: `/dev/tcp/`, `/dev/udp/`, `nc -e`, `socat TCP EXEC`, Python socket+subprocess, Perl Socket, Ruby TCPSocket, Awk /inet/tcp, Lua socket.tcp, PHP fsockopen — override gates
- **Shell obfuscation**: `$IFS`, ANSI-C hex quoting, ROT13 via `tr`, octal encoding, string reversal via `rev`
- **Encoding bypasses**: `base64 -d`, `base32 -d`, `xxd -r`, `printf \xHH`, OpenSSL decryption
- **Code execution**: `eval $var`, `eval $(base64 ...)`, gzip+exec, `python -c`, telnet pipe
- **Credential access**: SSH keys, browser profiles, GPG keyring, /etc/passwd, clipboard
- **Persistence**: systemd services, systemd user services, cron jobs, XDG autostart, udev rules, `at` jobs, PROMPT_COMMAND, .bash_logout, shell profile modification, LD_PRELOAD
- **Privilege escalation**: SUID/SGID bit, sudoers modification, polkit rules, Linux capabilities (setcap), named pipes (mkfifo)
- **Anti-forensics**: shell history clearing, system log clearing/truncation
- **Exfiltration**: Discord webhooks, URL shorteners, OpenSSL client connections, direct disk read/write, telnet
- **AUR-specific**: pacman hook creation, alias overrides of common commands

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
- `P-UDEV-RULE` (+45): Some legitimate packages install udev rules.
- `P-PACMAN-HOOK` (+50): Some legitimate packages install pacman hooks (e.g., traur itself).
