# Data

External configuration files loaded at compile time or runtime.

## patterns.toml

Regex pattern database used by pattern-based features (pkgbuild_analysis, install_script_analysis, source_url_analysis, gtfobins_analysis).

### Format

```toml
[[section_name]]
id = "SIGNAL-ID"
pattern = 'regex_pattern'
points = 90
description = "Human-readable description"
override_gate = true  # optional, default false
```

- `section_name` must match the feature's name (e.g., `pkgbuild_analysis`)
- `pattern` is a Rust regex (ripgrep-compatible)
- `override_gate = true` means this signal bypasses weighted scoring and escalates directly to MALICIOUS tier
- Patterns are compiled once via `OnceLock` and reused

### Pattern categories

- **pkgbuild_analysis** (84 patterns): download-and-execute, reverse shells (bash/python/perl/ruby/awk/lua/php/nc/socat), shell obfuscation ($IFS, ANSI-C hex, ROT13, octal, string reversal), encoding bypasses (base64/base32/xxd/openssl), credential theft, persistence (systemd/cron/XDG autostart/udev/at jobs/PROMPT_COMMAND/.bash_logout), privilege escalation (SUID/sudoers/polkit/capabilities), anti-forensics (history/log clearing), C2/exfiltration, crypto mining, download-chmod-execute, /tmp staging, process hiding, system recon, kernel modules, pacman hooks, alias overrides
- **install_script_analysis** (27 patterns): curl/wget in install, pipe to shell, persistence, credential access, obfuscation ($IFS, ANSI-C hex, ROT13), base64, eval, nohup, /tmp exec, chmod+exec, Python RCE, output suppression, crypto mining, kernel modules, env tokens, anti-forensics (history/log clearing), sudoers modification, PROMPT_COMMAND injection, XDG autostart
- **source_url_analysis** (11 patterns): raw IP, URL shortener, Discord webhook, pastebin, dynamic DNS, Telegram bot, tunnel service, HTTP source, ephemeral file hosting, Tor hidden service, MEGA
- **gtfobins_analysis** (117 patterns): reverse/bind shells via Node.js/Julia/Tcl/Java/Go/OpenSSL, pipe-to-interpreter (node/ruby/php/lua/tclsh/R/julia/awk/jjs/ksh/csh/zsh/fish/dash), tar checkpoint, zip -TT, vim shell escape, gdb batch, expect spawn, nsenter, capsh, unshare, nmap, SSH ProxyCommand, pkexec, docker/podman, systemd-run, strace, screen, tmux, find/xargs/sed/cpio, cmake, psql, dotnet, tcpdump, nano, ed, m4, ip netns, gcc wrapper

### Adding a new pattern

1. Add a `[[section_name]]` entry to patterns.toml
2. Use a descriptive `id` following the convention: `P-*` for Pkgbuild, `B-*` for Behavioral, etc.
3. Test the regex against known malicious and benign PKGBUILDs
4. Set `override_gate = true` only for patterns with near-zero false positive rates
