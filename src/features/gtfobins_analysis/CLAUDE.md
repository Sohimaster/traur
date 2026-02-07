# GTFOBins Analysis Feature

Detects abuse of legitimate Unix binaries catalogued on [GTFOBins](https://gtfobins.github.io/) that are not covered by other features.

## Scope

This feature fills detection gaps for the 469 GTFOBins entries, covering:

- **Reverse shells** via interpreters not caught by `pkgbuild_analysis` (Node.js, Julia, Tcl, Java Nashorn, Ksh, GDB, Go, socket utility)
- **Bind shells** (socat LISTEN+EXEC, nc -l -e)
- **Pipe-to-interpreter** download-and-execute patterns (curl/wget piped to node, ruby, php, lua, tclsh, R, julia, awk, jjs, ksh, csh, zsh, fish, dash, elvish)
- **Alternative pipe-to-shell** (aria2c, lwp-download, finger, whois, tftp, smbclient piped to sh/bash)
- **Non-obvious command execution** (tar --checkpoint-action, zip -TT, gdb batch, vim -c shell escape, expect spawn, nsenter, capsh, unshare, nmap scripting, SSH ProxyCommand, pkexec, emacs batch, rlwrap, sqlite3 .shell, screen -X stuff, tmux send-keys, busybox subcommands, doas, chroot shell, docker/podman volume mount, ctr, kubectl exec, lxd/lxc, snap --shell, systemd-run, strace, script -c, loginctl, start-stop-daemon, cpulimit, flock)
- **Alternative download utilities** (aria2c, lwp-download, tftp, finger, whois, ftp/ncftp/lftp, smbclient, scp, rsync, node http, urlget)
- **Interpreter inline execution** (node -e, ruby -e, php -r, lua -e, R -e, julia -e, jjs/jshell, tclsh heredoc, gdb python, gnuplot, octave, clisp, guile, irb, gimp Script-Fu)
- **Library injection** (LD_LIBRARY_PATH, ldconfig -f)
- **Sensitive file operations** (tee to sudoers/passwd/shadow, cp of auth files)
- **Encoding/exfiltration** (basenc/base58/ascii85 decode, hping3, CUPS cancel, restic backup)

## Signal IDs

All signal IDs use the `G-` prefix. Override gates are set for patterns that are unambiguously malicious (reverse shells, download-and-execute pipes, tar checkpoint exec).

## Category

All signals use `SignalCategory::Pkgbuild` (weight 0.45).
