# GTFOBins Analysis Feature

Detects abuse of legitimate Unix binaries catalogued on [GTFOBins](https://gtfobins.github.io/) that are not covered by other features.

## Scope

This feature fills detection gaps for the 469 GTFOBins entries, scoped to patterns that are realistic in the AUR PKGBUILD lifecycle (makepkg build phases + pacman .install scripts). Patterns for tools not available on Arch Linux or with high false-positive risk in legitimate builds have been excluded.

Covers:

- **Reverse shells** via interpreters not caught by `pkgbuild_analysis` (Node.js, Julia, Tcl, Java Nashorn, Ksh, GDB, Go, OpenSSL)
- **Bind shells** (socat LISTEN+EXEC, nc -l -e, Go net.Listen, Lua socket.bind)
- **Pipe-to-interpreter** download-and-execute patterns (curl/wget piped to node, ruby, php, lua, tclsh, R, julia, awk, jjs, ksh, csh, zsh, fish, dash)
- **Alternative pipe-to-shell** (aria2c, lwp-download, finger, whois, tftp, smbclient piped to sh/bash)
- **Non-obvious command execution** (tar --checkpoint-action, zip -TT, gdb batch, vim -c shell escape, expect spawn, nsenter, capsh, unshare, nmap scripting, SSH ProxyCommand, pkexec, emacs batch, rlwrap, sqlite3 .shell, screen -X stuff, tmux send-keys, busybox subcommands, doas, chroot shell, docker/podman volume mount, systemd-run, strace, script -c, flock, find -exec, xargs, sed e, split --filter, cpio --rsh-command, dc !, m4 esyscmd, ip netns exec, gcc -wrapper, cmake, psql \\!, dotnet fsi, tcpdump -z, docker exec/cp, nano -s, VS Code tunnel, ed !)
- **Alternative download utilities** (aria2c, lwp-download, tftp, finger, whois, ftp/ncftp/lftp, smbclient, scp, rsync, node http, sftp, sshfs, busybox wget)
- **Interpreter inline execution** (node -e, ruby -e, php -r, lua -e, R -e, julia -e, jjs/jshell, tclsh heredoc, gdb python, gnuplot, octave, guile, irb)
- **Library injection** (LD_LIBRARY_PATH, ldconfig -f, ssh-keygen -D, mysql --default-auth, nginx load_module)
- **Sensitive file operations** (tee to sudoers/passwd/shadow, cp of auth files, chown/ln sensitive, mount --bind, install SUID)
- **Encoding/exfiltration** (basenc/base58/ascii85 decode, hping3, CUPS cancel, restic backup, ab POST, tailscale file cp)
- **Persistence** (chattr +i, redis-cli config set, GIT_EXTERNAL_DIFF, iptables-save)

## Excluded (not applicable to AUR)

The following GTFOBins patterns were evaluated and excluded:
- **Not on Arch**: snap, rpm, start-stop-daemon, service (SysVinit), update-alternatives, rlogin, puppet
- **Near-zero value**: socket utility, elvish, urlget, clisp, gimp Script-Fu, cpulimit, loginctl user-shell, ctr, kubectl, lxd/lxc
- **High false-positive risk**: fzf --preview (legitimate use), TeX --shell-escape (legitimate LaTeX builds)

## Signal IDs

All signal IDs use the `G-` prefix. Override gates are set for patterns that are unambiguously malicious (reverse shells, download-and-execute pipes, tar checkpoint exec).

## Category

All signals use `SignalCategory::Pkgbuild` (weight 0.45).
