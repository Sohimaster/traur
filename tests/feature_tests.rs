//! Integration tests that verify the full scan pipeline:
//! coordinator -> all features -> scoring -> tier assignment.
//!
//! Individual pattern/signal tests live in each feature's #[cfg(test)] module.

use traur::coordinator::scan_pkgbuild;
use traur::shared::scoring::Tier;

fn signal_ids(result: &traur::shared::scoring::ScanResult) -> Vec<&str> {
    result.signals.iter().map(|s| s.id.as_str()).collect()
}

#[test]
fn malicious_curl_pipe_triggers_override_gate() {
    let pkgbuild = include_str!("fixtures/malicious/curl_pipe_bash.PKGBUILD");
    let result = scan_pkgbuild("firefox-fix-bin", pkgbuild);

    assert_eq!(result.tier, Tier::Malicious, "curl|bash should trigger MALICIOUS tier");
    assert!(
        result.override_gate_fired.is_some(),
        "Override gate should fire for curl|bash"
    );
}

#[test]
fn malicious_pkgbuild_accumulates_cross_feature_signals() {
    let pkgbuild = include_str!("fixtures/malicious/curl_pipe_bash.PKGBUILD");
    let result = scan_pkgbuild("firefox-fix-bin", pkgbuild);

    let ids = signal_ids(&result);

    // pkgbuild_analysis signal
    assert!(ids.contains(&"P-CURL-PIPE"), "got: {ids:?}");
    // source_url_analysis signals
    assert!(ids.contains(&"P-URL-SHORTENER"), "got: {ids:?}");
    assert!(ids.contains(&"P-RAW-IP-URL"), "got: {ids:?}");
    // name_analysis signal
    assert!(ids.contains(&"B-NAME-IMPERSONATE"), "got: {ids:?}");
}

#[test]
fn benign_pkgbuild_scores_low() {
    let pkgbuild = include_str!("fixtures/benign/yay.PKGBUILD");
    let result = scan_pkgbuild("yay", pkgbuild);

    assert!(
        result.tier <= Tier::Ok,
        "Benign PKGBUILD should score TRUSTED or OK, got {:?} (trust: {})",
        result.tier,
        result.score
    );
    assert!(
        result.override_gate_fired.is_none(),
        "No override gate should fire for benign package"
    );
}

#[test]
fn python_rce_triggers_override_gate() {
    let pkgbuild = include_str!("fixtures/malicious/python_rce.PKGBUILD");
    let result = scan_pkgbuild("python-helper", pkgbuild);

    assert_eq!(result.tier, Tier::Malicious, "Python exec(urlopen()) should trigger MALICIOUS");
    assert!(result.override_gate_fired.is_some());
}

#[test]
fn acroread_style_multi_signal_detection() {
    let pkgbuild = include_str!("fixtures/malicious/acroread_style.PKGBUILD");
    let result = scan_pkgbuild("acroread", pkgbuild);

    assert_eq!(result.tier, Tier::Malicious);

    let ids = signal_ids(&result);
    // Verifies signals from multiple features fire together
    assert!(ids.contains(&"P-CURL-PIPE"), "got: {ids:?}");
    assert!(ids.contains(&"P-PASTEBIN-CODE"), "got: {ids:?}");
    assert!(ids.contains(&"P-SYSINFO-RECON"), "got: {ids:?}");
    assert!(ids.contains(&"P-SYSTEMD-CREATE"), "got: {ids:?}");
}

#[test]
fn gtfobins_multi_signal_triggers_malicious() {
    let pkgbuild = include_str!("fixtures/malicious/gtfobins_multi.PKGBUILD");
    let result = scan_pkgbuild("evil-tool", pkgbuild);

    assert_eq!(
        result.tier,
        Tier::Malicious,
        "GTFOBins multi-vector attack should be MALICIOUS, got {:?} (score: {})",
        result.tier,
        result.score
    );
    assert!(
        result.override_gate_fired.is_some(),
        "Override gate should fire for GTFOBins attack patterns"
    );

    let ids = signal_ids(&result);
    // gtfobins_analysis signals
    assert!(ids.contains(&"G-TAR-CHECKPOINT"), "got: {ids:?}");
    assert!(ids.contains(&"G-DOWNLOAD-ARIA2C"), "got: {ids:?}");
    assert!(ids.contains(&"G-DOWNLOAD-LWP"), "got: {ids:?}");
    assert!(ids.contains(&"G-REVSHELL-NODE"), "got: {ids:?}");
    assert!(ids.contains(&"G-PIPE-RUBY"), "got: {ids:?}");
    // source_url_analysis signal for raw IP
    assert!(ids.contains(&"P-RAW-IP-URL"), "got: {ids:?}");
}

#[test]
fn atomic_arch_campaign_is_malicious() {
    // Issue #25: orphaned package adopted, malicious npm dependencies injected
    // at build time, credentials harvested.
    let pkgbuild = include_str!("fixtures/malicious/atomic_arch.PKGBUILD");
    let result = scan_pkgbuild("alvr", pkgbuild);
    let ids = signal_ids(&result);

    assert_eq!(result.tier, traur::shared::scoring::Tier::Malicious);
    assert!(ids.contains(&"P-NPM-ATOMIC-ARCH-NAMES"), "got: {ids:?}");
    assert!(ids.contains(&"P-NPM-INSTALL-BUILDTIME"), "got: {ids:?}");
    assert!(ids.contains(&"P-CLOUD-CRED-ACCESS"), "got: {ids:?}");
}

#[test]
fn ebpf_loading_is_flagged() {
    let pkgbuild = r#"pkgname=rootkit
pkgver=1
pkgrel=1
arch=('x86_64')
url=''
license=()
source=("$url/x.c")
sha256sums=('9f2c1b7e5d4a3c8b1e0f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d')
build() {
    gcc -o k x.c -lbpf
    cat > loader.c <<EOC
#include <bpf/libbpf.h>
bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
EOC
}
"#;
    let result = scan_pkgbuild("rootkit", pkgbuild);
    let ids = signal_ids(&result);
    assert!(ids.contains(&"P-EBPF-ROOTKIT"), "got: {ids:?}");
}

#[test]
fn benign_npm_usage_is_not_malicious() {
    // Ordinary `npm install` in a build() is a review prompt, not a verdict.
    let pkgbuild = r#"pkgname=code
pkgver=1
pkgrel=1
arch=('x86_64')
url='https://github.com/microsoft/vscode'
license=('MIT')
source=("$url/archive/v$pkgver.tar.gz")
sha256sums=('9f2c1b7e5d4a3c8b1e0f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d')
build() {
    cd "code-$pkgver"
    npm install
    npm run build
}
"#;
    let result = scan_pkgbuild("code", pkgbuild);
    assert!(
        result.tier < traur::shared::scoring::Tier::Suspicious,
        "plain npm install must not escalate to SUSPICIOUS, got {:?} ({})",
        result.tier,
        result.score
    );
}
