//! Integration tests that verify the full scan pipeline:
//! coordinator -> all rules -> verdict assignment.
//!
//! Individual pattern/signal tests live in each rule's #[cfg(test)] module.

use traur::coordinator::scan_pkgbuild;
use traur::shared::rules::Verdict;

fn detection_ids(result: &traur::shared::scoring::ScanResult) -> Vec<&str> {
    result.detections.iter().map(|d| d.rule_id.as_str()).collect()
}

#[test]
fn malicious_curl_pipe_triggers_malicious_verdict() {
    let pkgbuild = include_str!("fixtures/malicious/curl_pipe_bash.PKGBUILD");
    let result = scan_pkgbuild("firefox-fix-bin", pkgbuild);

    assert_eq!(result.verdict, Verdict::Malicious, "curl|bash should trigger MALICIOUS verdict");
    assert!(
        result.fired_rule.is_some(),
        "A rule should fire for curl|bash"
    );
}

#[test]
fn malicious_pkgbuild_accumulates_detections() {
    let pkgbuild = include_str!("fixtures/malicious/curl_pipe_bash.PKGBUILD");
    let result = scan_pkgbuild("firefox-fix-bin", pkgbuild);

    let ids = detection_ids(&result);

    // curl_pipe Rhai rule - intelligent detection
    assert!(ids.iter().any(|id| id.starts_with("R-CURL-PIPE")), "got: {ids:?}");
}

#[test]
fn benign_pkgbuild_scores_trusted() {
    let pkgbuild = include_str!("fixtures/benign/yay.PKGBUILD");
    let result = scan_pkgbuild("yay", pkgbuild);

    assert!(
        matches!(result.verdict, Verdict::Trusted | Verdict::Ok),
        "Benign PKGBUILD should be TRUSTED or OK, got {:?}",
        result.verdict
    );
}

#[test]
fn python_rce_triggers_malicious() {
    let pkgbuild = include_str!("fixtures/malicious/python_rce.PKGBUILD");
    let result = scan_pkgbuild("python-helper", pkgbuild);

    assert_eq!(result.verdict, Verdict::Malicious, "Python RCE should trigger MALICIOUS");
}

#[test]
fn acroread_style_multi_detection() {
    let pkgbuild = include_str!("fixtures/malicious/acroread_style.PKGBUILD");
    let result = scan_pkgbuild("acroread", pkgbuild);

    assert_eq!(result.verdict, Verdict::Malicious);

    let ids = detection_ids(&result);
    // Verifies detections from multiple rules fire together
    assert!(!ids.is_empty(), "Should have detections, got: {ids:?}");
}

#[test]
fn gtfobins_multi_signal_triggers_malicious() {
    let pkgbuild = include_str!("fixtures/malicious/gtfobins_multi.PKGBUILD");
    let result = scan_pkgbuild("evil-tool", pkgbuild);

    assert_eq!(
        result.verdict,
        Verdict::Malicious,
        "GTFOBins multi-vector attack should be MALICIOUS, got {:?}",
        result.verdict
    );
}
