//! E2E tests for scan output formatting.
//!
//! Verifies the output produced by `write_text` for various verdicts.

use traur::shared::output;
use traur::shared::scoring::{ScanResult, SignalCategory};
use traur::shared::rules::{Verdict, Detection};

fn make_detection(rule_id: &str, verdict: Verdict, category: SignalCategory, salience: u32, description: &str) -> Detection {
    Detection {
        rule_id: rule_id.to_string(),
        verdict,
        category,
        salience,
        description: description.to_string(),
        matched_line: None,
    }
}

fn render(result: &ScanResult, verbose: bool) -> String {
    colored::control::set_override(false);
    let mut buf = Vec::new();
    output::write_text(&mut buf, result, verbose);
    String::from_utf8(buf).unwrap()
}

// ---------- TRUSTED ----------

#[test]
fn trusted_no_detections() {
    let result = ScanResult {
        package: "yay".to_string(),
        verdict: Verdict::Trusted,
        fired_rule: None,
        detections: vec![],
    };
    let out = render(&result, false);
    assert!(out.contains("yay"), "output should contain package name");
    assert!(out.contains("Verdict:") && out.contains("TRUSTED"), "output should show TRUSTED verdict");
    assert!(out.contains("No detections"), "output should say no detections");
}

#[test]
fn trusted_with_detections() {
    let result = ScanResult {
        package: "eww".to_string(),
        verdict: Verdict::Trusted,
        fired_rule: Some("WHITELIST".to_string()),
        detections: vec![
            make_detection("WHITELIST", Verdict::Trusted, SignalCategory::Metadata, 1000, "Whitelisted package"),
        ],
    };
    let out = render(&result, false);
    assert!(out.contains("eww"), "output should contain package name");
    assert!(out.contains("Verdict:") && out.contains("TRUSTED"), "output should show TRUSTED verdict");
    assert!(out.contains("Detections:"), "output should list detections");
    assert!(out.contains("WHITELIST"), "output should contain fired rule");
}

// ---------- OK ----------

#[test]
fn ok_with_detections() {
    let result = ScanResult {
        package: "some-tool".to_string(),
        verdict: Verdict::Ok,
        fired_rule: None,
        detections: vec![
            make_detection("R-LOW-VOTES", Verdict::Ok, SignalCategory::Behavioral, 500, "Low vote count"),
        ],
    };
    let out = render(&result, false);
    assert!(out.contains("some-tool"), "output should contain package name");
    assert!(out.contains("Verdict:") && out.contains("OK"), "output should show OK verdict");
    assert!(out.contains("Detections:"), "output should list detections");
}

// ---------- SUSPICIOUS ----------

#[test]
fn suspicious_with_detections() {
    let result = ScanResult {
        package: "crypto-bad".to_string(),
        verdict: Verdict::Suspicious,
        fired_rule: Some("R-CURL-PIPE".to_string()),
        detections: vec![
            make_detection("R-CURL-PIPE", Verdict::Suspicious, SignalCategory::Pkgbuild, 600, "Download and execute detected"),
        ],
    };
    let out = render(&result, false);
    assert!(out.contains("crypto-bad"), "output should contain package name");
    assert!(out.contains("Verdict:") && out.contains("SUSPICIOUS"), "output should show SUSPICIOUS verdict");
    assert!(out.contains("Detections:"), "output should list detections");
}

// ---------- MALICIOUS ----------

#[test]
fn malicious_with_detections() {
    let result = ScanResult {
        package: "evil-package".to_string(),
        verdict: Verdict::Malicious,
        fired_rule: Some("R-CURL-PIPE-COORDINATED".to_string()),
        detections: vec![
            make_detection("R-CURL-PIPE-COORDINATED", Verdict::Malicious, SignalCategory::Pkgbuild, 800, "Coordinated attack detected"),
        ],
    };
    let out = render(&result, false);
    assert!(out.contains("evil-package"), "output should contain package name");
    assert!(out.contains("Verdict:") && out.contains("MALICIOUS"), "output should show MALICIOUS verdict");
    assert!(out.contains("Fired rule: R-CURL-PIPE-COORDINATED"), "output should show fired rule");
    assert!(out.contains("Detections:"), "output should list detections");
}

#[test]
fn malicious_shows_all_detections() {
    let pkgbuild = include_str!("fixtures/malicious/curl_pipe_bash.PKGBUILD");
    let result = traur::coordinator::scan_pkgbuild("test", pkgbuild);
    let out = render(&result, false);

    // Must show package header
    assert!(out.contains("traur: test"), "should show package header");
    assert!(out.contains("Verdict:") && out.contains("MALICIOUS"), "should show MALICIOUS verdict");

    // If there are detections, they must be listed
    if !result.detections.is_empty() {
        assert!(out.contains("Detections:"), "detections must be listed");
        for detection in &result.detections {
            assert!(out.contains(&detection.rule_id), "detection {} must appear in output", detection.rule_id);
            assert!(out.contains(&detection.description), "detection description must appear");
        }
    } else {
        assert!(out.contains("No detections"));
    }
}
