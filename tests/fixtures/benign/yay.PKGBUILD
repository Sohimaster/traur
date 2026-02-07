pkgname=yay
pkgver=12.4.2
pkgrel=1
pkgdesc='Yet another yogurt. Pacman wrapper and AUR helper written in go.'
arch=('x86_64')
url='https://github.com/Jguer/yay'
license=('GPL-3.0-or-later')
depends=('pacman' 'git')
makedepends=('go')
source=("${pkgname}-${pkgver}.tar.gz::https://github.com/Jguer/yay/archive/v${pkgver}.tar.gz")
sha256sums=('abc123def456')

build() {
    cd "$pkgname-$pkgver"
    export CGO_CPPFLAGS="${CPPFLAGS}"
    export CGO_CFLAGS="${CFLAGS}"
    export CGO_CXXFLAGS="${CXXFLAGS}"
    export CGO_LDFLAGS="${LDFLAGS}"
    export GOFLAGS="-buildmode=pie -trimpath -ldflags=-linkmode=external -mod=readonly -modcacherw"
    go build
}

package() {
    cd "$pkgname-$pkgver"
    install -Dm755 yay "${pkgdir}/usr/bin/yay"
    install -Dm644 doc/yay.8 "${pkgdir}/usr/share/man/man8/yay.8"
}
