pkgname=homeassistant-os-agent
pkgver=2022.4
pkgrel=1
pkgdesc='Patched OS-Agent for Home Assistant'
arch=('x86_64' 'armv7h' 'aarch64')
makedepends=(go)

build() {
  cd $srcdir/..
  go build -trimpath -ldflags="-s -w -X main.version=${pkgver}-${pkgrel}"
}

package()
{
  cd $pkgdir/../..
  install -Dm 755 "os-agent" -t "${pkgdir}/usr/bin"
  install -Dm 644 "contrib/haos-agent.service" -t "${pkgdir}/usr/lib/systemd/system"
  install -Dm 644 "contrib/io.hass.conf" -t "${pkgdir}/etc/dbus-1/system.d"
}
