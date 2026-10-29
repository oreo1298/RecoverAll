# Maintainer: oreo1298
#
# Arch Linux and Arch-based distributions (CachyOS, EndeavourOS, Manjaro, Garuda, ...).
# Builds the working tree this file sits in:
#
#   git clone https://github.com/oreo1298/RecoverAll.git
#   cd RecoverAll
#   makepkg -si
#
# Update:     git pull && makepkg -sif
# Uninstall:  sudo pacman -Rns recoverall

pkgname=recoverall
pkgver=1.0.0
pkgrel=1
pkgdesc="Recover deleted files, lost partitions and photos (NTFS, FAT, exFAT, ext4, XFS, HFS+...), repair and image disks"
arch=('any')
url="https://github.com/oreo1298/RecoverAll"
license=('MIT')
depends=('python' 'pyside6' 'qt6-svg' 'util-linux' 'polkit')
optdepends=('ddrescue: the best imager for failing disks'
            'smartmontools: disk health warnings'
            'sleuthkit: second engine (APFS, UFS, HFS)'
            'btrfs-progs: read and repair Btrfs'
            'cryptsetup: unlock LUKS and BitLocker volumes'
            'e2fsprogs: check and repair ext2/3/4'
            'dosfstools: check and repair FAT'
            'exfatprogs: check and repair exFAT'
            'ntfs-3g: fix common NTFS problems'
            'xfsprogs: check and repair XFS'
            'mdadm: read Linux software-RAID members'
            'ffmpeg: pictures from found videos'
            'f2fs-tools: check and repair F2FS'
            'jfsutils: check and repair JFS')
makedepends=('python-build' 'python-installer' 'python-setuptools' 'python-wheel')
checkdepends=('python-pytest')
install=recoverall.install

_srcdir="$startdir"

build() {
  cd "$_srcdir"
  rm -rf dist build
  python -m build --wheel --no-isolation
}

check() {
  cd "$_srcdir"
  QT_QPA_PLATFORM=offscreen PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider -m "not root" \
    tests/test_blockio.py tests/test_results.py tests/test_raid.py tests/test_ntfs_codecs.py tests/test_carve_engine.py \
    tests/test_cli.py tests/test_gui.py
}

package() {
  cd "$_srcdir"
  python -m installer --destdir="$pkgdir" dist/*.whl
  install -Dm755 packaging/recoverall-helper "$pkgdir/usr/lib/recoverall/recoverall-helper"
  sed -i "s#^exec recoverall-helper#exec /usr/bin/recoverall-helper#" "$pkgdir/usr/lib/recoverall/recoverall-helper"
  install -Dm644 packaging/polkit/io.github.oreo1298.RecoverAll.policy \
    "$pkgdir/usr/share/polkit-1/actions/io.github.oreo1298.RecoverAll.policy"
  install -Dm644 data/io.github.oreo1298.RecoverAll.desktop \
    "$pkgdir/usr/share/applications/io.github.oreo1298.RecoverAll.desktop"
  install -Dm644 data/io.github.oreo1298.RecoverAll.metainfo.xml \
    "$pkgdir/usr/share/metainfo/io.github.oreo1298.RecoverAll.metainfo.xml"
  install -Dm644 recoverall/data/recoverall.svg \
    "$pkgdir/usr/share/icons/hicolor/scalable/apps/io.github.oreo1298.RecoverAll.svg"
  install -dm755 "$pkgdir/var/lib/recoverall"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 NOTICE "$pkgdir/usr/share/licenses/$pkgname/NOTICE"
  install -Dm644 README.md docs/HOW-IT-WORKS.md -t "$pkgdir/usr/share/doc/$pkgname/"
}
