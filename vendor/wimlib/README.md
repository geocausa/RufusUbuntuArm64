# Bundled WIM engine

RufusArm64 0.6.0 includes a package-private AArch64 build of
`wimlib-imagex` 1.14.5 at `/usr/lib/rufusarm64/wimlib-imagex`.

The binary was built natively on Ubuntu 24.04 ARM64 from upstream commit
`cd5e231c348c255ae5088873b5a66ee0eb96fa07` using:

```text
./configure --without-fuse --without-ntfs-3g --disable-shared --enable-static
```

It links only to the standard GNU C runtime and does not require Ubuntu's
`wimtools`, FUSE, NTFS-3G, or libxml2 runtime packages. The application uses
this private binary only for WIM splitting and validation.

Upstream project: https://github.com/ebiggers/wimlib
Licence: GPL-3.0-or-later for the command-line program. See `COPYING` and
`COPYING.GPLv3` in this directory. The exact corresponding source archive is stored in `source/` and shipped with
every RufusArm64 source release.

The package also installs the complete upstream source archive and checksum under `/usr/share/doc/rufusarm64/wimlib/source/`, so corresponding source accompanies the binary.
