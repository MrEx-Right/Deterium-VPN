# Third-party software shipped inside `Deterium.exe`

Deterium's own code is not covered by this file. The release executable also
contains the following unmodified third-party programs, run as separate
programs (not linked into Deterium).

## OpenVPN 2.6.17 (Windows build)

- What: `openvpn.exe` and the DLLs it needs (OpenSSL 3, LZO, pkcs11-helper,
  Visual C++ runtime), embedded and unpacked to
  `C:\Program Files\Deterium\openvpn\` the first time a tunnel needs them.
- License: GNU GPL version 2, with the OpenSSL linking exception. The full text
  is `license.txt`, unpacked next to the program.
- Source code: <https://github.com/OpenVPN/openvpn> (tag `v2.6.17`) and
  <https://openvpn.net/community-downloads/>.
- Obtained from the official installer
  `OpenVPN-2.6.17-I001-amd64.msi` (signed by OpenVPN Inc.) by
  `tools/fetch-openvpn.ps1`, which pins its SHA-256 and checks the signature.
  The MSI is only unpacked, never installed.
- Why 2.6 and not 2.7: 2.7 removed Wintun support and needs the `ovpn-dco` or
  `tap-windows6` driver. Deterium only ever installs the Wintun driver.

## Wintun 0.14.1

- What: the Wintun virtual network adapter driver, `wintun.dll`
  (`crates/deterium-net/assets/wintun.dll`), embedded and unpacked to
  `C:\Program Files\Deterium\`.
- License: the Wintun prebuilt-binaries license from WireGuard LLC (free to
  redistribute unmodified, together with an application that uses it).
  See <https://www.wintun.net/>.
- The file is signed by WireGuard LLC and is byte-for-byte the official one.
