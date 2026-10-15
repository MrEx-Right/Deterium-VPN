<p align="center">
  <img src="docs/banner.png" alt="Deterium: self-hosted VPN. Your server, your rules." width="100%">
</p>

<p align="center">
  <b>An open-source VPN app for the server you already control.</b><br>
  WireGuard and OpenVPN in one native Windows app, with a real kill switch and no provider in the middle.
</p>

<p align="center">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%2011-0078D4">
  <img alt="Built with Rust" src="https://img.shields.io/badge/built%20with-Rust-orange">
  <img alt="Protocols" src="https://img.shields.io/badge/protocols-WireGuard%20%7C%20OpenVPN-3fb68b">
  <img alt="Status" src="https://img.shields.io/badge/status-early%20prototype-yellow">
</p>

---

## What is Deterium?

Most "VPN apps" are really VPN *providers*: they run the exit servers, see your traffic and tie you to one protocol. **Deterium removes the provider.** You bring a server you own (or a WireGuard / OpenVPN service you subscribe to). Deterium is the app that sets it up, lets you configure every detail, and connects.

- **Nothing of ours in the data path.** No Deterium servers, no accounts, no telemetry. Traffic only ever touches your server.
- **Bring your own protocol.** WireGuard (runs inside the app) and OpenVPN (bundled, nothing to install) behind one interface.
- **Everything from the UI.** Add, import, edit every setting, duplicate, export and delete servers without opening a file.
- **Self-hosting made easy.** The setup wizard turns any Debian/Ubuntu VPS into your VPN endpoint with one pasted script. Your private key never leaves your PC.
- **One file.** `Deterium.exe` is the app, the background service and the installer. The Wintun driver DLL and OpenVPN are inside it.

## Features

| | |
|---|---|
| **Protocols** | WireGuard (in-process) and OpenVPN 2.6.17 (bundled, unpacked on first use) |
| **Full tunnel** | Traffic, DNS and HTTPS go through your server; disconnecting restores the network exactly as it was |
| **Kill switch + DNS-leak block** | Windows Filtering Platform rules for both protocols: new connections outside the tunnel are blocked. OpenVPN is held back from its very first second, and after a reboot or a service restart the network stays blocked (except to your VPN server) until you connect again or turn the protection off |
| **Crash-safe** | The rules belong to the service process, so Windows lifts them by itself if it dies, and leftovers from a crashed run are cleaned up on the next start |
| **Health detection** | A silent server turns the status to *Reconnecting*, and the tunnel recovers on its own |
| **Background service** | Install once (one permission prompt) and never need administrator rights again; the tunnel survives closing or crashing the window |
| **System tray** | Colour-coded icon (grey / blue / green / orange), connect and disconnect from its menu, `--minimized` starts straight in the tray |
| **Secrets at rest** | Private keys, preshared keys and OpenVPN logins are encrypted with Windows DPAPI; the files only open for your Windows account on this PC |
| **Import / export** | WireGuard `.conf`, OpenVPN `.ovpn` and Deterium `.toml`, by file, paste or drag and drop. Imported configs that could run programs, write files or open a control port are refused |
| **Honest status** | Live download/upload speed, latency and totals read from the tunnel adapter (the same for WireGuard and OpenVPN), a two-minute traffic graph, and Traffic / Connection / Protection / Log tabs. Latency is a real ping to an address inside the tunnel; the exit IP is only looked up when you press the button. No fake speeds or placeholder IPs |

## Install

Deterium is built from source on your own PC. No ready-made program is distributed, so what runs is exactly the code you can read here. You need Windows 10 or 11 (64-bit), 5-8 GB of free disk space (almost all of it the build tools; Deterium's own build is about 1 GB) and 15-30 minutes the first time, mostly the one-off tool setup below.

**1. Install the build tools, once**

- Install [Rust](https://rustup.rs) with its default "MSVC" option.
- Rust needs Microsoft's C++ build tools. If you have never developed on Windows you don't have them: rustup then points you to **Visual Studio Build Tools**, where you tick **Desktop development with C++** (a download of a few GB). Do this before continuing.
- Open a **new** window afterwards (or sign out and in) so the tools are found.

**2. Get the code and install**

1. On GitHub choose **Code > Download ZIP**, then **extract it** (right-click > Extract All). Running the installer from inside the ZIP does not work.
2. Double-click **`Install-Deterium.bat`**. Windows may warn "Windows protected your PC" because the file came from the internet and is not signed; choose **More info > Run anyway**. The file is a short wrapper around [`tools/install.ps1`](tools/install.ps1), which is short and readable.

It then builds the app (a few minutes), asks whether to include the official OpenVPN (downloaded from OpenVPN Inc., checked against a pinned SHA-256 and signature, only unpacked, never installed), and installs for your user only: `Deterium.exe` lands on your **Desktop**, plus a Start Menu shortcut and an entry in *Settings > Apps*. The uninstaller is kept in `%LOCALAPPDATA%\Deterium`.

No administrator rights are needed to install. The installer puts no driver on your PC. When you connect, the app uses the signed **Wintun** adapter driver from WireGuard LLC (inside `Deterium.exe`); that is the only driver Deterium ever uses.

Keep `Deterium.exe` where the installer put it: moving or deleting it breaks the Start Menu shortcut. The background service, if you installed it, keeps its own copy in `C:\Program Files\Deterium` and is not affected.

**Update:** download the new code, close Deterium (also from the tray icon) and run `Install-Deterium.bat` again. Your servers are kept.

**Remove:** *Settings > Apps > Deterium VPN*, or run `uninstall.ps1` from `%LOCALAPPDATA%\Deterium`. It deletes only `Deterium.exe`, never your Desktop folder, and removes the background service if it is installed (one permission prompt). Your saved servers are kept unless you pass `-RemoveData`.

**If something goes wrong**

| Message or symptom | What to do |
|---|---|
| `Rust isn't installed` right after installing it | Open a new window, or sign out and in, then run the installer again. |
| `linker 'link.exe' not found` or a build error mentioning MSVC | The C++ build tools are missing: install **Visual Studio Build Tools > Desktop development with C++**. |
| `Couldn't replace ...\Deterium.exe` | Deterium is still running. Quit it from the tray icon and run the installer again. |
| Antivirus quarantines `Deterium.exe` | The app is not code-signed, so some scanners are suspicious of any new program that changes routes. Check the source and the build yourself, then allow the file. |
| Anything else | Run `tools\install.ps1` in a PowerShell window to see the full output, and open an issue with it. |

## Get started

1. Open **Deterium VPN** from the Start Menu.
2. **Add a server:** import a `.conf` / `.ovpn`, paste a config, drop a file on the window, or let the **setup wizard** prepare a fresh VPS for you.
3. Press the power button. The first time, Deterium offers to install the **background service** (recommended, one permission prompt) or to restart as administrator.

Turn on the **kill switch** per server in its editor. Servers are saved as one `.toml` file each in `%APPDATA%\Deterium\profiles` (set `DETERIUM_DATA_DIR` to move them).

To remove the service, use the sidebar's *Background service* entry, or run `Deterium.exe service uninstall` from an administrator prompt. `Deterium.exe service status` tells you whether it is installed.

## Build by hand

```bash
cargo run -p deterium-gui              # run the app
cargo build --release -p deterium-gui  # release build (target\release\deterium-gui.exe)
cargo test --workspace
pwsh ./tools/fetch-openvpn.ps1         # optional, once: bundle OpenVPN before building
```

The release binary is the whole app; rename it to `Deterium.exe` if you like (the service installer copies whatever file is running to `C:\Program Files\Deterium`). Without the OpenVPN step the build still works, just without built-in OpenVPN.

## Status

**Early but working prototype.** Everything under *Verified live* was run on real hardware (Windows 11, real WireGuard and OpenVPN servers), not just in unit tests.

**Verified live**
- Full tunnel with DNS and HTTPS through the server, clean disconnect, cleanup after a crashed run.
- Kill switch and DNS-leak blocking for WireGuard and OpenVPN: with the tunnel's routes removed to imitate a drop, outside traffic was blocked, and disconnecting restored everything.
- Connection-health detection and automatic recovery.
- Background service: an unprivileged client connects and is then killed, and the tunnel and kill switch stay up. Killing the service lifts the rules within seconds and it restarts by itself.
- Built-in OpenVPN against a real public server: traffic exits from the server's IP, and routes, adapters and internet are back as before afterwards.
- Tray icon, including connecting from the tray while the window is hidden.
- DPAPI encryption of keys and logins, and the whole add / import / edit / export / delete flow in the GUI.
- OpenVPN kill switch from before OpenVPN starts: with the real OpenVPN 2.6.17, other traffic is refused by the firewall while it is connecting, and a connection that never comes up gives the network back.
- Armed kill switch after a restart: a second service process that finds the first one's note holds the network (the VPN server stays reachable) until the protection is turned off; checked against the real Windows Filtering Platform.
- WireGuard kill switch from before the tunnel is built: while the adapter and routes are created, the firewall refused other traffic from the first moment (123 of 124 probes during the 1.1 s build), and disconnecting gave the network back exactly as it was.

**Not yet**
- "Start with Windows" (connects to one server when you sign in) is built and unit-tested, but has not been run through a real sign-in yet
- Installer (MSI/NSIS) and code signing
- Linux and macOS (the platform layer is the seam; Windows is the product for now)
- IPv6 connectivity has not been tested live
- The kill switch cannot act in the few seconds between Windows starting and the service starting, or while Windows restarts a crashed service (about 5 s). From the moment the service is up again it holds the network before it answers anything

The known limits are listed honestly in [SECURITY.md](SECURITY.md).

## How it works

```
 deterium-gui ──► deterium-engine ──► deterium-proto-wireguard   (in-process)
 (the app)             │          └─► deterium-proto-openvpn     (bundled child process)
                       │
            named pipe │ (restricted to your user)
                       ▼
             deterium-service ──► deterium-net      Wintun adapter, routes, DNS, WFP kill switch
                                  deterium-secrets  DPAPI
```

The GUI holds no connection logic. It hands a profile to the engine, which runs it directly or through the Windows service. Crates in `crates/`:

| Crate | Job |
|---|---|
| `deterium-core` | Profile model, validation, import/export, server-setup script generator |
| `deterium-proto-wireguard` | WireGuard adapter and key generation |
| `deterium-proto-openvpn` | OpenVPN adapter, bundled binaries, OpenVPN kill-switch logic |
| `deterium-net` | Adapter, routes, DNS, elevation, leak-protection firewall, guaranteed undo |
| `deterium-secrets` | DPAPI encryption of saved secrets |
| `deterium-ipc` | App ↔ service protocol and named-pipe transport |
| `deterium-service` | The Windows service; installs and removes itself |
| `deterium-engine` | Picks the adapter for a profile; shared by the app and the service |
| `deterium-gui` | The native desktop app (egui) |

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design. The decision records are in [docs/adr](docs/adr): [bring your own protocol](docs/adr/0001-bring-your-own-protocol.md), [default servers](docs/adr/0002-default-servers.md), [privilege model](docs/adr/0003-privilege-model.md), [Windows service](docs/adr/0004-windows-service.md).

## Automated checks

These workflows live in `.github/workflows`, one file each. All of them run on every push to `main`, on every pull request and, for the scheduled ones, every Monday at 08:00 (Turkey time), and any of them can also be started by hand from the *Actions* tab:

| Workflow | What it proves |
|---|---|
| **Build (Windows)** | formatting, lints, every test, no leaked keys, and a release build with OpenVPN built in |
| **Build (Linux)** | the portable crates still build and pass (the app itself is Windows-only for now) |
| **CodeQL** | GitHub's security scanner over the Rust code and the workflow files |
| **VPN check** | a real tunnel (Cloudflare WARP over WireGuard) comes up, carries traffic and goes away again |
| **Tunnel test** | three connect/disconnect rounds and a simulated crash each leave the network exactly as it was |
| **Encryption test** | everything that leaves the PC through the tunnel is WireGuard ciphertext: a recognisable plaintext is sent and never appears on the wire |

The three tunnel workflows route only `1.1.1.1` and `1.0.0.1` into the tunnel, so the CI machine itself is never cut off. They use a free, anonymous Cloudflare WARP device, so a red result there is something to read before it is trusted: it can come from that service rather than from Deterium. No workflow uploads or publishes a binary.

## Security

Deterium changes how your computer routes traffic and handles private keys, so it is built defensively. It installs no new drivers (only the signed Wintun driver), the bundled programs live in an administrator-only folder, secrets are encrypted at rest, and the service's pipe only accepts the user who installed it. See the [security policy](SECURITY.md) for what is in scope and how to report a vulnerability privately. `tools/scan-secrets.ps1` checks that no key ends up in the repository.

## Third-party software

`Deterium.exe` embeds, unmodified and run as separate programs, **OpenVPN 2.6.17** (GPL-2.0 with the OpenSSL exception) and the **Wintun 0.14.1** driver DLL (WireGuard LLC). Versions, licenses, sources and the reason for OpenVPN 2.6 instead of 2.7 are in [THIRD-PARTY.md](THIRD-PARTY.md).

## License

TBD. A permissive or copyleft open-source license will be chosen before the first release.
