# Architecture

## 1. Core idea: Bring Your Own Protocol / Server (BYOP)

Deterium VPN is split into two things that are easy to conflate:

1. A **client** that establishes a tunnel.
2. A **server** that terminates it.

Deterium VPN only ever ships the client side (plus an optional helper that runs *on the user's own server*). The server itself — WireGuard, OpenVPN, or whatever comes later — is deployed, owned, and controlled entirely by the user. Deterium never operates infrastructure that carries user traffic.

This means the client cannot hardcode one protocol's wire format. It needs a stable internal abstraction that different protocol implementations plug into.

## 2. Workspace layout (Rust)

Cargo workspace, crates split by responsibility so protocol support can be added without touching the core or the UI:

```
deterium-vpn/
├── crates/
│   ├── deterium-core/        # ProtocolAdapter trait, ServerProfile, validation, import/export, server-setup script generator
│   ├── deterium-proto-wireguard/   # WireGuard adapter (in-process, boringtun) + key generation
│   ├── deterium-proto-openvpn/     # OpenVPN adapter (drives the system `openvpn` client)
│   ├── deterium-net/          # OS networking: adapter, routes, DNS, elevation, leak-protection firewall, guaranteed undo (see its README)
│   ├── deterium-secrets/      # encrypts the secrets inside saved profiles (Windows DPAPI)
│   ├── deterium-ipc/          # app <-> background-service protocol (JSON lines) and the Windows named-pipe transport
│   ├── deterium-service/      # the Windows service: owns the tunnel, installs/uninstalls itself
│   ├── deterium-engine/       # maps a profile's protocol to its adapter; used by the GUI and the service
│   └── deterium-gui/          # native desktop GUI (egui/eframe), Windows-first
└── docs/
    ├── ARCHITECTURE.md
    └── adr/
```

## 3. The `ProtocolAdapter` abstraction

Everything protocol-specific lives behind one trait in `deterium-core`. `ConnectionConfig`/`TunnelHandle` are associated types, not one shared struct — WireGuard's connect-time data (raw keys, a UDP socket) and OpenVPN's (eventually, a child process handle) don't share a shape, and callers already pick the concrete adapter via `ServerProfile::protocol` before calling in, so static dispatch per protocol was the real shape from the start:

```rust
pub trait ProtocolAdapter {
    type ConnectionConfig;
    type TunnelHandle;

    /// Parse/validate a server profile for this protocol.
    fn load_profile(&self, profile: &ServerProfile) -> Result<Self::ConnectionConfig, AdapterError>;

    /// Bring the tunnel up. Returns a handle used for status/teardown.
    fn connect(&self, config: Self::ConnectionConfig) -> Result<Self::TunnelHandle, AdapterError>;

    fn disconnect(&self, handle: Self::TunnelHandle) -> Result<(), AdapterError>;

    fn status(&self, handle: &Self::TunnelHandle) -> TunnelStatus;
}
```

**Status.**

- **WireGuard** has two modes. *Full* is a real VPN: `deterium-net` creates a Wintun adapter and applies addresses, routes, DNS and MTU (1420 unless the profile says otherwise), and guarantees they are undone; the data plane in `deterium-proto-wireguard/src/pump.rs` moves IP packets between that adapter and the server with `boringtun`, drops decrypted packets whose source the server isn't allowed to use, and counts real bytes. *Handshake only* ("Test connection") does the real handshake and nothing else: no adapter, no routes, no rights needed. It also honors the profile's preshared key, fixed listen port and keepalive, and binds an IPv6 socket for IPv6 endpoints.
  - **Connection health.** WireGuard has no "connected" state, so liveness is judged by handshake age (`health.rs`, pure and unit-tested): with keepalives on, the client starts its own handshake when the last one is older than 45 s, and a handshake older than 90 s means the server stopped answering. The status then drops to `Reconnecting`, handshakes are retried every 10 s, and the UDP socket is replaced every 20 s so a network change or resume from sleep can't leave the tunnel sending into a dead socket. Recovery is automatic. (Before this the status could stay `Connected` forever after the server went quiet.)
  - **Leak protection** (`leak.rs` + `wfp.rs`): optional *kill switch* (block everything outside the tunnel, with the LAN optionally allowed) and *DNS-leak blocking* (only applied when the tunnel really carries the DNS servers, otherwise it would cut off name lookups for the whole PC). The policy is a pure rule list whose ordering is unit-tested (the VPN server, the tunnel adapter, loopback and DHCP are always permitted before the catch-all block); Windows Filtering Platform filters are installed in one transaction inside a **dynamic session**, so Windows removes them by itself if Deterium closes or crashes. If the rules can't be installed the connection fails rather than connecting unprotected.
  - **Verified on a real Windows 11 PC against a real WireGuard server (a VirtualBox Ubuntu VM), elevated, with the official signed Wintun driver:** adapter, address, routes, DNS and MTU are created and pings answer through the tunnel (0-2 ms, 0% loss); disconnect removes everything and leaves the default routes untouched; when a tunnel route covers the server's own address a host route keeps it on the real interface; after the process is killed outright the journal lists the leftovers and the next start reverts them; **a full tunnel (`0.0.0.0/1` + `128.0.0.0/1`, with `::/1` + `8000::/1`) sends all traffic through the server** (`tracert` shows the server as first hop, DNS and HTTPS work through the tunnel, the server's NAT counters rise, the original default route stays in place); stopping WireGuard on the server under a live tunnel made the status drop to `Reconnecting` after 82 s and return to `Connected` by itself 10 s after the server came back; and with the kill switch on, new connections outside the tunnel are blocked while the tunnel and the LAN keep working, DNS to the LAN router is blocked on a full tunnel, and killing the app lifted the rules within 2 s with no cleanup. These were manual hardware runs, not part of the automated test suite.
  - **Not verified live:** actual IPv6 connectivity through a tunnel (the IPv6 default-route halves are installed and unit-tested), and DNS resolution *by name* against a tunnel-only resolver beyond the lookups above. Observations: a new adapter attracts Windows' own background traffic (multicast, name discovery), so the byte counters move even when nothing is being used; and the first packet after "connected" can take about 1-2 s to get through.
- **OpenVPN** is real in a different way: Deterium does not reimplement the protocol, it drives the system `openvpn` client as a child process, which needs administrator rights (the adapter asks for them like WireGuard's Full mode). The `.ovpn` text goes to a private temp file (removed on disconnect), the client's log is parsed to derive state ("Initialization Sequence Completed" = connected), and the recent log is exposed so the UI can show the real failure reason (for example missing administrator rights). The client must be installed; if it isn't, the UI says so. The lifecycle (spawn, log parsing, kill, cleanup) is tested against a stand-in `openvpn`, and **against a live OpenVPN 2.6 server** (a test PKI on the VirtualBox VM): the Rust adapter connects in about 6-8 seconds, reaches `Connected` from the real `Initialization Sequence Completed` line and disconnects cleanly (`crates/deterium-proto-openvpn/tests/live_server.rs`, ignored by default). Real client output is kept as a fixture so the log parsing is checked against what OpenVPN actually prints. Caveat: that run used the Linux `openvpn` inside WSL through a wrapper, so the Windows `openvpn.exe` path (service/driver, administrator rights) has not been exercised. Shutdown ends the whole process tree on Windows so launchers/wrappers can't leave a client running.
- **Untrusted configs.** An imported `.ovpn` can ask OpenVPN to run programs (`up`, `down`, `script-security 2`, `plugin`, ...). Those directives are rejected by `ServerProfile::check` (so the editor refuses to save) and again by the adapter, since a profile file can be hand-edited.

- `ServerProfile` is Deterium's normalized, protocol-tagged config format — a thin wrapper around whatever the user already has (a `.conf` for WireGuard, a `.ovpn` for OpenVPN), plus metadata (name, protocol id, optional companion endpoint).
- New protocol support = new crate implementing this trait + one variant in `deterium-engine`. The GUI never branches on protocol type themselves: they call `deterium_engine::connect(&profile)` and get a `Tunnel` to poll and disconnect.
- WireGuard runs in-process (`boringtun`) so the client doesn't need the `wg` binary; OpenVPN shells out because a pure-Rust implementation is a much larger undertaking.

## 3a. `ServerProfile` format

**Container format: TOML.** One `.toml` file per server. Matches the Rust ecosystem's own convention (`Cargo.toml`), supports comments (useful since these are hand-editable, unlike JSON), and maps cleanly onto serde.

**Envelope + protocol table.** Every profile has a small protocol-agnostic envelope, plus exactly one protocol-specific table (`[wireguard]` or `[openvpn]`) matching the `protocol` field:

```toml
deterium_profile_version = 1
id = "b3f1b1a0-7e34-4c9a-9b7a-2e9a9c6b7e10"   # stable UUID, assigned on import, never reused for a different server
name = "Home Server"                          # user-facing, freely renamable
protocol = "wireguard"                        # "wireguard" | "openvpn" (more added as adapters land)
tags = ["home"]                                # optional, organizational only
notes = "bought 2026, EU"                      # optional free text, never interpreted

```

**WireGuard (`[wireguard]`)** — structured fields, a near 1:1 mapping of a standard `.conf`, so import is a straight parse and export is a straight re-emit:

```toml
[wireguard.interface]
private_key = "yJ3z...base64..."
address = ["10.6.0.2/32"]
dns = ["10.6.0.1"]            # optional
mtu = 1420                     # optional
listen_port = 51000            # optional fixed local UDP port; absent = random

[wireguard.peer]
public_key = "xT9p...base64..."
preshared_key = "Qf2m...base64..."   # optional
endpoint = "vpn.example.com:51820"
allowed_ips = ["0.0.0.0/0", "::/0"]
persistent_keepalive = 25      # optional
```

One peer per profile in phase one (client connecting to one server) — multi-peer/multi-hop is explicitly deferred, not designed in yet.

**OpenVPN (`[openvpn]`)** — **not** remodeled field-by-field. A `.ovpn` file is a full config language with inline `<ca>`/`<cert>`/`<key>` blocks, and reimplementing that as structured TOML is a parser project of its own with little payoff. Instead the native file is embedded verbatim:

```toml
[openvpn]
raw_config = """
client
dev tun
proto udp
remote vpn.example.com 1194
<ca>
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
</ca>
...
"""
```

This keeps OpenVPN import fully lossless (literally "bring your own .ovpn") at the cost of Deterium not being able to show/edit individual OpenVPN fields in the GUI for phase one — only pass the blob to the `openvpn` binary. Structured fields can be added later without breaking old profiles (old ones just keep using `raw_config`).

**Two levels of validation, both in `deterium-core`:**
- *Structural* (`ServerProfile::parse`): exactly one of `[wireguard]` / `[openvpn]` must be present and match `protocol`, otherwise the file fails to load.
- *Semantic* (`ServerProfile::check`): returns every problem keyed by a stable field id: keys must be 32-byte base64, addresses and routes must be valid CIDRs, the endpoint must be `host:port` (IPv6 in brackets), MTU 576-9000, keepalive at most 65535, and an OpenVPN config must not run programs. The GUI editor shows these inline; adapters re-check what they depend on. A server file with semantic problems still loads (so the user can open it and fix it), but it can't be saved from the editor or connected until it's clean.

**Import paths into this format** (`deterium_core::import`; lenient: keep what parses, report what was dropped):
- WireGuard `.conf` becomes `[wireguard.interface]`/`[wireguard.peer]`. Unsupported things (`PostUp`/`PreUp`/`Table`/`FwMark`, DNS search domains, extra peers) are reported as warnings, not silently lost.
- OpenVPN `.ovpn` is wrapped whole into `[openvpn] raw_config`.
- A Deterium `.toml` is loaded with a fresh `id`, so importing a copy never collides with the original.

**Export** (`deterium_core::export`): a `wg-quick`-compatible `.conf` (round-trips through import), the `.ovpn` text, or the Deterium `.toml`. Exports contain the private key, and the GUI says so.

**Secrets:** phase one stores keys/certs in plain text inside the profile file itself (matching how a native `.conf`/`.ovpn` already behaves — protected only by filesystem permissions). No OS keychain integration yet; flagged in Open Questions (§7) as a planned hardening step, not a phase-one blocker.

## 4a. Bring-your-own-server onboarding

Most people who want a self-hosted VPN already have a rented VPS but have never configured WireGuard. The app removes that step without hosting anything:

- **"Set up my own server" wizard.** The user enters the VPS address; the app generates a *device* key pair locally and produces a bash script (`deterium_core::provision`, Debian/Ubuntu) that installs WireGuard on the VPS, creates the server key on the server, enables forwarding and NAT, opens the port in `ufw` if it's active, and allows this device as a peer. The script only ever contains the device's **public** key; the server's public key is printed at the end and pasted back into the app, which then saves a complete profile. Nothing passes through Deterium.
- **Safe by construction.** The generator validates every value that reaches the shell (the key must decode as base64-32, subnets must parse as CIDR, the port must be numeric), so nothing attacker-shaped can be interpolated. Tests assert that, that no private key literal is ever emitted, and that the output passes `bash -n`. It uses its own interface (`deterium0`) so an existing `wg0` on that VPS is left alone, and it backs up its own previous config.
- **Provider configs.** A purchased VPN subscription typically hands out a `.conf` or `.ovpn`; "Import a config file", "Paste a config" and drag-and-drop cover it, with the editor to review every setting before saving.
- **Built-in catalog (plumbing only).** The store also reads a read-only `catalog/` directory: its servers appear under "Built-in", can be connected and duplicated (to customize), but not edited or deleted. It ships empty. Whether to bundle any default servers is an open product decision, see [ADR 0002](adr/0002-default-servers.md).

## 5. Client responsibilities

Beyond calling into the chosen adapter, the client owns:

- **Profile management** — creating, editing, duplicating, exporting and deleting `ServerProfile`s (import from a file, paste or drop; the setup wizard; or manual entry), one `.toml` per server in the user's data folder (`%APPDATA%\Deterium\profiles` on Windows, `~/.config/deterium/profiles` elsewhere; `DETERIUM_DATA_DIR` overrides it; servers saved by earlier versions in `./profiles` are moved there on first start), written atomically (temp file + rename).
- **System integration** — implemented in `deterium-net` (see `crates/deterium-net/README.md`): adapter, routes, DNS and elevation behind a `Platform` trait, with a journal so a crash can't leave the user's routing table altered. Windows only. The kill switch / DNS-leak blocking (Windows Filtering Platform) covers both protocols. For OpenVPN, Deterium creates the Wintun adapter itself (so its identity is known), and puts a hold in place *before* OpenVPN starts (only the server addresses from the `.ovpn`, DHCP and, if allowed, the LAN are reachable; plain DNS too when the config names its server) and installs the full rules when OpenVPN reports it is connected: the tunnel adapter, the server addresses (from the `.ovpn` and from OpenVPN's own log) and DHCP are permitted, everything else is blocked; DNS-leak blocking applies when the server pushes DNS servers and `redirect-gateway`. If the rules cannot be installed the connection is ended instead of staying unprotected.
- **State machine** — connecting / connected / reconnecting / error, independent of which adapter is active.

## 5a. Desktop GUI (`deterium-gui`)

The GUI is a genuine native desktop app, not a webview/Electron/Tauri shell — no HTML/CSS/JS in the client. Built with **egui** (via `eframe`): pure Rust, immediate-mode, renders through `wgpu`/OpenGL, single static binary, no embedded browser runtime.

- **Windows-first.** First phase targets Windows only; `deterium-gui` is built and tested there. The toolkit itself is cross-platform (Linux/macOS come later by building the same crate on those targets — no rewrite expected).
- **Thin shell over `deterium-engine`.** The GUI holds no protocol or connection logic itself: it asks the engine to connect a profile and polls the `Tunnel`, the same engine the background service runs.
- **Everything about servers is done in the UI.** The user never has to touch a file: add (wizard, import, paste, drop, manual), edit every setting (keys with generate/show/copy and a live-derived public key, addresses, DNS, MTU, local port, preshared key, routed networks with presets, keepalive, tags, notes; or the full OpenVPN config), duplicate, export, delete (with confirmation). The editor shows the exact `[Peer]` block to add on the server. Fields are validated live with the same checks the adapters rely on, and an error only appears once a field has content or Save was attempted.
- **Honest status.** Everything on screen is real state, with no placeholder speeds or IPs. A real WireGuard connection shows "Connected" with real downloaded/uploaded byte counts; "Test connection" shows "Server reachable" and says plainly that no traffic is routed; OpenVPN shows "Connected" because its client really sets up the tunnel.
- **Threading.** No async runtime is needed: WireGuard's session runs on its own thread inside the adapter and OpenVPN is a child process; the egui loop only polls cheap shared state each frame and never blocks on I/O.
- **Module layout** (`crates/deterium-gui/src`): `theme` (palette, painting helpers, widgets), `store` (disk persistence and catalog), `draft` (the editor's text-field model to and from `ServerProfile`, tested), `editor` (chooser, editor form, setup wizard), `hero` (power button, tiles, server rows), `main` (app state and screens).
- **Administrator rights.** Two ways, see [ADR 0004](adr/0004-windows-service.md) and [ADR 0003](adr/0003-privilege-model.md). With the **background service** installed (sidebar footer or the permission dialog, one UAC prompt, once) the app runs as a normal user, sends the profile to the service over a user-restricted named pipe, and the tunnel and kill switch belong to the service: closing or crashing the window changes nothing, and the next start re-attaches (with the real uptime). Without it, connecting opens a dialog: *Install background service (recommended)*, *Restart as administrator* (relaunches through UAC and reconnects via `--connect <id>`), *Test connection only*, or *Cancel*. An elevated start also reverts network changes a crashed earlier run left behind.
- **System tray** (`crates/deterium-gui/src/tray.rs`): the icon is drawn in code (no image files), shows the connection state and has Open / Connect-Disconnect / Quit. Closing the window parks it instead of quitting. It is deliberately *not* hidden or minimised, because Windows stops redrawing such windows and the app would no longer notice tray clicks or connection changes: it loses its taskbar button and moves off screen as a tool window. `--minimized` starts parked.
- **Not built yet:** auto-connect at Windows start.

## 5b. Secrets at rest

`deterium-secrets` encrypts the sensitive fields of a saved profile — the WireGuard private key, the preshared key, and the whole OpenVPN config (it embeds private keys) — with **Windows DPAPI**. A protected value looks like `dpapi:v1:<base64>` in the `.toml`; public keys and everything else stay readable. Properties:

- Tied to the current Windows user: another user, another PC, or a copied/backed-up/synced profile file can't decrypt it, and no password has to be remembered.
- Transparent: the store decrypts on load and encrypts on save, so the editor, the engine and the adapters only ever see ordinary profiles.
- **Upgrades itself.** A profile written before this existed is encrypted the first time it is loaded, *verified by reading it back and decrypting*, and the original bytes are restored if that check fails — an upgrade can't lose a key. The GUI says how many it protected.
- Honest limits: it protects keys at rest, not from programs already running as the same user, and the app holds them in memory while connected. Exporting writes plain keys (the GUI warns). The OpenVPN client needs a readable config file, so a temporary one is written to a per-user folder (`%LOCALAPPDATA%\Deterium\run`) and deleted on disconnect; stale ones from a crash are purged.

## 6. Security model

- No Deterium-operated server ever sits in the data path; trust boundary is exactly "you and your own server."
- No telemetry/phone-home from the app by default.
- Secrets (private keys, auth tokens) stay on-device/on-server; `ServerProfile` export redacts or re-generates keys rather than reusing a single shared secret across exports where the protocol allows it (e.g. per-peer WireGuard keys).

## 7. Open questions (to resolve before implementation)

- The kill switch survives the *app* crashing (the background service owns it). Its rules are a dynamic WFP session, so Windows removes them if the service process ends (deliberate, a bug can never lock someone offline; the service restarts itself within 5 s). Once a tunnel with the kill switch has come up, the service keeps a note (`armed.json`) and a service that starts with the note present holds the network before it answers anyone, until the user connects or turns the protection off. What remains open is the time before the service is running; persistent filters would close it but a wrong persistent rule can lock a user out.
- Secrets are encrypted at rest on Windows (DPAPI, tied to the Windows user) but the app and any program running as the same user can still read them while it runs; Linux has no equivalent yet (files are `0600`). The service never stores a profile: the app decrypts it and sends it over the pipe, and the service keeps it in memory only.
- License choice (see README).
- Whether to bundle default servers at all, and if so which and with what consent flow: [ADR 0002](adr/0002-default-servers.md).

## 8. Non-goals

- Deterium does not and will not operate VPN exit servers.
- Deterium does not aim to be a multi-tenant SaaS control plane across users' servers.
- No built-in protocol obfuscation/censorship-circumvention features in the first phase (may be revisited later as an adapter, not a core feature).
