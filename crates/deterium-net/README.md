# deterium-net

The operating-system networking layer of Deterium VPN: everything needed to
turn "a tunnel that can encrypt packets" into "a VPN that actually carries
this PC's traffic" — a virtual adapter, addresses, routes, DNS, administrator
rights — and, above all, to **undo all of it reliably**.

It is protocol-agnostic. It knows nothing about WireGuard or OpenVPN; the
WireGuard crate uses it today and any future protocol can.

## Why this is its own crate

Changing a user's routing table is the riskiest thing this app does. A bug
here doesn't crash a window, it takes the user's internet away. So the code
that decides *what* to change, the code that *performs* the change, and the
code that *reverses* it are separated, and the first and last are testable
with no operating system involved.

## Layers

```
 proto-wireguard (data plane)            ← what to send where, crypto, keepalives
        │ uses
        ▼
 platform.rs   bring_up(platform, spec)  ← the only entry point: all-or-nothing
        │
        ├── plan.rs      PURE   spec → ordered [Op]       (safety rules live here)
        ├── system.rs    PORTABLE  NetworkGuard + Journal  (apply, rollback, crash recovery)
        │        ▲ drives
        ├── tun.rs       trait TunDevice (read/write one IP packet)
        └── Platform trait  ─────────────┬──────────────────────────┐
                                         ▼                          ▼
                                  windows.rs                  testing.rs
                              Wintun · IP Helper · netsh   FakePlatform / FakeTun
```

| File | What it is | Needs the OS? |
|---|---|---|
| `cidr.rs` | IP prefixes, `AllowedIps` (cryptokey-routing source filter) | no |
| `plan.rs` | `build_plan`: turns the profile's wishes into an ordered list of operations and enforces the safety rules | no |
| `system.rs` | `SystemNet` trait, `NetworkGuard` (apply / revert / drop), `Journal`, `recover_stale` | no (generic over `SystemNet`) |
| `tun.rs` | `TunDevice` trait + in-memory `FakeTun` | no |
| `platform.rs` | `Platform` trait, `bring_up`, `RoutedNetwork` | no |
| `leak.rs` | `LeakPolicy` -> ordered firewall `Rule`s (kill switch, DNS-leak blocking); the safety-critical ordering is unit-tested | no |
| `elevation.rs` | `is_elevated`, `relaunch_elevated`, `run_elevated_and_wait` (UAC), `current_user_sid` | yes |
| `windows.rs` | Wintun adapter, IP Helper routes/addresses, `netsh` DNS | yes |
| `wfp.rs` | Windows Filtering Platform: rules -> filters, in one transaction, in a dynamic session | yes |
| `testing.rs` | `FakePlatform`: a recording fake OS usable from other crates' tests | no |

## Safety rules (each is a unit test)

1. **Never replace the default route.** "Route everything" (`0.0.0.0/0`) is
   installed as two halves, `0.0.0.0/1` + `128.0.0.0/1`. They win by being
   more specific, and the user's original default route is never touched, so
   it is still there, intact, when the tunnel goes away.
2. **The server must stay reachable.** If any tunnel route would swallow the
   VPN server's own address, a host route for it via the *real* gateway is
   installed first. If the OS has no such route, the plan is **refused**
   (`RoutingLoop`) rather than installed — a loop would silently kill the
   connection.
3. **Nothing happens without administrator rights.** `bring_up` checks first
   and touches nothing otherwise.
4. **All or nothing.** If step *n* of the plan fails, steps *1..n-1* are
   reverted before the error is returned.
5. **Every change has an undo, written to disk before the next change.** The
   undo list (`%LOCALAPPDATA%\Deterium\net-journal.json`) survives a crash.
   On the next start, `recover_leftovers()` replays it. A missing or corrupt
   journal is not fatal.
6. **Revert on drop, newest first, idempotent.** Disconnect, a panic, or a
   closed window all run the same path; a failure to undo one step never
   stops the others.
7. **Routes are reverted before the adapter is removed** (field order in
   `RoutedNetwork`), and only after the data-plane threads have been joined.
8. **Source filtering.** `AllowedIps` drops decrypted packets whose source
   address the server isn't entitled to use.
9. **The VPN can never be firewalled off from itself.** In the leak policy the
   permits for loopback, the tunnel adapter, the VPN server (UDP, its port)
   and DHCP are always evaluated before any block; a test asserts it.
10. **Firewall rules cannot outlive the process.** They are installed in a WFP
    *dynamic session*: Windows removes them when the engine handle closes,
    including when the app crashes or is killed. A bug can block the network
    only while the app is running. They are added in a single transaction
    (all or nothing), and if they can't be installed the connection fails
    instead of connecting unprotected.
11. **DNS blocking outranks the LAN permit**, so the router's resolver is not
    a leak path; and it is only requested when the tunnel carries the DNS
    servers, otherwise it would break name lookups for the whole PC.

## Testing

* `cargo test -p deterium-net` — plan rules, guard rollback, crash recovery,
  the connect/disconnect flow against `FakePlatform`. No admin, no driver.
* `cargo test -p deterium-proto-wireguard` — two real WireGuard peers over
  loopback UDP, each with an in-memory adapter: IP packets cross in both
  directions, spoofed sources are dropped, byte counters are exact.
* The Windows modules (`windows.rs`, `wfp.rs`) can only be *exercised* with
  administrator rights and `wintun.dll`. It has been, end to end, against a
  real WireGuard server: adapter + address + route + DNS + MTU created,
  pings answered through the tunnel, everything removed on disconnect, the
  server's own address kept off the tunnel by a host route, and a killed
  process cleaned up from the journal on the next start. The test only used
  routes for the test VM's own subnets, so it could not affect the PC's
  internet at first; later runs covered a full `0.0.0.0/0` tunnel through a NAT'ing server and the kill switch (including killing the process). These were manual hardware tests, run by hand against a real server.

## Requirements and platform status

* **Windows**: `wintun.dll` (64-bit) next to the executable, from
  <https://www.wintun.net/>. It is loaded **only** from the executable's
  folder — an elevated process must not pick up a DLL from the working
  directory or `PATH`.
* **Linux / macOS**: not implemented; `system_platform()` returns a platform
  whose operations report `Unsupported`. The trait seams are in place; a port
  is a new `Platform` implementation (TUN device + `ip`/`route` or netlink),
  not a redesign.

## Known limits (honest list)

* **The kill switch lives as long as the process that made it.** That is the
  price of rule 10: the rules are a WFP *dynamic session*, so Windows removes
  them the moment that process ends, and a bug can never leave anyone offline
  (verified: 2 s after killing it). With the background service
  (`docs/adr/0004-windows-service.md`) that process is the service, not the
  window, so closing or crashing the app no longer drops protection (verified:
  app killed, tunnel and rules stayed). Protection before the service starts at
  boot, and after the service itself dies, would need persistent filters.
* **Established connections are not cut.** WFP's connect layers decide about
  *new* connections; a download already running when the tunnel drops keeps
  its connection.
* **With "allow local network" on, DNS to a LAN resolver is permitted** unless
  the tunnel carries the profile's DNS (then it is blocked and DNS goes through
  the tunnel). Turn the LAN permit off for strict behavior.
* **IPv6** is covered through routes (`::/0` is split like `0.0.0.0/0`) and,
  with the kill switch, by the catch-all block. IPv6 connectivity through a
  tunnel was not verified live.
* **OpenVPN's kill switch starts when OpenVPN is connected**, not before: the
  rules need the tunnel adapter and the server addresses OpenVPN actually uses.
  Deterium creates the adapter itself (`hold_openvpn_adapter`), so the rules can
  name it by its LUID. If OpenVPN switches to a server that was in neither the
  config nor its earlier log lines, the rules are replaced when it reconnects.
* **Linux/macOS** are not implemented; `system_platform()` reports `Unsupported`.
* **Privilege model**: the app either talks to the background service
  (`docs/adr/0004-windows-service.md`) or restarts itself elevated on request
  (`docs/adr/0003-privilege-model.md`). Both run the same `deterium-engine`.