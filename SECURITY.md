# Security policy

Deterium VPN changes how a computer's traffic is routed and handles private
keys, so security reports are taken seriously.

## Reporting a vulnerability

Please **don't open a public issue** for a security problem. Use GitHub's
private reporting instead: the repository's *Security* tab, *Report a
vulnerability*. Include what you found, how to reproduce it, and the version.
You'll get an answer as soon as the maintainer can read it; this is a
volunteer project, so there is no guaranteed response time.

## What is in scope

- Anything that lets a program or user without administrator rights gain them
  through Deterium, or change another user's network settings.
- Leaks: traffic that should have gone through the tunnel (or been blocked by
  the kill switch) but didn't.
- Private keys, preshared keys or OpenVPN logins being readable by something
  that shouldn't be able to read them.
- An imported config (`.conf`, `.ovpn`, `.toml`) that can run a program, write
  a file, or open a port on the user's machine.

## How the sensitive parts are built

The design decisions behind these are written down so they can be reviewed:

- Privilege model and the background service's access rules:
  `docs/adr/0004-windows-service.md` (and the fallback in `0003-privilege-model.md`)
- Secrets at rest (Windows DPAPI): `docs/ARCHITECTURE.md`, section 5b
- Network changes, crash recovery and the kill switch:
  `crates/deterium-net/README.md` (the 11 safety rules and the known limits)

## Known limits (not bugs)

These are documented and on the roadmap:

- The kill switch lasts as long as the background service runs; it is not
  enforced before the service starts at boot, or after the service itself dies
  (it restarts within seconds). Without the service installed it lasts only as
  long as the app.
- The OpenVPN kill switch is installed the moment OpenVPN reports it is connected (like the WireGuard one it needs the tunnel adapter to exist), so the first seconds of a connection are as exposed as without a VPN.
- The built-in OpenVPN is run as a separate program from an administrator-only folder; its own vulnerabilities are fixed by updating Deterium (see THIRD-PARTY.md for the bundled version).
- Secrets are protected against other Windows accounts and against copying the
  files to another PC, **not** against malware already running as the same user.
- Deterium is not distributed as a ready-made binary and is not code-signed: you build it from source (`Install-Deterium.bat`), so what runs is the code you can read.
- WireGuard packets are not padded. The WireGuard paper suggests padding the
  data to a multiple of 16 bytes; the library Deterium uses (boringtun) leaves
  that out, so someone watching your connection can see roughly how big each
  packet is. The contents stay encrypted (the encryption test checks that every
  byte leaving the PC is ciphertext), but sizes are not hidden.
- Installing the service from a folder ordinary users can write to (only
  allowed with `--dev-insecure-location`) lets any program running as that user
  become SYSTEM. Real installs must be under Program Files.

## Supported versions

Until a 1.0 release only the latest version receives fixes.
