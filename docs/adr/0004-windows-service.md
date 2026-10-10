# ADR 0004: A background service for the privileged work (Windows)

## Status

Accepted. Supersedes the "revisit" note in ADR 0003; the self-elevating
fallback from that ADR stays for machines where the service isn't installed.

## Context

ADR 0003 chose "the app restarts itself elevated when you connect". That works
but has three costs that showed up once the kill switch existed:

1. **A UAC prompt on every app start**, and the whole window (file dialogs,
   text parsing) running as administrator afterwards.
2. **The kill switch dies with the app.** Firewall rules live in a Windows
   Filtering Platform *dynamic session* owned by the process that made them, so
   a crash or an "End task" of the GUI drops the protection exactly when it is
   needed.
3. **Hostile-looking behaviour.** Programs that re-launch themselves through
   `runas` look like malware to heuristics and to users.

## Decision

Split the program in two:

* **The service** — a Windows service (LocalSystem, automatic start, restarts
  itself after a crash). It is the app's own executable started as
  `Deterium.exe service run`, so there is nothing else to ship. It owns the
  network adapter, routes, DNS, the WireGuard data plane, the OpenVPN child
  process and the firewall rules, using the *same engine* the app uses without
  a service (`deterium_engine::connect`).
* **The app** runs as the normal user. To connect it sends the profile to the
  service and polls its status. It no longer needs rights for anything except
  the one-time install.

The service is installed once (`Deterium.exe service install`, one UAC prompt,
started from the app's "Background service" dialog). Without it everything
behaves as in ADR 0003.

### The pipe is the security boundary

Anything that can talk to the service can change this PC's routing, so:

* **Who may connect.** The named pipe `\\.\pipe\deterium-vpn` has an explicit
  access list: SYSTEM, Administrators, and the **one user who installed the
  service** (their SID is stored in the service's own command line, which only
  administrators can change). No other account, no remote clients
  (`PIPE_REJECT_REMOTE_CLIENTS`). The rights granted are read/write data only,
  deliberately *not* the "create pipe instance" right that generic-write
  includes.
* **Who the client talks to.** Before sending a profile (which contains keys),
  the client checks that the process serving the pipe is the process the
  Service Control Manager reports for `DeteriumVPN`. A program that squats the
  pipe name while the service is stopped therefore receives nothing.
* **First instance.** The service creates the pipe with
  `FILE_FLAG_FIRST_PIPE_INSTANCE` and refuses to start if the name is taken.
* **Where the service lives.** `install` refuses unless the executable is
  under Program Files (an administrator-only location). Otherwise any program
  running as the user could overwrite the file that later runs as SYSTEM.
  `--dev-insecure-location` exists for development and says so loudly.
* **What the service accepts.** Only the profile and a few commands. The
  profile goes through the same `check()` as everywhere (imported OpenVPN
  configs that could run programs or write files are rejected there), and the
  service keeps it in memory only.
* **Secrets.** Profiles stay DPAPI-encrypted for the *user* on disk. The GUI
  decrypts them and sends them over the local pipe; the service never needs
  the user's DPAPI key and never writes a profile to disk.

### Tunnel lifetime

The tunnel belongs to the service, not to the window. Closing the GUI, or the
GUI crashing, leaves the tunnel and the kill switch in place; the GUI re-attaches
to it on the next start and shows it as connected. "Disconnect" is explicit.
Stopping or uninstalling the service tears everything down and removes the
rules.

## Consequences

* The crash-surviving kill switch is now real for as long as the service runs.
  It is still a dynamic WFP session: if the *service* dies, Windows removes the
  rules, so a bug can't leave someone permanently offline. The service restarts
  itself within seconds and the crash journal cleans up leftover routes on start.
* Persistent (boot-time) filters, which would also protect the moments before
  the service starts, are a possible later step and deliberately not part of
  this one: they can lock a user out of the network if they are ever wrong.
* The installer (MSI/NSIS, not written yet) must place both executables and
  `wintun.dll` in Program Files and register the service with the invoking
  user's SID; `deterium-service install` is what it should call.
* Only one tunnel at a time, as before.
* A second Windows account on the same PC cannot control the VPN unless it
  installs its own service allowance (not implemented: one user per install).
