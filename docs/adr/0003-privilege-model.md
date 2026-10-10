# ADR 0003: Privilege model — restart elevated on request

## Status

Superseded for installed systems by [ADR 0004](0004-windows-service.md), which
adds a background service. This model remains the fallback when the service
isn't installed.

## Context

A real VPN must create a virtual network adapter and change routes. On
Windows both need administrator rights. The rest of the app (browsing a list
of servers, editing settings, importing a file) does not. We have to decide
where the privileged code runs.

## Options

1. **Always run the whole app as administrator** (manifest
   `requireAdministrator`). Simplest. But a UI full of file dialogs, text
   parsing and drag-and-drop then runs with full rights all the time, and
   Windows blocks drag-and-drop from a normal Explorer into an elevated
   window.
2. **Unprivileged UI + privileged helper service** (what WireGuard for Windows
   does): the service runs as SYSTEM, the UI asks it to start/stop tunnels
   over an IPC channel, tunnel configs live in an admin-only folder. This is
   the right end state. It also needs a service installer, an IPC protocol
   and a permission model for who may ask the service to do what — a
   substantial piece of security-sensitive work.
3. **One app that restarts itself elevated, on request.** The app starts
   unprivileged. When the user connects, it explains why rights are needed
   and, on confirmation, relaunches itself through the standard Windows UAC
   prompt and reconnects automatically (`--connect <id>`).

## Decision

Option 3 for now.

* There is **no IPC surface**: no pipe or socket that an unprivileged process
  can talk to in order to make an elevated process change the network. The
  usual hole in a quick "helper process" design (any program running as the
  same user can drive the elevated helper) does not exist here, because the
  elevated process is simply the user's own app, started by the user through
  UAC.
* The privileged code is already isolated behind `deterium-net`'s `Platform`
  trait and the `deterium-engine::connect` API, so moving it into a service
  later means putting an IPC boundary at that API, not rewriting it.
* A "Test connection" mode (WireGuard handshake only) works without any
  rights and changes nothing, so a user can verify a server before granting
  anything.

## Consequences

* While connected via an elevated instance, the whole UI runs elevated.
  Anything the UI parses (imported configs) is therefore security-relevant:
  imported OpenVPN configs are rejected if they can run programs, file paths
  are never executed, and `wintun.dll` is loaded only from the executable's
  folder.
* Drag-and-drop into an elevated window does not work (a Windows restriction).
  Importing via the file dialog and paste still do.
* Each new connection after a restart needs one UAC confirmation per app
  start, not per connect: once elevated, the session stays elevated.
* An elevated instance cleans up network changes left by a crashed earlier
  run at startup (`recover_leftovers`).
* Not solved by this decision: the app is not protected against a user
  account that is already compromised, and there is no kill switch if the
  process dies (see `crates/deterium-net/README.md`, "Known limits").

## Update (kill switch)

The kill switch was built inside this model and has the limit this ADR predicts:
its firewall rules deliberately live in a Windows Filtering Platform *dynamic
session*, so they vanish if the app dies. That is the right default (a bug can
never leave someone permanently offline) and the reason protection ends with the
process. Protection that outlives a crash is the concrete requirement that
justifies the privileged-service option below.

## When to revisit

Before a public release, or as soon as a kill switch is built — that work
needs Windows Filtering Platform rules whose natural home is a service.
