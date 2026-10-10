# ADR 0001: Bring-your-own-protocol / bring-your-own-server

## Status

Accepted

## Context

Deterium VPN aims to be a fully self-hosted, open-source VPN solution. A conventional VPN app design hardcodes one protocol and assumes the vendor operates the server fleet. That model requires the vendor (Deterium) to run infrastructure that sees user traffic, which conflicts with the project's privacy and self-hosting goals, and locks users into whatever single protocol was chosen.

## Decision

Deterium VPN will not operate any VPN servers and will not hardcode a single tunnel protocol. Instead:

- The **client** depends on a `ProtocolAdapter` trait (see [ARCHITECTURE.md](../ARCHITECTURE.md#3-the-protocoladapter-abstraction)), not a specific protocol.
- The **server** is always the user's own, already-deployed VPN server (WireGuard first, OpenVPN second, more later).
- An optional **companion** daemon may be deployed by the user alongside their own server to ease configuration, but it is not a Deterium-run service and has no cross-user/cross-server component.

## Consequences

- No Deterium-run infrastructure is ever in the data path — stronger privacy story, lower operating cost/liability, but also no "it just works out of the box with zero setup" experience; the user must have (or stand up) their own server.
- Every new protocol requires a new adapter crate, but the app and core state machine never need to change to support it.
- The companion daemon must be designed so it cannot become a de facto central control plane (no required phone-home, no cross-deployment coupling).
