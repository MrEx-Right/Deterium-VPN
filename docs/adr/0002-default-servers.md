# ADR 0002: Default (built-in) servers for first-run users

## Status

Open — the mechanism exists, the decision does not. No server is bundled today.

## Context

Deterium is "bring your own server" ([ADR 0001](0001-bring-your-own-protocol.md)). That is the right model for privacy, but it means a user who just downloaded the app has nothing to connect to until they rent a VPS or import a provider config. Some users will not want to do any VPN configuration at all and would rather install and benefit immediately — for example by shipping a list of free public OpenVPN servers.

## What already exists

The store reads a read-only `catalog/` directory next to `profiles/`. Anything in it is shown under **Built-in** in the sidebar, can be connected and duplicated (to customize into a normal editable server), and cannot be edited or deleted. `catalog/` is empty by default, and the sidebar section is hidden when it is. Turning the feature on later is a data change (drop `.toml` files in), not a code change.

## The tension

A free public relay is the opposite of the trust model the rest of the project is built on:

- The operator of a free relay can see where the traffic goes, and can read anything that isn't itself encrypted (plain HTTP, DNS). Many such relays log, and some exist specifically to collect traffic.
- "Open-source VPN" in the product's name will read to users as "private", so a default that quietly isn't would be a trust problem for the project, not just a technical one.
- Bundled servers are an ongoing operational commitment: they disappear, change keys, or get abused, and the app would then ship broken defaults or have to update the list.

## Options

1. **Ship nothing.** Keep the first-run flow as it is: the empty state offers "Set up my own server" (one pasted script on any VPS) and "Import a config". Simplest and fully consistent with ADR 0001.
2. **Opt-in catalog.** Ship the mechanism plus a clearly labelled list that is off until the user turns it on, behind a plain-language screen (who can see what, no logging guarantee, not for sensitive use). Sources must be redistributable and reviewable.
3. **On by default.** Rejected unless the list is audited and the app is explicit about the limits. It would cut against the project's reason to exist.

## Leaning

Option 1 for the first release, option 2 if first-run drop-off turns out to be the real problem. If a catalog is ever shipped it should: be opt-in; show the consent screen above; label every entry with its operator and logging policy; use only sources whose licence allows redistribution; and keep OpenVPN public relays separate from "your own" servers in the UI, which the Built-in section already does.

## Consequences

Nothing changes for users today. When the decision is made, the work is content and copy (the list, the consent screen), not engineering.
