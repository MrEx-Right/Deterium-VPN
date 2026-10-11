//! Leak protection: what traffic may leave the PC *outside* the tunnel.
//!
//! Routes alone only say where traffic should go. If the tunnel dies, or a
//! program asks a DNS server on another network adapter, packets still leave
//! the normal way. This module decides the firewall rules that stop that.
//! It is pure — it produces a list of [`Rule`]s — and the Windows code turns
//! them into Windows Filtering Platform filters. Keeping the policy separate
//! means the safety-critical ordering (permits before the catch-all block, so
//! the VPN itself can never be cut off) is checked by unit tests.
//!
//! Rules are evaluated highest `weight` first; the first match decides.

use crate::cidr::Cidr;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

/// What the user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakPolicy {
    /// Block everything that isn't the tunnel (or needed to keep it alive).
    pub kill_switch: bool,
    /// With the kill switch on, still let the local network through
    /// (printers, NAS, the router's admin page).
    pub allow_lan: bool,
    /// Block DNS requests that aren't going through the tunnel.
    pub block_dns_leaks: bool,
    /// The VPN server(s). Their traffic must always be able to flow.
    pub servers: Vec<Server>,
}

/// One address the VPN client itself talks to, outside the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Server {
    pub addr: SocketAddr,
    pub protocol: Protocol,
}

impl Server {
    pub fn udp(addr: SocketAddr) -> Self {
        Self {
            addr,
            protocol: Protocol::Udp,
        }
    }

    pub fn tcp(addr: SocketAddr) -> Self {
        Self {
            addr,
            protocol: Protocol::Tcp,
        }
    }
}

impl LeakPolicy {
    pub fn is_active(&self) -> bool {
        self.kill_switch || self.block_dns_leaks
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Permit,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matcher {
    /// Traffic to or from this PC itself.
    Loopback,
    /// Traffic on the VPN adapter, identified by its interface LUID.
    TunnelInterface(u64),
    RemoteAddress(Cidr),
    Protocol(Protocol),
    RemotePort(u16),
    LocalPort(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub name: &'static str,
    pub action: Action,
    /// Higher is evaluated first (0-15).
    pub weight: u8,
    /// All must match. Empty = matches everything.
    pub when: Vec<Matcher>,
}

const LAN_RANGES: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "fe80::/10",
    "fc00::/7",
    "ff00::/8",
];

/// The rules for a policy, highest weight first.
pub fn build_rules(policy: &LeakPolicy, tunnel_luid: u64) -> Vec<Rule> {
    if !policy.is_active() {
        return Vec::new();
    }
    let mut rules = Vec::new();

    // --- Always allowed: without these the VPN itself would be cut off. ---
    rules.push(Rule {
        name: "loopback",
        action: Action::Permit,
        weight: 15,
        when: vec![Matcher::Loopback],
    });
    rules.push(Rule {
        name: "tunnel adapter",
        action: Action::Permit,
        weight: 14,
        when: vec![Matcher::TunnelInterface(tunnel_luid)],
    });
    for server in &policy.servers {
        rules.push(Rule {
            name: "VPN server",
            action: Action::Permit,
            weight: 13,
            when: vec![
                Matcher::RemoteAddress(Cidr::host(server.addr.ip())),
                Matcher::Protocol(server.protocol),
                Matcher::RemotePort(server.addr.port()),
            ],
        });
    }
    // Without DHCP the network's own lease can lapse and take everything
    // (the VPN's route to its server included) down with it.
    for (name, local, remote) in [("DHCPv4", 68, 67), ("DHCPv6", 546, 547)] {
        rules.push(Rule {
            name,
            action: Action::Permit,
            weight: 12,
            when: vec![
                Matcher::Protocol(Protocol::Udp),
                Matcher::LocalPort(local),
                Matcher::RemotePort(remote),
            ],
        });
    }

    // --- DNS must not slip out past the tunnel, even to a LAN resolver. ---
    // Above the LAN permit on purpose: the router's DNS is a leak too.
    if policy.block_dns_leaks {
        for (name, protocol, port) in [
            ("DNS (UDP)", Protocol::Udp, 53),
            ("DNS (TCP)", Protocol::Tcp, 53),
            ("DNS over TLS", Protocol::Tcp, 853),
        ] {
            rules.push(Rule {
                name,
                action: Action::Block,
                weight: 11,
                when: vec![Matcher::Protocol(protocol), Matcher::RemotePort(port)],
            });
        }
    }

    if policy.kill_switch {
        if policy.allow_lan {
            for range in LAN_RANGES {
                rules.push(Rule {
                    name: "local network",
                    action: Action::Permit,
                    weight: 10,
                    when: vec![Matcher::RemoteAddress(
                        Cidr::parse(range).expect("built-in range is valid"),
                    )],
                });
            }
        }
        rules.push(Rule {
            name: "everything else",
            action: Action::Block,
            weight: 1,
            when: Vec::new(),
        });
    }

    rules.sort_by_key(|r| std::cmp::Reverse(r.weight));
    rules
}

/// The rules for a "hold" state: the kill switch is up but the tunnel is not
/// (yet) carrying traffic. Used while a connection is being set up and by the
/// service after a restart, so nothing leaves the PC except what is needed to
/// reach the VPN server.
///
/// `tunnel_luid` is 0 when no adapter exists; the tunnel permit is then left
/// out altogether rather than written with an identity nothing has. With
/// `allow_dns_lookup`, plain DNS is permitted too: OpenVPN resolves the names
/// in its own config, and without it a `remote vpn.example.com` could never
/// connect. Only the server's name leaks that way, and only until the tunnel
/// is up.
pub fn build_hold_rules(
    servers: Vec<Server>,
    allow_lan: bool,
    tunnel_luid: u64,
    allow_dns_lookup: bool,
) -> Vec<Rule> {
    let policy = LeakPolicy {
        kill_switch: true,
        allow_lan,
        block_dns_leaks: false,
        servers,
    };
    let mut rules = build_rules(&policy, tunnel_luid);
    if tunnel_luid == 0 {
        rules.retain(|r| r.name != "tunnel adapter");
    }
    if allow_dns_lookup {
        for (name, protocol) in [
            ("DNS lookup of the VPN server (UDP)", Protocol::Udp),
            ("DNS lookup of the VPN server (TCP)", Protocol::Tcp),
        ] {
            rules.push(Rule {
                name,
                action: Action::Permit,
                weight: 12,
                when: vec![Matcher::Protocol(protocol), Matcher::RemotePort(53)],
            });
        }
        rules.sort_by_key(|r| std::cmp::Reverse(r.weight));
    }
    rules
}

/// Addresses that are never worth firewalling off (used by callers that want
/// to describe the policy to the user).
pub fn is_local_network(ip: IpAddr) -> bool {
    LAN_RANGES
        .iter()
        .filter_map(|r| Cidr::parse(r).ok())
        .any(|c| c.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(kill: bool, lan: bool, dns: bool) -> LeakPolicy {
        LeakPolicy {
            kill_switch: kill,
            allow_lan: lan,
            block_dns_leaks: dns,
            servers: vec![Server::udp("203.0.113.10:51820".parse().unwrap())],
        }
    }

    fn names(rules: &[Rule]) -> Vec<&'static str> {
        rules.iter().map(|r| r.name).collect()
    }

    #[test]
    fn an_inactive_policy_produces_no_rules() {
        assert!(build_rules(&policy(false, true, false), 7).is_empty());
    }

    #[test]
    fn the_vpn_itself_is_always_permitted_before_anything_is_blocked() {
        let rules = build_rules(&policy(true, false, true), 7);
        let first_block = rules
            .iter()
            .position(|r| r.action == Action::Block)
            .unwrap();
        for essential in ["loopback", "tunnel adapter", "VPN server", "DHCPv4"] {
            let at = rules
                .iter()
                .position(|r| r.name == essential)
                .expect(essential);
            assert!(
                at < first_block,
                "{essential} must be evaluated before any block rule"
            );
            assert_eq!(rules[at].action, Action::Permit);
        }
    }

    #[test]
    fn every_server_gets_its_own_permit_with_its_own_protocol() {
        let mut p = policy(true, false, false);
        p.servers = vec![
            Server::udp("203.0.113.10:1194".parse().unwrap()),
            Server::tcp("198.51.100.7:443".parse().unwrap()),
        ];
        let rules = build_rules(&p, 7);
        let servers: Vec<_> = rules.iter().filter(|r| r.name == "VPN server").collect();
        assert_eq!(servers.len(), 2);
        assert!(servers[0].when.contains(&Matcher::Protocol(Protocol::Udp)));
        assert!(servers
            .iter()
            .any(|r| r.when.contains(&Matcher::Protocol(Protocol::Tcp))
                && r.when.contains(&Matcher::RemotePort(443))));
        // All of them still come before the catch-all block.
        let block = rules.iter().position(|r| r.when.is_empty()).unwrap();
        assert!(rules
            .iter()
            .rposition(|r| r.name == "VPN server")
            .is_some_and(|at| at < block));
    }

    #[test]
    fn the_catch_all_block_is_last_and_matches_everything() {
        let rules = build_rules(&policy(true, true, false), 7);
        let last = rules.last().unwrap();
        assert_eq!(last.name, "everything else");
        assert_eq!(last.action, Action::Block);
        assert!(last.when.is_empty());
        assert_eq!(rules.iter().filter(|r| r.when.is_empty()).count(), 1);
    }

    #[test]
    fn dns_only_protection_never_blocks_all_traffic() {
        let rules = build_rules(&policy(false, true, true), 7);
        assert!(!names(&rules).contains(&"everything else"));
        assert!(names(&rules).contains(&"DNS (UDP)"));
        assert!(rules.iter().filter(|r| r.action == Action::Block).all(|r| r
            .when
            .iter()
            .any(|m| matches!(m, Matcher::RemotePort(53 | 853)))));
    }

    #[test]
    fn dns_blocking_outranks_the_lan_permit_so_the_routers_dns_cannot_leak() {
        let rules = build_rules(&policy(true, true, true), 7);
        let dns = rules.iter().position(|r| r.name == "DNS (UDP)").unwrap();
        let lan = rules
            .iter()
            .position(|r| r.name == "local network")
            .unwrap();
        assert!(
            dns < lan,
            "DNS block must be evaluated before the LAN permit"
        );
    }

    #[test]
    fn the_tunnel_is_exempt_from_the_dns_block() {
        let rules = build_rules(&policy(true, true, true), 7);
        let tunnel = rules
            .iter()
            .position(|r| r.name == "tunnel adapter")
            .unwrap();
        let dns = rules.iter().position(|r| r.name == "DNS (UDP)").unwrap();
        assert!(
            tunnel < dns,
            "DNS inside the tunnel is the point of the tunnel"
        );
    }

    #[test]
    fn the_lan_is_only_open_when_asked() {
        assert!(names(&build_rules(&policy(true, true, false), 7)).contains(&"local network"));
        assert!(!names(&build_rules(&policy(true, false, false), 7)).contains(&"local network"));
    }

    #[test]
    fn the_server_rule_is_as_narrow_as_possible() {
        let rules = build_rules(&policy(true, false, false), 7);
        let server = rules.iter().find(|r| r.name == "VPN server").unwrap();
        assert!(server.when.contains(&Matcher::Protocol(Protocol::Udp)));
        assert!(server.when.contains(&Matcher::RemotePort(51820)));
        assert!(server.when.contains(&Matcher::RemoteAddress(Cidr::host(
            "203.0.113.10".parse().unwrap()
        ))));
    }

    #[test]
    fn the_tunnel_rule_uses_the_adapters_own_identity() {
        let rules = build_rules(&policy(true, false, false), 4242);
        let tunnel = rules.iter().find(|r| r.name == "tunnel adapter").unwrap();
        assert_eq!(tunnel.when, vec![Matcher::TunnelInterface(4242)]);
    }

    fn hold(allow_dns: bool) -> Vec<Rule> {
        build_hold_rules(
            vec![Server::udp("203.0.113.10:1194".parse().unwrap())],
            false,
            0,
            allow_dns,
        )
    }

    #[test]
    fn a_hold_blocks_everything_but_the_vpn_servers_loopback_and_dhcp() {
        let rules = hold(false);
        let permits: Vec<_> = rules
            .iter()
            .filter(|r| r.action == Action::Permit)
            .map(|r| r.name)
            .collect();
        assert!(permits.contains(&"VPN server"));
        assert!(permits.contains(&"loopback"));
        assert!(permits.contains(&"DHCPv4"));
        assert!(!permits.contains(&"local network"), "LAN was not asked for");
        let last = rules.last().unwrap();
        assert_eq!(last.name, "everything else");
        assert_eq!(last.action, Action::Block);
        assert!(last.when.is_empty());
    }

    #[test]
    fn a_hold_without_dns_lookup_never_permits_dns() {
        assert!(!hold(false)
            .iter()
            .any(|r| r.when.contains(&Matcher::RemotePort(53))));
    }

    #[test]
    fn dns_lookup_is_permitted_before_the_catch_all_block_and_stays_ordered() {
        let rules = hold(true);
        let dns = rules
            .iter()
            .position(|r| r.when.contains(&Matcher::RemotePort(53)))
            .expect("DNS permit");
        let block = rules.iter().position(|r| r.when.is_empty()).unwrap();
        assert!(dns < block);
        assert_eq!(rules[dns].action, Action::Permit);
        assert!(rules.windows(2).all(|w| w[0].weight >= w[1].weight));
    }

    #[test]
    fn a_hold_with_no_adapter_has_no_tunnel_rule_and_one_with_an_adapter_has() {
        assert!(!hold(false).iter().any(|r| r.name == "tunnel adapter"));
        let with = build_hold_rules(Vec::new(), false, 99, false);
        let tunnel = with.iter().find(|r| r.name == "tunnel adapter").unwrap();
        assert_eq!(tunnel.when, vec![Matcher::TunnelInterface(99)]);
    }

    #[test]
    fn rules_come_out_strictly_ordered_by_weight() {
        let rules = build_rules(&policy(true, true, true), 7);
        assert!(rules.windows(2).all(|w| w[0].weight >= w[1].weight));
    }
}
