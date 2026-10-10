//! Turns "what the profile asks for" into an ordered list of OS operations.
//! Pure and OS-free, so every safety rule (no routing loop, don't replace the
//! default route, endpoint stays reachable) is unit-tested without touching
//! a real network.

use crate::cidr::Cidr;
use std::net::IpAddr;

/// How the OS reaches a destination right now, before the tunnel exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PhysicalRoute {
    pub interface_index: u32,
    /// `None` = the destination is directly on that link (no gateway).
    pub next_hop: Option<IpAddr>,
}

pub struct PlanInput {
    /// This device's addresses inside the tunnel.
    pub interface_addresses: Vec<Cidr>,
    /// Everything that should go through the tunnel (WireGuard "AllowedIPs").
    pub routed: Vec<Cidr>,
    pub dns: Vec<IpAddr>,
    pub mtu: Option<u32>,
    /// The VPN server's public address. Its own traffic must never be
    /// routed into the tunnel, or the tunnel could never carry it.
    pub endpoint: IpAddr,
    /// How the OS reaches `endpoint` today; needed whenever a tunnel route
    /// would otherwise swallow it.
    pub endpoint_route: Option<PhysicalRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    AssignAddress(Cidr),
    SetMtu(u32),
    /// Lowers the tunnel's interface metric so its DNS servers win.
    SetInterfaceMetric(u32),
    /// Keeps the VPN server reachable over the real network.
    BypassRoute {
        dest: Cidr,
        via: PhysicalRoute,
    },
    /// Sends `dest` into the tunnel.
    TunnelRoute {
        dest: Cidr,
    },
    SetDns(Vec<IpAddr>),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkPlan {
    pub ops: Vec<Op>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error(
        "the VPN server ({0}) would be routed into its own tunnel and the OS has no route to it"
    )]
    RoutingLoop(IpAddr),
}

/// WireGuard's standard tunnel MTU. Without it Windows gives a new adapter an
/// MTU of 65535 and large packets would be fragmented on the real network.
pub const DEFAULT_MTU: u32 = 1420;

pub fn build_plan(input: &PlanInput) -> Result<NetworkPlan, PlanError> {
    let mut ops = Vec::new();

    let mut seen = Vec::new();
    for addr in &input.interface_addresses {
        if !seen.contains(addr) {
            seen.push(*addr);
            ops.push(Op::AssignAddress(*addr));
        }
    }
    ops.push(Op::SetMtu(input.mtu.unwrap_or(DEFAULT_MTU)));
    if !input.dns.is_empty() {
        ops.push(Op::SetInterfaceMetric(1));
    }

    let routes = tunnel_routes(&input.routed);

    // Order matters: the bypass must exist before any route that could
    // swallow the server's address, or the handshake traffic would loop.
    if routes.iter().any(|r| r.contains(input.endpoint)) {
        let via = input
            .endpoint_route
            .ok_or(PlanError::RoutingLoop(input.endpoint))?;
        ops.push(Op::BypassRoute {
            dest: Cidr::host(input.endpoint),
            via,
        });
    }
    ops.extend(routes.into_iter().map(|dest| Op::TunnelRoute { dest }));

    if !input.dns.is_empty() {
        ops.push(Op::SetDns(input.dns.clone()));
    }

    Ok(NetworkPlan { ops })
}

/// Normalizes the routed set. A "route everything" prefix is installed as two
/// halves (`0.0.0.0/1` + `128.0.0.0/1`): they win over the existing default
/// route by being more specific, so the original default route is never
/// touched and is still there, intact, once the tunnel is gone.
fn tunnel_routes(routed: &[Cidr]) -> Vec<Cidr> {
    let mut out: Vec<Cidr> = Vec::new();
    for cidr in routed {
        let normalized = cidr.network();
        let expanded = if normalized.is_default() {
            normalized.halves().map(Vec::from).unwrap_or_default()
        } else {
            vec![normalized]
        };
        for route in expanded {
            if !out.contains(&route) {
                out.push(route);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn lan_route() -> PhysicalRoute {
        PhysicalRoute {
            interface_index: 12,
            next_hop: Some(ip("192.168.1.1")),
        }
    }
    fn input(routed: &[&str]) -> PlanInput {
        PlanInput {
            interface_addresses: vec![c("10.6.0.2/32")],
            routed: routed.iter().map(|s| c(s)).collect(),
            dns: vec![],
            mtu: None,
            endpoint: ip("203.0.113.10"),
            endpoint_route: Some(lan_route()),
        }
    }
    fn tunnel_dests(plan: &NetworkPlan) -> Vec<Cidr> {
        plan.ops
            .iter()
            .filter_map(|op| match op {
                Op::TunnelRoute { dest } => Some(*dest),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn full_tunnel_never_replaces_the_default_route() {
        let plan = build_plan(&input(&["0.0.0.0/0", "::/0"])).unwrap();
        assert_eq!(
            tunnel_dests(&plan),
            [c("0.0.0.0/1"), c("128.0.0.0/1"), c("::/1"), c("8000::/1")]
        );
        assert!(!tunnel_dests(&plan).iter().any(Cidr::is_default));
    }

    #[test]
    fn full_tunnel_gets_a_bypass_for_the_server_before_any_tunnel_route() {
        let plan = build_plan(&input(&["0.0.0.0/0"])).unwrap();
        let bypass = plan
            .ops
            .iter()
            .position(|op| matches!(op, Op::BypassRoute { .. }))
            .expect("bypass route");
        let first_tunnel = plan
            .ops
            .iter()
            .position(|op| matches!(op, Op::TunnelRoute { .. }))
            .unwrap();
        assert!(bypass < first_tunnel);
        assert_eq!(
            plan.ops[bypass],
            Op::BypassRoute {
                dest: c("203.0.113.10/32"),
                via: lan_route()
            }
        );
    }

    #[test]
    fn split_tunnel_that_excludes_the_server_needs_no_bypass() {
        let plan = build_plan(&input(&["10.6.0.0/24"])).unwrap();
        assert!(!plan
            .ops
            .iter()
            .any(|op| matches!(op, Op::BypassRoute { .. })));
        assert_eq!(tunnel_dests(&plan), [c("10.6.0.0/24")]);
    }

    #[test]
    fn a_routing_loop_is_refused_instead_of_installed() {
        let mut bad = input(&["0.0.0.0/0"]);
        bad.endpoint_route = None;
        assert_eq!(
            build_plan(&bad),
            Err(PlanError::RoutingLoop(ip("203.0.113.10")))
        );
    }

    #[test]
    fn routes_are_normalized_and_deduplicated() {
        let plan = build_plan(&input(&["10.6.0.7/24", "10.6.0.0/24", "0.0.0.0/0"])).unwrap();
        let dests = tunnel_dests(&plan);
        assert_eq!(dests.iter().filter(|d| **d == c("10.6.0.0/24")).count(), 1);
    }

    #[test]
    fn dns_prefers_the_tunnel_and_is_applied_last() {
        let mut with_dns = input(&["10.6.0.0/24"]);
        with_dns.dns = vec![ip("10.6.0.1")];
        let plan = build_plan(&with_dns).unwrap();
        assert!(plan.ops.contains(&Op::SetInterfaceMetric(1)));
        assert_eq!(plan.ops.last(), Some(&Op::SetDns(vec![ip("10.6.0.1")])));
    }

    #[test]
    fn mtu_defaults_to_1420_when_the_profile_has_none() {
        let plan = build_plan(&input(&["10.6.0.0/24"])).unwrap();
        assert!(plan.ops.contains(&Op::SetMtu(DEFAULT_MTU)));
    }

    #[test]
    fn address_and_mtu_come_first() {
        let mut with_mtu = input(&["10.6.0.0/24"]);
        with_mtu.mtu = Some(1380);
        let plan = build_plan(&with_mtu).unwrap();
        assert_eq!(plan.ops[0], Op::AssignAddress(c("10.6.0.2/32")));
        assert_eq!(plan.ops[1], Op::SetMtu(1380));
    }
}
