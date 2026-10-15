//! The seam between portable logic and one operating system. Everything the
//! data plane needs from the OS goes through [`Platform`], so the whole
//! connect/disconnect flow runs against [`crate::testing::FakePlatform`] in
//! tests without admin rights or a driver.

use crate::cidr::Cidr;
use crate::leak::{LeakPolicy, Server};
use crate::plan::{build_plan, NetworkPlan, PhysicalRoute, PlanInput};
use crate::system::{NetError, TunInfo};
use crate::tun::TunDevice;
use std::net::IpAddr;
use std::sync::Arc;

pub trait Platform: Send + Sync {
    fn is_elevated(&self) -> bool;

    /// Creates (or reopens) the virtual adapter.
    fn open_tun(&self, name: &str) -> Result<Arc<dyn TunDevice>, NetError>;

    /// How the OS reaches `dest` right now.
    fn route_to(&self, dest: IpAddr) -> Result<PhysicalRoute, NetError>;

    /// Applies the plan. Dropping the returned guard reverts it.
    fn apply_plan(&self, tun: &TunInfo, plan: &NetworkPlan) -> Result<Box<dyn Send>, NetError>;

    /// Installs the leak-protection firewall rules. Dropping the returned
    /// guard removes them. They must never outlive the process.
    fn guard_leaks(&self, tun: &TunInfo, policy: &LeakPolicy) -> Result<Box<dyn Send>, NetError>;

    /// Blocks everything except the VPN servers (and the local network if
    /// asked) while there is no tunnel yet. Dropping the guard lifts the block.
    /// Same lifetime rule as [`Platform::guard_leaks`].
    fn guard_hold(&self, servers: Vec<Server>, allow_lan: bool) -> Result<Box<dyn Send>, NetError>;
}

/// What a connection needs from the network.
pub struct TunnelSpec {
    pub interface_addresses: Vec<Cidr>,
    pub routed: Vec<Cidr>,
    pub dns: Vec<IpAddr>,
    pub mtu: Option<u32>,
    pub endpoint: IpAddr,
    /// Firewall protection to apply once the tunnel is configured.
    pub leak: Option<LeakPolicy>,
}

/// A configured virtual adapter plus the guards that undo its routes and
/// firewall rules. Field order is deliberate (fields drop in order): routes
/// are reverted *before* the adapter goes, and the firewall rules last.
pub struct RoutedNetwork {
    _guard: Box<dyn Send>,
    tun: Arc<dyn TunDevice>,
    _leak_guard: Option<Box<dyn Send>>,
}

impl RoutedNetwork {
    pub fn tun(&self) -> Arc<dyn TunDevice> {
        self.tun.clone()
    }
}

/// Creates the adapter and applies addresses, routes and DNS. All or
/// nothing: on any failure whatever was applied is already reverted.
pub fn bring_up(
    platform: &dyn Platform,
    adapter_name: &str,
    spec: &TunnelSpec,
) -> Result<RoutedNetwork, NetError> {
    if !platform.is_elevated() {
        return Err(NetError::NotElevated);
    }

    // With a kill switch the network is blocked (except the VPN server) before
    // the adapter exists, so not even the seconds it takes to set the tunnel up
    // are exposed. Fails closed. The block is lifted once the full rules are in
    // force, and on any error below, so a failed attempt never leaves the PC
    // offline. DNS-leak blocking alone doesn't hold: it must not cut off name
    // lookups while connecting.
    let hold = match &spec.leak {
        Some(policy) if policy.kill_switch => {
            Some(platform.guard_hold(policy.servers.clone(), policy.allow_lan)?)
        }
        _ => None,
    };

    // Looked up first: once routes change, the answer may too.
    let endpoint_route = platform.route_to(spec.endpoint).ok();
    let tun = platform.open_tun(adapter_name)?;

    let plan = build_plan(&PlanInput {
        interface_addresses: spec.interface_addresses.clone(),
        routed: spec.routed.clone(),
        dns: spec.dns.clone(),
        mtu: spec.mtu,
        endpoint: spec.endpoint,
        endpoint_route,
    })?;

    let guard = platform.apply_plan(tun.info(), &plan)?;

    // Last, once the tunnel exists to be exempted. If this fails the whole
    // connection fails (and the guards above revert): a user who asked for a
    // kill switch must never end up connected without one.
    let leak_guard = match &spec.leak {
        Some(policy) if policy.is_active() => Some(platform.guard_leaks(tun.info(), policy)?),
        _ => None,
    };
    // New rules first, the hold after: there is never a moment without any.
    drop(hold);
    Ok(RoutedNetwork {
        _guard: guard,
        tun,
        _leak_guard: leak_guard,
    })
}

/// The platform this build runs on.
pub fn system_platform() -> Box<dyn Platform> {
    #[cfg(windows)]
    {
        Box::new(crate::windows::WindowsPlatform)
    }
    #[cfg(not(windows))]
    {
        Box::new(UnsupportedPlatform)
    }
}

#[cfg(not(windows))]
struct UnsupportedPlatform;

#[cfg(not(windows))]
impl Platform for UnsupportedPlatform {
    fn is_elevated(&self) -> bool {
        crate::elevation::is_elevated()
    }
    fn open_tun(&self, _: &str) -> Result<Arc<dyn TunDevice>, NetError> {
        Err(NetError::Unsupported)
    }
    fn route_to(&self, _: IpAddr) -> Result<PhysicalRoute, NetError> {
        Err(NetError::Unsupported)
    }
    fn apply_plan(&self, _: &TunInfo, _: &NetworkPlan) -> Result<Box<dyn Send>, NetError> {
        Err(NetError::Unsupported)
    }
    fn guard_leaks(&self, _: &TunInfo, _: &LeakPolicy) -> Result<Box<dyn Send>, NetError> {
        Err(NetError::Unsupported)
    }
    fn guard_hold(&self, _: Vec<Server>, _: bool) -> Result<Box<dyn Send>, NetError> {
        Err(NetError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakePlatform;

    fn spec(routed: &[&str]) -> TunnelSpec {
        TunnelSpec {
            interface_addresses: vec![Cidr::parse("10.6.0.2/32").unwrap()],
            routed: routed.iter().map(|s| Cidr::parse(s).unwrap()).collect(),
            dns: vec![],
            mtu: None,
            endpoint: "203.0.113.10".parse().unwrap(),
            leak: None,
        }
    }

    #[test]
    fn refuses_without_administrator_rights_and_touches_nothing() {
        let platform = FakePlatform::new(false);
        let result = bring_up(&platform, "Deterium", &spec(&["10.6.0.0/24"]));
        assert!(matches!(result, Err(NetError::NotElevated)));
        assert!(platform.entries().is_empty());
    }

    #[test]
    fn dropping_the_network_reverts_routes_newest_first() {
        let platform = FakePlatform::new(true);
        let network = bring_up(&platform, "Deterium", &spec(&["0.0.0.0/0"])).unwrap();
        let applied = platform.entries().len();
        assert!(
            applied > 3,
            "address, bypass and two tunnel routes expected"
        );

        drop(network);
        let entries = platform.entries();
        let undos: Vec<_> = entries.iter().filter(|e| e.starts_with("undo")).collect();
        assert_eq!(undos.len(), 3, "bypass + two halves: {entries:?}");
        // Newest first: the last route applied is the first undone.
        assert!(undos[0].contains("128.0.0.0"), "{undos:?}");
        assert!(undos[2].contains("203.0.113.10"), "{undos:?}");
    }

    #[test]
    fn a_routing_loop_is_an_error_before_any_route_is_applied() {
        let mut platform = FakePlatform::new(true);
        platform.physical = None;
        let result = bring_up(&platform, "Deterium", &spec(&["0.0.0.0/0"]));
        assert!(matches!(result, Err(NetError::Plan(_))));
        assert!(
            !platform.entries().iter().any(|e| e.starts_with("apply")),
            "no operation may run when the plan is refused"
        );
    }

    fn kill_switch_spec() -> TunnelSpec {
        let mut spec = spec(&["0.0.0.0/0"]);
        spec.leak = Some(crate::leak::LeakPolicy {
            kill_switch: true,
            allow_lan: true,
            block_dns_leaks: false,
            servers: vec![crate::leak::Server::udp(
                "203.0.113.10:51820".parse().unwrap(),
            )],
        });
        spec
    }

    #[test]
    fn firewall_rules_come_last_and_go_last() {
        let platform = FakePlatform::new(true);
        let network = bring_up(&platform, "Deterium", &kill_switch_spec()).unwrap();

        let entries = platform.entries();
        let last_route = entries
            .iter()
            .rposition(|e| e.starts_with("apply"))
            .unwrap();
        let guard_on = entries
            .iter()
            .position(|e| e.starts_with("leak_guard on"))
            .unwrap();
        assert!(
            guard_on > last_route,
            "rules go in after the tunnel exists to be exempted: {entries:?}"
        );

        drop(network);
        let entries = platform.entries();
        let last_undo = entries.iter().rposition(|e| e.starts_with("undo")).unwrap();
        let guard_off = entries.iter().position(|e| e == "leak_guard off").unwrap();
        assert!(
            guard_off > last_undo,
            "rules are lifted after the routes: {entries:?}"
        );
    }

    #[test]
    fn a_kill_switch_that_cannot_be_installed_fails_the_whole_connection() {
        let mut platform = FakePlatform::new(true);
        platform.fail_leak_guard = true;

        let result = bring_up(&platform, "Deterium", &kill_switch_spec());
        assert!(
            result.is_err(),
            "never connect without the protection that was asked for"
        );

        let entries = platform.entries();
        assert!(!entries.iter().any(|e| e.starts_with("leak_guard on")));
        assert!(
            entries.iter().filter(|e| e.starts_with("undo")).count() >= 3,
            "the routes that were already applied are reverted: {entries:?}"
        );
    }

    fn at(entries: &[String], starts_with: &str) -> usize {
        entries
            .iter()
            .position(|e| e.starts_with(starts_with))
            .unwrap_or_else(|| panic!("no `{starts_with}` in {entries:?}"))
    }

    #[test]
    fn the_hold_goes_in_before_the_adapter_exists_and_is_lifted_after_the_full_rules() {
        let platform = FakePlatform::new(true);
        let network = bring_up(&platform, "Deterium", &kill_switch_spec()).unwrap();

        let entries = platform.entries();
        let hold_on = at(&entries, "hold on");
        assert!(
            hold_on < at(&entries, "open_tun"),
            "blocked before the adapter is created: {entries:?}"
        );
        assert!(
            hold_on < at(&entries, "apply"),
            "blocked before the first route is applied: {entries:?}"
        );
        assert!(
            at(&entries, "hold off") > at(&entries, "leak_guard on"),
            "the full rules are in force before the hold is lifted: {entries:?}"
        );
        drop(network);
    }

    #[test]
    fn a_failed_attempt_lifts_the_hold_so_the_pc_is_not_left_offline() {
        let mut platform = FakePlatform::new(true);
        platform.physical = None; // a routing loop: the plan is refused
        let result = bring_up(&platform, "Deterium", &kill_switch_spec());
        assert!(matches!(result, Err(NetError::Plan(_))));

        let entries = platform.entries();
        assert!(entries.iter().any(|e| e.starts_with("hold on")));
        assert!(entries.iter().any(|e| e == "hold off"), "{entries:?}");
        assert!(!entries.iter().any(|e| e.starts_with("leak_guard on")));
    }

    #[test]
    fn a_failed_full_rule_install_also_lifts_the_hold() {
        let mut platform = FakePlatform::new(true);
        platform.fail_leak_guard = true;
        assert!(bring_up(&platform, "Deterium", &kill_switch_spec()).is_err());
        let entries = platform.entries();
        assert!(entries.iter().any(|e| e == "hold off"), "{entries:?}");
    }

    #[test]
    fn a_hold_that_cannot_be_installed_stops_the_connection_before_anything_is_touched() {
        let mut platform = FakePlatform::new(true);
        platform.fail_hold = true;
        assert!(bring_up(&platform, "Deterium", &kill_switch_spec()).is_err());
        assert!(
            platform.entries().is_empty(),
            "never connect without the protection that was asked for: {:?}",
            platform.entries()
        );
    }

    #[test]
    fn dns_leak_blocking_alone_does_not_hold_the_network() {
        let platform = FakePlatform::new(true);
        let mut spec = kill_switch_spec();
        spec.leak = Some(crate::leak::LeakPolicy {
            kill_switch: false,
            allow_lan: true,
            block_dns_leaks: true,
            servers: vec![crate::leak::Server::udp(
                "203.0.113.10:51820".parse().unwrap(),
            )],
        });
        let _network = bring_up(&platform, "Deterium", &spec).unwrap();
        assert!(!platform.entries().iter().any(|e| e.starts_with("hold")));
    }

    #[test]
    fn no_policy_means_no_firewall_rules() {
        let platform = FakePlatform::new(true);
        let _network = bring_up(&platform, "Deterium", &spec(&["10.6.0.0/24"])).unwrap();
        assert!(!platform.entries().iter().any(|e| e.contains("leak_guard")));
    }
}
