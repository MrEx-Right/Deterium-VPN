//! `deterium-net`: the operating-system networking layer.
//!
//! Protocol-agnostic. It knows how to create a virtual adapter, work out and
//! apply addresses/routes/DNS, and — above all — undo them reliably. It
//! knows nothing about WireGuard or OpenVPN. See the README in this crate
//! for the layering and the safety rules.

mod cidr;
mod deploy;
mod elevation;
mod leak;
mod plan;
mod platform;
mod stats;
mod system;
pub mod testing;
mod tun;

#[cfg(windows)]
mod wfp;
#[cfg(windows)]
mod windows;

pub use cidr::{AllowedIps, Cidr};
pub use deploy::{ensure_wintun, ensure_wintun_in, install_dir, WINTUN_DLL};
pub use elevation::{
    current_user_sid, is_elevated, relaunch_elevated, run_elevated_and_wait, ElevateError,
};
pub use leak::{
    build_hold_rules, build_rules, is_local_network, Action, LeakPolicy, Matcher, Protocol, Rule,
    Server,
};
pub use plan::{build_plan, NetworkPlan, Op, PhysicalRoute, PlanError, PlanInput};
pub use platform::{bring_up, system_platform, Platform, RoutedNetwork, TunnelSpec};
pub use stats::{adapter_counters, ping, AdapterCounters};
pub use system::{recover_stale, Journal, NetError, NetworkGuard, SystemNet, TunInfo, Undo};
pub use tun::{FakeTun, FakeTunPeer, TunDevice};

#[cfg(windows)]
pub use windows::{
    clear_adapter_routes, guard_blocked, guard_openvpn_connecting, guard_openvpn_leaks,
    hold_openvpn_adapter, HeldAdapter, OPENVPN_ADAPTER_NAME,
};

/// Stand-ins so callers don't need `cfg`: only Windows has Wintun adapters.
#[cfg(not(windows))]
pub const OPENVPN_ADAPTER_NAME: &str = "Deterium OpenVPN";
#[cfg(not(windows))]
pub struct HeldAdapter;
#[cfg(not(windows))]
pub fn hold_openvpn_adapter() -> Result<HeldAdapter, NetError> {
    Ok(HeldAdapter)
}
#[cfg(not(windows))]
pub fn clear_adapter_routes(_name: &str) -> usize {
    0
}
#[cfg(not(windows))]
pub fn guard_openvpn_leaks(_policy: &LeakPolicy) -> Result<Box<dyn Send>, NetError> {
    Err(NetError::Unsupported)
}
#[cfg(not(windows))]
pub fn guard_openvpn_connecting(
    _servers: Vec<Server>,
    _allow_lan: bool,
    _allow_dns_lookup: bool,
) -> Result<Box<dyn Send>, NetError> {
    Err(NetError::Unsupported)
}
#[cfg(not(windows))]
pub fn guard_blocked(
    _servers: Vec<Server>,
    _allow_lan: bool,
    _allow_dns_lookup: bool,
) -> Result<Box<dyn Send>, NetError> {
    Err(NetError::Unsupported)
}

/// Reverts network changes left behind by a previous run that crashed or was
/// killed. Call once at startup, when running with administrator rights.
/// Returns how many leftovers were reverted.
pub fn recover_leftovers() -> usize {
    #[cfg(windows)]
    {
        windows::recover_leftovers()
    }
    #[cfg(not(windows))]
    {
        0
    }
}
