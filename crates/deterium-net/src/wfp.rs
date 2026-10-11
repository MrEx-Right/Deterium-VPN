//! Windows Filtering Platform: turns the portable [`Rule`]s into real
//! firewall filters.
//!
//! The one property that makes this safe to ship: the filters live in a
//! **dynamic session**. Windows removes them by itself when the session's
//! engine handle closes — which also happens if the process crashes or is
//! killed. A bug here can therefore block the network only for as long as
//! the app is running; it can never leave the user permanently offline.
//! (The flip side, documented in the README: if the app itself dies, the
//! kill switch dies with it. Surviving that needs a service.)
//!
//! All filters are added in one transaction: either the complete rule set
//! is in force or none of it is.

use crate::cidr::Cidr;
use crate::leak::{Action, Matcher, Protocol, Rule};
use crate::system::NetError;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

/// Identifies our rules so they can be told apart in Windows' own tools. The
/// last four bytes of `data1` and `data2`/`data3` are replaced per install, see
/// [`fresh_sublayer_key`].
const SUBLAYER_KEY: GUID = GUID {
    data1: 0xd37e_0a0c,
    data2: 0x6b21,
    data3: 0x4f0a,
    data4: [0x9c, 0x31, 0x5e, 0x77, 0x0d, 0x42, 0xa1, 0x08],
};
static INSTALLS: AtomicU32 = AtomicU32::new(0);

/// A sublayer key no other install in this or another Deterium process has.
///
/// Sublayer keys are global in Windows' filtering engine, even for dynamic
/// sessions: adding a second sublayer under a key that exists fails. Rules are
/// replaced "new ones first, old ones after" (so there is never a gap), which
/// means two installs are alive at once, and each therefore needs its own key.
/// The process id and a counter make it unique; the rest identifies Deterium.
fn fresh_sublayer_key() -> GUID {
    let count = INSTALLS.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let mut key = SUBLAYER_KEY;
    key.data1 = count;
    key.data2 = (pid & 0xFFFF) as u16;
    key.data3 = (pid >> 16) as u16;
    key
}
const AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
const FLAG_IS_LOOPBACK: u32 = 0x0000_0001;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// Kept alive until the filter has been added (Windows copies the values).
///
/// The `Box`es are deliberate: conditions hold raw pointers to these values,
/// and a plain `Vec<u64>` could move its elements when it grows, leaving the
/// pointers dangling. A boxed value never moves.
#[derive(Default)]
#[allow(clippy::vec_box)]
struct Owned {
    luids: Vec<Box<u64>>,
    v4: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
    v6: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
}

/// The filters in force. Dropping it closes the engine, which removes them.
pub struct WfpGuard {
    engine: HANDLE,
}

// SAFETY: the engine handle is an opaque token that may be closed from any thread.
unsafe impl Send for WfpGuard {}

impl Drop for WfpGuard {
    fn drop(&mut self) {
        // SAFETY: `engine` was opened by `install` and is closed exactly once.
        unsafe {
            FwpmEngineClose0(self.engine);
        }
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn fail(op: &'static str, code: u32) -> NetError {
    NetError::Os {
        op,
        message: format!("Windows error 0x{code:08X}"),
    }
}

/// Installs the rules. All or nothing.
pub fn install(rules: &[Rule]) -> Result<WfpGuard, NetError> {
    let session_name = wide("Deterium kill switch");
    let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name = session_name.as_ptr() as *mut u16;

    let mut engine: HANDLE = unsafe { std::mem::zeroed() };
    // SAFETY: `session` and the name buffer outlive the call; `engine` is a valid out-pointer.
    let code = unsafe {
        FwpmEngineOpen0(
            std::ptr::null(),
            AUTHN_DEFAULT,
            std::ptr::null_mut(),
            &session,
            &mut engine,
        )
    };
    if code != 0 {
        return Err(fail("FwpmEngineOpen0", code));
    }
    // From here on, any early return drops the guard and closes the engine.
    let guard = WfpGuard { engine };

    // SAFETY: valid engine handle.
    let code = unsafe { FwpmTransactionBegin0(engine, 0) };
    if code != 0 {
        return Err(fail("FwpmTransactionBegin0", code));
    }

    let result = add_everything(engine, rules);
    if let Err(err) = result {
        // SAFETY: valid engine handle with an open transaction.
        unsafe { FwpmTransactionAbort0(engine) };
        return Err(err);
    }

    // SAFETY: valid engine handle with an open transaction.
    let code = unsafe { FwpmTransactionCommit0(engine) };
    if code != 0 {
        return Err(fail("FwpmTransactionCommit0", code));
    }
    Ok(guard)
}

fn add_everything(engine: HANDLE, rules: &[Rule]) -> Result<(), NetError> {
    let sublayer_key = fresh_sublayer_key();
    let sublayer_name = wide("Deterium");
    let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
    sublayer.subLayerKey = sublayer_key;
    sublayer.displayData.name = sublayer_name.as_ptr() as *mut u16;
    // High, so our verdicts are reached before lower sublayers' ones.
    sublayer.weight = 0xFFFE;
    // SAFETY: valid engine; `sublayer` and its name outlive the call.
    let code = unsafe { FwpmSubLayerAdd0(engine, &sublayer, std::ptr::null_mut()) };
    if code != 0 {
        return Err(fail("FwpmSubLayerAdd0", code));
    }

    for rule in rules {
        for (layer, family) in layers_for(rule) {
            add_filter(engine, rule, layer, family, sublayer_key)?;
        }
    }
    Ok(())
}

/// Outbound connections and inbound accepts, for the address families the
/// rule can apply to.
fn layers_for(rule: &Rule) -> Vec<(GUID, Family)> {
    let only = rule.when.iter().find_map(|m| match m {
        Matcher::RemoteAddress(Cidr { addr, .. }) => Some(match addr {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }),
        _ => None,
    });

    let mut layers = Vec::new();
    if only != Some(Family::V6) {
        layers.push((FWPM_LAYER_ALE_AUTH_CONNECT_V4, Family::V4));
        layers.push((FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, Family::V4));
    }
    if only != Some(Family::V4) {
        layers.push((FWPM_LAYER_ALE_AUTH_CONNECT_V6, Family::V6));
        layers.push((FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, Family::V6));
    }
    layers
}

fn add_filter(
    engine: HANDLE,
    rule: &Rule,
    layer: GUID,
    family: Family,
    sublayer_key: GUID,
) -> Result<(), NetError> {
    let mut owned = Owned::default();
    let mut conditions: Vec<FWPM_FILTER_CONDITION0> = rule
        .when
        .iter()
        .map(|m| condition(m, family, &mut owned))
        .collect();

    let name = wide(&format!("Deterium: {}", rule.name));
    let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
    filter.displayData.name = name.as_ptr() as *mut u16;
    filter.layerKey = layer;
    filter.subLayerKey = sublayer_key;
    filter.weight.r#type = FWP_UINT8;
    filter.weight.Anonymous.uint8 = rule.weight;
    filter.numFilterConditions = conditions.len() as u32;
    filter.filterCondition = if conditions.is_empty() {
        std::ptr::null_mut()
    } else {
        conditions.as_mut_ptr()
    };
    filter.action.r#type = match rule.action {
        Action::Permit => FWP_ACTION_PERMIT,
        Action::Block => FWP_ACTION_BLOCK,
    };

    let mut id = 0u64;
    // SAFETY: valid engine inside a transaction; the filter, its conditions
    // and everything they point at (`owned`, `name`) outlive the call, and
    // Windows copies them.
    let code = unsafe { FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut id) };
    drop(owned);
    if code != 0 {
        return Err(fail("FwpmFilterAdd0", code));
    }
    Ok(())
}

fn condition(matcher: &Matcher, family: Family, owned: &mut Owned) -> FWPM_FILTER_CONDITION0 {
    // SAFETY: all-zero is a valid (empty) condition; we set the fields that matter.
    let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
    c.matchType = FWP_MATCH_EQUAL;

    match matcher {
        Matcher::Loopback => {
            c.fieldKey = FWPM_CONDITION_FLAGS;
            c.matchType = FWP_MATCH_FLAGS_ALL_SET;
            c.conditionValue.r#type = FWP_UINT32;
            c.conditionValue.Anonymous.uint32 = FLAG_IS_LOOPBACK;
        }
        Matcher::TunnelInterface(luid) => {
            let mut boxed = Box::new(*luid);
            c.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
            c.conditionValue.r#type = FWP_UINT64;
            c.conditionValue.Anonymous.uint64 = &mut *boxed;
            owned.luids.push(boxed);
        }
        Matcher::Protocol(protocol) => {
            c.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            c.conditionValue.r#type = FWP_UINT8;
            c.conditionValue.Anonymous.uint8 = match protocol {
                Protocol::Tcp => 6,
                Protocol::Udp => 17,
            };
        }
        Matcher::RemotePort(port) => {
            c.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
            c.conditionValue.r#type = FWP_UINT16;
            c.conditionValue.Anonymous.uint16 = *port;
        }
        Matcher::LocalPort(port) => {
            c.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
            c.conditionValue.r#type = FWP_UINT16;
            c.conditionValue.Anonymous.uint16 = *port;
        }
        Matcher::RemoteAddress(cidr) => {
            c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            match (cidr.addr, family) {
                (IpAddr::V4(addr), Family::V4) => {
                    let mask = if cidr.prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - cidr.prefix as u32)
                    };
                    let mut boxed = Box::new(FWP_V4_ADDR_AND_MASK {
                        addr: u32::from(addr) & mask,
                        mask,
                    });
                    c.conditionValue.r#type = FWP_V4_ADDR_MASK;
                    c.conditionValue.Anonymous.v4AddrMask = &mut *boxed;
                    owned.v4.push(boxed);
                }
                (IpAddr::V6(addr), Family::V6) => {
                    let mut boxed = Box::new(FWP_V6_ADDR_AND_MASK {
                        addr: addr.octets(),
                        prefixLength: cidr.prefix,
                    });
                    c.conditionValue.r#type = FWP_V6_ADDR_MASK;
                    c.conditionValue.Anonymous.v6AddrMask = &mut *boxed;
                    owned.v6.push(boxed);
                }
                // `layers_for` only pairs an address with its own family.
                _ => unreachable!("address family mismatch"),
            }
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    fn block(network: &str) -> Vec<Rule> {
        vec![Rule {
            name: "test block",
            action: Action::Block,
            weight: 5,
            when: vec![Matcher::RemoteAddress(Cidr::parse(network).unwrap())],
        }]
    }

    /// How a connection attempt to a documentation-only address (TEST-NET-1,
    /// never routed) ends: refused by the firewall, or anything else.
    fn blocked_by_the_firewall(ip: &str) -> bool {
        let addr: SocketAddr = format!("{ip}:80").parse().unwrap();
        TcpStream::connect_timeout(&addr, Duration::from_millis(1500))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
    }

    #[test]
    fn every_install_gets_its_own_sublayer_key() {
        let (a, b) = (fresh_sublayer_key(), fresh_sublayer_key());
        assert_ne!((a.data1, a.data2, a.data3), (b.data1, b.data2, b.data3));
        assert_eq!(a.data4, SUBLAYER_KEY.data4, "still recognisably Deterium's");
    }

    /// Runs against the real Windows Filtering Platform, so it needs
    /// administrator rights: `cargo test -p deterium-net wfp -- --ignored`.
    /// Only 192.0.2.0/24 (documentation addresses nothing is routed to) is
    /// blocked, so the PC's real traffic is never touched.
    #[test]
    #[ignore = "needs administrator rights"]
    fn two_installs_live_side_by_side_and_each_goes_when_dropped() {
        let first = install(&block("192.0.2.0/25")).expect("first install");
        let second = install(&block("192.0.2.128/25"))
            .expect("a second install must not clash with the first one's sublayer");
        assert!(blocked_by_the_firewall("192.0.2.1"), "first install blocks");
        assert!(
            blocked_by_the_firewall("192.0.2.200"),
            "second install blocks"
        );

        drop(first);
        assert!(!blocked_by_the_firewall("192.0.2.1"), "first is gone");
        assert!(
            blocked_by_the_firewall("192.0.2.200"),
            "second is untouched"
        );

        drop(second);
        assert!(!blocked_by_the_firewall("192.0.2.200"), "second is gone");
    }

    /// The real "hold" (what the service puts up after a reboot, and what
    /// OpenVPN puts up before it starts). While it stands, *all* of this PC's
    /// traffic is held back except what it permits, so run it when the network
    /// is not needed: it lasts about three seconds.
    #[test]
    #[ignore = "needs administrator rights and blocks this PC's network for ~3 s"]
    fn a_real_hold_lets_through_only_its_server_loopback_and_dns_when_asked() {
        use crate::leak::{build_hold_rules, Server};
        use std::net::TcpListener;

        // The "VPN server" is a documentation address: permitted means the
        // attempt is not refused by the firewall (it then just goes nowhere).
        let server = Server::tcp("192.0.2.1:80".parse().unwrap());
        let hold = install(&build_hold_rules(vec![server], false, 0, false)).expect("hold");

        assert!(
            !blocked_by_the_firewall("192.0.2.1"),
            "the VPN server is let through"
        );
        assert!(
            blocked_by_the_firewall("192.0.2.2"),
            "everything else is refused"
        );
        assert!(blocked_by_the_firewall("203.0.113.9"), "in any range");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        TcpStream::connect(listener.local_addr().unwrap()).expect("loopback still works");

        let dns = |ip: &str| {
            let addr: SocketAddr = format!("{ip}:53").parse().unwrap();
            TcpStream::connect_timeout(&addr, Duration::from_millis(800))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
        };
        assert!(dns("192.0.2.53"), "DNS is closed in the strict hold");

        // The hold used while a connection is being set up also lets DNS out.
        let connecting = install(&build_hold_rules(vec![server], false, 0, true)).expect("hold");
        drop(hold);
        assert!(!dns("192.0.2.53"), "DNS lookups are open while connecting");
        assert!(blocked_by_the_firewall("192.0.2.2"), "but nothing else is");

        drop(connecting);
        assert!(
            !blocked_by_the_firewall("192.0.2.2"),
            "dropping the hold gives the network back"
        );
    }
}
