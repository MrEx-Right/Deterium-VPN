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
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

/// Identifies our rules so they can be told apart in Windows' own tools.
const SUBLAYER_KEY: GUID = GUID {
    data1: 0xd37e_0a0c,
    data2: 0x6b21,
    data3: 0x4f0a,
    data4: [0x9c, 0x31, 0x5e, 0x77, 0x0d, 0x42, 0xa1, 0x08],
};
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
    let sublayer_name = wide("Deterium");
    let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
    sublayer.subLayerKey = SUBLAYER_KEY;
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
            add_filter(engine, rule, layer, family)?;
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

fn add_filter(engine: HANDLE, rule: &Rule, layer: GUID, family: Family) -> Result<(), NetError> {
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
    filter.subLayerKey = SUBLAYER_KEY;
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
