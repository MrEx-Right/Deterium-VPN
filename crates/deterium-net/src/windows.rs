//! Windows implementation: a Wintun adapter, IP Helper for addresses and
//! routes, and `netsh` for DNS. Everything here is `unsafe` FFI kept in small
//! functions with their invariants stated; the portable logic that decides
//! *what* to do lives in `plan.rs` / `system.rs` and is tested without any of
//! this.

use crate::cidr::Cidr;
use crate::leak::{build_rules, LeakPolicy};
use crate::plan::{NetworkPlan, Op, PhysicalRoute};
use crate::platform::Platform;
use crate::system::{Journal, NetError, NetworkGuard, SystemNet, TunInfo, Undo};
use crate::tun::TunDevice;
use libloading::Library;
use std::ffi::c_void;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToIndex,
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2, FreeMibTable,
    GetBestRoute2, GetIpForwardTable2, GetIpInterfaceEntry, InitializeIpForwardEntry,
    InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry, SetIpInterfaceEntry,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const ADAPTER_TUNNEL_TYPE: &str = "Deterium";
/// A fixed identity for the adapter so Windows doesn't create a new network
/// profile ("Unidentified network 7") on every connect.
const ADAPTER_GUID: GUID = GUID {
    data1: 0x5b7a6f0e,
    data2: 0x8b2f,
    data3: 0x4a0a,
    data4: [0x9a, 0x54, 0x6d, 0x1c, 0x3a, 0x8e, 0x2f, 0x11],
};
const RING_CAPACITY: u32 = 0x40_0000;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const ROUTE_METRIC: u32 = 1;

const NO_ERROR: u32 = 0;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_NOT_FOUND: u32 = 1168;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;
const WAIT_TIMEOUT: u32 = 258;

fn os_error(op: &'static str, code: u32) -> NetError {
    let hint = match code {
        ERROR_ACCESS_DENIED => " (access denied — administrator rights are required)",
        ERROR_NOT_FOUND => " (not found)",
        _ => "",
    };
    NetError::Os {
        op,
        message: format!("Windows error {code}{hint}"),
    }
}

// ----------------------------------------------------------- platform --

pub struct WindowsPlatform;

impl Platform for WindowsPlatform {
    fn is_elevated(&self) -> bool {
        crate::elevation::is_elevated()
    }

    fn open_tun(&self, name: &str) -> Result<Arc<dyn TunDevice>, NetError> {
        Ok(Arc::new(WintunTun::open(name)?))
    }

    fn route_to(&self, dest: IpAddr) -> Result<PhysicalRoute, NetError> {
        WindowsNet.route_to(dest)
    }

    fn apply_plan(&self, tun: &TunInfo, plan: &NetworkPlan) -> Result<Box<dyn Send>, NetError> {
        let guard = NetworkGuard::apply(WindowsNet, tun, plan, Some(Journal::default_location()))?;
        Ok(Box::new(guard))
    }

    fn guard_leaks(&self, tun: &TunInfo, policy: &LeakPolicy) -> Result<Box<dyn Send>, NetError> {
        let rules = build_rules(policy, tun.luid);
        Ok(Box::new(crate::wfp::install(&rules)?))
    }
}

/// Reverts anything an earlier run left behind (it crashed or was killed
/// before it could clean up).
pub fn recover_leftovers() -> usize {
    let reverted = crate::system::recover_stale(&mut WindowsNet, &Journal::default_location());
    // OpenVPN adds its own routes (not in our journal); if it died abruptly they
    // would still point at its adapter and cut the PC off the network.
    reverted + clear_adapter_routes(OPENVPN_ADAPTER_NAME)
}

// ----------------------------------------------------- addresses/routes --

pub struct WindowsNet;

fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    // SAFETY: SOCKADDR_INET is a plain-old-data union; all-zero is a valid
    // value, and we then set the family and address of exactly one variant.
    unsafe {
        let mut sa: SOCKADDR_INET = std::mem::zeroed();
        match ip {
            IpAddr::V4(v4) => {
                sa.Ipv4.sin_family = AF_INET;
                sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
            }
            IpAddr::V6(v6) => {
                sa.Ipv6.sin6_family = AF_INET6;
                sa.Ipv6.sin6_addr.u.Byte = v6.octets();
            }
        }
        sa
    }
}

fn ip_of(sa: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: `si_family` is valid for every variant of the union, and tells
    // us which variant to read.
    unsafe {
        match sa.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                sa.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(sa.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

fn unspecified_like(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

fn luid_from_index(index: u32) -> Result<u64, NetError> {
    let mut luid = NET_LUID_LH { Value: 0 };
    // SAFETY: `luid` is a valid out-pointer.
    let code = unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) };
    if code != NO_ERROR {
        return Err(os_error("ConvertInterfaceIndexToLuid", code));
    }
    // SAFETY: reading the integer view of the LUID union.
    Ok(unsafe { luid.Value })
}

/// Adds a route. `Ok(false)` means an identical route already existed (and
/// so isn't ours to remove later).
fn add_route(
    luid: u64,
    dest: Cidr,
    next_hop: Option<IpAddr>,
    metric: u32,
) -> Result<bool, NetError> {
    // SAFETY: the row is initialized by Windows before we fill in the fields
    // that identify the route; the pointer is valid for the call.
    let code = unsafe {
        let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        InitializeIpForwardEntry(&mut row);
        row.InterfaceLuid = NET_LUID_LH { Value: luid };
        row.DestinationPrefix.Prefix = sockaddr(dest.addr);
        row.DestinationPrefix.PrefixLength = dest.prefix;
        row.NextHop = sockaddr(next_hop.unwrap_or_else(|| unspecified_like(dest.addr)));
        row.Metric = metric;
        // MIB_IPPROTO_NETMGMT: a route installed by a management application.
        row.Protocol = 3;
        CreateIpForwardEntry2(&row)
    };
    match code {
        NO_ERROR => Ok(true),
        ERROR_OBJECT_ALREADY_EXISTS => Ok(false),
        other => Err(os_error("CreateIpForwardEntry2", other)),
    }
}

fn remove_route(
    interface_index: u32,
    dest: Cidr,
    next_hop: Option<IpAddr>,
) -> Result<(), NetError> {
    // The interface may be gone already (a Wintun adapter takes its routes
    // with it); that's a successful undo.
    let Ok(luid) = luid_from_index(interface_index) else {
        return Ok(());
    };
    // SAFETY: as in `add_route`; Delete only needs the identifying fields.
    let code = unsafe {
        let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        InitializeIpForwardEntry(&mut row);
        row.InterfaceLuid = NET_LUID_LH { Value: luid };
        row.DestinationPrefix.Prefix = sockaddr(dest.addr);
        row.DestinationPrefix.PrefixLength = dest.prefix;
        row.NextHop = sockaddr(next_hop.unwrap_or_else(|| unspecified_like(dest.addr)));
        DeleteIpForwardEntry2(&row)
    };
    match code {
        NO_ERROR | ERROR_NOT_FOUND => Ok(()),
        other => Err(os_error("DeleteIpForwardEntry2", other)),
    }
}

fn assign_address(luid: u64, addr: Cidr) -> Result<(), NetError> {
    // SAFETY: row initialized by Windows, then identifying fields filled in.
    let code = unsafe {
        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceLuid = NET_LUID_LH { Value: luid };
        row.Address = sockaddr(addr.addr);
        row.OnLinkPrefixLength = addr.prefix;
        // IpDadStatePreferred: a point-to-point tunnel has no neighbours to
        // collide with, and waiting out duplicate-address detection would
        // leave the first seconds after "connected" unable to send anything.
        row.DadState = 4;
        CreateUnicastIpAddressEntry(&row)
    };
    match code {
        NO_ERROR | ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
        other => Err(os_error("CreateUnicastIpAddressEntry", other)),
    }
}

/// Sets MTU and/or metric for one address family. A family the adapter
/// doesn't have (IPv6 disabled) is skipped, not an error.
fn set_interface(
    luid: u64,
    ipv6: bool,
    mtu: Option<u32>,
    metric: Option<u32>,
) -> Result<(), NetError> {
    // SAFETY: row initialized by Windows; we read the current settings, change
    // two fields and write it back, per the documented Get-modify-Set pattern.
    let code = unsafe {
        let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
        InitializeIpInterfaceEntry(&mut row);
        row.Family = if ipv6 { AF_INET6 } else { AF_INET };
        row.InterfaceLuid = NET_LUID_LH { Value: luid };
        let got = GetIpInterfaceEntry(&mut row);
        if got != NO_ERROR {
            got
        } else {
            // Documented quirk: SetIpInterfaceEntry rejects IPv4 rows unless
            // SitePrefixLength is zero.
            row.SitePrefixLength = 0;
            if let Some(mtu) = mtu {
                row.NlMtu = mtu;
            }
            if let Some(metric) = metric {
                row.UseAutomaticMetric = 0;
                row.Metric = metric;
            }
            SetIpInterfaceEntry(&mut row)
        }
    };
    match code {
        NO_ERROR => Ok(()),
        ERROR_NOT_FOUND if ipv6 => Ok(()),
        other => Err(os_error("SetIpInterfaceEntry", other)),
    }
}

fn set_dns(adapter_name: &str, servers: &[IpAddr]) -> Result<(), NetError> {
    for (family, is_v6) in [("ipv4", false), ("ipv6", true)] {
        let list: Vec<&IpAddr> = servers.iter().filter(|s| s.is_ipv6() == is_v6).collect();
        for (i, server) in list.iter().enumerate() {
            let mut command = Command::new("netsh");
            command.creation_flags(CREATE_NO_WINDOW);
            command.args(["interface", family]);
            if i == 0 {
                command.args(["set", "dnsservers"]);
                command.arg(format!("name={adapter_name}"));
                command.args(["source=static", &format!("address={server}")]);
                if !is_v6 {
                    command.arg("register=none");
                }
            } else {
                command.args(["add", "dnsservers"]);
                command.arg(format!("name={adapter_name}"));
                command.arg(format!("address={server}"));
                command.arg(format!("index={}", i + 1));
            }
            command.arg("validate=no");

            let output = command.output().map_err(|e| NetError::Os {
                op: "netsh",
                message: e.to_string(),
            })?;
            if !output.status.success() {
                return Err(NetError::Os {
                    op: "netsh dnsservers",
                    message: String::from_utf8_lossy(&output.stdout).trim().to_string(),
                });
            }
        }
    }
    Ok(())
}

impl SystemNet for WindowsNet {
    fn route_to(&self, dest: IpAddr) -> Result<PhysicalRoute, NetError> {
        let destination = sockaddr(dest);
        // SAFETY: out-parameters are valid zeroed structs; null means "any
        // interface" / "no source address hint", as documented.
        let (code, route) = unsafe {
            let mut route: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
            let mut source: SOCKADDR_INET = std::mem::zeroed();
            let code = GetBestRoute2(
                std::ptr::null(),
                0,
                std::ptr::null(),
                &destination,
                0,
                &mut route,
                &mut source,
            );
            (code, route)
        };
        if code != NO_ERROR {
            return Err(os_error("GetBestRoute2", code));
        }

        let next_hop = ip_of(&route.NextHop).filter(|ip| !ip.is_unspecified());
        Ok(PhysicalRoute {
            interface_index: route.InterfaceIndex,
            next_hop,
        })
    }

    fn apply(&mut self, tun: &TunInfo, op: &Op) -> Result<Option<Undo>, NetError> {
        match op {
            Op::AssignAddress(addr) => {
                assign_address(tun.luid, *addr)?;
                Ok(None)
            }
            Op::SetMtu(mtu) => {
                set_interface(tun.luid, false, Some(*mtu), None)?;
                set_interface(tun.luid, true, Some(*mtu), None)?;
                Ok(None)
            }
            Op::SetInterfaceMetric(metric) => {
                set_interface(tun.luid, false, None, Some(*metric))?;
                set_interface(tun.luid, true, None, Some(*metric))?;
                Ok(None)
            }
            Op::BypassRoute { dest, via } => {
                let luid = luid_from_index(via.interface_index)?;
                let created = add_route(luid, *dest, via.next_hop, ROUTE_METRIC)?;
                Ok(created.then_some(Undo::RemoveRoute {
                    dest: *dest,
                    interface_index: via.interface_index,
                    next_hop: via.next_hop,
                }))
            }
            Op::TunnelRoute { dest } => {
                let created = add_route(tun.luid, *dest, None, ROUTE_METRIC)?;
                Ok(created.then_some(Undo::RemoveRoute {
                    dest: *dest,
                    interface_index: tun.interface_index,
                    next_hop: None,
                }))
            }
            Op::SetDns(servers) => {
                set_dns(&tun.name, servers)?;
                Ok(None)
            }
        }
    }

    fn undo(&mut self, undo: &Undo) -> Result<(), NetError> {
        match undo {
            Undo::RemoveRoute {
                dest,
                interface_index,
                next_hop,
            } => remove_route(*interface_index, *dest, *next_hop),
        }
    }
}

// -------------------------------------------------------------- wintun --

type CreateAdapterFn =
    unsafe extern "system" fn(*const u16, *const u16, *const GUID) -> *mut c_void;
type OpenAdapterFn = unsafe extern "system" fn(*const u16) -> *mut c_void;
type CloseAdapterFn = unsafe extern "system" fn(*mut c_void);
type GetLuidFn = unsafe extern "system" fn(*mut c_void, *mut NET_LUID_LH);
type StartSessionFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
type EndSessionFn = unsafe extern "system" fn(*mut c_void);
type ReadEventFn = unsafe extern "system" fn(*mut c_void) -> HANDLE;
type ReceiveFn = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut u8;
type ReleaseFn = unsafe extern "system" fn(*mut c_void, *const u8);
type AllocSendFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut u8;
type SendFn = unsafe extern "system" fn(*mut c_void, *const u8);

struct WintunApi {
    create_adapter: CreateAdapterFn,
    open_adapter: OpenAdapterFn,
    close_adapter: CloseAdapterFn,
    get_luid: GetLuidFn,
    start_session: StartSessionFn,
    end_session: EndSessionFn,
    read_event: ReadEventFn,
    receive: ReceiveFn,
    release: ReleaseFn,
    alloc_send: AllocSendFn,
    send: SendFn,
}

fn load_wintun() -> Result<(Library, WintunApi), NetError> {
    // The driver DLL is built into the executable and deployed to an
    // administrator-only folder (see `deploy.rs`); an elevated process must
    // never pick one up from the current directory, PATH or a user-writable
    // folder.
    let path = crate::deploy::ensure_wintun().map_err(|e| {
        NetError::DriverMissing(format!(
            "couldn't set up the Wintun driver in {}: {e}",
            crate::deploy::install_dir().display()
        ))
    })?;

    // SAFETY: loading Wintun's DLL runs its (trusted, signed) initialization;
    // each symbol is looked up by name and cast to its documented signature
    // (wintun.h). The fn pointers stay valid because `Library` is kept alive
    // alongside them in `WintunTun`.
    unsafe {
        let lib = Library::new(&path).map_err(|e| {
            NetError::DriverMissing(format!("couldn't load {}: {e}", path.display()))
        })?;
        macro_rules! sym {
            ($name:literal) => {
                *lib.get($name).map_err(|e| {
                    NetError::DriverMissing(format!(
                        "{} doesn't look like a Wintun DLL: {e}",
                        path.display()
                    ))
                })?
            };
        }
        let api = WintunApi {
            create_adapter: sym!(b"WintunCreateAdapter\0"),
            open_adapter: sym!(b"WintunOpenAdapter\0"),
            close_adapter: sym!(b"WintunCloseAdapter\0"),
            get_luid: sym!(b"WintunGetAdapterLUID\0"),
            start_session: sym!(b"WintunStartSession\0"),
            end_session: sym!(b"WintunEndSession\0"),
            read_event: sym!(b"WintunGetReadWaitEvent\0"),
            receive: sym!(b"WintunReceivePacket\0"),
            release: sym!(b"WintunReleaseReceivePacket\0"),
            alloc_send: sym!(b"WintunAllocateSendPacket\0"),
            send: sym!(b"WintunSendPacket\0"),
        };
        Ok((lib, api))
    }
}

fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub struct WintunTun {
    // Field order = drop order: the session/adapter are released in `Drop`
    // first, the DLL is unloaded last.
    api: WintunApi,
    adapter: *mut c_void,
    session: *mut c_void,
    read_event: HANDLE,
    info: TunInfo,
    _lib: Library,
}

// SAFETY: Wintun documents its session functions as safe to call from
// multiple threads (one receiver and one sender concurrently, which is what
// we do); the raw pointers are opaque handles owned by this struct.
unsafe impl Send for WintunTun {}
unsafe impl Sync for WintunTun {}

impl WintunTun {
    pub fn open(name: &str) -> Result<Self, NetError> {
        let (lib, api) = load_wintun()?;
        let name_w = wide(name);
        let type_w = wide(ADAPTER_TUNNEL_TYPE);

        // SAFETY: wintun.h signatures; pointers are NUL-terminated UTF-16 that
        // outlive the calls.
        unsafe {
            // Reuse the adapter if a previous run left it behind.
            let mut adapter = (api.open_adapter)(name_w.as_ptr());
            if adapter.is_null() {
                adapter = (api.create_adapter)(name_w.as_ptr(), type_w.as_ptr(), &ADAPTER_GUID);
            }
            if adapter.is_null() {
                return Err(os_error("WintunCreateAdapter", GetLastError()));
            }

            let mut luid = NET_LUID_LH { Value: 0 };
            (api.get_luid)(adapter, &mut luid);
            let mut index = 0u32;
            let code = ConvertInterfaceLuidToIndex(&luid, &mut index);
            if code != NO_ERROR {
                (api.close_adapter)(adapter);
                return Err(os_error("ConvertInterfaceLuidToIndex", code));
            }

            let session = (api.start_session)(adapter, RING_CAPACITY);
            if session.is_null() {
                let err = os_error("WintunStartSession", GetLastError());
                (api.close_adapter)(adapter);
                return Err(err);
            }
            let read_event = (api.read_event)(session);

            Ok(Self {
                info: TunInfo {
                    name: name.to_string(),
                    interface_index: index,
                    luid: luid.Value,
                },
                api,
                adapter,
                session,
                read_event,
                _lib: lib,
            })
        }
    }
}

/// The adapter OpenVPN uses. OpenVPN 2.6 doesn't create Wintun adapters, it
/// opens one that already exists, so Deterium creates it (with the same
/// verified Wintun code as for WireGuard) and removes it afterwards.
pub const OPENVPN_ADAPTER_NAME: &str = "Deterium OpenVPN";

/// A different identity from the WireGuard adapter so the two can't clash.
const OPENVPN_ADAPTER_GUID: GUID = GUID {
    data1: 0x7c3e91b4,
    data2: 0x2d58,
    data3: 0x4f6a,
    data4: [0x8e, 0x17, 0x40, 0xb9, 0x5a, 0x6c, 0x0d, 0x23],
};

/// A Wintun adapter that is held open (no data session) for another program to
/// use. Dropping it removes the adapter.
pub struct HeldAdapter {
    // Boxed so a handle holding one stays small.
    api: Box<WintunApi>,
    adapter: *mut c_void,
    _lib: Library,
}

// SAFETY: an opaque Wintun handle with no thread affinity.
unsafe impl Send for HeldAdapter {}
unsafe impl Sync for HeldAdapter {}

impl Drop for HeldAdapter {
    fn drop(&mut self) {
        // SAFETY: closed once; removes the adapter this process created.
        unsafe { (self.api.close_adapter)(self.adapter) };
    }
}

/// Creates (or reuses) the adapter OpenVPN will open, and first removes any
/// routes an earlier, abruptly ended run left pointing at it.
pub fn hold_openvpn_adapter() -> Result<HeldAdapter, NetError> {
    clear_adapter_routes(OPENVPN_ADAPTER_NAME);
    let (lib, api) = load_wintun()?;
    let name = wide(OPENVPN_ADAPTER_NAME);
    let kind = wide(ADAPTER_TUNNEL_TYPE);
    // SAFETY: wintun.h signatures; NUL-terminated buffers outlive the calls.
    let adapter = unsafe {
        let mut adapter = (api.open_adapter)(name.as_ptr());
        if adapter.is_null() {
            adapter = (api.create_adapter)(name.as_ptr(), kind.as_ptr(), &OPENVPN_ADAPTER_GUID);
        }
        if adapter.is_null() {
            return Err(os_error("WintunCreateAdapter", GetLastError()));
        }
        adapter
    };
    Ok(HeldAdapter {
        api: Box::new(api),
        adapter,
        _lib: lib,
    })
}

/// Installs the kill switch / DNS-leak rules around the OpenVPN adapter (which
/// must exist, see [`hold_openvpn_adapter`]). The rules live in a dynamic WFP
/// session, so Windows removes them the moment this process ends.
pub fn guard_openvpn_leaks(policy: &LeakPolicy) -> Result<Box<dyn Send>, NetError> {
    let alias = wide(OPENVPN_ADAPTER_NAME);
    let mut luid = NET_LUID_LH { Value: 0 };
    // SAFETY: NUL-terminated name; Windows fills `luid`.
    let code = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) };
    if code != NO_ERROR {
        return Err(os_error("ConvertInterfaceAliasToLuid", code));
    }
    // SAFETY: reading the plain integer view of the union we just filled in.
    let rules = build_rules(policy, unsafe { luid.Value });
    Ok(Box::new(crate::wfp::install(&rules)?))
}

/// Deletes every route bound to the network adapter called `name`. Returns how
/// many were removed (0 when there is no such adapter).
pub fn clear_adapter_routes(name: &str) -> usize {
    let alias = wide(name);
    // SAFETY: Windows allocates the table and stores its address in `table`; it
    // is only read while it is alive and freed afterwards, and rows are only used
    // to identify routes to delete.
    unsafe {
        let mut luid = NET_LUID_LH { Value: 0 };
        if ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) != NO_ERROR {
            return 0;
        }
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        if GetIpForwardTable2(AF_UNSPEC, &mut table) != NO_ERROR {
            return 0;
        }
        if table.is_null() {
            return 0;
        }
        // `Table` is declared as a one-element array but really holds
        // `NumEntries` rows. Take its address without creating a reference to
        // that one-element array, so the pointer keeps the whole allocation as
        // its range and reading the other rows stays inside it.
        let first = std::ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>();
        let rows = std::slice::from_raw_parts(first, (*table).NumEntries as usize);
        let mut removed = 0;
        for row in rows {
            if row.InterfaceLuid.Value == luid.Value && DeleteIpForwardEntry2(row) == NO_ERROR {
                removed += 1;
            }
        }
        FreeMibTable(table as *const c_void);
        removed
    }
}

impl TunDevice for WintunTun {
    fn info(&self) -> &TunInfo {
        &self.info
    }

    fn read_packet(&self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
        let millis = timeout.as_millis().min(u32::MAX as u128) as u32;
        // SAFETY: `session` is live for the lifetime of `self`; the packet
        // pointer Wintun returns is valid for `size` bytes until released.
        unsafe {
            loop {
                let mut size = 0u32;
                let packet = (self.api.receive)(self.session, &mut size);
                if !packet.is_null() {
                    let n = (size as usize).min(buf.len());
                    std::ptr::copy_nonoverlapping(packet, buf.as_mut_ptr(), n);
                    (self.api.release)(self.session, packet);
                    return Ok(Some(n));
                }

                let code = GetLastError();
                if code != ERROR_NO_MORE_ITEMS {
                    return Err(io::Error::from_raw_os_error(code as i32));
                }
                // Queue is empty: sleep until Wintun signals a packet (or timeout).
                if WaitForSingleObject(self.read_event, millis) == WAIT_TIMEOUT {
                    return Ok(None);
                }
            }
        }
    }

    fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        // SAFETY: Wintun hands out a buffer of exactly the requested size,
        // which we fill and then give back via Send.
        unsafe {
            let out = (self.api.alloc_send)(self.session, packet.len() as u32);
            if out.is_null() {
                // Ring full: dropping a packet is what a real NIC does too.
                return Ok(());
            }
            std::ptr::copy_nonoverlapping(packet.as_ptr(), out, packet.len());
            (self.api.send)(self.session, out);
        }
        Ok(())
    }
}

impl Drop for WintunTun {
    fn drop(&mut self) {
        // SAFETY: both handles were created in `open` and are released once.
        unsafe {
            (self.api.end_session)(self.session);
            (self.api.close_adapter)(self.adapter);
        }
    }
}
