//! One place that knows which adapter serves which protocol, so the GUI and
//! the background service just say "connect this profile" and never branch on
//! protocol themselves. Adding a protocol means adding a variant here.

use deterium_core::{
    AdapterError, ConnectMode, Protocol, ProtocolAdapter, ServerProfile, TunnelStatus,
};
use deterium_proto_openvpn::{OpenVpnAdapter, OpenVpnTunnelHandle};
use deterium_proto_wireguard::{WireGuardAdapter, WireGuardTunnelHandle};

mod remote;

pub use deterium_ipc::{service_state, ServiceState};
pub use deterium_net::{
    adapter_counters, current_user_sid, is_elevated, ping, recover_leftovers, relaunch_elevated,
    run_elevated_and_wait, AdapterCounters, ElevateError, Protocol as ServerProtocol, Server,
    OPENVPN_ADAPTER_NAME,
};
pub use deterium_proto_openvpn::{bundled_available, bundled_version, find_openvpn};
pub use deterium_proto_wireguard::TunnelStats;
pub use remote::{service_armed, service_disarm, RemoteTunnel};

pub enum Tunnel {
    WireGuard(WireGuardTunnelHandle),
    OpenVpn(OpenVpnTunnelHandle),
    /// Held by the background service; closing the app leaves it running.
    Remote(RemoteTunnel),
}

/// Like [`connect`], but a real VPN goes through the background service when
/// it is running, so no administrator rights are needed in this process and
/// the tunnel survives this process exiting. Connection tests, and machines
/// without the service, connect directly.
pub fn connect_auto(profile: &ServerProfile, mode: ConnectMode) -> Result<Tunnel, AdapterError> {
    if mode == ConnectMode::Full {
        if let Some(remote) = remote::connect_via_service(profile)? {
            return Ok(Tunnel::Remote(remote));
        }
    }
    connect(profile, mode)
}

/// The tunnel the background service is already holding, if any, with the
/// profile it belongs to.
pub fn attach() -> Option<(deterium_core::Uuid, Tunnel)> {
    attach_checked().ok().flatten()
}

/// Like [`attach`], but says why when the service couldn't be asked.
pub fn attach_checked() -> Result<Option<(deterium_core::Uuid, Tunnel)>, String> {
    match remote::attach_to_service() {
        Ok(Some(remote)) => Ok(Some((remote.profile_id(), Tunnel::Remote(remote)))),
        Ok(None) => Ok(None),
        Err(err) => Err(err.to_string()),
    }
}

/// The servers the profile's tunnel has to reach from outside the tunnel
/// (names resolved now). A firewall hold that must still let the VPN connect
/// permits exactly these. Empty when they can't be worked out.
pub fn guard_servers(profile: &ServerProfile) -> Vec<Server> {
    match profile.protocol {
        Protocol::Wireguard => WireGuardAdapter
            .load_profile(profile)
            .map(|config| vec![Server::udp(config.endpoint())])
            .unwrap_or_default(),
        Protocol::Openvpn => profile
            .openvpn
            .as_ref()
            .map(|ovpn| deterium_proto_openvpn::configured_servers(&ovpn.raw_config))
            .unwrap_or_default(),
    }
}

/// Starts a tunnel for the profile using the adapter for its protocol.
///
/// [`ConnectMode::Full`] makes a real VPN (needs administrator rights);
/// [`ConnectMode::HandshakeOnly`] only checks a WireGuard server answers and
/// changes nothing on the system.
pub fn connect(profile: &ServerProfile, mode: ConnectMode) -> Result<Tunnel, AdapterError> {
    match profile.protocol {
        Protocol::Wireguard => {
            let adapter = WireGuardAdapter;
            let mut config = adapter.load_profile(profile)?;
            config.set_mode(mode);
            adapter.connect(config).map(Tunnel::WireGuard)
        }
        Protocol::Openvpn => {
            if mode == ConnectMode::HandshakeOnly {
                return Err(AdapterError::ConnectFailed(
                    "A connection test is only available for WireGuard servers".into(),
                ));
            }
            let adapter = OpenVpnAdapter::default();
            let config = adapter.load_profile(profile)?;
            adapter.connect(config).map(Tunnel::OpenVpn)
        }
    }
}

impl Tunnel {
    pub fn status(&self) -> TunnelStatus {
        match self {
            Tunnel::WireGuard(handle) => WireGuardAdapter.status(handle),
            Tunnel::OpenVpn(handle) => OpenVpnAdapter::default().status(handle),
            Tunnel::Remote(remote) => remote.status(),
        }
    }

    pub fn disconnect(self) -> Result<(), AdapterError> {
        match self {
            Tunnel::WireGuard(handle) => WireGuardAdapter.disconnect(handle),
            Tunnel::OpenVpn(handle) => OpenVpnAdapter::default().disconnect(handle),
            Tunnel::Remote(remote) => remote.disconnect(),
        }
    }

    /// What kind of connection this is. OpenVPN always sets up a real tunnel.
    pub fn mode(&self) -> ConnectMode {
        match self {
            Tunnel::WireGuard(handle) => handle.mode(),
            Tunnel::OpenVpn(_) | Tunnel::Remote(_) => ConnectMode::Full,
        }
    }

    /// Real traffic counters, for connections whose data plane Deterium runs
    /// itself (WireGuard). OpenVPN's traffic is handled inside its own
    /// process, so there is nothing to report.
    pub fn stats(&self) -> Option<TunnelStats> {
        match self {
            Tunnel::WireGuard(handle) => Some(handle.stats()),
            Tunnel::OpenVpn(_) => None,
            Tunnel::Remote(remote) => remote.stats(),
        }
    }

    /// How long the tunnel has already been up, when it was started by an
    /// earlier run of the app (only the background service remembers that).
    pub fn existing_uptime(&self) -> Option<std::time::Duration> {
        match self {
            Tunnel::Remote(remote) => remote.uptime(),
            _ => None,
        }
    }

    /// Whether firewall rules currently block traffic outside the tunnel.
    pub fn leak_protection(&self) -> bool {
        match self {
            Tunnel::WireGuard(handle) => handle.leak_protection(),
            Tunnel::OpenVpn(handle) => handle.leak_protection(),
            Tunnel::Remote(remote) => remote.leak_protection(),
        }
    }

    /// Recent log lines from the underlying client. Only OpenVPN has one
    /// (it is a separate program); WireGuard runs in-process.
    pub fn log(&self) -> Vec<String> {
        match self {
            Tunnel::WireGuard(_) => Vec::new(),
            Tunnel::OpenVpn(handle) => handle.recent_log(),
            Tunnel::Remote(remote) => remote.log(),
        }
    }
}
