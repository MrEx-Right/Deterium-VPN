//! WireGuard `ProtocolAdapter` implementation.
//!
//! Two ways to connect ([`ConnectMode`]):
//!
//! * **Full** — a real VPN. A virtual adapter is created, the profile's
//!   addresses/routes/DNS are applied (via `deterium-net`, which also
//!   guarantees they are undone), and the data plane in [`pump`] moves IP
//!   packets between that adapter and the server using `boringtun` in
//!   library mode. Needs administrator rights and the Wintun driver.
//! * **Handshake only** — a real WireGuard handshake against the server and
//!   nothing else: no adapter, no routes, no special rights. A safe way to
//!   check a server is reachable and the keys match.

mod health;
mod pump;

use base64::{engine::general_purpose::STANDARD, Engine};
use boringtun::noise::Tunn;
use boringtun::x25519::{PublicKey, StaticSecret};
use deterium_core::validate::decode_key;
use deterium_core::{
    AdapterError, ConnectMode, ProtocolAdapter, SecurityOptions, ServerProfile, TunnelStatus,
};
use deterium_net::{
    bring_up, AllowedIps, Cidr, LeakPolicy, NetError, Platform, RoutedNetwork, TunnelSpec,
};
use health::Policy;
use pump::{Shared, SocketFactory};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

/// Name of the virtual adapter as the user sees it in Windows.
pub const ADAPTER_NAME: &str = "Deterium";

pub struct WireGuardConnectionConfig {
    private_key: StaticSecret,
    peer_public_key: PublicKey,
    preshared_key: Option<[u8; 32]>,
    endpoint: SocketAddr,
    listen_port: Option<u16>,
    keepalive: Option<u16>,
    interface_addresses: Vec<Cidr>,
    allowed_ips: Vec<Cidr>,
    dns: Vec<IpAddr>,
    mtu: Option<u32>,
    security: SecurityOptions,
    mode: ConnectMode,
}

impl WireGuardConnectionConfig {
    pub fn set_mode(&mut self, mode: ConnectMode) {
        self.mode = mode;
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
}

/// Real traffic through a tunnel, as measured by the data plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelStats {
    /// Bytes delivered from the server to this PC.
    pub rx_bytes: u64,
    /// Bytes sent from this PC to the server.
    pub tx_bytes: u64,
    /// Time since the last completed handshake, if there has been one.
    pub last_handshake: Option<Duration>,
}

pub struct WireGuardTunnelHandle {
    shared: Arc<Shared>,
    workers: Vec<JoinHandle<()>>,
    /// Routes + adapter. Only dropped once the workers have been joined, so
    /// nothing is using the adapter when it is removed.
    network: Option<RoutedNetwork>,
    mode: ConnectMode,
    leak_protection: bool,
}

impl WireGuardTunnelHandle {
    pub fn mode(&self) -> ConnectMode {
        self.mode
    }

    /// Whether firewall rules are blocking traffic outside the tunnel.
    pub fn leak_protection(&self) -> bool {
        self.leak_protection
    }

    pub fn stats(&self) -> TunnelStats {
        let counters = &self.shared.counters;
        TunnelStats {
            rx_bytes: counters.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: counters.tx_bytes.load(Ordering::Relaxed),
            last_handshake: counters.last_handshake(),
        }
    }

    /// Stops the data plane, then reverts routes and removes the adapter.
    fn shutdown(&mut self) {
        self.shared.shutdown.store(true, Ordering::Relaxed);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        self.network = None;
        self.shared.set_status(TunnelStatus::Disconnected);
    }
}

impl Drop for WireGuardTunnelHandle {
    // A handle dropped without `disconnect` (profile switch, window close)
    // must still stop its threads and undo its network changes.
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Debug, Default)]
pub struct WireGuardAdapter;

impl ProtocolAdapter for WireGuardAdapter {
    type ConnectionConfig = WireGuardConnectionConfig;
    type TunnelHandle = WireGuardTunnelHandle;

    fn load_profile(
        &self,
        profile: &ServerProfile,
    ) -> Result<Self::ConnectionConfig, AdapterError> {
        let wg = profile.wireguard.as_ref().ok_or_else(|| {
            AdapterError::InvalidProfile("profile has no [wireguard] table".into())
        })?;
        let invalid =
            |field: &str, e: String| AdapterError::InvalidProfile(format!("{field}: {e}"));

        let private_key = decode_key(&wg.interface.private_key)
            .map(StaticSecret::from)
            .map_err(|e| invalid("interface.private_key", e))?;
        let peer_public_key = decode_key(&wg.peer.public_key)
            .map(PublicKey::from)
            .map_err(|e| invalid("peer.public_key", e))?;

        let endpoint = wg
            .peer
            .endpoint
            .to_socket_addrs()
            .map_err(|e| invalid("peer.endpoint", e.to_string()))?
            .next()
            .ok_or_else(|| invalid("peer.endpoint", "resolved to no addresses".into()))?;

        let preshared_key = match wg.peer.preshared_key.as_deref().map(str::trim) {
            Some(k) if !k.is_empty() => {
                Some(decode_key(k).map_err(|e| invalid("peer.preshared_key", e))?)
            }
            _ => None,
        };

        let keepalive = match wg.peer.persistent_keepalive {
            None | Some(0) => None,
            Some(v) => Some(
                u16::try_from(v)
                    .map_err(|_| invalid("peer.persistent_keepalive", "must be 0-65535".into()))?,
            ),
        };

        let cidrs = |field: &str, list: &[String]| -> Result<Vec<Cidr>, AdapterError> {
            list.iter()
                .map(|s| Cidr::parse(s).map_err(|e| invalid(field, e)))
                .collect()
        };
        let dns = wg
            .interface
            .dns
            .iter()
            .flatten()
            .map(|s| {
                s.trim()
                    .parse::<IpAddr>()
                    .map_err(|_| invalid("interface.dns", format!("`{s}` is not an IP address")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(WireGuardConnectionConfig {
            private_key,
            peer_public_key,
            preshared_key,
            endpoint,
            listen_port: wg.interface.listen_port,
            keepalive,
            interface_addresses: cidrs("interface.address", &wg.interface.address)?,
            allowed_ips: cidrs("peer.allowed_ips", &wg.peer.allowed_ips)?,
            dns,
            mtu: wg.interface.mtu,
            security: profile.security.clone(),
            mode: ConnectMode::default(),
        })
    }

    fn connect(&self, config: Self::ConnectionConfig) -> Result<Self::TunnelHandle, AdapterError> {
        connect_with(config, &*deterium_net::system_platform())
    }

    fn disconnect(&self, mut handle: Self::TunnelHandle) -> Result<(), AdapterError> {
        handle.shutdown();
        Ok(())
    }

    fn status(&self, handle: &Self::TunnelHandle) -> TunnelStatus {
        *handle.shared.status.lock().expect("status mutex poisoned")
    }
}

/// [`ProtocolAdapter::connect`] against an explicit platform, so the whole
/// flow can run against a fake operating system in tests.
pub fn connect_with(
    config: WireGuardConnectionConfig,
    platform: &dyn Platform,
) -> Result<WireGuardTunnelHandle, AdapterError> {
    let mode = config.mode;

    // The adapter and routes come first: if they can't be set up (no admin
    // rights, no driver, would-loop routes) nothing else has been touched.
    let leak = leak_policy(&config);
    let leak_protection = leak.is_some();
    let network = match mode {
        ConnectMode::Full => {
            let spec = TunnelSpec {
                interface_addresses: config.interface_addresses.clone(),
                routed: config.allowed_ips.clone(),
                dns: config.dns.clone(),
                mtu: config.mtu,
                endpoint: config.endpoint.ip(),
                leak,
            };
            Some(bring_up(platform, ADAPTER_NAME, &spec).map_err(net_error)?)
        }
        ConnectMode::HandshakeOnly => None,
    };

    let endpoint = config.endpoint;
    let listen_port = config.listen_port;
    let open = move || open_socket(endpoint, listen_port);
    let socket = open()
        .map_err(|e| AdapterError::ConnectFailed(format!("open UDP socket to {endpoint}: {e}")))?;

    let tunn = Tunn::new(
        config.private_key,
        config.peer_public_key,
        config.preshared_key,
        config.keepalive,
        0,
        None,
    )
    .map_err(|e| AdapterError::ConnectFailed(format!("initialize noise tunnel: {e}")))?;

    let factory: SocketFactory = Box::new(open);
    let shared = Shared::new(
        tunn,
        socket,
        Some(factory),
        config.keepalive.is_some(),
        Policy::default(),
        AllowedIps::new(config.allowed_ips),
        network.as_ref().map(RoutedNetwork::tun),
    );
    let workers = pump::spawn(&shared);

    Ok(WireGuardTunnelHandle {
        shared,
        workers,
        network,
        mode,
        leak_protection: leak_protection && mode == ConnectMode::Full,
    })
}

/// Which firewall protection to ask for. DNS-leak blocking is only sensible
/// when the tunnel really carries the DNS servers; otherwise it would cut off
/// all name resolution for the rest of the PC.
fn leak_policy(config: &WireGuardConnectionConfig) -> Option<LeakPolicy> {
    let dns_through_tunnel = !config.dns.is_empty()
        && config.dns.iter().all(|server| {
            config
                .allowed_ips
                .iter()
                .any(|route| route.contains(*server))
        });

    let policy = LeakPolicy {
        kill_switch: config.security.kill_switch,
        allow_lan: config.security.allow_lan,
        block_dns_leaks: config.security.block_dns_leaks && dns_through_tunnel,
        servers: vec![deterium_net::Server::udp(config.endpoint)],
    };
    policy.is_active().then_some(policy)
}

/// A connected UDP socket to the server. A fixed local port is used when the
/// profile asks for one; if it can't be had (still held by the socket being
/// replaced, or taken by another program) a random port is used instead,
/// since staying connected matters more than the port number.
fn open_socket(endpoint: SocketAddr, listen_port: Option<u16>) -> std::io::Result<UdpSocket> {
    let any: IpAddr = if endpoint.is_ipv6() {
        Ipv6Addr::UNSPECIFIED.into()
    } else {
        Ipv4Addr::UNSPECIFIED.into()
    };
    let socket = match listen_port {
        Some(port) => UdpSocket::bind((any, port)).or_else(|_| UdpSocket::bind((any, 0)))?,
        None => UdpSocket::bind((any, 0))?,
    };
    socket.connect(endpoint)?;
    socket.set_read_timeout(Some(pump::POLL_INTERVAL))?;
    Ok(socket)
}

fn net_error(error: NetError) -> AdapterError {
    match error {
        NetError::NotElevated => AdapterError::PermissionRequired(
            "Deterium needs administrator rights to create the VPN adapter and routes".into(),
        ),
        other => AdapterError::ConnectFailed(other.to_string()),
    }
}

/// Generates a new WireGuard private key (base64), clamped as `wg genkey` does.
pub fn generate_private_key() -> Result<String, String> {
    let mut bytes = random_32()?;
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    Ok(STANDARD.encode(bytes))
}

/// Generates a 32-byte random preshared key (base64), as `wg genpsk` does.
pub fn generate_preshared_key() -> Result<String, String> {
    Ok(STANDARD.encode(random_32()?))
}

/// Derives the public key (base64) from a base64 private key.
pub fn public_key_from_private(private_key: &str) -> Result<String, String> {
    let secret = StaticSecret::from(decode_key(private_key)?);
    Ok(STANDARD.encode(PublicKey::from(&secret).as_bytes()))
}

fn random_32() -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("system randomness unavailable: {e}"))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use deterium_core::import::parse_wireguard_conf;
    use deterium_net::testing::FakePlatform;
    use std::time::Instant;

    const CONF: &str = "[Interface]\nPrivateKey = AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=\nAddress = 10.6.0.2/32\nDNS = 10.6.0.1\nMTU = 1380\n[Peer]\nPublicKey = hNB8xHQbFgfPavZ3NEhjv5+SRZ6TESr65wrlc71XuxA=\nEndpoint = 127.0.0.1:51999\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n";

    fn config(mode: ConnectMode) -> WireGuardConnectionConfig {
        let profile = parse_wireguard_conf(CONF, "t").unwrap().profile;
        let mut config = WireGuardAdapter.load_profile(&profile).unwrap();
        config.set_mode(mode);
        config
    }

    #[test]
    fn generated_keys_are_valid_and_unique() {
        let a = generate_private_key().unwrap();
        let b = generate_private_key().unwrap();
        assert_ne!(a, b);
        assert!(decode_key(&a).is_ok());
        assert_eq!(a.len(), 44);
    }

    #[test]
    fn public_key_matches_known_pair() {
        // Pair generated earlier for the VirtualBox test server's client.
        let public =
            public_key_from_private("AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=").unwrap();
        assert_eq!(public, "rJ7Pb5Ej25Q/LET9w856N4pej7pF4+UT7BSdLnfsKmo=");
    }

    #[test]
    fn generated_psk_decodes() {
        assert!(decode_key(&generate_preshared_key().unwrap()).is_ok());
    }

    #[test]
    fn load_profile_rejects_bad_routes_and_dns() {
        let mut profile = parse_wireguard_conf(CONF, "t").unwrap().profile;
        profile.wireguard.as_mut().unwrap().peer.allowed_ips = vec!["10.0.0.0/99".into()];
        assert!(WireGuardAdapter.load_profile(&profile).is_err());

        let mut profile = parse_wireguard_conf(CONF, "t").unwrap().profile;
        profile.wireguard.as_mut().unwrap().interface.dns = Some(vec!["not-an-ip".into()]);
        assert!(WireGuardAdapter.load_profile(&profile).is_err());
    }

    #[test]
    fn full_mode_without_administrator_rights_asks_for_them_and_changes_nothing() {
        let platform = FakePlatform::new(false);
        let result = connect_with(config(ConnectMode::Full), &platform);
        assert!(matches!(result, Err(AdapterError::PermissionRequired(_))));
        assert!(
            platform.entries().is_empty(),
            "no network change without rights"
        );
    }

    #[test]
    fn handshake_only_mode_never_touches_the_system_network() {
        let platform = FakePlatform::new(false);
        let handle = connect_with(config(ConnectMode::HandshakeOnly), &platform).unwrap();
        assert!(platform.entries().is_empty());
        assert_eq!(handle.mode(), ConnectMode::HandshakeOnly);
        WireGuardAdapter.disconnect(handle).unwrap();
    }

    #[test]
    fn full_mode_applies_the_network_and_disconnect_reverts_it() {
        let platform = FakePlatform::new(true);
        let handle = connect_with(config(ConnectMode::Full), &platform).unwrap();

        let applied = platform.entries();
        assert!(applied.iter().any(|e| e.starts_with("open_tun")));
        assert!(applied.iter().any(|e| e.contains("SetMtu(1380)")));
        assert!(applied.iter().any(|e| e.contains("SetDns")));
        assert!(
            applied.iter().any(|e| e.contains("BypassRoute")),
            "a full tunnel must keep the server reachable: {applied:?}"
        );
        assert!(!applied.iter().any(|e| e.starts_with("undo")));

        let started = Instant::now();
        WireGuardAdapter.disconnect(handle).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "disconnect must not hang"
        );

        let undos = platform
            .entries()
            .iter()
            .filter(|e| e.starts_with("undo"))
            .count();
        assert_eq!(
            undos, 5,
            "bypass + IPv4 and IPv6 default-route halves are reverted"
        );
    }

    #[test]
    fn dropping_a_handle_without_disconnect_still_reverts() {
        let platform = FakePlatform::new(true);
        let handle = connect_with(config(ConnectMode::Full), &platform).unwrap();
        drop(handle);
        assert!(platform.entries().iter().any(|e| e.starts_with("undo")));
    }

    fn config_with(kill_switch: bool, allowed_ips: &str, dns: &str) -> WireGuardConnectionConfig {
        let mut profile = parse_wireguard_conf(CONF, "t").unwrap().profile;
        {
            let wg = profile.wireguard.as_mut().unwrap();
            wg.peer.allowed_ips = vec![allowed_ips.into()];
            wg.interface.dns = Some(vec![dns.into()]);
        }
        profile.security.kill_switch = kill_switch;
        let mut config = WireGuardAdapter.load_profile(&profile).unwrap();
        config.set_mode(ConnectMode::Full);
        config
    }

    #[test]
    fn dns_leak_blocking_is_only_asked_for_when_the_tunnel_carries_the_dns() {
        // Full tunnel: DNS goes through it, so blocking DNS elsewhere is right.
        let full = leak_policy(&config_with(false, "0.0.0.0/0", "10.6.0.1")).unwrap();
        assert!(full.block_dns_leaks && !full.kill_switch);

        // Split tunnel whose DNS server is outside it: blocking DNS elsewhere
        // would cut off name resolution for the whole PC.
        assert!(leak_policy(&config_with(false, "10.7.0.0/24", "10.6.0.1")).is_none());
    }

    #[test]
    fn the_kill_switch_is_off_unless_the_profile_asks_for_it() {
        assert!(
            !leak_policy(&config_with(false, "0.0.0.0/0", "10.6.0.1"))
                .unwrap()
                .kill_switch
        );
        let on = leak_policy(&config_with(true, "10.7.0.0/24", "10.6.0.1")).unwrap();
        assert!(on.kill_switch);
        assert_eq!(
            on.servers[0].addr.port(),
            51999,
            "the server stays reachable"
        );
    }

    #[test]
    fn connecting_with_a_kill_switch_installs_it_and_disconnecting_lifts_it() {
        let platform = FakePlatform::new(true);
        let handle = connect_with(config_with(true, "10.6.0.0/24", "10.6.0.1"), &platform).unwrap();
        assert!(handle.leak_protection());
        assert!(platform
            .entries()
            .iter()
            .any(|e| e.starts_with("leak_guard on")));

        WireGuardAdapter.disconnect(handle).unwrap();
        assert!(platform.entries().iter().any(|e| e == "leak_guard off"));
    }

    #[test]
    fn the_handshake_test_mode_never_installs_firewall_rules() {
        let platform = FakePlatform::new(false);
        let mut config = config_with(true, "10.6.0.0/24", "10.6.0.1");
        config.set_mode(ConnectMode::HandshakeOnly);
        let handle = connect_with(config, &platform).unwrap();
        assert!(!handle.leak_protection());
        assert!(platform.entries().is_empty());
        WireGuardAdapter.disconnect(handle).unwrap();
    }
}
