//! The WireGuard data plane: moves packets between the virtual adapter and
//! the network socket, encrypting one way and decrypting (and filtering) the
//! other, while `boringtun` runs the handshake, rekeying and keepalives.
//!
//! Generic over [`TunDevice`], so the same code runs against a real Wintun
//! adapter and against an in-memory one in tests. With no adapter it is
//! "handshake only": it still talks to the server but forwards no traffic.
//!
//! It also watches the connection's health ([`crate::health`]): when the
//! server stops answering the status drops to `Reconnecting`, handshakes are
//! retried, and the UDP socket is replaced so a network change can't leave
//! the tunnel talking into a dead socket.

use crate::health::{assess, should_probe, Health, Observation, Policy};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use deterium_core::TunnelStatus;
use deterium_net::{AllowedIps, TunDevice};
use std::io::{self, ErrorKind};
use std::net::{IpAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Large enough for a jumbo packet plus WireGuard's framing overhead.
const BUF_SIZE: usize = 65_536 + 128;
const NO_HANDSHAKE: u64 = u64::MAX;

/// Opens a fresh, connected UDP socket to the server.
pub(crate) type SocketFactory = Box<dyn Fn() -> io::Result<UdpSocket> + Send + Sync>;

/// Plaintext bytes carried through the tunnel (what a user would call
/// "downloaded"/"uploaded"), not WireGuard framing overhead.
#[derive(Default)]
pub(crate) struct Counters {
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    /// How many times the socket was replaced after the server went quiet.
    pub rebinds: AtomicU64,
    /// Milliseconds since the last completed handshake, or `NO_HANDSHAKE`.
    last_handshake_ms: AtomicU64,
}

impl Counters {
    fn new() -> Self {
        Self {
            last_handshake_ms: AtomicU64::new(NO_HANDSHAKE),
            ..Default::default()
        }
    }

    pub fn last_handshake(&self) -> Option<Duration> {
        match self.last_handshake_ms.load(Ordering::Relaxed) {
            NO_HANDSHAKE => None,
            ms => Some(Duration::from_millis(ms)),
        }
    }
}

pub(crate) struct Shared {
    tunn: Mutex<Tunn>,
    socket: Mutex<Arc<UdpSocket>>,
    factory: Option<SocketFactory>,
    keepalive: bool,
    policy: Policy,
    pub status: Mutex<TunnelStatus>,
    pub shutdown: AtomicBool,
    /// Set when something unrecoverable happened (the adapter vanished).
    failed: AtomicBool,
    pub counters: Counters,
    /// Source addresses the server is allowed to use for packets it sends us.
    allowed: AllowedIps,
    tun: Option<Arc<dyn TunDevice>>,
}

impl Shared {
    pub fn new(
        tunn: Tunn,
        socket: UdpSocket,
        factory: Option<SocketFactory>,
        keepalive: bool,
        policy: Policy,
        allowed: AllowedIps,
        tun: Option<Arc<dyn TunDevice>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            tunn: Mutex::new(tunn),
            socket: Mutex::new(Arc::new(socket)),
            factory,
            keepalive,
            policy,
            status: Mutex::new(TunnelStatus::Connecting),
            shutdown: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            counters: Counters::new(),
            allowed,
            tun,
        })
    }

    pub fn set_status(&self, status: TunnelStatus) {
        *self.status.lock().expect("status mutex poisoned") = status;
    }

    fn stopping(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    fn socket(&self) -> Arc<UdpSocket> {
        self.socket.lock().expect("socket mutex poisoned").clone()
    }

    fn send(&self, packet: &[u8]) {
        // UDP is best effort; WireGuard retransmits handshakes by itself.
        let _ = self.socket().send(packet);
    }

    /// Replaces the socket with a fresh one. Returns whether it worked.
    fn rebind(&self) -> bool {
        let Some(factory) = &self.factory else {
            return false;
        };
        match factory() {
            Ok(fresh) => {
                *self.socket.lock().expect("socket mutex poisoned") = Arc::new(fresh);
                self.counters.rebinds.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => false,
        }
    }
}

pub(crate) fn spawn(shared: &Arc<Shared>) -> Vec<JoinHandle<()>> {
    let mut workers = vec![thread::spawn({
        let shared = shared.clone();
        move || control_loop(&shared)
    })];
    if shared.tun.is_some() {
        workers.push(thread::spawn({
            let shared = shared.clone();
            move || outbound_loop(&shared)
        }));
    }
    workers
}

/// Network -> adapter: receives from the server, decrypts, filters by source
/// address and hands packets to the OS. Also drives handshakes, timers and
/// the connection-health state machine.
fn control_loop(shared: &Shared) {
    let mut out = vec![0u8; BUF_SIZE];
    let mut recv = vec![0u8; BUF_SIZE];

    {
        let mut tunn = shared.tunn.lock().expect("tunnel poisoned");
        if let TunnResult::WriteToNetwork(packet) =
            tunn.format_handshake_initiation(&mut out, false)
        {
            shared.send(packet);
        }
    }

    let started = Instant::now();
    let mut ever_connected = false;
    let mut last_probe = started;
    let mut last_rebind = started;

    while !shared.stopping() {
        match shared.socket().recv(&mut recv) {
            Ok(n) => handle_incoming(shared, &recv[..n], &mut out),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            // An ICMP "port unreachable" from an earlier send surfaces as a
            // recv error on a connected UDP socket (ConnectionReset on
            // Windows, ConnectionRefused elsewhere). It only means the server
            // isn't answering right now; health tracking handles that.
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::ConnectionReset | ErrorKind::ConnectionRefused
                ) => {}
            Err(_) => {
                // Anything else usually means the socket itself is bad (for
                // example after a network change); replace it.
                shared.rebind();
            }
        }

        let mut tunn = shared.tunn.lock().expect("tunnel poisoned");
        let expired = match tunn.update_timers(&mut out) {
            // Keepalives and handshake retransmissions come out of here.
            TunnResult::WriteToNetwork(packet) => {
                shared.send(packet);
                false
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => true,
            _ => false,
        };
        let age = tunn.time_since_last_handshake();
        let health = assess(
            &Observation {
                handshake_age: age,
                ever_connected,
                keepalive: shared.keepalive,
                expired,
            },
            &shared.policy,
        );

        shared.counters.last_handshake_ms.store(
            age.map_or(NO_HANDSHAKE, |a| a.as_millis() as u64),
            Ordering::Relaxed,
        );

        if !shared.failed.load(Ordering::Relaxed) {
            shared.set_status(match health {
                Health::Connecting => TunnelStatus::Connecting,
                Health::Healthy => TunnelStatus::Connected,
                Health::Reconnecting => TunnelStatus::Reconnecting,
            });
        }
        ever_connected |= health == Health::Healthy;

        if should_probe(
            health,
            shared.keepalive,
            age,
            last_probe.elapsed(),
            &shared.policy,
        ) {
            if let TunnResult::WriteToNetwork(packet) =
                tunn.format_handshake_initiation(&mut out, true)
            {
                shared.send(packet);
            }
            last_probe = Instant::now();
        }
        drop(tunn);

        if health != Health::Healthy && last_rebind.elapsed() >= shared.policy.rebind_every {
            shared.rebind();
            last_rebind = Instant::now();
        }
    }

    shared.set_status(TunnelStatus::Disconnected);
}

fn handle_incoming(shared: &Shared, datagram: &[u8], out: &mut [u8]) {
    let mut first = true;
    loop {
        // Only the first call carries the datagram; the follow-up calls with
        // an empty one flush packets boringtun queued (e.g. after a handshake).
        let input = if first { datagram } else { &[] };
        first = false;

        let result = {
            let mut tunn = shared.tunn.lock().expect("tunnel poisoned");
            tunn.decapsulate(None, input, out)
        };
        match result {
            TunnResult::Done => return,
            // A bad packet (wrong MAC, replayed counter, ...) is normal on the
            // open internet and says nothing about the tunnel's health.
            TunnResult::Err(_) => return,
            TunnResult::WriteToNetwork(packet) => shared.send(packet),
            TunnResult::WriteToTunnelV4(packet, src) => deliver(shared, packet, IpAddr::V4(src)),
            TunnResult::WriteToTunnelV6(packet, src) => deliver(shared, packet, IpAddr::V6(src)),
        }
    }
}

fn deliver(shared: &Shared, packet: &[u8], src: IpAddr) {
    let Some(tun) = &shared.tun else { return };
    // Cryptokey routing: drop anything claiming a source the server isn't
    // entitled to, so it can't inject traffic that pretends to be elsewhere.
    if !shared.allowed.contains(src) {
        return;
    }
    if tun.write_packet(packet).is_ok() {
        shared
            .counters
            .rx_bytes
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
    }
}

/// Adapter -> network: takes packets the OS routed into the tunnel and
/// encrypts them toward the server.
fn outbound_loop(shared: &Shared) {
    let Some(tun) = &shared.tun else { return };
    let mut packet = vec![0u8; BUF_SIZE];
    let mut out = vec![0u8; BUF_SIZE];

    while !shared.stopping() {
        let n = match tun.read_packet(&mut packet, POLL_INTERVAL) {
            Ok(Some(n)) => n,
            Ok(None) => continue,
            Err(_) => {
                // The adapter went away under us; nothing more can flow.
                shared.failed.store(true, Ordering::Relaxed);
                shared.set_status(TunnelStatus::Error);
                return;
            }
        };

        let mut tunn = shared.tunn.lock().expect("tunnel poisoned");
        match tunn.encapsulate(&packet[..n], &mut out) {
            TunnResult::WriteToNetwork(encrypted) => {
                shared.send(encrypted);
                shared
                    .counters
                    .tx_bytes
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
            // No session yet: boringtun queued the packet and sends it as soon
            // as the handshake completes, so it still counts as sent.
            TunnResult::Done => {
                shared
                    .counters
                    .tx_bytes
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::x25519::{PublicKey, StaticSecret};
    use deterium_net::{Cidr, FakeTun, FakeTunPeer};
    use std::net::SocketAddr;

    /// Fast timings so health transitions happen in a couple of seconds.
    const FAST: Policy = Policy {
        probe_after: Duration::from_millis(700),
        stale_after: Duration::from_millis(1_800),
        retry_every: Duration::from_millis(400),
        rebind_every: Duration::from_millis(500),
    };

    fn ipv4_packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = (20 + payload.len()) as u16;
        let mut p = vec![
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0,
            0,
            64,
            17,
            0,
            0,
        ];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(payload);
        p
    }

    struct Peer {
        shared: Arc<Shared>,
        workers: Vec<JoinHandle<()>>,
        os: FakeTunPeer,
    }

    impl Peer {
        fn stop(mut self) {
            self.shared.shutdown.store(true, Ordering::Relaxed);
            for w in self.workers.drain(..) {
                let _ = w.join();
            }
        }
    }

    fn secret(seed: u8) -> StaticSecret {
        StaticSecret::from([seed; 32])
    }

    fn allowed(list: &[&str]) -> AllowedIps {
        AllowedIps::new(list.iter().map(|c| Cidr::parse(c).unwrap()).collect())
    }

    fn connected_pair(client: &UdpSocket, server: &UdpSocket) {
        client.connect(server.local_addr().unwrap()).unwrap();
        server.connect(client.local_addr().unwrap()).unwrap();
        for s in [client, server] {
            s.set_read_timeout(Some(POLL_INTERVAL)).unwrap();
        }
    }

    /// One WireGuard peer with an in-memory adapter, on an existing socket.
    fn peer(
        key: StaticSecret,
        peer_pub: PublicKey,
        socket: UdpSocket,
        allowed_ips: AllowedIps,
        factory: Option<SocketFactory>,
        name: &str,
    ) -> Peer {
        let tunn = Tunn::new(key, peer_pub, None, Some(1), 0, None).unwrap();
        let (tun, os) = FakeTun::pair(name);
        let shared = Shared::new(tunn, socket, factory, true, FAST, allowed_ips, Some(tun));
        let workers = spawn(&shared);
        Peer {
            shared,
            workers,
            os,
        }
    }

    /// Two peers wired to each other over loopback UDP.
    fn pair(client_allowed: &[&str], server_allowed: &[&str]) -> (Peer, Peer) {
        let (client_key, server_key) = (secret(1), secret(2));
        let (client_pub, server_pub) = (PublicKey::from(&client_key), PublicKey::from(&server_key));
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        connected_pair(&client_socket, &server_socket);

        (
            peer(
                client_key,
                server_pub,
                client_socket,
                allowed(client_allowed),
                None,
                "client",
            ),
            peer(
                server_key,
                client_pub,
                server_socket,
                allowed(server_allowed),
                None,
                "server",
            ),
        )
    }

    fn wait_for(peer: &Peer, wanted: TunnelStatus, seconds: u64) {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        while *peer.shared.status.lock().unwrap() != wanted {
            assert!(
                Instant::now() < deadline,
                "never reached {wanted:?}; status is {:?}",
                *peer.shared.status.lock().unwrap()
            );
            thread::sleep(Duration::from_millis(30));
        }
    }

    #[test]
    fn ip_packets_cross_the_tunnel_in_both_directions() {
        let (client, server) = pair(&["10.66.66.0/24"], &["10.66.66.2/32"]);

        let request = ipv4_packet([10, 66, 66, 2], [10, 66, 66, 1], b"ping from the client");
        client.os.send(&request);
        let seen = server.os.recv_timeout(Duration::from_secs(10));
        assert_eq!(seen.as_deref(), Some(&request[..]), "client -> server");

        wait_for(&client, TunnelStatus::Connected, 10);
        let reply = ipv4_packet([10, 66, 66, 1], [10, 66, 66, 2], b"pong from the server");
        server.os.send(&reply);
        let seen = client.os.recv_timeout(Duration::from_secs(10));
        assert_eq!(seen.as_deref(), Some(&reply[..]), "server -> client");

        // The counters are bumped just after the packet is handed on, so the other
        // end can see the packet a moment before the count catches up.
        wait_for_count(
            &client.shared.counters.tx_bytes,
            request.len() as u64,
            "bytes sent",
        );
        wait_for_count(
            &client.shared.counters.rx_bytes,
            reply.len() as u64,
            "bytes received",
        );

        client.stop();
        server.stop();
    }

    /// Waits until `counter` reads exactly `wanted`, failing if it never does
    /// (or overshoots, which would mean a packet was counted twice).
    fn wait_for_count(counter: &AtomicU64, wanted: u64, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let now = counter.load(Ordering::Relaxed);
            if now == wanted {
                return;
            }
            assert!(
                now < wanted && Instant::now() < deadline,
                "{what}: expected {wanted}, counter reads {now}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn packets_with_a_source_the_peer_may_not_use_are_dropped() {
        // The server only lets this client use 10.66.66.2/32.
        let (client, server) = pair(&["10.66.66.0/24"], &["10.66.66.2/32"]);

        let spoofed = ipv4_packet(
            [10, 99, 99, 9],
            [10, 66, 66, 1],
            b"pretending to be elsewhere",
        );
        client.os.send(&spoofed);
        let legit = ipv4_packet([10, 66, 66, 2], [10, 66, 66, 1], b"legit");
        client.os.send(&legit);

        // Only the legitimate packet comes out the other side.
        let first = server.os.recv_timeout(Duration::from_secs(10));
        assert_eq!(first.as_deref(), Some(&legit[..]));
        assert!(server.os.recv_timeout(Duration::from_millis(700)).is_none());

        client.stop();
        server.stop();
    }

    #[test]
    fn handshake_only_mode_forwards_nothing_but_still_connects() {
        let (a, b) = (secret(5), secret(6));
        let (a_pub, b_pub) = (PublicKey::from(&a), PublicKey::from(&b));
        let sa = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sb = UdpSocket::bind("127.0.0.1:0").unwrap();
        connected_pair(&sa, &sb);

        let client = Shared::new(
            Tunn::new(a, b_pub, None, Some(1), 0, None).unwrap(),
            sa,
            None,
            true,
            FAST,
            AllowedIps::default(),
            None,
        );
        let server = Shared::new(
            Tunn::new(b, a_pub, None, Some(1), 0, None).unwrap(),
            sb,
            None,
            true,
            FAST,
            AllowedIps::default(),
            None,
        );
        let workers: Vec<_> = spawn(&client).into_iter().chain(spawn(&server)).collect();
        assert_eq!(workers.len(), 2, "no outbound thread without an adapter");

        let deadline = Instant::now() + Duration::from_secs(10);
        while *client.status.lock().unwrap() != TunnelStatus::Connected {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(50));
        }
        assert!(client.counters.last_handshake().is_some());

        for s in [&client, &server] {
            s.shutdown.store(true, Ordering::Relaxed);
        }
        for w in workers {
            let _ = w.join();
        }
    }

    #[test]
    fn a_server_that_goes_silent_is_noticed_and_recovery_is_automatic() {
        let (client_key, server_key) = (secret(1), secret(2));
        let (client_pub, server_pub) = (PublicKey::from(&client_key), PublicKey::from(&server_key));
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (client_addr, server_addr): (SocketAddr, SocketAddr) = (
            client_socket.local_addr().unwrap(),
            server_socket.local_addr().unwrap(),
        );
        connected_pair(&client_socket, &server_socket);

        let client = peer(
            client_key,
            server_pub,
            client_socket,
            allowed(&["10.66.66.0/24"]),
            None,
            "client",
        );
        let server = peer(
            server_key.clone(),
            client_pub,
            server_socket,
            allowed(&["10.66.66.2/32"]),
            None,
            "server",
        );
        wait_for(&client, TunnelStatus::Connected, 10);

        // The server disappears (machine off, Wi-Fi gone).
        server.stop();
        wait_for(&client, TunnelStatus::Reconnecting, 15);

        // It comes back on the same address; nobody tells the client.
        let revived_socket = UdpSocket::bind(server_addr).unwrap();
        revived_socket.connect(client_addr).unwrap();
        revived_socket
            .set_read_timeout(Some(POLL_INTERVAL))
            .unwrap();
        let revived = peer(
            server_key,
            client_pub,
            revived_socket,
            allowed(&["10.66.66.2/32"]),
            None,
            "server",
        );

        wait_for(&client, TunnelStatus::Connected, 15);
        // And it is genuinely usable again, not just labelled so.
        let packet = ipv4_packet([10, 66, 66, 2], [10, 66, 66, 1], b"after the outage");
        client.os.send(&packet);
        assert_eq!(
            revived.os.recv_timeout(Duration::from_secs(10)).as_deref(),
            Some(&packet[..])
        );

        client.stop();
        revived.stop();
    }

    #[test]
    fn the_socket_is_replaced_while_the_server_stays_silent() {
        // A port nobody listens on, to play the part of an unreachable server.
        let dead = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let make = move || {
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            socket.connect(dead_addr)?;
            socket.set_read_timeout(Some(POLL_INTERVAL))?;
            Ok(socket)
        };
        let client = peer(
            secret(1),
            PublicKey::from(&secret(2)),
            make().unwrap(),
            allowed(&["10.66.66.0/24"]),
            Some(Box::new(make)),
            "client",
        );

        let deadline = Instant::now() + Duration::from_secs(10);
        while client.shared.counters.rebinds.load(Ordering::Relaxed) < 2 {
            assert!(Instant::now() < deadline, "socket was never replaced");
            thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(
            *client.shared.status.lock().unwrap(),
            TunnelStatus::Connecting,
            "never reached the server, so it is still just connecting"
        );
        client.stop();
    }
}
