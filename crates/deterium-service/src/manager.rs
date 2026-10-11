//! The service's brain: holds at most one tunnel and answers requests.
//! Knows nothing about pipes or the Service Control Manager, so it is tested
//! with a fake connector, a fake firewall and an in-memory note.
//!
//! It also keeps the kill switch *armed*: once a tunnel with the kill switch
//! has come up, a restart of the service (a reboot, a crash) puts the network
//! on hold until the user connects again or turns the protection off. See
//! [`crate::armed`].

use crate::armed::{ArmedState, ArmedStore, Blocker, FileStore, NetBlocker};
use deterium_core::{AdapterError, ConnectMode, ServerProfile, TunnelStatus, Uuid};
use deterium_engine::{Server, Tunnel};
use deterium_ipc::{
    ActiveTunnel, ErrorKind, Request, Response, ServiceStatus, WireStats, PROTOCOL_VERSION,
};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// A tunnel as the manager sees it.
pub trait Running: Send {
    fn status(&self) -> TunnelStatus;
    fn stats(&self) -> Option<WireStats>;
    fn leak_protection(&self) -> bool;
    fn log(&self) -> Vec<String>;
    fn stop(self: Box<Self>) -> Result<(), AdapterError>;
}

/// Starts tunnels. The real one is [`EngineConnector`].
pub trait Connector: Send + Sync {
    fn connect(&self, profile: &ServerProfile) -> Result<Box<dyn Running>, AdapterError>;

    /// The servers the profile's tunnel must reach from outside the tunnel,
    /// names resolved now. Empty when they can't be worked out.
    fn guard_servers(&self, _profile: &ServerProfile) -> Vec<Server> {
        Vec::new()
    }
}

pub struct EngineConnector;

impl Connector for EngineConnector {
    fn connect(&self, profile: &ServerProfile) -> Result<Box<dyn Running>, AdapterError> {
        // Always a real tunnel: "test only" connections never need the service.
        deterium_engine::connect(profile, ConnectMode::Full)
            .map(|t| Box::new(t) as Box<dyn Running>)
    }

    fn guard_servers(&self, profile: &ServerProfile) -> Vec<Server> {
        deterium_engine::guard_servers(profile)
    }
}

impl Running for Tunnel {
    fn status(&self) -> TunnelStatus {
        Tunnel::status(self)
    }

    fn stats(&self) -> Option<WireStats> {
        Tunnel::stats(self).map(|s| WireStats {
            rx_bytes: s.rx_bytes,
            tx_bytes: s.tx_bytes,
            last_handshake_secs: s.last_handshake.map(|d| d.as_secs()),
        })
    }

    fn leak_protection(&self) -> bool {
        Tunnel::leak_protection(self)
    }

    fn log(&self) -> Vec<String> {
        Tunnel::log(self)
    }

    fn stop(self: Box<Self>) -> Result<(), AdapterError> {
        (*self).disconnect()
    }
}

struct Active {
    profile_id: Uuid,
    tunnel: Box<dyn Running>,
    since: Instant,
    /// Becomes the armed state once the tunnel has really come up. Arming at
    /// the moment of the request would block the PC after a reboot for a
    /// connection that never worked (wrong password, dead server).
    pending_arm: Option<ArmedState>,
}

/// The kill switch is armed: the note is on disk and, while no tunnel is up,
/// `hold` blocks the network.
struct Armed {
    state: ArmedState,
    /// `None` while a tunnel carries its own rules, or when the hold could not
    /// be installed (then it is retried).
    hold: Option<Box<dyn Send>>,
    next_retry: Instant,
}

#[derive(Default)]
struct Inner {
    active: Option<Active>,
    armed: Option<Armed>,
}

pub struct Manager {
    connector: Box<dyn Connector>,
    store: Box<dyn ArmedStore>,
    blocker: Box<dyn Blocker>,
    log: Box<dyn Fn(&str) + Send + Sync>,
    /// How soon a hold that failed to install is tried again.
    retry_every: Duration,
    inner: Mutex<Inner>,
}

impl Manager {
    /// The real service: the note in the install folder, the real firewall.
    pub fn new(connector: Box<dyn Connector>) -> Self {
        Self::with_parts(
            connector,
            Box::new(FileStore::standard()),
            Box::new(NetBlocker),
            Box::new(crate::log),
            Duration::from_secs(2),
        )
    }

    pub fn with_parts(
        connector: Box<dyn Connector>,
        store: Box<dyn ArmedStore>,
        blocker: Box<dyn Blocker>,
        log: Box<dyn Fn(&str) + Send + Sync>,
        retry_every: Duration,
    ) -> Self {
        Self {
            connector,
            store,
            blocker,
            log,
            retry_every,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn handle(&self, request: Request) -> Response {
        match request {
            Request::Hello => Response::Hello {
                protocol: PROTOCOL_VERSION,
                service_version: env!("CARGO_PKG_VERSION").to_string(),
            },
            Request::Connect { profile } => self.connect(&profile),
            Request::Disconnect => self.disconnect(),
            Request::Status => Response::Status(self.status()),
        }
    }

    /// Call once at start, before answering anyone: if the kill switch was
    /// armed when the service last ran, put the network on hold right away.
    /// Returns whether it was armed.
    pub fn restore(&self) -> bool {
        let Some(state) = self.store.load() else {
            return false;
        };
        let hold = self
            .blocker
            .block(state.servers(), state.allow_lan, false)
            .inspect_err(|why| {
                (self.log)(&format!(
                    "couldn't put the network on hold ({why}); will keep trying"
                ));
            })
            .ok();
        (self.log)(&format!(
            "the kill switch was armed: {}",
            if hold.is_some() {
                "traffic is blocked except to the VPN server until you connect or turn it off"
            } else {
                "waiting for the firewall"
            }
        ));
        self.lock().armed = Some(Armed {
            state,
            hold,
            next_retry: Instant::now() + self.retry_every,
        });
        true
    }

    /// Housekeeping, called a few times a second by the service loop: arms the
    /// kill switch once a tunnel is really up, and retries a hold that could
    /// not be installed.
    pub fn tick(&self) {
        let mut inner = self.lock();

        let promote = match inner.active.as_mut() {
            Some(active) if active.tunnel.status() == TunnelStatus::Connected => {
                active.pending_arm.take()
            }
            _ => None,
        };
        if let Some(state) = promote {
            match self.store.save(&state) {
                Ok(()) => (self.log)("the kill switch is armed: it will hold after a restart"),
                Err(err) => (self.log)(&format!(
                    "couldn't remember the kill switch for the next start: {err}"
                )),
            }
            inner.armed = Some(Armed {
                state,
                hold: None,
                next_retry: Instant::now(),
            });
        }

        if inner.active.is_none() {
            if let Some(armed) = inner.armed.as_mut() {
                if armed.hold.is_none() && Instant::now() >= armed.next_retry {
                    match self
                        .blocker
                        .block(armed.state.servers(), armed.state.allow_lan, false)
                    {
                        Ok(guard) => {
                            armed.hold = Some(guard);
                            (self.log)("the network is on hold now");
                        }
                        Err(_) => armed.next_retry = Instant::now() + self.retry_every,
                    }
                }
            }
        }
    }

    /// Replaces the hold with one that also permits `extra` servers and, for a
    /// connection being set up, DNS. The new rules go in before the old ones
    /// leave, so there is never a moment without any. If they can't be
    /// installed the old hold stays.
    fn rehold(&self, armed: &mut Armed, allow_dns_lookup: bool, extra: &[Server]) {
        let mut servers = armed.state.servers();
        for server in extra {
            if !servers.contains(server) {
                servers.push(*server);
            }
        }
        match self
            .blocker
            .block(servers, armed.state.allow_lan, allow_dns_lookup)
        {
            Ok(guard) => armed.hold = Some(guard),
            Err(why) => (self.log)(&format!("couldn't adjust the network hold: {why}")),
        }
    }

    /// Forgets the armed state and gives the network back.
    fn disarm(&self, inner: &mut Inner) {
        inner.armed = None;
        if let Err(err) = self.store.clear() {
            (self.log)(&format!("couldn't remove the kill switch note: {err}"));
        }
    }

    fn connect(&self, profile: &ServerProfile) -> Response {
        let problems = profile.check();
        if !problems.is_empty() {
            let message = problems
                .iter()
                .map(|p| format!("{}: {}", p.field, p.message))
                .collect::<Vec<_>>()
                .join("; ");
            return Response::Error {
                kind: ErrorKind::InvalidProfile,
                message,
            };
        }

        // The lock is held for the whole switch, so two clients can't
        // interleave a disconnect and a connect.
        let mut inner = self.lock();

        // Armed: keep the network held (DNS open, so the new connection can
        // find its server) before anything else changes, so swapping tunnels
        // is not a gap.
        if let Some(armed) = inner.armed.as_mut() {
            self.rehold(armed, true, &[]);
        }

        if let Some(previous) = inner.active.take() {
            if let Err(err) = previous.tunnel.stop() {
                if let Some(armed) = inner.armed.as_mut() {
                    self.rehold(armed, false, &[]);
                }
                return Response::Error {
                    kind: ErrorKind::DisconnectFailed,
                    message: format!("couldn't stop the previous tunnel: {err}"),
                };
            }
        }

        // Where the new tunnel connects to has to be known now, while names
        // still resolve outside any tunnel.
        let kill_switch = profile.security.kill_switch;
        let servers = if kill_switch {
            self.connector.guard_servers(profile)
        } else {
            Vec::new()
        };
        if let Some(armed) = inner.armed.as_mut() {
            self.rehold(armed, true, &servers);
        }

        match self.connector.connect(profile) {
            Ok(tunnel) => {
                let pending_arm = (kill_switch && !servers.is_empty())
                    .then(|| ArmedState::new(profile.id, profile.security.allow_lan, &servers));
                if pending_arm.is_none() {
                    if kill_switch {
                        (self.log)(
                            "couldn't work out the VPN server's address, so the kill switch will not hold after a restart",
                        );
                    }
                    // This connection has no kill switch: nothing to keep armed.
                    self.disarm(&mut inner);
                } else if let Some(armed) = inner.armed.as_mut() {
                    // The tunnel's own rules take over from the hold.
                    armed.hold = None;
                }
                inner.active = Some(Active {
                    profile_id: profile.id,
                    tunnel,
                    since: Instant::now(),
                    pending_arm,
                });
                Response::Ok
            }
            Err(err) => {
                // Still armed (the user's kill switch has not been turned
                // off): go back to the strict hold.
                if let Some(armed) = inner.armed.as_mut() {
                    self.rehold(armed, false, &[]);
                }
                match err {
                    AdapterError::InvalidProfile(message) => Response::Error {
                        kind: ErrorKind::InvalidProfile,
                        message,
                    },
                    other => Response::Error {
                        kind: ErrorKind::ConnectFailed,
                        message: other.to_string(),
                    },
                }
            }
        }
    }

    /// Takes the tunnel down and turns the kill switch off: this is the one
    /// way the user gives the network back after a restart.
    fn disconnect(&self) -> Response {
        let mut inner = self.lock();
        let stopped = inner.active.take().map(|current| current.tunnel.stop());
        self.disarm(&mut inner);
        match stopped {
            Some(Err(err)) => Response::Error {
                kind: ErrorKind::DisconnectFailed,
                message: err.to_string(),
            },
            _ => Response::Ok,
        }
    }

    pub fn status(&self) -> ServiceStatus {
        let inner = self.lock();
        ServiceStatus {
            active: inner.active.as_ref().map(|a| ActiveTunnel {
                profile_id: a.profile_id,
                status: a.tunnel.status(),
                uptime_secs: a.since.elapsed().as_secs(),
                stats: a.tunnel.stats(),
                leak_protection: a.tunnel.leak_protection(),
                log: a.tunnel.log(),
            }),
            armed: inner.armed.as_ref().map(|a| a.state.profile_id),
        }
    }

    /// Takes the tunnel down because the service is stopping. `disarm` is for
    /// a stop somebody asked for; when Windows itself is shutting down the
    /// note is kept, so the next boot starts with the network on hold.
    pub fn shutdown(&self, disarm: bool) {
        let mut inner = self.lock();
        if let Some(current) = inner.active.take() {
            let _ = current.tunnel.stop();
        }
        if disarm {
            self.disarm(&mut inner);
        } else {
            inner.armed = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deterium_core::import::parse_wireguard_conf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    const CONF: &str = "[Interface]\nPrivateKey = AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=\nAddress = 10.6.0.2/32\n[Peer]\nPublicKey = hNB8xHQbFgfPavZ3NEhjv5+SRZ6TESr65wrlc71XuxA=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n";

    #[derive(Default)]
    struct Counters {
        connected: AtomicUsize,
        stopped: AtomicUsize,
        /// What the fake tunnels report.
        coming_up: AtomicBool,
    }

    struct FakeTunnel(Arc<Counters>);

    impl Running for FakeTunnel {
        fn status(&self) -> TunnelStatus {
            if self.0.coming_up.load(Ordering::SeqCst) {
                TunnelStatus::Connecting
            } else {
                TunnelStatus::Connected
            }
        }
        fn stats(&self) -> Option<WireStats> {
            None
        }
        fn leak_protection(&self) -> bool {
            true
        }
        fn log(&self) -> Vec<String> {
            Vec::new()
        }
        fn stop(self: Box<Self>) -> Result<(), AdapterError> {
            self.0.stopped.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn server() -> Server {
        Server::udp("1.2.3.4:51820".parse().unwrap())
    }

    struct FakeConnector {
        counters: Arc<Counters>,
        fail_with: Option<fn() -> AdapterError>,
        servers: Vec<Server>,
    }

    impl Connector for FakeConnector {
        fn connect(&self, _: &ServerProfile) -> Result<Box<dyn Running>, AdapterError> {
            if let Some(fail) = self.fail_with {
                return Err(fail());
            }
            self.counters.connected.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FakeTunnel(self.counters.clone())))
        }

        fn guard_servers(&self, _: &ServerProfile) -> Vec<Server> {
            self.servers.clone()
        }
    }

    /// The note in memory.
    #[derive(Clone, Default)]
    struct MemStore(Arc<Mutex<Option<ArmedState>>>);

    impl ArmedStore for MemStore {
        fn load(&self) -> Option<ArmedState> {
            self.0.lock().unwrap().clone()
        }
        fn save(&self, state: &ArmedState) -> std::io::Result<()> {
            *self.0.lock().unwrap() = Some(state.clone());
            Ok(())
        }
        fn clear(&self) -> std::io::Result<()> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    /// One call to the fake firewall: how many servers, whether DNS was open.
    type Call = (usize, bool);

    /// A firewall that records its calls and counts the holds still alive.
    #[derive(Clone, Default)]
    struct FakeBlocker {
        calls: Arc<Mutex<Vec<Call>>>,
        alive: Arc<AtomicUsize>,
        failing: Arc<AtomicBool>,
    }

    struct Hold(Arc<AtomicUsize>);
    impl Drop for Hold {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl Blocker for FakeBlocker {
        fn block(
            &self,
            servers: Vec<Server>,
            _allow_lan: bool,
            allow_dns_lookup: bool,
        ) -> Result<Box<dyn Send>, String> {
            if self.failing.load(Ordering::SeqCst) {
                return Err("firewall not ready".into());
            }
            self.calls
                .lock()
                .unwrap()
                .push((servers.len(), allow_dns_lookup));
            self.alive.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Hold(self.alive.clone())))
        }
    }

    struct Rig {
        manager: Manager,
        counters: Arc<Counters>,
        store: MemStore,
        blocker: FakeBlocker,
    }

    fn rig_with(
        fail_with: Option<fn() -> AdapterError>,
        servers: Vec<Server>,
        store: MemStore,
    ) -> Rig {
        let counters = Arc::new(Counters::default());
        let blocker = FakeBlocker::default();
        let manager = Manager::with_parts(
            Box::new(FakeConnector {
                counters: counters.clone(),
                fail_with,
                servers,
            }),
            Box::new(store.clone()),
            Box::new(blocker.clone()),
            Box::new(|_| {}),
            Duration::ZERO,
        );
        Rig {
            manager,
            counters,
            store,
            blocker,
        }
    }

    fn rig() -> Rig {
        rig_with(None, vec![server()], MemStore::default())
    }

    fn manager(fail_with: Option<fn() -> AdapterError>) -> (Manager, Arc<Counters>) {
        let rig = rig_with(fail_with, vec![server()], MemStore::default());
        (rig.manager, rig.counters)
    }

    fn profile(name: &str) -> Box<ServerProfile> {
        Box::new(parse_wireguard_conf(CONF, name).unwrap().profile)
    }

    fn protected(name: &str) -> Box<ServerProfile> {
        let mut p = profile(name);
        p.security.kill_switch = true;
        p
    }

    fn active_id(manager: &Manager) -> Option<Uuid> {
        manager.status().active.map(|a| a.profile_id)
    }

    #[test]
    fn connect_then_status_then_disconnect() {
        let (manager, counters) = manager(None);
        assert_eq!(active_id(&manager), None);

        let p = profile("a");
        let id = p.id;
        assert!(matches!(
            manager.handle(Request::Connect { profile: p }),
            Response::Ok
        ));
        let status = manager.status().active.unwrap();
        assert_eq!(status.profile_id, id);
        assert_eq!(status.status, TunnelStatus::Connected);
        assert!(status.leak_protection);

        assert!(matches!(manager.handle(Request::Disconnect), Response::Ok));
        assert_eq!(active_id(&manager), None);
        assert_eq!(counters.stopped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn connecting_another_server_replaces_the_first_one() {
        let (manager, counters) = manager(None);
        let (a, b) = (profile("a"), profile("b"));
        let b_id = b.id;
        manager.handle(Request::Connect { profile: a });
        manager.handle(Request::Connect { profile: b });

        assert_eq!(active_id(&manager), Some(b_id));
        assert_eq!(counters.connected.load(Ordering::SeqCst), 2);
        assert_eq!(
            counters.stopped.load(Ordering::SeqCst),
            1,
            "the first tunnel must be torn down, not leaked"
        );
    }

    #[test]
    fn disconnect_with_nothing_up_is_fine() {
        let (manager, counters) = manager(None);
        assert!(matches!(manager.handle(Request::Disconnect), Response::Ok));
        assert_eq!(counters.stopped.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_incomplete_profile_is_refused_before_anything_is_touched() {
        let (manager, counters) = manager(None);
        let mut p = profile("a");
        p.name = String::new();
        match manager.handle(Request::Connect { profile: p }) {
            Response::Error { kind, message } => {
                assert_eq!(kind, ErrorKind::InvalidProfile);
                assert!(message.contains("name"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(counters.connected.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_failed_connect_leaves_nothing_active_and_reports_why() {
        let (manager, _) = manager(Some(|| AdapterError::ConnectFailed("no route".into())));
        match manager.handle(Request::Connect {
            profile: profile("a"),
        }) {
            Response::Error { kind, message } => {
                assert_eq!(kind, ErrorKind::ConnectFailed);
                assert!(message.contains("no route"));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(active_id(&manager), None);
    }

    #[test]
    fn shutdown_takes_the_tunnel_down() {
        let (manager, counters) = manager(None);
        manager.handle(Request::Connect {
            profile: profile("a"),
        });
        manager.shutdown(true);
        assert_eq!(counters.stopped.load(Ordering::SeqCst), 1);
        assert_eq!(active_id(&manager), None);
    }

    #[test]
    fn hello_reports_the_protocol_version() {
        let (manager, _) = manager(None);
        match manager.handle(Request::Hello) {
            Response::Hello { protocol, .. } => assert_eq!(protocol, PROTOCOL_VERSION),
            other => panic!("{other:?}"),
        }
    }

    // --- the armed kill switch -------------------------------------------

    #[test]
    fn a_tunnel_with_the_kill_switch_is_armed_only_once_it_is_really_up() {
        let rig = rig();
        rig.counters.coming_up.store(true, Ordering::SeqCst);
        rig.manager.handle(Request::Connect {
            profile: protected("a"),
        });
        rig.manager.tick();
        assert_eq!(
            rig.store.load(),
            None,
            "still connecting: nothing to hold yet"
        );
        assert_eq!(rig.manager.status().armed, None);

        rig.counters.coming_up.store(false, Ordering::SeqCst);
        rig.manager.tick();
        let note = rig.store.load().expect("armed once connected");
        assert_eq!(note.servers().len(), 1);
        assert_eq!(rig.manager.status().armed, Some(note.profile_id));
        assert_eq!(
            rig.blocker.alive.load(Ordering::SeqCst),
            0,
            "while the tunnel is up its own rules protect; no second hold"
        );
    }

    #[test]
    fn a_profile_without_the_kill_switch_is_never_armed() {
        let rig = rig();
        rig.manager.handle(Request::Connect {
            profile: profile("a"),
        });
        rig.manager.tick();
        assert_eq!(rig.store.load(), None);
        assert_eq!(rig.manager.status().armed, None);
    }

    #[test]
    fn without_a_known_server_there_is_nothing_to_hold_open_so_it_is_not_armed() {
        let rig = rig_with(None, vec![], MemStore::default());
        rig.manager.handle(Request::Connect {
            profile: protected("a"),
        });
        rig.manager.tick();
        assert_eq!(rig.store.load(), None);
    }

    #[test]
    fn after_a_restart_the_network_is_on_hold_before_anyone_connects() {
        let first = rig();
        first.manager.handle(Request::Connect {
            profile: protected("a"),
        });
        first.manager.tick();
        let id = first.store.load().unwrap().profile_id;

        // "Reboot": a new service with the same note and nothing else.
        let second = rig_with(None, vec![server()], first.store.clone());
        assert!(second.manager.restore());
        assert_eq!(second.blocker.alive.load(Ordering::SeqCst), 1);
        assert_eq!(
            *second.blocker.calls.lock().unwrap(),
            vec![(1, false)],
            "the VPN server is let through, DNS is not"
        );
        let status = second.manager.status();
        assert_eq!(status.active, None);
        assert_eq!(status.armed, Some(id));
    }

    #[test]
    fn nothing_is_held_when_nothing_was_armed() {
        let rig = rig();
        assert!(!rig.manager.restore());
        assert_eq!(rig.blocker.alive.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn turning_it_off_gives_the_network_back_and_forgets_the_note() {
        let store = MemStore::default();
        store
            .save(&ArmedState::new(Uuid::new_v4(), true, &[server()]))
            .unwrap();
        let rig = rig_with(None, vec![server()], store);
        rig.manager.restore();
        assert_eq!(rig.blocker.alive.load(Ordering::SeqCst), 1);

        assert!(matches!(
            rig.manager.handle(Request::Disconnect),
            Response::Ok
        ));
        assert_eq!(rig.blocker.alive.load(Ordering::SeqCst), 0);
        assert_eq!(rig.store.load(), None);
        assert_eq!(rig.manager.status().armed, None);
    }

    #[test]
    fn disconnecting_a_running_tunnel_also_disarms_it() {
        let rig = rig();
        rig.manager.handle(Request::Connect {
            profile: protected("a"),
        });
        rig.manager.tick();
        assert!(rig.store.load().is_some());
        rig.manager.handle(Request::Disconnect);
        assert_eq!(rig.store.load(), None);
        assert_eq!(rig.manager.status().armed, None);
    }

    #[test]
    fn connecting_from_the_hold_opens_dns_only_for_the_attempt() {
        let store = MemStore::default();
        store
            .save(&ArmedState::new(Uuid::new_v4(), true, &[server()]))
            .unwrap();
        let rig = rig_with(None, vec![server()], store);
        rig.manager.restore();

        rig.manager.handle(Request::Connect {
            profile: protected("a"),
        });
        let calls = rig.blocker.calls.lock().unwrap().clone();
        assert!(
            calls.iter().any(|&(_, dns)| dns),
            "the new connection must be able to look up its server: {calls:?}"
        );
        assert_eq!(
            rig.blocker.alive.load(Ordering::SeqCst),
            0,
            "once the tunnel is up its own rules take over from the hold"
        );
        assert!(rig.store.load().is_some(), "still armed");
    }

    #[test]
    fn a_failed_attempt_from_the_hold_goes_back_to_the_strict_hold_and_stays_armed() {
        let store = MemStore::default();
        store
            .save(&ArmedState::new(Uuid::new_v4(), true, &[server()]))
            .unwrap();
        let rig = rig_with(
            Some(|| AdapterError::ConnectFailed("down".into())),
            vec![server()],
            store,
        );
        rig.manager.restore();
        rig.manager.handle(Request::Connect {
            profile: protected("a"),
        });

        assert_eq!(rig.blocker.alive.load(Ordering::SeqCst), 1);
        assert!(
            !rig.blocker.calls.lock().unwrap().last().copied().unwrap().1,
            "DNS is closed again"
        );
        assert!(
            rig.store.load().is_some(),
            "a failed attempt is not a turn-off"
        );
        assert!(rig.manager.status().armed.is_some());
    }

    #[test]
    fn switching_to_a_profile_without_the_kill_switch_disarms() {
        let rig = rig();
        rig.manager.handle(Request::Connect {
            profile: protected("a"),
        });
        rig.manager.tick();
        assert!(rig.store.load().is_some());

        rig.manager.handle(Request::Connect {
            profile: profile("b"),
        });
        assert_eq!(rig.store.load(), None);
        assert_eq!(rig.manager.status().armed, None);
    }

    #[test]
    fn a_hold_that_could_not_be_installed_is_retried() {
        let store = MemStore::default();
        store
            .save(&ArmedState::new(Uuid::new_v4(), true, &[server()]))
            .unwrap();
        let rig = rig_with(None, vec![server()], store);
        rig.blocker.failing.store(true, Ordering::SeqCst);
        assert!(
            rig.manager.restore(),
            "armed even though the firewall isn't ready"
        );
        assert_eq!(rig.blocker.alive.load(Ordering::SeqCst), 0);

        rig.manager.tick();
        assert_eq!(rig.blocker.alive.load(Ordering::SeqCst), 0, "still failing");

        rig.blocker.failing.store(false, Ordering::SeqCst);
        rig.manager.tick();
        assert_eq!(rig.blocker.alive.load(Ordering::SeqCst), 1);
        rig.manager.tick();
        assert_eq!(
            rig.blocker.alive.load(Ordering::SeqCst),
            1,
            "no second hold"
        );
    }

    #[test]
    fn an_asked_for_stop_disarms_but_a_windows_shutdown_keeps_the_note() {
        let rig = rig();
        rig.manager.handle(Request::Connect {
            profile: protected("a"),
        });
        rig.manager.tick();
        rig.manager.shutdown(false);
        assert!(
            rig.store.load().is_some(),
            "the next boot must start with the network on hold"
        );

        let rig2 = rig_with(None, vec![server()], rig.store.clone());
        rig2.manager.restore();
        rig2.manager.shutdown(true);
        assert_eq!(rig2.store.load(), None);
        assert_eq!(rig2.blocker.alive.load(Ordering::SeqCst), 0);
    }
}
