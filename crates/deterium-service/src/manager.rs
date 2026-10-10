//! The service's brain: holds at most one tunnel and answers requests.
//! Knows nothing about pipes or the Service Control Manager, so it is tested
//! with a fake connector.

use deterium_core::{AdapterError, ConnectMode, ServerProfile, TunnelStatus, Uuid};
use deterium_engine::Tunnel;
use deterium_ipc::{
    ActiveTunnel, ErrorKind, Request, Response, ServiceStatus, WireStats, PROTOCOL_VERSION,
};
use std::sync::Mutex;
use std::time::Instant;

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
}

pub struct EngineConnector;

impl Connector for EngineConnector {
    fn connect(&self, profile: &ServerProfile) -> Result<Box<dyn Running>, AdapterError> {
        // Always a real tunnel: "test only" connections never need the service.
        deterium_engine::connect(profile, ConnectMode::Full)
            .map(|t| Box::new(t) as Box<dyn Running>)
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
}

pub struct Manager {
    connector: Box<dyn Connector>,
    active: Mutex<Option<Active>>,
}

impl Manager {
    pub fn new(connector: Box<dyn Connector>) -> Self {
        Self {
            connector,
            active: Mutex::new(None),
        }
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
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(previous) = active.take() {
            if let Err(err) = previous.tunnel.stop() {
                return Response::Error {
                    kind: ErrorKind::DisconnectFailed,
                    message: format!("couldn't stop the previous tunnel: {err}"),
                };
            }
        }

        match self.connector.connect(profile) {
            Ok(tunnel) => {
                *active = Some(Active {
                    profile_id: profile.id,
                    tunnel,
                    since: Instant::now(),
                });
                Response::Ok
            }
            Err(AdapterError::InvalidProfile(message)) => Response::Error {
                kind: ErrorKind::InvalidProfile,
                message,
            },
            Err(other) => Response::Error {
                kind: ErrorKind::ConnectFailed,
                message: other.to_string(),
            },
        }
    }

    fn disconnect(&self) -> Response {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        match active.take() {
            Some(current) => match current.tunnel.stop() {
                Ok(()) => Response::Ok,
                Err(err) => Response::Error {
                    kind: ErrorKind::DisconnectFailed,
                    message: err.to_string(),
                },
            },
            None => Response::Ok,
        }
    }

    pub fn status(&self) -> ServiceStatus {
        let active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        ServiceStatus {
            active: active.as_ref().map(|a| ActiveTunnel {
                profile_id: a.profile_id,
                status: a.tunnel.status(),
                uptime_secs: a.since.elapsed().as_secs(),
                stats: a.tunnel.stats(),
                leak_protection: a.tunnel.leak_protection(),
                log: a.tunnel.log(),
            }),
        }
    }

    /// Takes the tunnel down (the service is stopping).
    pub fn shutdown(&self) {
        let _ = self.disconnect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deterium_core::import::parse_wireguard_conf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const CONF: &str = "[Interface]\nPrivateKey = AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=\nAddress = 10.6.0.2/32\n[Peer]\nPublicKey = hNB8xHQbFgfPavZ3NEhjv5+SRZ6TESr65wrlc71XuxA=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n";

    #[derive(Default)]
    struct Counters {
        connected: AtomicUsize,
        stopped: AtomicUsize,
    }

    struct FakeTunnel(Arc<Counters>);

    impl Running for FakeTunnel {
        fn status(&self) -> TunnelStatus {
            TunnelStatus::Connected
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

    struct FakeConnector {
        counters: Arc<Counters>,
        fail_with: Option<fn() -> AdapterError>,
    }

    impl Connector for FakeConnector {
        fn connect(&self, _: &ServerProfile) -> Result<Box<dyn Running>, AdapterError> {
            if let Some(fail) = self.fail_with {
                return Err(fail());
            }
            self.counters.connected.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FakeTunnel(self.counters.clone())))
        }
    }

    fn manager(fail_with: Option<fn() -> AdapterError>) -> (Manager, Arc<Counters>) {
        let counters = Arc::new(Counters::default());
        let manager = Manager::new(Box::new(FakeConnector {
            counters: counters.clone(),
            fail_with,
        }));
        (manager, counters)
    }

    fn profile(name: &str) -> Box<ServerProfile> {
        Box::new(parse_wireguard_conf(CONF, name).unwrap().profile)
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
        manager.shutdown();
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
}
