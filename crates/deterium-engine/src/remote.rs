//! A tunnel that lives in the background service. The app holds one of these
//! as its handle: it shows what the service reports and can ask it to
//! disconnect, but dropping it (closing the window) leaves the tunnel up.

use deterium_core::{AdapterError, ServerProfile, TunnelStatus, Uuid};
use deterium_ipc::{ActiveTunnel, Client, ErrorKind, IpcError, Request, Response, ServiceState};
use deterium_proto_wireguard::TunnelStats;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const POLL_EVERY: Duration = Duration::from_millis(400);

/// What the last poll of the service said.
#[derive(Default)]
struct Snapshot {
    active: Option<ActiveTunnel>,
    /// Set when the service stopped answering.
    lost_contact: bool,
}

pub struct RemoteTunnel {
    profile_id: Uuid,
    client: Client,
    snapshot: Arc<Mutex<Snapshot>>,
    stop: Arc<AtomicBool>,
    poller: Option<JoinHandle<()>>,
}

impl RemoteTunnel {
    fn watching(profile_id: Uuid, initial: Option<ActiveTunnel>) -> Self {
        let snapshot = Arc::new(Mutex::new(Snapshot {
            active: initial,
            lost_contact: false,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let poller = {
            let (snapshot, stop) = (snapshot.clone(), stop.clone());
            thread::spawn(move || {
                let client = Client::new();
                while !stop.load(Ordering::Relaxed) {
                    let reply = client.call(&Request::Status);
                    let mut shared = snapshot.lock().unwrap_or_else(|e| e.into_inner());
                    match reply {
                        Ok(Response::Status(status)) => {
                            shared.active = status.active;
                            shared.lost_contact = false;
                        }
                        _ => shared.lost_contact = true,
                    }
                    drop(shared);
                    thread::sleep(POLL_EVERY);
                }
            })
        };
        Self {
            profile_id,
            client: Client::new(),
            snapshot,
            stop,
            poller: Some(poller),
        }
    }

    fn mine(&self) -> Option<ActiveTunnel> {
        let shared = self.snapshot.lock().unwrap_or_else(|e| e.into_inner());
        shared
            .active
            .clone()
            .filter(|a| a.profile_id == self.profile_id)
    }

    pub fn profile_id(&self) -> Uuid {
        self.profile_id
    }

    pub fn status(&self) -> TunnelStatus {
        if self
            .snapshot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .lost_contact
        {
            return TunnelStatus::Error;
        }
        // Gone from the service (disconnected from elsewhere) reads as disconnected.
        self.mine().map_or(TunnelStatus::Disconnected, |a| a.status)
    }

    pub fn stats(&self) -> Option<TunnelStats> {
        self.mine().and_then(|a| a.stats).map(|s| TunnelStats {
            rx_bytes: s.rx_bytes,
            tx_bytes: s.tx_bytes,
            last_handshake: s.last_handshake_secs.map(Duration::from_secs),
        })
    }

    /// How long the service has held this tunnel.
    pub fn uptime(&self) -> Option<Duration> {
        self.mine().map(|a| Duration::from_secs(a.uptime_secs))
    }

    pub fn leak_protection(&self) -> bool {
        self.mine().is_some_and(|a| a.leak_protection)
    }

    pub fn log(&self) -> Vec<String> {
        let lost = self
            .snapshot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .lost_contact;
        let mut lines = self.mine().map(|a| a.log).unwrap_or_default();
        if lost {
            lines.push("lost contact with the Deterium background service".into());
        }
        lines
    }

    /// Asks the service to take the tunnel down.
    pub fn disconnect(mut self) -> Result<(), AdapterError> {
        let reply = self.client.call(&Request::Disconnect);
        self.stop_polling();
        match reply {
            Ok(Response::Ok) => Ok(()),
            Ok(Response::Error { message, .. }) => Err(AdapterError::DisconnectFailed(message)),
            Ok(other) => Err(AdapterError::DisconnectFailed(format!(
                "unexpected reply: {other:?}"
            ))),
            Err(err) => Err(AdapterError::DisconnectFailed(err.to_string())),
        }
    }

    fn stop_polling(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(poller) = self.poller.take() {
            let _ = poller.join();
        }
    }
}

impl Drop for RemoteTunnel {
    fn drop(&mut self) {
        // Closing the app must not take the VPN down.
        self.stop_polling();
    }
}

fn ipc_to_adapter(err: IpcError) -> AdapterError {
    AdapterError::ConnectFailed(err.to_string())
}

/// Connects through the service if it is running. `Ok(None)` means there is
/// no service to use (the caller should connect directly).
pub fn connect_via_service(profile: &ServerProfile) -> Result<Option<RemoteTunnel>, AdapterError> {
    if deterium_ipc::service_state() != ServiceState::Running {
        return Ok(None);
    }
    let client = Client::new();
    match client.handshake() {
        Ok(()) => {}
        Err(IpcError::Unavailable) => return Ok(None),
        Err(other) => return Err(ipc_to_adapter(other)),
    }

    let reply = client
        .call(&Request::Connect {
            profile: Box::new(profile.clone()),
        })
        .map_err(ipc_to_adapter)?;
    match reply {
        Response::Ok => Ok(Some(RemoteTunnel::watching(profile.id, None))),
        Response::Error {
            kind: ErrorKind::InvalidProfile,
            message,
        } => Err(AdapterError::InvalidProfile(message)),
        Response::Error { message, .. } => Err(AdapterError::ConnectFailed(message)),
        other => Err(AdapterError::ConnectFailed(format!(
            "unexpected reply from the service: {other:?}"
        ))),
    }
}

/// Picks up a tunnel the service already holds, e.g. after the app was
/// closed and opened again. `Ok(None)`: no service, or it holds nothing.
pub fn attach_to_service() -> Result<Option<RemoteTunnel>, IpcError> {
    if deterium_ipc::service_state() != ServiceState::Running {
        return Ok(None);
    }
    let client = Client::new();
    client.handshake()?;
    match client.call(&Request::Status)? {
        Response::Status(status) => Ok(status
            .active
            .map(|active| RemoteTunnel::watching(active.profile_id, Some(active)))),
        other => Err(IpcError::Protocol(format!("unexpected reply {other:?}"))),
    }
}
