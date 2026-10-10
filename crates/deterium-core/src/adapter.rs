//! `ProtocolAdapter`: the abstraction every VPN protocol implementation
//! (`deterium-proto-wireguard`, `deterium-proto-openvpn`, ...) plugs into.
//! `deterium-engine` and `deterium-gui` depend only on this trait, never on a
//! specific protocol crate's internals. See `docs/ARCHITECTURE.md` §3.
//!
//! `ConnectionConfig`/`TunnelHandle` are associated types rather than one
//! shared concrete struct: each protocol's connect-time data and live
//! handle look nothing alike (WireGuard needs raw keys + a UDP socket,
//! OpenVPN will need a child process handle), and forcing them through one
//! opaque shape would mean either a `Box<dyn Any>` downcast or a dead
//! `_private: ()` placeholder. Callers that need to pick a protocol at
//! runtime (the engine, the GUI) already match on `ServerProfile::protocol`
//! to choose *which* adapter to call, so static dispatch per protocol was
//! already the shape in practice — this just stops fighting it.

use crate::profile::ServerProfile;

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("invalid profile for this protocol: {0}")]
    InvalidProfile(String),
    #[error("failed to bring tunnel up: {0}")]
    ConnectFailed(String),
    #[error("failed to tear tunnel down: {0}")]
    DisconnectFailed(String),
    /// The OS needs administrator/root rights for this (virtual adapter,
    /// routes). The UI turns this into a "restart as administrator" prompt.
    #[error("{0}")]
    PermissionRequired(String),
    #[error("not yet implemented")]
    NotImplemented,
}

/// How far a connection goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectMode {
    /// A real VPN: virtual adapter, routes and DNS are configured so traffic
    /// flows through the tunnel. Needs administrator rights.
    #[default]
    Full,
    /// Only prove the server answers (WireGuard handshake). Touches no
    /// system network settings and needs no special rights.
    HandshakeOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TunnelStatus {
    Connecting,
    Connected,
    Disconnected,
    Reconnecting,
    Error,
}

pub trait ProtocolAdapter {
    /// Protocol-specific data produced by `load_profile` and consumed by
    /// `connect` (e.g. parsed keys, endpoint, allowed IPs for WireGuard).
    type ConnectionConfig;

    /// Protocol-specific handle to a live tunnel, returned by `connect`.
    type TunnelHandle;

    /// Parse/validate a `ServerProfile` for this protocol.
    fn load_profile(&self, profile: &ServerProfile)
        -> Result<Self::ConnectionConfig, AdapterError>;

    /// Bring the tunnel up. Returns a handle used for status/teardown.
    fn connect(&self, config: Self::ConnectionConfig) -> Result<Self::TunnelHandle, AdapterError>;

    fn disconnect(&self, handle: Self::TunnelHandle) -> Result<(), AdapterError>;

    fn status(&self, handle: &Self::TunnelHandle) -> TunnelStatus;
}
