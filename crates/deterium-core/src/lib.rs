//! Protocol-agnostic core of Deterium VPN.
//!
//! Everything protocol-specific lives in `deterium-proto-*` crates behind
//! the `ProtocolAdapter` trait defined here. See `docs/ARCHITECTURE.md`.

pub mod adapter;
pub mod export;
pub mod import;
pub mod profile;
pub mod provision;
pub mod validate;

pub use adapter::{AdapterError, ConnectMode, ProtocolAdapter, TunnelStatus};
pub use profile::{
    CompanionInfo, OpenVpnConfig, Protocol, SecurityOptions, ServerProfile, WireGuardConfig,
    WireGuardInterface, WireGuardPeer, PROFILE_VERSION,
};
pub use uuid::Uuid;
pub use validate::Problem;
