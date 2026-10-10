//! The messages between the app and the background service.
//!
//! One request per pipe connection, one response back, each a single line of
//! JSON. That keeps the service stateless per connection: there is no session
//! to hijack and nothing to clean up if a client disappears halfway.

use deterium_core::{ServerProfile, TunnelStatus, Uuid};
use serde::{Deserialize, Serialize};

/// Bumped whenever a message changes shape. Client and service must agree.
pub const PROTOCOL_VERSION: u32 = 1;

/// The name of the Windows service, and what the client checks the pipe
/// server against.
pub const SERVICE_NAME: &str = "DeteriumVPN";

/// The named pipe the service listens on.
pub const PIPE_NAME: &str = r"\\.\pipe\deterium-vpn";

/// A single message may not exceed this (a large `.ovpn` with embedded
/// certificates is a few tens of kilobytes).
pub const MAX_MESSAGE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// "Who are you?" — used to check both sides speak the same protocol.
    Hello,
    /// Bring this server up as a real VPN, replacing any tunnel that is up.
    Connect { profile: Box<ServerProfile> },
    /// Take the active tunnel down. Succeeds when there is none.
    Disconnect,
    /// What is the service doing right now?
    Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Hello {
        protocol: u32,
        service_version: String,
    },
    Ok,
    Status(ServiceStatus),
    Error {
        kind: ErrorKind,
        message: String,
    },
}

/// Why a request failed, so the app can react (show the profile's problems,
/// offer to retry) instead of parsing text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    InvalidProfile,
    ConnectFailed,
    DisconnectFailed,
    BadRequest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceStatus {
    /// The tunnel the service is holding, if any.
    pub active: Option<ActiveTunnel>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveTunnel {
    pub profile_id: Uuid,
    pub status: TunnelStatus,
    /// How long the service has been holding this tunnel, so an app that
    /// reconnects to it can show the real uptime.
    pub uptime_secs: u64,
    /// Real traffic counters (WireGuard only).
    pub stats: Option<WireStats>,
    /// Whether firewall rules currently block traffic outside the tunnel.
    pub leak_protection: bool,
    /// Recent output of the underlying client (OpenVPN only).
    pub log: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_secs: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use deterium_core::import::parse_wireguard_conf;

    const CONF: &str = "[Interface]\nPrivateKey = AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=\nAddress = 10.6.0.2/32\n[Peer]\nPublicKey = hNB8xHQbFgfPavZ3NEhjv5+SRZ6TESr65wrlc71XuxA=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n";

    #[test]
    fn a_connect_request_carries_the_whole_profile_through_json() {
        let profile = parse_wireguard_conf(CONF, "t").unwrap().profile;
        let line = serde_json::to_string(&Request::Connect {
            profile: Box::new(profile.clone()),
        })
        .unwrap();
        assert!(!line.contains('\n'), "one message must be one line");

        let Request::Connect { profile: back } = serde_json::from_str(&line).unwrap() else {
            panic!("wrong variant");
        };
        assert_eq!(back.id, profile.id);
        assert_eq!(
            back.wireguard.unwrap().interface.private_key,
            profile.wireguard.unwrap().interface.private_key
        );
    }

    #[test]
    fn status_responses_round_trip() {
        let status = Response::Status(ServiceStatus {
            active: Some(ActiveTunnel {
                profile_id: Uuid::nil(),
                status: TunnelStatus::Reconnecting,
                uptime_secs: 42,
                stats: Some(WireStats {
                    rx_bytes: 7,
                    tx_bytes: 9,
                    last_handshake_secs: Some(3),
                }),
                leak_protection: true,
                log: vec!["a line".into()],
            }),
        });
        let line = serde_json::to_string(&status).unwrap();
        let Response::Status(back) = serde_json::from_str(&line).unwrap() else {
            panic!("wrong variant");
        };
        let active = back.active.unwrap();
        assert_eq!(active.status, TunnelStatus::Reconnecting);
        assert!(active.leak_protection);
        assert_eq!(active.uptime_secs, 42);
        assert_eq!(active.stats.unwrap().tx_bytes, 9);
    }

    #[test]
    fn unknown_requests_are_rejected_not_guessed() {
        assert!(serde_json::from_str::<Request>(r#"{"type":"format_disk"}"#).is_err());
        assert!(serde_json::from_str::<Request>("not json").is_err());
    }
}
