//! `ServerProfile`: the TOML format describing one user-owned VPN server.
//! Schema and rationale documented in `docs/ARCHITECTURE.md` §3a — keep
//! that doc and this file in sync when the format changes.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("toml parse error: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("toml serialize error: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("protocol is `{protocol:?}` but no matching `[{protocol:?}]` table is present")]
    MissingProtocolTable { protocol: Protocol },
    #[error("protocol is `{declared:?}` but a `[{other:?}]` table is also present")]
    ConflictingProtocolTable { declared: Protocol, other: Protocol },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Wireguard,
    Openvpn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanionInfo {
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardInterface {
    pub private_key: String,
    pub address: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// Fixed local UDP port; `None` lets the OS pick an ephemeral one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardPeer {
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    pub interface: WireGuardInterface,
    pub peer: WireGuardPeer,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OpenVpnConfig {
    /// The `.ovpn` file content, embedded verbatim. See ARCHITECTURE.md §3a
    /// for why OpenVPN is not remodeled into structured fields.
    pub raw_config: String,
    /// Login for servers that use `auth-user-pass`. The password is stored
    /// encrypted (see `deterium-secrets`) and only written to disk in clear
    /// text, owner-only, for the lifetime of a connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl OpenVpnConfig {
    /// Whether the config contains a bare `auth-user-pass`, i.e. the server
    /// wants a login that the `.ovpn` file itself doesn't supply.
    pub fn asks_for_login(&self) -> bool {
        crate::validate::openvpn_asks_for_login(&self.raw_config)
    }

    /// The saved login, when both halves are present.
    pub fn login(&self) -> Option<(&str, &str)> {
        match (self.username.as_deref(), self.password.as_deref()) {
            (Some(user), Some(pass)) if !user.is_empty() => Some((user, pass)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerProfile {
    pub deterium_profile_version: u32,
    pub id: Uuid,
    pub name: String,
    pub protocol: Protocol,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Free-form user notes, never interpreted.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    #[serde(default, skip_serializing_if = "SecurityOptions::is_default")]
    pub security: SecurityOptions,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub companion: Option<CompanionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wireguard: Option<WireGuardConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openvpn: Option<OpenVpnConfig>,
}

pub const PROFILE_VERSION: u32 = 1;

fn yes() -> bool {
    true
}

/// How strictly to keep traffic inside the tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityOptions {
    /// Block all traffic outside the tunnel while connected, so a dropped
    /// tunnel can't silently expose it.
    #[serde(default)]
    pub kill_switch: bool,
    /// With the kill switch on, still allow the local network.
    #[serde(default = "yes")]
    pub allow_lan: bool,
    /// Block DNS requests that don't go through the tunnel (only applied
    /// when the tunnel actually carries the profile's DNS servers).
    #[serde(default = "yes")]
    pub block_dns_leaks: bool,
}

impl Default for SecurityOptions {
    fn default() -> Self {
        Self {
            kill_switch: false,
            allow_lan: true,
            block_dns_leaks: true,
        }
    }
}

impl SecurityOptions {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

impl ServerProfile {
    pub fn new_id() -> Uuid {
        Uuid::new_v4()
    }

    pub fn parse(toml_str: &str) -> Result<Self, ProfileError> {
        let profile: ServerProfile = toml::from_str(toml_str)?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn to_toml_string(&self) -> Result<String, ProfileError> {
        self.validate()?;
        Ok(toml::to_string_pretty(self)?)
    }

    /// Enforces the rule from ARCHITECTURE.md §3a: exactly one protocol
    /// table present, matching the declared `protocol` tag.
    pub fn validate(&self) -> Result<(), ProfileError> {
        match self.protocol {
            Protocol::Wireguard => {
                if self.wireguard.is_none() {
                    return Err(ProfileError::MissingProtocolTable {
                        protocol: Protocol::Wireguard,
                    });
                }
                if self.openvpn.is_some() {
                    return Err(ProfileError::ConflictingProtocolTable {
                        declared: Protocol::Wireguard,
                        other: Protocol::Openvpn,
                    });
                }
            }
            Protocol::Openvpn => {
                if self.openvpn.is_none() {
                    return Err(ProfileError::MissingProtocolTable {
                        protocol: Protocol::Openvpn,
                    });
                }
                if self.wireguard.is_some() {
                    return Err(ProfileError::ConflictingProtocolTable {
                        declared: Protocol::Openvpn,
                        other: Protocol::Wireguard,
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_wireguard_toml() -> &'static str {
        r#"
deterium_profile_version = 1
id = "b3f1b1a0-7e34-4c9a-9b7a-2e9a9c6b7e10"
name = "Home Server"
protocol = "wireguard"
tags = ["home"]

[wireguard.interface]
private_key = "private-key-placeholder"
address = ["10.6.0.2/32"]

[wireguard.peer]
public_key = "public-key-placeholder"
endpoint = "vpn.example.com:51820"
allowed_ips = ["0.0.0.0/0", "::/0"]
"#
    }

    #[test]
    fn parses_valid_wireguard_profile() {
        let profile = ServerProfile::parse(sample_wireguard_toml()).unwrap();
        assert_eq!(profile.name, "Home Server");
        assert!(profile.wireguard.is_some());
        assert!(profile.openvpn.is_none());
    }

    #[test]
    fn rejects_missing_protocol_table() {
        let toml_str = r#"
deterium_profile_version = 1
id = "b3f1b1a0-7e34-4c9a-9b7a-2e9a9c6b7e10"
name = "Broken"
protocol = "wireguard"
"#;
        let err = ServerProfile::parse(toml_str).unwrap_err();
        assert!(matches!(err, ProfileError::MissingProtocolTable { .. }));
    }

    #[test]
    fn round_trips_through_toml() {
        let profile = ServerProfile::parse(sample_wireguard_toml()).unwrap();
        let serialized = profile.to_toml_string().unwrap();
        let reparsed = ServerProfile::parse(&serialized).unwrap();
        assert_eq!(profile.id, reparsed.id);
        assert_eq!(profile.name, reparsed.name);
    }
}
