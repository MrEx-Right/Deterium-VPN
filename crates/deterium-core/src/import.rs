//! Turns configs people already have (`wg-quick` `.conf`, `.ovpn`, or a
//! Deterium `.toml`) into `ServerProfile`s. Imports are lenient — they keep
//! whatever parses and report what was dropped as warnings; strict checking
//! is `ServerProfile::check`, which the editor runs afterwards.

use crate::profile::{
    OpenVpnConfig, ProfileError, Protocol, ServerProfile, WireGuardConfig, WireGuardInterface,
    WireGuardPeer, PROFILE_VERSION,
};
use std::net::IpAddr;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("the config is empty")]
    Empty,
    #[error(
        "this doesn't look like a WireGuard (.conf), OpenVPN (.ovpn) or Deterium (.toml) profile"
    )]
    Unrecognized,
    #[error("the WireGuard config has no [Interface] section")]
    MissingInterface,
    #[error("invalid Deterium profile: {0}")]
    Deterium(#[from] ProfileError),
}

#[derive(Debug)]
pub struct Imported {
    pub profile: ServerProfile,
    /// Things that were present in the source but not carried over.
    pub warnings: Vec<String>,
}

pub fn parse_any(text: &str, name_hint: &str) -> Result<Imported, ImportError> {
    if text.trim().is_empty() {
        return Err(ImportError::Empty);
    }
    let lower = text.to_ascii_lowercase();

    if lower.contains("deterium_profile_version") {
        let mut profile = ServerProfile::parse(text)?;
        profile.id = ServerProfile::new_id();
        return Ok(Imported {
            profile,
            warnings: Vec::new(),
        });
    }
    if lower.contains("[interface]") {
        return parse_wireguard_conf(text, name_hint);
    }
    let looks_like_ovpn = text.lines().any(|l| {
        let l = l.trim_start();
        l.starts_with("remote ") || l.starts_with("<ca>") || l == "client"
    });
    if looks_like_ovpn {
        return parse_openvpn(text, name_hint);
    }
    Err(ImportError::Unrecognized)
}

pub fn parse_openvpn(text: &str, name_hint: &str) -> Result<Imported, ImportError> {
    if text.trim().is_empty() {
        return Err(ImportError::Empty);
    }
    let config = OpenVpnConfig {
        raw_config: text.replace("\r\n", "\n"),
        ..Default::default()
    };
    let mut warnings = Vec::new();
    if config.asks_for_login() {
        warnings.push(
            "This server asks for a username and password. Enter them in the editor \
             before connecting."
                .to_string(),
        );
    }
    Ok(Imported {
        profile: ServerProfile {
            deterium_profile_version: PROFILE_VERSION,
            id: ServerProfile::new_id(),
            name: display_name(name_hint),
            protocol: Protocol::Openvpn,
            tags: Vec::new(),
            notes: String::new(),
            security: Default::default(),
            companion: None,
            wireguard: None,
            openvpn: Some(config),
        },
        warnings,
    })
}

#[derive(Default)]
struct PeerAcc {
    public_key: String,
    preshared_key: Option<String>,
    endpoint: String,
    allowed_ips: Vec<String>,
    keepalive: Option<u32>,
}

#[derive(Clone, Copy, PartialEq)]
enum Section {
    None,
    Interface,
    Peer,
}

pub fn parse_wireguard_conf(text: &str, name_hint: &str) -> Result<Imported, ImportError> {
    let mut warnings = Vec::new();
    let mut section = Section::None;
    let mut saw_interface = false;

    let mut private_key = String::new();
    let mut address = Vec::new();
    let mut dns = Vec::new();
    let mut mtu = None;
    let mut listen_port = None;
    let mut peers: Vec<PeerAcc> = Vec::new();

    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let name = line[1..line.len() - 1].trim().to_ascii_lowercase();
            section = match name.as_str() {
                "interface" => {
                    saw_interface = true;
                    Section::Interface
                }
                "peer" => {
                    peers.push(PeerAcc::default());
                    Section::Peer
                }
                other => {
                    warnings.push(format!("Unknown section [{other}] was ignored"));
                    Section::None
                }
            };
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            warnings.push(format!("Couldn't read the line `{line}`"));
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        let list = || {
            value
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        };

        match (section, key.as_str()) {
            (Section::Interface, "privatekey") => private_key = value.to_string(),
            (Section::Interface, "address") => address.extend(list()),
            (Section::Interface, "dns") => {
                for entry in list() {
                    if entry.parse::<IpAddr>().is_ok() {
                        dns.push(entry);
                    } else {
                        warnings.push(format!("DNS search domain `{entry}` was ignored"));
                    }
                }
            }
            (Section::Interface, "mtu") => match value.parse() {
                Ok(v) => mtu = Some(v),
                Err(_) => warnings.push(format!("MTU `{value}` isn't a number and was ignored")),
            },
            (Section::Interface, "listenport") => match value.parse() {
                Ok(v) => listen_port = Some(v),
                Err(_) => warnings.push(format!("ListenPort `{value}` was ignored")),
            },
            (
                Section::Interface,
                k @ ("preup" | "postup" | "predown" | "postdown" | "table" | "saveconfig"
                | "fwmark"),
            ) => {
                warnings.push(format!("`{k}` isn't supported and was ignored"));
            }
            (Section::Peer, "publickey") => last(&mut peers).public_key = value.to_string(),
            (Section::Peer, "presharedkey") => {
                last(&mut peers).preshared_key = Some(value.to_string())
            }
            (Section::Peer, "endpoint") => last(&mut peers).endpoint = value.to_string(),
            (Section::Peer, "allowedips") => last(&mut peers).allowed_ips.extend(list()),
            (Section::Peer, "persistentkeepalive") => {
                last(&mut peers).keepalive = if value.eq_ignore_ascii_case("off") {
                    None
                } else {
                    value.parse().ok()
                };
            }
            (_, other) => warnings.push(format!("`{other}` was ignored")),
        }
    }

    if !saw_interface {
        return Err(ImportError::MissingInterface);
    }
    if peers.len() > 1 {
        warnings.push(format!(
            "Found {} peers; Deterium connects to one server, so only the first was kept",
            peers.len()
        ));
    }
    let peer = peers.into_iter().next().unwrap_or_default();

    Ok(Imported {
        profile: ServerProfile {
            deterium_profile_version: PROFILE_VERSION,
            id: ServerProfile::new_id(),
            name: display_name(name_hint),
            protocol: Protocol::Wireguard,
            tags: Vec::new(),
            notes: String::new(),
            security: Default::default(),
            companion: None,
            wireguard: Some(WireGuardConfig {
                interface: WireGuardInterface {
                    private_key,
                    address,
                    dns: if dns.is_empty() { None } else { Some(dns) },
                    mtu,
                    listen_port,
                },
                peer: WireGuardPeer {
                    public_key: peer.public_key,
                    preshared_key: peer.preshared_key,
                    endpoint: peer.endpoint,
                    allowed_ips: peer.allowed_ips,
                    persistent_keepalive: peer.keepalive,
                },
            }),
            openvpn: None,
        },
        warnings,
    })
}

fn last(peers: &mut [PeerAcc]) -> &mut PeerAcc {
    // A [Peer] key can only be reached after its section header pushed one.
    peers.last_mut().expect("peer section without a peer")
}

fn display_name(hint: &str) -> String {
    let hint = hint.trim();
    if hint.is_empty() {
        "Imported server".to_string()
    } else {
        hint.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "\
# my home server
[Interface]
PrivateKey = AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=
Address = 10.6.0.2/32, fd00::2/128
DNS = 10.6.0.1, home.lan
MTU = 1380
PostUp = iptables -A FORWARD -j ACCEPT

[Peer]
PublicKey = hNB8xHQbFgfPavZ3NEhjv5+SRZ6TESr65wrlc71XuxA=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
";

    #[test]
    fn imports_a_wg_quick_conf() {
        let imported = parse_wireguard_conf(CONF, "home").unwrap();
        let wg = imported.profile.wireguard.as_ref().unwrap();
        assert_eq!(imported.profile.name, "home");
        assert_eq!(wg.interface.address, ["10.6.0.2/32", "fd00::2/128"]);
        assert_eq!(
            wg.interface.dns.as_deref(),
            Some(&["10.6.0.1".to_string()][..])
        );
        assert_eq!(wg.interface.mtu, Some(1380));
        assert_eq!(wg.peer.allowed_ips, ["0.0.0.0/0", "::/0"]);
        assert_eq!(wg.peer.persistent_keepalive, Some(25));
        assert!(imported.profile.check().is_empty());
    }

    #[test]
    fn reports_what_it_dropped() {
        let imported = parse_wireguard_conf(CONF, "home").unwrap();
        assert!(imported.warnings.iter().any(|w| w.contains("home.lan")));
        assert!(imported.warnings.iter().any(|w| w.contains("postup")));
    }

    #[test]
    fn base64_padding_equals_sign_survives() {
        let imported = parse_wireguard_conf(CONF, "x").unwrap();
        let key = &imported.profile.wireguard.unwrap().interface.private_key;
        assert!(key.ends_with('='));
    }

    #[test]
    fn extra_peers_are_flagged() {
        let conf = format!("{CONF}\n[Peer]\nPublicKey = abc\nAllowedIPs = 10.0.0.0/8\n");
        let imported = parse_wireguard_conf(&conf, "x").unwrap();
        assert!(imported.warnings.iter().any(|w| w.contains("2 peers")));
    }

    #[test]
    fn conf_without_interface_is_rejected() {
        assert!(matches!(
            parse_wireguard_conf("[Peer]\nPublicKey = x\n", "x"),
            Err(ImportError::MissingInterface)
        ));
    }

    #[test]
    fn parse_any_detects_formats() {
        assert!(parse_any(CONF, "a").unwrap().profile.wireguard.is_some());
        let ovpn = "client\ndev tun\nremote vpn.example.com 1194\n";
        assert!(parse_any(ovpn, "a").unwrap().profile.openvpn.is_some());
        assert!(matches!(
            parse_any("hello world", "a"),
            Err(ImportError::Unrecognized)
        ));
        assert!(matches!(parse_any("  \n", "a"), Err(ImportError::Empty)));
    }

    #[test]
    fn deterium_toml_gets_a_fresh_id() {
        let toml =
            crate::export::to_deterium_toml(&parse_wireguard_conf(CONF, "x").unwrap().profile)
                .unwrap();
        let original = parse_any(&toml, "x").unwrap().profile;
        let again = parse_any(&toml, "x").unwrap().profile;
        assert_ne!(original.id, again.id);
    }
}
