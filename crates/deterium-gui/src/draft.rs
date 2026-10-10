//! The editor's working copy of a server: every field is plain text, the
//! way a text box holds it. `build` turns it into a real `ServerProfile`
//! (or a list of problems keyed by field id) — the same checks the engine and
//! the adapters rely on, so the form can't accept what a connect would reject.

use deterium_core::import::Imported;
use deterium_core::{
    CompanionInfo, OpenVpnConfig, Problem, Protocol, SecurityOptions, ServerProfile, Uuid,
    WireGuardConfig, WireGuardInterface, WireGuardPeer, PROFILE_VERSION,
};
use deterium_proto_wireguard::{generate_private_key, public_key_from_private};

pub const ROUTE_ALL: &str = "0.0.0.0/0, ::/0";
pub const ROUTE_PRIVATE_ONLY: &str = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16";

#[derive(Clone)]
pub struct Draft {
    pub id: Option<Uuid>,
    pub protocol: Protocol,
    pub name: String,
    pub tags: String,
    pub notes: String,
    pub companion: Option<CompanionInfo>,

    pub kill_switch: bool,
    pub allow_lan: bool,
    pub block_dns_leaks: bool,

    pub private_key: String,
    pub address: String,
    pub dns: String,
    pub mtu: String,
    pub listen_port: String,
    pub peer_public_key: String,
    pub preshared_key: String,
    pub endpoint: String,
    pub allowed_ips: String,
    pub keepalive: String,

    pub raw_config: String,
    pub username: String,
    pub password: String,
}

impl Draft {
    /// A fresh WireGuard server with sensible defaults and a newly
    /// generated device key, so the user only has to fill in the server.
    pub fn new_wireguard() -> Self {
        Self {
            private_key: generate_private_key().unwrap_or_default(),
            ..Self::blank()
        }
    }

    /// WireGuard defaults with no key; callers fill it in themselves.
    pub fn blank() -> Self {
        Self {
            id: None,
            protocol: Protocol::Wireguard,
            name: String::new(),
            tags: String::new(),
            notes: String::new(),
            companion: None,
            kill_switch: false,
            allow_lan: true,
            block_dns_leaks: true,
            private_key: String::new(),
            address: "10.66.66.2/32".into(),
            dns: "1.1.1.1".into(),
            mtu: String::new(),
            listen_port: String::new(),
            peer_public_key: String::new(),
            preshared_key: String::new(),
            endpoint: String::new(),
            allowed_ips: ROUTE_ALL.into(),
            keepalive: "25".into(),
            raw_config: String::new(),
            username: String::new(),
            password: String::new(),
        }
    }

    pub fn new_openvpn() -> Self {
        Self {
            protocol: Protocol::Openvpn,
            ..Self::new_wireguard()
        }
    }

    pub fn from_profile(profile: &ServerProfile) -> Self {
        let mut draft = Self::new_wireguard();
        draft.id = Some(profile.id);
        draft.protocol = profile.protocol;
        draft.name = profile.name.clone();
        draft.tags = profile.tags.join(", ");
        draft.notes = profile.notes.clone();
        draft.companion = profile.companion.clone();
        draft.kill_switch = profile.security.kill_switch;
        draft.allow_lan = profile.security.allow_lan;
        draft.block_dns_leaks = profile.security.block_dns_leaks;

        // Fields that don't apply to the stored protocol start empty rather
        // than carrying the "new server" defaults.
        draft.private_key.clear();
        draft.address.clear();
        draft.dns.clear();
        draft.peer_public_key.clear();
        draft.allowed_ips.clear();
        draft.keepalive.clear();

        if let Some(wg) = &profile.wireguard {
            draft.private_key = wg.interface.private_key.clone();
            draft.address = wg.interface.address.join(", ");
            draft.dns = wg.interface.dns.clone().unwrap_or_default().join(", ");
            draft.mtu = wg.interface.mtu.map(|v| v.to_string()).unwrap_or_default();
            draft.listen_port = wg
                .interface
                .listen_port
                .map(|v| v.to_string())
                .unwrap_or_default();
            draft.peer_public_key = wg.peer.public_key.clone();
            draft.preshared_key = wg.peer.preshared_key.clone().unwrap_or_default();
            draft.endpoint = wg.peer.endpoint.clone();
            draft.allowed_ips = wg.peer.allowed_ips.join(", ");
            draft.keepalive = wg
                .peer
                .persistent_keepalive
                .map(|v| v.to_string())
                .unwrap_or_default();
        }
        if let Some(ovpn) = &profile.openvpn {
            draft.raw_config = ovpn.raw_config.clone();
            draft.username = ovpn.username.clone().unwrap_or_default();
            draft.password = ovpn.password.clone().unwrap_or_default();
        }
        draft
    }

    /// Replaces the form contents with an imported config, keeping the
    /// identity (id) of the server being edited.
    pub fn apply_import(&mut self, imported: Imported) {
        let keep_id = self.id;
        let keep_name = self.name.trim().to_string();
        *self = Self::from_profile(&imported.profile);
        self.id = keep_id;
        if !keep_name.is_empty() && imported.profile.name == "Imported server" {
            self.name = keep_name;
        }
    }

    /// Changes protocol, filling in WireGuard defaults the first time it's
    /// chosen on a draft that came from an OpenVPN server.
    pub fn switch_to(&mut self, protocol: Protocol) {
        self.protocol = protocol;
        if protocol == Protocol::Wireguard {
            if self.private_key.trim().is_empty() {
                self.private_key = generate_private_key().unwrap_or_default();
            }
            if self.address.trim().is_empty() {
                self.address = "10.66.66.2/32".into();
            }
            if self.allowed_ips.trim().is_empty() {
                self.allowed_ips = ROUTE_ALL.into();
            }
        }
    }

    /// Public key matching the current private key, if it parses.
    pub fn public_key(&self) -> Option<String> {
        public_key_from_private(&self.private_key).ok()
    }

    /// The `[Peer]` block to add on the server so this device is allowed in.
    pub fn server_peer_snippet(&self) -> Option<String> {
        let public = self.public_key()?;
        let allowed = split_list(&self.address).join(", ");
        let mut out = format!("[Peer]\nPublicKey = {public}\nAllowedIPs = {allowed}\n");
        if !self.preshared_key.trim().is_empty() {
            out.push_str(&format!("PresharedKey = {}\n", self.preshared_key.trim()));
        }
        Some(out)
    }

    /// Whether the OpenVPN config in the form wants a username and password.
    pub fn asks_for_login(&self) -> bool {
        self.protocol == Protocol::Openvpn
            && deterium_core::validate::openvpn_asks_for_login(&self.raw_config)
    }

    /// Non-blocking advice about things that will likely not work.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.protocol == Protocol::Openvpn
            && !self.asks_for_login()
            && !self.username.trim().is_empty()
            && !self.raw_config.trim().is_empty()
        {
            warnings.push(
                "This config doesn't contain an `auth-user-pass` line, so the server may \
                 ignore the login below."
                    .to_string(),
            );
        }
        warnings
    }

    pub fn problems(&self) -> Vec<Problem> {
        self.build().err().unwrap_or_default()
    }

    pub fn build(&self) -> Result<ServerProfile, Vec<Problem>> {
        let mut problems = Vec::new();

        let profile = ServerProfile {
            deterium_profile_version: PROFILE_VERSION,
            id: self.id.unwrap_or_else(ServerProfile::new_id),
            name: self.name.trim().to_string(),
            protocol: self.protocol,
            tags: split_list(&self.tags),
            notes: self.notes.trim().to_string(),
            security: SecurityOptions {
                kill_switch: self.kill_switch,
                allow_lan: self.allow_lan,
                block_dns_leaks: self.block_dns_leaks,
            },
            companion: self.companion.clone(),
            wireguard: (self.protocol == Protocol::Wireguard).then(|| WireGuardConfig {
                interface: WireGuardInterface {
                    private_key: self.private_key.trim().to_string(),
                    address: split_list(&self.address),
                    dns: Some(split_list(&self.dns)).filter(|d| !d.is_empty()),
                    mtu: parse_optional(&self.mtu, "mtu", "an MTU", &mut problems),
                    listen_port: parse_optional(
                        &self.listen_port,
                        "listen_port",
                        "a port",
                        &mut problems,
                    ),
                },
                peer: WireGuardPeer {
                    public_key: self.peer_public_key.trim().to_string(),
                    preshared_key: Some(self.preshared_key.trim().to_string())
                        .filter(|k| !k.is_empty()),
                    endpoint: self.endpoint.trim().to_string(),
                    allowed_ips: split_list(&self.allowed_ips),
                    persistent_keepalive: parse_optional(
                        &self.keepalive,
                        "keepalive",
                        "a number of seconds",
                        &mut problems,
                    ),
                },
            }),
            openvpn: (self.protocol == Protocol::Openvpn).then(|| OpenVpnConfig {
                raw_config: self.raw_config.replace("\r\n", "\n"),
                username: Some(self.username.trim().to_string()).filter(|u| !u.is_empty()),
                password: Some(self.password.clone()).filter(|p| !p.is_empty()),
            }),
        };

        problems.extend(profile.check());
        if problems.is_empty() {
            Ok(profile)
        } else {
            Err(problems)
        }
    }
}

/// Splits a text box holding a list (commas, spaces or new lines).
pub fn split_list(text: &str) -> Vec<String> {
    text.split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_optional<T: std::str::FromStr>(
    text: &str,
    field: &'static str,
    what: &str,
    problems: &mut Vec<Problem>,
) -> Option<T> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    match text.parse() {
        Ok(value) => Some(value),
        Err(_) => {
            problems.push(Problem::new(
                field,
                format!("Enter {what} as a plain number, or leave this empty"),
            ));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_wireguard() -> Draft {
        let mut d = Draft::new_wireguard();
        d.name = "Test".into();
        d.peer_public_key = "hNB8xHQbFgfPavZ3NEhjv5+SRZ6TESr65wrlc71XuxA=".into();
        d.endpoint = "vpn.example.com:51820".into();
        d
    }

    #[test]
    fn a_new_wireguard_draft_only_misses_the_server_details() {
        let problems = Draft::new_wireguard().problems();
        let fields: Vec<_> = problems.iter().map(|p| p.field).collect();
        assert!(fields.contains(&"name"));
        assert!(fields.contains(&"peer_public_key"));
        assert!(fields.contains(&"endpoint"));
        assert!(
            !fields.contains(&"private_key"),
            "a key is generated up front"
        );
        assert!(!fields.contains(&"address"));
    }

    #[test]
    fn completed_draft_builds_a_valid_profile() {
        let profile = valid_wireguard().build().unwrap();
        let wg = profile.wireguard.unwrap();
        assert_eq!(wg.peer.allowed_ips, ["0.0.0.0/0", "::/0"]);
        assert_eq!(wg.peer.persistent_keepalive, Some(25));
        assert!(profile.openvpn.is_none());
    }

    #[test]
    fn non_numeric_numbers_are_reported_on_their_own_field() {
        let mut d = valid_wireguard();
        d.mtu = "big".into();
        d.keepalive = "often".into();
        let fields: Vec<_> = d.problems().iter().map(|p| p.field).collect();
        assert!(fields.contains(&"mtu"));
        assert!(fields.contains(&"keepalive"));
    }

    #[test]
    fn semantic_problems_surface_through_check() {
        let mut d = valid_wireguard();
        d.endpoint = "no-port".into();
        d.address = "10.0.0.2/99".into();
        let fields: Vec<_> = d.problems().iter().map(|p| p.field).collect();
        assert!(fields.contains(&"endpoint"));
        assert!(fields.contains(&"address"));
    }

    #[test]
    fn profile_round_trips_through_a_draft_without_losing_settings() {
        let mut d = valid_wireguard();
        d.dns = "1.1.1.1, 9.9.9.9".into();
        d.mtu = "1380".into();
        d.listen_port = "51000".into();
        d.preshared_key = "rJ7Pb5Ej25Q/LET9w856N4pej7pF4+UT7BSdLnfsKmo=".into();
        d.tags = "work, eu".into();
        d.notes = "bought 2026".into();
        d.kill_switch = true;
        d.allow_lan = false;
        d.block_dns_leaks = false;
        let original = d.build().unwrap();

        let rebuilt = Draft::from_profile(&original).build().unwrap();
        assert_eq!(rebuilt.id, original.id);
        assert_eq!(rebuilt.tags, ["work", "eu"]);
        assert_eq!(rebuilt.notes, "bought 2026");
        assert_eq!(rebuilt.security, original.security);
        assert!(rebuilt.security.kill_switch && !rebuilt.security.allow_lan);
        let (a, b) = (original.wireguard.unwrap(), rebuilt.wireguard.unwrap());
        assert_eq!(a.interface.dns, b.interface.dns);
        assert_eq!(a.interface.mtu, b.interface.mtu);
        assert_eq!(a.interface.listen_port, b.interface.listen_port);
        assert_eq!(a.peer.preshared_key, b.peer.preshared_key);
    }

    #[test]
    fn openvpn_drafts_validate_the_config_text() {
        let mut d = Draft::new_openvpn();
        d.name = "Provider".into();
        assert!(d.problems().iter().any(|p| p.field == "raw_config"));

        d.raw_config = "client\nremote a 1194\nup /tmp/x.sh\n".into();
        assert!(d.problems().iter().any(|p| p.message.contains("`up`")));

        d.raw_config = "client\nremote a 1194\n".into();
        assert!(d.build().is_ok());
    }

    #[test]
    fn peer_snippet_uses_the_derived_public_key() {
        let mut d = valid_wireguard();
        d.private_key = "AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=".into();
        d.address = "10.6.0.2/32".into();
        let snippet = d.server_peer_snippet().unwrap();
        assert!(snippet.contains("rJ7Pb5Ej25Q/LET9w856N4pej7pF4+UT7BSdLnfsKmo="));
        assert!(snippet.contains("AllowedIPs = 10.6.0.2/32"));
    }

    #[test]
    fn a_server_that_asks_for_a_login_needs_one_before_it_can_be_saved() {
        let mut d = Draft::new_openvpn();
        d.name = "Provider".into();
        d.raw_config = "client\nremote a 1194\nauth-user-pass\n".into();
        assert!(d.asks_for_login());
        assert!(d.problems().iter().any(|p| p.field == "username"));

        d.username = "alice".into();
        assert!(
            d.problems().iter().any(|p| p.field == "password"),
            "a username alone is incomplete"
        );

        d.password = "s3cret".into();
        let profile = d.build().unwrap();
        let ovpn = profile.openvpn.unwrap();
        assert_eq!(ovpn.login(), Some(("alice", "s3cret")));

        // And it comes back out of the profile into the form unchanged.
        let again = Draft::from_profile(&d.build().unwrap());
        assert_eq!(
            (again.username.as_str(), again.password.as_str()),
            ("alice", "s3cret")
        );
    }

    #[test]
    fn a_login_for_a_config_that_never_asks_is_flagged_but_allowed() {
        let mut d = Draft::new_openvpn();
        d.name = "Provider".into();
        d.raw_config = "client\nremote a 1194\n".into();
        d.username = "alice".into();
        d.password = "pw".into();
        assert_eq!(d.warnings().len(), 1);
        assert!(d.build().is_ok());
    }

    #[test]
    fn a_config_that_reads_the_login_from_a_file_is_rejected_with_advice() {
        let mut d = Draft::new_openvpn();
        d.name = "Provider".into();
        d.raw_config = "client\nremote a 1194\nauth-user-pass creds.txt\n".into();
        let problems = d.problems();
        assert!(problems
            .iter()
            .any(|p| p.field == "raw_config" && p.message.contains("enter")));
    }

    #[test]
    fn list_splitting_accepts_commas_spaces_and_newlines() {
        assert_eq!(split_list("a, b  c\nd,,"), ["a", "b", "c", "d"]);
    }
}
