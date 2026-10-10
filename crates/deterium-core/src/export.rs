//! Writes a `ServerProfile` back out as files other tools understand.

use crate::profile::{ProfileError, ServerProfile};

pub fn to_deterium_toml(profile: &ServerProfile) -> Result<String, ProfileError> {
    profile.to_toml_string()
}

/// A `wg-quick`-compatible `.conf`. `None` for non-WireGuard profiles.
pub fn to_wireguard_conf(profile: &ServerProfile) -> Option<String> {
    let wg = profile.wireguard.as_ref()?;
    let mut out = format!("# {}\n[Interface]\n", profile.name.trim());

    out.push_str(&format!("PrivateKey = {}\n", wg.interface.private_key));
    if !wg.interface.address.is_empty() {
        out.push_str(&format!("Address = {}\n", wg.interface.address.join(", ")));
    }
    if let Some(dns) = wg.interface.dns.as_ref().filter(|d| !d.is_empty()) {
        out.push_str(&format!("DNS = {}\n", dns.join(", ")));
    }
    if let Some(mtu) = wg.interface.mtu {
        out.push_str(&format!("MTU = {mtu}\n"));
    }
    if let Some(port) = wg.interface.listen_port {
        out.push_str(&format!("ListenPort = {port}\n"));
    }

    out.push_str("\n[Peer]\n");
    out.push_str(&format!("PublicKey = {}\n", wg.peer.public_key));
    if let Some(psk) = wg
        .peer
        .preshared_key
        .as_deref()
        .filter(|k| !k.trim().is_empty())
    {
        out.push_str(&format!("PresharedKey = {psk}\n"));
    }
    out.push_str(&format!("Endpoint = {}\n", wg.peer.endpoint));
    if !wg.peer.allowed_ips.is_empty() {
        out.push_str(&format!(
            "AllowedIPs = {}\n",
            wg.peer.allowed_ips.join(", ")
        ));
    }
    if let Some(keepalive) = wg.peer.persistent_keepalive {
        out.push_str(&format!("PersistentKeepalive = {keepalive}\n"));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::parse_wireguard_conf;

    const CONF: &str = "\
[Interface]
PrivateKey = AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=
Address = 10.6.0.2/32
DNS = 10.6.0.1
ListenPort = 51000

[Peer]
PublicKey = hNB8xHQbFgfPavZ3NEhjv5+SRZ6TESr65wrlc71XuxA=
PresharedKey = rJ7Pb5Ej25Q/LET9w856N4pej7pF4+UT7BSdLnfsKmo=
Endpoint = vpn.example.com:51820
AllowedIPs = 10.6.0.0/24
PersistentKeepalive = 25
";

    #[test]
    fn wg_conf_survives_import_then_export_then_import() {
        let first = parse_wireguard_conf(CONF, "t").unwrap().profile;
        let exported = to_wireguard_conf(&first).unwrap();
        let second = parse_wireguard_conf(&exported, "t").unwrap().profile;

        let (a, b) = (first.wireguard.unwrap(), second.wireguard.unwrap());
        assert_eq!(a.interface.private_key, b.interface.private_key);
        assert_eq!(a.interface.listen_port, Some(51000));
        assert_eq!(b.interface.listen_port, Some(51000));
        assert_eq!(a.peer.preshared_key, b.peer.preshared_key);
        assert_eq!(a.peer.endpoint, b.peer.endpoint);
        assert_eq!(a.peer.allowed_ips, b.peer.allowed_ips);
    }

    #[test]
    fn openvpn_profiles_have_no_wg_conf() {
        let ovpn = crate::import::parse_openvpn("client\nremote a 1194\n", "o")
            .unwrap()
            .profile;
        assert!(to_wireguard_conf(&ovpn).is_none());
    }
}
