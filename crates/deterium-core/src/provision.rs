//! "Bring your own server" onboarding: generates the shell script a user
//! runs on a VPS they already own to turn it into a WireGuard server for
//! this client. The script only ever contains the client's *public* key —
//! the server generates its own private key locally and prints the matching
//! public key for the user to paste back into the app.

use crate::validate::{decode_key, parse_cidr};
use std::net::IpAddr;

const INTERFACE_NAME: &str = "deterium0";

#[derive(Debug, Clone)]
pub struct WireGuardServerSetup {
    pub listen_port: u16,
    /// The server's own address inside the tunnel, e.g. `10.66.66.1/24`.
    pub server_cidr: String,
    /// The address this client gets inside the tunnel, e.g. `10.66.66.2/32`.
    pub client_address: String,
    pub client_public_key: String,
}

impl WireGuardServerSetup {
    pub fn new(client_public_key: impl Into<String>) -> Self {
        Self {
            listen_port: 51820,
            server_cidr: "10.66.66.1/24".into(),
            client_address: "10.66.66.2/32".into(),
            client_public_key: client_public_key.into(),
        }
    }
}

/// Bash script for Debian/Ubuntu. Inputs are validated first, so nothing
/// attacker-shaped can reach the shell.
pub fn wireguard_server_script(setup: &WireGuardServerSetup) -> Result<String, String> {
    if setup.listen_port == 0 {
        return Err("port must be 1-65535".into());
    }
    decode_key(&setup.client_public_key).map_err(|e| format!("client public key: {e}"))?;

    let (server_ip, prefix) = parse_cidr(&setup.server_cidr)?;
    let IpAddr::V4(server_v4) = server_ip else {
        return Err("the tunnel subnet must be IPv4, e.g. 10.66.66.1/24".into());
    };
    if prefix > 30 {
        return Err(
            "the tunnel subnet needs room for at least two hosts (prefix 30 or less)".into(),
        );
    }
    let (client_ip, _) = parse_cidr(&setup.client_address)?;
    if !client_ip.is_ipv4() {
        return Err("the client tunnel address must be IPv4".into());
    }

    let mask = u32::MAX << (32 - prefix as u32);
    let network = std::net::Ipv4Addr::from(u32::from(server_v4) & mask);
    let nat_subnet = format!("{network}/{prefix}");

    let port = setup.listen_port;
    let server_cidr = setup.server_cidr.trim();
    let client_address = setup.client_address.trim();
    let client_key = setup.client_public_key.trim();

    Ok(format!(
        r#"#!/usr/bin/env bash
# Deterium VPN - turns this server into a WireGuard endpoint for one client.
# Debian/Ubuntu, run as root:   sudo bash deterium-setup.sh
# Uses its own interface ({iface}), so an existing wg0 is left untouched.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || {{ echo "Please run as root (sudo)."; exit 1; }}

apt-get update -y
apt-get install -y wireguard

umask 077
mkdir -p /etc/wireguard
[ -f /etc/wireguard/{iface}_private.key ] || wg genkey > /etc/wireguard/{iface}_private.key
wg pubkey < /etc/wireguard/{iface}_private.key > /etc/wireguard/{iface}_public.key

OUT_IF="$(ip route get 1.1.1.1 | awk '{{for(i=1;i<=NF;i++) if($i=="dev"){{print $(i+1); exit}}}}')"
[ -n "$OUT_IF" ] || {{ echo "Could not detect the outbound network interface."; exit 1; }}

[ -f /etc/wireguard/{iface}.conf ] && cp /etc/wireguard/{iface}.conf /etc/wireguard/{iface}.conf.bak

cat > /etc/wireguard/{iface}.conf <<EOF
[Interface]
Address = {server_cidr}
ListenPort = {port}
PrivateKey = $(cat /etc/wireguard/{iface}_private.key)
PostUp = sysctl -w net.ipv4.ip_forward=1; iptables -t nat -A POSTROUTING -s {nat_subnet} -o $OUT_IF -j MASQUERADE; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s {nat_subnet} -o $OUT_IF -j MASQUERADE; iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT

[Peer]
# Your Deterium client
PublicKey = {client_key}
AllowedIPs = {client_address}
EOF

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow {port}/udp
fi

systemctl enable --now wg-quick@{iface} >/dev/null 2>&1 || true
systemctl restart wg-quick@{iface}

echo
echo "Done. Paste this server public key into Deterium:"
echo
echo "    SERVER PUBLIC KEY: $(cat /etc/wireguard/{iface}_public.key)"
echo
echo "Also make sure UDP port {port} is open in your hosting provider's firewall."
"#,
        iface = INTERFACE_NAME,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "rJ7Pb5Ej25Q/LET9w856N4pej7pF4+UT7BSdLnfsKmo=";

    #[test]
    fn script_contains_the_client_key_and_settings() {
        let script = wireguard_server_script(&WireGuardServerSetup::new(KEY)).unwrap();
        assert!(script.contains(KEY));
        assert!(script.contains("ListenPort = 51820"));
        assert!(script.contains("-s 10.66.66.0/24"));
        assert!(script.contains("wg-quick@deterium0"));
        assert!(script.starts_with("#!/usr/bin/env bash"));
    }

    #[test]
    fn script_never_contains_a_private_key_literal() {
        let script = wireguard_server_script(&WireGuardServerSetup::new(KEY)).unwrap();
        // The only PrivateKey line must read the server's own key at run time.
        for line in script.lines().filter(|l| l.contains("PrivateKey")) {
            assert!(line.contains("$(cat"), "unexpected literal key: {line}");
        }
    }

    #[test]
    fn generated_script_passes_bash_syntax_check() {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let Ok(mut child) = Command::new("bash")
            .arg("-n")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        else {
            return; // no bash on this machine; syntax check not possible
        };
        let script = wireguard_server_script(&WireGuardServerSetup::new(KEY)).unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "bash -n failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn shell_metacharacters_are_rejected() {
        let mut setup = WireGuardServerSetup::new(KEY);
        setup.client_public_key = "x\"; rm -rf / #".into();
        assert!(wireguard_server_script(&setup).is_err());

        let mut setup = WireGuardServerSetup::new(KEY);
        setup.server_cidr = "10.0.0.1/24; reboot".into();
        assert!(wireguard_server_script(&setup).is_err());
    }

    #[test]
    fn custom_subnet_is_masked_correctly() {
        let mut setup = WireGuardServerSetup::new(KEY);
        setup.server_cidr = "192.168.77.1/24".into();
        setup.client_address = "192.168.77.2/32".into();
        let script = wireguard_server_script(&setup).unwrap();
        assert!(script.contains("-s 192.168.77.0/24"));
    }
}
