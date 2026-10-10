//! What the kill switch / DNS-leak rules need to know about an OpenVPN
//! connection, worked out from the `.ovpn` and from OpenVPN's own log.
//!
//! This is pure logic (no firewall calls), so it is unit tested. Installing
//! the rules happens in `lib.rs` once OpenVPN reports it is connected: before
//! that the PC is exactly as exposed as it was without a VPN, and after it the
//! tunnel adapter, the VPN server(s), DHCP and (if allowed) the local network
//! are permitted and everything else is blocked.

use deterium_core::validate::openvpn_directives;
use deterium_core::SecurityOptions;
use deterium_net::{LeakPolicy, Protocol, Server};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

/// A `remote` (or proxy) the OpenVPN client itself connects to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
}

/// What the server told the client to do (from its `PUSH_REPLY`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushInfo {
    pub dns: Vec<IpAddr>,
    /// All traffic is sent through the tunnel (`redirect-gateway`).
    pub full_tunnel: bool,
}

fn protocol_of(word: &str) -> Protocol {
    if word.to_ascii_lowercase().starts_with("tcp") {
        Protocol::Tcp
    } else {
        Protocol::Udp
    }
}

/// Every server the config can connect to: `remote` lines (with their port and
/// protocol, or the global `port` / `proto`) and an HTTP/SOCKS proxy if one is
/// configured (the outer connection then goes to the proxy).
pub fn parse_remotes(raw_config: &str) -> Vec<Remote> {
    let directives = openvpn_directives(raw_config);

    let mut default_port = 1194u16;
    let mut default_protocol = Protocol::Udp;
    for (name, args) in &directives {
        match (name.as_str(), args.first()) {
            ("port" | "rport", Some(port)) => {
                if let Ok(port) = port.parse() {
                    default_port = port;
                }
            }
            ("proto", Some(word)) => default_protocol = protocol_of(word),
            _ => {}
        }
    }

    let mut remotes = Vec::new();
    for (name, args) in &directives {
        match name.as_str() {
            "remote" => {
                let Some(host) = args.first() else { continue };
                let port = args
                    .get(1)
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(default_port);
                let protocol = args.get(2).map_or(default_protocol, |p| protocol_of(p));
                remotes.push(Remote {
                    host: (*host).to_string(),
                    port,
                    protocol,
                });
            }
            "http-proxy" | "socks-proxy" => {
                if let (Some(host), Some(port)) = (args.first(), args.get(1)) {
                    if let Ok(port) = port.parse() {
                        remotes.push(Remote {
                            host: (*host).to_string(),
                            port,
                            protocol: Protocol::Tcp,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    remotes
}

/// Turns remotes into addresses. IP literals are used as they are; names are
/// looked up with `resolve` (every address it returns is permitted).
pub fn resolve_servers(
    remotes: &[Remote],
    resolve: impl Fn(&str, u16) -> Vec<IpAddr>,
) -> Vec<Server> {
    let mut servers = Vec::new();
    for remote in remotes {
        let addresses: Vec<IpAddr> = match remote.host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => resolve(&remote.host, remote.port),
        };
        for ip in addresses {
            let server = Server {
                addr: SocketAddr::new(ip, remote.port),
                protocol: remote.protocol,
            };
            if !servers.contains(&server) {
                servers.push(server);
            }
        }
    }
    servers
}

/// The system resolver.
pub fn system_resolver(host: &str, port: u16) -> Vec<IpAddr> {
    (host, port)
        .to_socket_addrs()
        .map(|addrs| addrs.map(|a| a.ip()).collect())
        .unwrap_or_default()
}

/// The server address OpenVPN is actually talking to, from lines such as
/// `TCP/UDP: Preserving recently used remote address: [AF_INET]1.2.3.4:443` or
/// `UDPv4 link remote: [AF_INET]1.2.3.4:1194`. The line doesn't always say
/// which protocol, so both are permitted for that exact address and port.
pub fn servers_from_log(line: &str) -> Vec<Server> {
    let mentions_remote = line.contains("link remote")
        || line.contains("Preserving recently used remote address")
        || line.contains("Peer Connection Initiated with")
        || line.contains("Attempting to establish TCP connection with")
        || line.contains("TCP connection established with");
    if !mentions_remote {
        return Vec::new();
    }
    let Some(start) = line.find("[AF_INET]") else {
        return Vec::new();
    };
    let rest = &line[start + "[AF_INET]".len()..];
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == ':'))
        .unwrap_or(rest.len());
    let Ok(addr) = rest[..end].parse::<SocketAddr>() else {
        return Vec::new();
    };
    vec![Server::tcp(addr), Server::udp(addr)]
}

/// Reads the DNS servers and the full-tunnel flag out of a `PUSH_REPLY` line.
pub fn push_from_log(line: &str) -> Option<PushInfo> {
    let reply = &line[line.find("PUSH_REPLY")?..];
    let mut info = PushInfo {
        full_tunnel: reply.contains("redirect-gateway"),
        ..Default::default()
    };
    for part in reply.split(',') {
        if let Some(ip) = part.trim().strip_prefix("dhcp-option DNS ") {
            if let Ok(ip) = ip.trim().parse() {
                info.dns.push(ip);
            }
        }
    }
    Some(info)
}

/// The firewall policy for a connected tunnel, or `None` when the profile asks
/// for no protection. DNS-leak blocking is only applied when everything goes
/// through the tunnel *and* the server pushed DNS servers; otherwise it would
/// cut off name resolution for the rest of the PC.
pub fn build_policy(
    security: &SecurityOptions,
    servers: Vec<Server>,
    push: &PushInfo,
) -> Option<LeakPolicy> {
    let policy = LeakPolicy {
        kill_switch: security.kill_switch,
        allow_lan: security.allow_lan,
        block_dns_leaks: security.block_dns_leaks && push.full_tunnel && !push.dns.is_empty(),
        servers,
    };
    policy.is_active().then_some(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "client\ndev tun\nproto tcp\nremote vpn.example.com 443\nremote 203.0.113.9 1194 udp\nremote-random\n<ca>\nremote not.a.directive 1\n</ca>\n";

    #[test]
    fn remotes_carry_their_own_port_and_protocol_or_the_global_ones() {
        let remotes = parse_remotes(CONFIG);
        assert_eq!(remotes.len(), 2, "the one inside <ca> is not a directive");
        assert_eq!(
            remotes[0],
            Remote {
                host: "vpn.example.com".into(),
                port: 443,
                protocol: Protocol::Tcp
            }
        );
        assert_eq!(remotes[1].protocol, Protocol::Udp);
        assert_eq!(remotes[1].port, 1194);
    }

    #[test]
    fn the_defaults_are_udp_1194_and_a_global_port_applies() {
        let r = parse_remotes("client\nremote a.example\n");
        assert_eq!((r[0].port, r[0].protocol), (1194, Protocol::Udp));
        let r = parse_remotes("client\nport 5000\nproto tcp-client\nremote a.example\n");
        assert_eq!((r[0].port, r[0].protocol), (5000, Protocol::Tcp));
    }

    #[test]
    fn a_proxy_is_a_server_too() {
        let r = parse_remotes("client\nremote a.example 1194\nhttp-proxy 10.0.0.5 3128\n");
        assert!(r
            .iter()
            .any(|r| r.host == "10.0.0.5" && r.port == 3128 && r.protocol == Protocol::Tcp));
    }

    #[test]
    fn names_are_resolved_and_literals_are_not() {
        let remotes = parse_remotes(CONFIG);
        let servers = resolve_servers(&remotes, |host, _| {
            assert_eq!(host, "vpn.example.com", "literals must not be looked up");
            vec![
                "198.51.100.1".parse().unwrap(),
                "198.51.100.2".parse().unwrap(),
            ]
        });
        assert_eq!(servers.len(), 3);
        assert!(servers.contains(&Server::udp("203.0.113.9:1194".parse().unwrap())));
        assert!(servers.contains(&Server::tcp("198.51.100.2:443".parse().unwrap())));
    }

    #[test]
    fn an_unresolvable_name_gives_no_server_instead_of_an_error() {
        let servers = resolve_servers(&parse_remotes("remote nope.example 1\n"), |_, _| vec![]);
        assert!(servers.is_empty());
    }

    #[test]
    fn real_openvpn_log_lines_name_the_server() {
        let log = include_str!("../tests/fixtures/real-client-connect.log");
        let learned: Vec<Server> = log.lines().flat_map(servers_from_log).collect();
        assert!(
            learned
                .iter()
                .any(|s| s.addr == "192.168.236.193:1194".parse().unwrap()),
            "{learned:?}"
        );
        assert!(servers_from_log("something unrelated [AF_INET]1.2.3.4:5").is_empty());
        let l = servers_from_log(
            "2026-10-06 18:15:39 TCP/UDP: Preserving recently used remote address: [AF_INET]142.4.216.196:443",
        );
        assert!(l.contains(&Server::tcp("142.4.216.196:443".parse().unwrap())));
    }

    #[test]
    fn push_replies_give_dns_and_the_full_tunnel_flag() {
        let line = "PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.8.0.1,dhcp-option DNS 8.8.8.8,route-gateway 10.8.0.1,ifconfig 10.8.0.2 255.255.255.0'";
        let info = push_from_log(line).unwrap();
        assert!(info.full_tunnel);
        assert_eq!(info.dns.len(), 2);
        assert_eq!(info.dns[0], "10.8.0.1".parse::<IpAddr>().unwrap());

        let split =
            push_from_log("PUSH_REPLY,route 10.9.0.0 255.255.0.0,ifconfig 10.8.0.2 10.8.0.1")
                .unwrap();
        assert!(!split.full_tunnel);
        assert!(push_from_log("TLS: Initial packet from").is_none());
    }

    fn security(kill: bool, dns: bool) -> SecurityOptions {
        SecurityOptions {
            kill_switch: kill,
            allow_lan: true,
            block_dns_leaks: dns,
        }
    }

    #[test]
    fn no_protection_requested_means_no_policy() {
        assert!(build_policy(&security(false, false), vec![], &PushInfo::default()).is_none());
    }

    #[test]
    fn dns_blocking_needs_a_full_tunnel_with_pushed_dns() {
        let full = PushInfo {
            dns: vec!["10.8.0.1".parse().unwrap()],
            full_tunnel: true,
        };
        assert!(build_policy(&security(false, true), vec![], &full).is_some());
        // Same setting, but a split tunnel or no pushed DNS: nothing to block.
        let split = PushInfo {
            full_tunnel: false,
            ..full.clone()
        };
        assert!(build_policy(&security(false, true), vec![], &split).is_none());
        let no_dns = PushInfo {
            dns: vec![],
            ..full
        };
        assert!(build_policy(&security(false, true), vec![], &no_dns).is_none());
        // The kill switch itself never depends on the push.
        assert!(build_policy(&security(true, true), vec![], &PushInfo::default()).is_some());
    }
}
