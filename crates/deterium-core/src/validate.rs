//! Field-level validation for `ServerProfile`, shared by the GUI editor
//! (inline errors), the importers, and the WireGuard adapter. `field` names
//! are stable ids the UI uses to attach a message to the right input.

use crate::profile::ServerProfile;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub field: &'static str,
    pub message: String,
}

impl Problem {
    pub fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }
}

/// Decodes a WireGuard base64 key into its raw 32 bytes.
pub fn decode_key(s: &str) -> Result<[u8; 32], String> {
    let bytes = STANDARD
        .decode(s.trim())
        .map_err(|_| "not valid base64".to_string())?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 32 bytes, got {}", v.len()))
}

/// Parses `10.6.0.2/32`, `fd00::2/128`, or a bare IP (treated as a host).
pub fn parse_cidr(s: &str) -> Result<(IpAddr, u8), String> {
    let s = s.trim();
    let (ip_part, prefix_part) = match s.split_once('/') {
        Some((ip, prefix)) => (ip, Some(prefix)),
        None => (s, None),
    };
    let ip: IpAddr = ip_part
        .trim()
        .parse()
        .map_err(|_| format!("`{s}` is not a valid IP address"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_part {
        Some(p) => p
            .trim()
            .parse::<u8>()
            .ok()
            .filter(|p| *p <= max)
            .ok_or_else(|| format!("prefix length must be 0-{max}"))?,
        None => max,
    };
    Ok((ip, prefix))
}

/// Parses `host:port` or `[v6]:port`. The host may be a DNS name.
pub fn parse_endpoint(s: &str) -> Result<(String, u16), String> {
    let s = s.trim();
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or("missing closing `]` for the IPv6 address")?;
        let port = after
            .strip_prefix(':')
            .ok_or("expected `:port` after the IPv6 address")?;
        (host, port)
    } else {
        s.rsplit_once(':')
            .ok_or("expected the form host:port, e.g. vpn.example.com:51820")?
    };
    if host.is_empty() || host.chars().any(char::is_whitespace) {
        return Err("host is empty or contains spaces".into());
    }
    if !s.starts_with('[') && host.contains(':') {
        return Err("wrap IPv6 addresses in brackets, e.g. [fd00::1]:51820".into());
    }
    let port: u16 = port
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or("port must be 1-65535")?;
    Ok((host.to_string(), port))
}

impl ServerProfile {
    /// Every problem that would stop this profile from connecting, keyed by
    /// field. Empty means the profile is complete and well-formed.
    pub fn check(&self) -> Vec<Problem> {
        let mut problems = Vec::new();

        if self.name.trim().is_empty() {
            problems.push(Problem::new("name", "Give this server a name"));
        }

        if let Some(wg) = &self.wireguard {
            check_wireguard(wg, &mut problems);
        }

        if let Some(ovpn) = &self.openvpn {
            if ovpn.raw_config.trim().is_empty() {
                problems.push(Problem::new(
                    "raw_config",
                    "Paste or import an .ovpn config",
                ));
            }
            for directive in risky_openvpn_directives(&ovpn.raw_config) {
                problems.push(Problem::new(
                    "raw_config",
                    if directive == "auth-user-pass" {
                        "`auth-user-pass` points at a file. Remove the file name and enter \
                         the username and password below instead"
                            .to_string()
                    } else {
                        format!(
                            "Contains `{directive}`, which could run programs or change files \
                             on your PC. Remove that line to continue"
                        )
                    },
                ));
            }

            let user = ovpn.username.as_deref().unwrap_or("");
            let pass = ovpn.password.as_deref().unwrap_or("");
            if user.contains(['\n', '\r', '\0']) {
                problems.push(Problem::new(
                    "username",
                    "The username can't contain line breaks",
                ));
            }
            if pass.contains(['\n', '\r', '\0']) {
                problems.push(Problem::new(
                    "password",
                    "The password can't contain line breaks",
                ));
            }
            if user.is_empty() != pass.is_empty() {
                problems.push(Problem::new(
                    if user.is_empty() {
                        "username"
                    } else {
                        "password"
                    },
                    "Enter both the username and the password, or leave both empty",
                ));
            }
            if ovpn.asks_for_login() && user.is_empty() {
                problems.push(Problem::new(
                    "username",
                    "This server asks for a username and password",
                ));
            }
        }

        problems
    }
}

/// The directives of an `.ovpn`, lower-cased and without any leading `--`,
/// each with its arguments. Comments and inline `<ca>...</ca>` blocks are
/// skipped.
pub fn openvpn_directives(raw_config: &str) -> Vec<(String, Vec<&str>)> {
    let mut out = Vec::new();
    let mut in_block = false;

    for line in raw_config.lines() {
        let line = line.trim();
        if in_block {
            in_block = !line.starts_with("</");
            continue;
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('<') {
            in_block = !line.starts_with("</");
            continue;
        }

        let mut tokens = line.split_whitespace();
        // OpenVPN removes quotes while splitting a line, so `"up"`, `u"p"` and
        // `'plugin'` are the directives `up` and `plugin`. Do the same here, or
        // quoting a name would slip it past every check below.
        let directive: String = tokens
            .next()
            .unwrap_or("")
            .chars()
            .filter(|c| *c != '"' && *c != '\'')
            .collect::<String>()
            .trim_start_matches("--")
            .to_ascii_lowercase();
        out.push((directive, tokens.collect()));
    }
    out
}

/// OpenVPN directives an imported `.ovpn` from an untrusted source must not
/// contain, because the client runs with administrator rights: they make it
/// execute programs, write files wherever the config says, open a control
/// port, read an arbitrary file as the login, or pull in further config
/// files. They are blocked rather than merely warned about.
pub fn risky_openvpn_directives(raw_config: &str) -> Vec<String> {
    /// Run programs.
    const RUN: &[&str] = &[
        "up",
        "down",
        "route-up",
        "route-pre-down",
        "ipchange",
        "tls-verify",
        "auth-user-pass-verify",
        "client-connect",
        "client-disconnect",
        "learn-address",
        "plugin",
        // Load a native library (an OpenSSL provider or engine, a PKCS#11
        // module) by name or path, whatever `script-security` says.
        "providers",
        "engine",
        "pkcs11-providers",
        // Where OpenVPN looks for route.exe and netsh.exe.
        "win-sys",
        // Runs a program to apply pushed DNS settings.
        "dns-updown",
    ];
    /// Write files, open a control port, or change how the process runs.
    const SIDE_EFFECTS: &[&str] = &[
        "tls-export-cert",
        "genkey",
        "log",
        "log-append",
        "writepid",
        "status",
        "management",
        "management-client",
        "daemon",
        "cd",
        "chroot",
        "tmp-dir",
        "config",
        "askpass",
    ];

    let mut found: Vec<String> = Vec::new();
    for (directive, args) in openvpn_directives(raw_config) {
        let risky = RUN.contains(&directive.as_str())
            || SIDE_EFFECTS.contains(&directive.as_str())
            || (directive == "script-security"
                && args
                    .first()
                    .and_then(|level| level.parse::<u8>().ok())
                    .is_none_or(|level| level >= 2))
            // `auth-user-pass <file>` would send that file's first two lines to
            // the server; the login is entered in the editor instead.
            || (directive == "auth-user-pass" && !args.is_empty())
            || sends_a_file_to_a_proxy(&directive, &args)
            // A network path (`\\host\share`) makes this PC reach out to that
            // host, and Windows offers its credentials while doing so.
            || args.iter().any(|arg| is_network_path(arg));

        if risky && !found.contains(&directive) {
            found.push(directive);
        }
    }
    found
}

fn unquoted(arg: &str) -> String {
    arg.chars().filter(|c| *c != '"' && *c != '\'').collect()
}

fn is_network_path(arg: &str) -> bool {
    let arg = unquoted(arg);
    arg.starts_with("\\\\") || arg.starts_with("//")
}

/// Proxy directives that name a file whose first two lines (a login) are sent
/// to the proxy, which the config itself chooses.
fn sends_a_file_to_a_proxy(directive: &str, args: &[&str]) -> bool {
    match directive {
        // http-proxy server port [authfile | auto | auto-nct] [auth-method]
        "http-proxy" => args.get(2).is_some_and(|a| {
            !matches!(
                unquoted(a).to_ascii_lowercase().as_str(),
                "auto" | "auto-nct"
            )
        }),
        "http-proxy-user-pass" => !args.is_empty(),
        // socks-proxy server [port] [authfile]
        "socks-proxy" => {
            args.len() >= 3 || (args.len() == 2 && unquoted(args[1]).parse::<u16>().is_err())
        }
        _ => false,
    }
}

/// True when the config has `auth-user-pass` without a file, i.e. the server
/// expects a username and password that the file itself doesn't contain.
pub fn openvpn_asks_for_login(raw_config: &str) -> bool {
    openvpn_directives(raw_config)
        .iter()
        .any(|(directive, args)| directive == "auth-user-pass" && args.is_empty())
}

fn check_wireguard(wg: &crate::profile::WireGuardConfig, problems: &mut Vec<Problem>) {
    let key_hint = "must be a 32-byte base64 key (44 characters)";

    if decode_key(&wg.interface.private_key).is_err() {
        problems.push(Problem::new(
            "private_key",
            format!("Private key {key_hint}"),
        ));
    }

    if wg.interface.address.is_empty() {
        problems.push(Problem::new(
            "address",
            "At least one tunnel address is required",
        ));
    }
    for addr in &wg.interface.address {
        if let Err(e) = parse_cidr(addr) {
            problems.push(Problem::new("address", e));
        }
    }

    for dns in wg.interface.dns.iter().flatten() {
        if dns.trim().parse::<IpAddr>().is_err() {
            problems.push(Problem::new(
                "dns",
                format!("`{dns}` is not a valid IP address"),
            ));
        }
    }

    if let Some(mtu) = wg.interface.mtu {
        if !(576..=9000).contains(&mtu) {
            problems.push(Problem::new("mtu", "MTU must be between 576 and 9000"));
        }
    }

    if wg.interface.listen_port == Some(0) {
        problems.push(Problem::new(
            "listen_port",
            "Port must be 1-65535 (or empty for automatic)",
        ));
    }

    if decode_key(&wg.peer.public_key).is_err() {
        problems.push(Problem::new(
            "peer_public_key",
            format!("Server public key {key_hint}"),
        ));
    }

    if let Some(psk) = wg
        .peer
        .preshared_key
        .as_deref()
        .filter(|k| !k.trim().is_empty())
    {
        if decode_key(psk).is_err() {
            problems.push(Problem::new(
                "preshared_key",
                format!("Preshared key {key_hint}"),
            ));
        }
    }

    if let Err(e) = parse_endpoint(&wg.peer.endpoint) {
        problems.push(Problem::new("endpoint", e));
    }

    if wg.peer.allowed_ips.is_empty() {
        problems.push(Problem::new(
            "allowed_ips",
            "Add at least one network to route",
        ));
    }
    for ip in &wg.peer.allowed_ips {
        if let Err(e) = parse_cidr(ip) {
            problems.push(Problem::new("allowed_ips", e));
        }
    }

    if let Some(keepalive) = wg.peer.persistent_keepalive {
        if keepalive > u16::MAX as u32 {
            problems.push(Problem::new(
                "keepalive",
                "Keepalive must be 0-65535 seconds",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_accepts_v4_v6_and_bare_ips() {
        assert_eq!(parse_cidr("10.6.0.2/32").unwrap().1, 32);
        assert_eq!(parse_cidr("fd00::2/64").unwrap().1, 64);
        assert_eq!(parse_cidr("10.6.0.2").unwrap().1, 32);
        assert_eq!(parse_cidr("::1").unwrap().1, 128);
    }

    #[test]
    fn cidr_rejects_garbage_and_oversized_prefix() {
        assert!(parse_cidr("10.6.0.2/33").is_err());
        assert!(parse_cidr("fd00::/129").is_err());
        assert!(parse_cidr("not-an-ip/24").is_err());
        assert!(parse_cidr("10.6.0.2/abc").is_err());
    }

    #[test]
    fn endpoint_forms() {
        assert_eq!(parse_endpoint("vpn.example.com:51820").unwrap().1, 51820);
        assert_eq!(parse_endpoint("192.168.1.1:1").unwrap().0, "192.168.1.1");
        assert_eq!(parse_endpoint("[fd00::1]:51820").unwrap().0, "fd00::1");
    }

    #[test]
    fn endpoint_rejects_bad_input() {
        assert!(parse_endpoint("vpn.example.com").is_err());
        assert!(parse_endpoint("vpn.example.com:0").is_err());
        assert!(parse_endpoint("vpn.example.com:99999").is_err());
        assert!(parse_endpoint("fd00::1:51820").is_err());
        assert!(parse_endpoint(":51820").is_err());
    }

    #[test]
    fn flags_openvpn_directives_that_run_programs() {
        let cfg = "client
remote a 1194
script-security 2
up /tmp/x.sh
--down /tmp/y
";
        let found = risky_openvpn_directives(cfg);
        assert_eq!(found, ["script-security", "up", "down"]);
    }

    #[test]
    fn flags_directives_that_write_files_or_open_a_control_port() {
        let cfg = "client\nremote a 1194\nlog /Windows/x.log\nmanagement 127.0.0.1 7505\n\
                   writepid C:/p\nconfig other.ovpn\nauth-user-pass C:/secret.txt\n";
        assert_eq!(
            risky_openvpn_directives(cfg),
            ["log", "management", "writepid", "config", "auth-user-pass"]
        );
    }

    #[test]
    fn a_bare_auth_user_pass_means_the_server_wants_a_login() {
        assert!(openvpn_asks_for_login("client\nauth-user-pass\n"));
        assert!(openvpn_asks_for_login("client\n--auth-user-pass\n"));
        assert!(!openvpn_asks_for_login("client\nauth-user-pass x.txt\n"));
        assert!(!openvpn_asks_for_login("client\n# auth-user-pass\n"));
        assert!(!openvpn_asks_for_login("<ca>\nauth-user-pass\n</ca>\n"));
        assert!(
            risky_openvpn_directives("client\nauth-user-pass\n").is_empty(),
            "the bare form is how a login is requested and is fine"
        );
    }

    #[test]
    fn flags_directives_that_load_native_libraries_or_change_where_tools_run_from() {
        let cfg = "client\nremote a 1194\nproviders C:/Temp/evil.dll\nengine dynamic\n\
                   pkcs11-providers C:/Temp/p11.dll\nwin-sys C:/Temp\ndns-updown C:/x.exe\n\
                   tls-export-cert C:/Temp\ngenkey secret C:/x.key\n";
        assert_eq!(
            risky_openvpn_directives(cfg),
            [
                "providers",
                "engine",
                "pkcs11-providers",
                "win-sys",
                "dns-updown",
                "tls-export-cert",
                "genkey"
            ]
        );
    }

    #[test]
    fn quoting_a_directive_name_does_not_hide_it() {
        // OpenVPN strips the quotes, so all of these are real directives.
        for line in [
            "\"plugin\" evil.dll",
            "'plugin' evil.dll",
            "pl\"ug\"in evil.dll",
            "\"--up\" /tmp/x",
            "\"providers\" C:/Temp/evil.dll",
        ] {
            let cfg = format!("client\nremote a 1194\n{line}\n");
            assert!(
                !risky_openvpn_directives(&cfg).is_empty(),
                "{line} must be flagged"
            );
        }
        assert!(openvpn_asks_for_login("client\n\"auth-user-pass\"\n"));
    }

    #[test]
    fn flags_network_paths_that_would_make_this_pc_reach_out() {
        for cfg in [
            "ca \\\\attacker\\share\\ca.crt",
            "cert //attacker/share/c.crt",
            "tls-crypt \"\\\\attacker\\x\"",
        ] {
            let cfg = format!("client\nremote a 1194\n{cfg}\n");
            assert!(
                !risky_openvpn_directives(&cfg).is_empty(),
                "{cfg} must be flagged"
            );
        }
    }

    #[test]
    fn flags_proxy_settings_that_send_a_file_to_the_proxy() {
        assert!(!risky_openvpn_directives("http-proxy p 8080 C:/secret.txt\n").is_empty());
        assert!(!risky_openvpn_directives("http-proxy-user-pass C:/secret.txt\n").is_empty());
        assert!(!risky_openvpn_directives("socks-proxy p 1080 C:/secret.txt\n").is_empty());
        assert!(!risky_openvpn_directives("socks-proxy p C:/secret.txt\n").is_empty());
        // The same directives without a file are ordinary.
        for ok in [
            "http-proxy p 8080\n",
            "http-proxy p 8080 auto\n",
            "http-proxy p 8080 auto-nct basic\n",
            "socks-proxy p\n",
            "socks-proxy p 1080\n",
        ] {
            assert!(risky_openvpn_directives(ok).is_empty(), "{ok} is fine");
        }
    }

    #[test]
    fn harmless_openvpn_config_passes() {
        let cfg = "client
dev tun
remote a 1194
script-security 1
                   <ca>
up this is just PEM-ish text
</ca>
# up /not/a/directive
";
        assert!(risky_openvpn_directives(cfg).is_empty());
    }

    #[test]
    fn check_rejects_an_openvpn_profile_that_runs_programs() {
        let imported = crate::import::parse_openvpn(
            "client
remote a 1194
up /tmp/x.sh
",
            "t",
        )
        .unwrap();
        let problems = imported.profile.check();
        assert!(problems
            .iter()
            .any(|p| p.field == "raw_config" && p.message.contains("`up`")));

        let ok = crate::import::parse_openvpn(
            "client
remote a 1194
",
            "t",
        )
        .unwrap();
        assert!(ok.profile.check().is_empty());
    }

    #[test]
    fn key_decoding_checks_length() {
        let good = "AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=";
        assert!(decode_key(good).is_ok());
        assert!(decode_key("tooshort").is_err());
        assert!(decode_key("%%%").is_err());
    }
}
