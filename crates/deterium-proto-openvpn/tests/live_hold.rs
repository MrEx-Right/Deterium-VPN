//! Checks, on a real PC with the real OpenVPN, that the kill switch is in force
//! from *before* OpenVPN starts, and that a connection which never comes up
//! lets the network go again. Ignored by default: it needs administrator
//! rights, and it holds this PC's network for the few seconds the attempt
//! lasts. Run it when the network is not needed:
//!
//! ```text
//! DETERIUM_OVPN_HOLD_CONFIG=path\to\client.ovpn cargo test -p deterium-proto-openvpn \
//!     --test live_hold -- --ignored --nocapture
//! ```
//!
//! The `.ovpn` only has to be valid (certificates and all); its `remote` is
//! replaced by a documentation address (192.0.2.50, TEST-NET-1) that never
//! answers, so no real server is involved. The probes also use TEST-NET
//! addresses, so what is measured is the firewall's verdict, not the internet.

use deterium_core::import::parse_openvpn;
use deterium_core::{ProtocolAdapter, TunnelStatus};
use deterium_proto_openvpn::OpenVpnAdapter;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Whether Windows Filtering Platform refused a connection to `ip` itself
/// (as opposed to the address simply not answering).
fn refused_by_the_firewall(ip: &str) -> bool {
    let addr: SocketAddr = format!("{ip}:80").parse().unwrap();
    TcpStream::connect_timeout(&addr, Duration::from_millis(700))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
}

#[test]
#[ignore = "needs administrator rights and holds this PC's network for ~10 s"]
fn the_kill_switch_holds_before_openvpn_starts_and_lets_go_when_the_attempt_fails() {
    let path = std::env::var("DETERIUM_OVPN_HOLD_CONFIG")
        .expect("set DETERIUM_OVPN_HOLD_CONFIG to a valid client .ovpn");
    let original = std::fs::read_to_string(path).unwrap();
    let mut config: Vec<String> = original
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("remote ") {
                "remote 192.0.2.50 1194 udp".to_string()
            } else {
                line.to_string()
            }
        })
        .collect();
    // Give up quickly instead of retrying for ever.
    config.push("hand-window 5".into());
    config.push("tls-exit".into());

    let mut profile = parse_openvpn(&config.join("\n"), "hold test")
        .unwrap()
        .profile;
    profile.security.kill_switch = true;
    profile.security.allow_lan = true;
    profile.security.block_dns_leaks = false;

    let adapter = OpenVpnAdapter::default();
    let handle = adapter
        .connect(adapter.load_profile(&profile).unwrap())
        .expect("OpenVPN should start");

    // OpenVPN has only just been started and has certainly not connected.
    assert_eq!(adapter.status(&handle), TunnelStatus::Connecting);
    assert!(
        handle.leak_protection(),
        "the hold must already be in force"
    );
    assert!(
        refused_by_the_firewall("192.0.2.77"),
        "traffic to anywhere but the VPN server must be refused while connecting"
    );
    println!("HELD: while connecting, other traffic is refused by the firewall");

    let deadline = Instant::now() + Duration::from_secs(40);
    while adapter.status(&handle) != TunnelStatus::Error {
        assert!(
            Instant::now() < deadline,
            "the attempt never failed; log: {:#?}",
            handle.recent_log()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    for line in handle.recent_log() {
        println!("openvpn | {line}");
    }

    assert!(
        !handle.leak_protection(),
        "a connection that never came up must not leave the PC blocked"
    );
    assert!(
        !refused_by_the_firewall("192.0.2.77"),
        "the network must be back"
    );
    assert!(handle
        .recent_log()
        .iter()
        .any(|l| l.contains("back to normal")));
    println!("RELEASED: the failed attempt gave the network back");

    adapter.disconnect(handle).unwrap();
}
