//! Checks, on a real PC, that a WireGuard connection with the kill switch
//! blocks the network *before* the tunnel is built, so not even the seconds it
//! takes to create the adapter and routes are exposed. Ignored by default: it
//! needs administrator rights and the Wintun driver, and it holds this PC's
//! network for the few seconds the test lasts. Run it when the network is not
//! needed:
//!
//! ```text
//! cargo test -p deterium-proto-wireguard --test live_hold -- --ignored --nocapture
//! ```
//!
//! The server is a documentation address (192.0.2.50, TEST-NET-1) that never
//! answers, and the probes use another one, so what is measured is the
//! firewall's verdict, not the internet.
#![cfg(windows)]

use deterium_core::import::parse_wireguard_conf;
use deterium_core::{ProtocolAdapter, TunnelStatus};
use deterium_net::Server;
use deterium_proto_wireguard::WireGuardAdapter;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CONF: &str = "[Interface]\nPrivateKey = AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=\nAddress = 10.6.0.2/32\nDNS = 10.6.0.1\n[Peer]\nPublicKey = hNB8xHQbFgfPavZ3NEhjv5+SRZ6TESr65wrlc71XuxA=\nEndpoint = 192.0.2.50:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n";

/// Whether Windows Filtering Platform refused a connection to this address
/// itself (as opposed to it simply not answering, which only takes the timeout).
fn refused_by_the_firewall(ip: &str) -> bool {
    let addr: SocketAddr = format!("{ip}:80").parse().unwrap();
    TcpStream::connect_timeout(&addr, Duration::from_millis(20))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
}

#[test]
#[ignore = "needs administrator rights and holds this PC's network for ~10 s"]
fn the_kill_switch_holds_before_the_tunnel_is_built_and_lets_go_on_disconnect() {
    const PROBE: &str = "192.0.2.77";

    // Calibration: the probe really does see the firewall's verdict.
    assert!(!refused_by_the_firewall(PROBE), "nothing may block yet");
    {
        let _hold = deterium_net::guard_blocked(
            vec![Server::udp("192.0.2.50:51820".parse().unwrap())],
            true,
            false,
        )
        .expect("a hold should install (administrator rights?)");
        assert!(
            refused_by_the_firewall(PROBE),
            "the probe must see a hold's refusal, or this test proves nothing"
        );
    }
    assert!(
        !refused_by_the_firewall(PROBE),
        "the calibration hold must be gone"
    );
    println!("CALIBRATED: the probe sees the firewall's verdict");

    let mut profile = parse_wireguard_conf(CONF, "hold test").unwrap().profile;
    profile.security.kill_switch = true;
    profile.security.allow_lan = true;
    profile.security.block_dns_leaks = false;

    // Probe every few milliseconds from before the connection starts to after
    // it has finished, noting when each verdict was reached.
    let stop = Arc::new(AtomicBool::new(false));
    let samples: Arc<Mutex<Vec<(Instant, bool)>>> = Arc::default();
    let prober = {
        let (stop, samples) = (stop.clone(), samples.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let verdict = refused_by_the_firewall(PROBE);
                samples.lock().unwrap().push((Instant::now(), verdict));
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };
    std::thread::sleep(Duration::from_millis(300));

    let adapter = WireGuardAdapter;
    let started = Instant::now();
    let handle = adapter
        .connect(adapter.load_profile(&profile).unwrap())
        .expect("the tunnel should be built (administrator rights, Wintun driver?)");
    let finished = Instant::now();
    assert!(handle.leak_protection(), "the kill switch must be in force");
    assert_ne!(adapter.status(&handle), TunnelStatus::Error);
    std::thread::sleep(Duration::from_millis(500));

    adapter.disconnect(handle).unwrap();
    let disconnected = Instant::now();
    std::thread::sleep(Duration::from_millis(500));
    stop.store(true, Ordering::Relaxed);
    prober.join().unwrap();

    let samples = samples.lock().unwrap().clone();
    let before: Vec<_> = samples.iter().filter(|(t, _)| *t < started).collect();
    let during: Vec<_> = samples
        .iter()
        .filter(|(t, _)| *t >= started && *t <= finished)
        .collect();
    let after: Vec<_> = samples
        .iter()
        .filter(|(t, _)| *t > disconnected + Duration::from_millis(100))
        .collect();
    let blocked_during = during.iter().filter(|(_, blocked)| *blocked).count();
    println!(
        "building the tunnel took {:?}: {} of {} probes were refused while it was being built",
        finished - started,
        blocked_during,
        during.len()
    );

    assert!(
        before.iter().all(|(_, blocked)| !blocked),
        "the network was open before connecting"
    );
    let first_block = during.iter().find(|(_, blocked)| *blocked);
    let first_probe = during.first();
    assert!(
        matches!((first_block, first_probe), (Some((b, _)), Some((p, _))) if *b - *p < Duration::from_millis(250)),
        "the block must be in force right from the start of the connection, not later: {blocked_during} refused of {}",
        during.len()
    );
    assert!(
        !after.is_empty() && after.iter().all(|(_, blocked)| !blocked),
        "the network must be back after disconnecting"
    );
    println!("HELD: blocked from the first moment of the connection; RELEASED: open again after disconnecting");
}
