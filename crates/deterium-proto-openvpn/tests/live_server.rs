//! Connects the real adapter to a real OpenVPN server. Ignored by default
//! because it needs one; run it explicitly:
//!
//! ```text
//! DETERIUM_OVPN_LIVE_PROFILE=path\to\profile.toml cargo test -p deterium-proto-openvpn \
//!     --test live_server -- --ignored --nocapture
//! ```
//!
//! `DETERIUM_OPENVPN` may point at any executable that behaves like
//! `openvpn` (for example a wrapper that forwards into WSL on Windows). The
//! adapter's administrator check is switched off here: whatever `openvpn`
//! the wrapper runs has its own rights.

use deterium_core::{ProtocolAdapter, ServerProfile, TunnelStatus};
use deterium_proto_openvpn::OpenVpnAdapter;
use std::time::{Duration, Instant};

#[test]
#[ignore = "needs a live OpenVPN server; see the module docs"]
fn connects_to_a_real_openvpn_server_and_disconnects_cleanly() {
    let path = std::env::var("DETERIUM_OVPN_LIVE_PROFILE").expect(
        "set DETERIUM_OVPN_LIVE_PROFILE to a Deterium profile (.toml) for an OpenVPN server",
    );
    let profile = ServerProfile::parse(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(profile.check().is_empty(), "profile must be valid");

    let adapter = OpenVpnAdapter {
        require_elevation: false,
        real_program: false,
    };
    let config = adapter.load_profile(&profile).unwrap();
    let handle = adapter.connect(config).expect("openvpn should start");

    let deadline = Instant::now() + Duration::from_secs(40);
    let mut seen = Vec::new();
    while adapter.status(&handle) != TunnelStatus::Connected {
        for line in handle.recent_log() {
            if !seen.contains(&line) {
                println!("openvpn | {line}");
                seen.push(line);
            }
        }
        assert!(
            Instant::now() < deadline,
            "never reached Connected; status {:?}",
            adapter.status(&handle)
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    let log = handle.recent_log();
    assert!(
        log.iter()
            .any(|l| l.contains("Initialization Sequence Completed")),
        "the log must show the real success line"
    );
    println!("CONNECTED after {} log lines", log.len());

    adapter.disconnect(handle).unwrap();
}
