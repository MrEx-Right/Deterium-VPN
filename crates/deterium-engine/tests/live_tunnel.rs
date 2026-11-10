//! Real-tunnel tests, driven by the CI workflows in `.github/workflows`
//! (`vpn-check`, `tunnel-test`, `encryption-test`). Ignored by default: they
//! bring up a real Wintun adapter and routes, so they need Windows, an
//! administrator token and a server that answers.
//!
//! The Rust side only holds a tunnel open and reports through files in
//! `DETERIUM_LIVE_DIR`; the workflow's PowerShell does the measuring while the
//! tunnel is up. That keeps what is being asserted visible in the workflow.
//!
//! ```text
//! DETERIUM_LIVE_PROFILE=server.conf DETERIUM_LIVE_DIR=out \
//!   cargo test -p deterium-engine --test live_tunnel hold_tunnel_open -- --ignored --nocapture
//! ```
//!
//! Files written to `DETERIUM_LIVE_DIR`:
//! * `ready`: the tunnel is connected and a handshake has completed.
//! * `failed`: it never got there (the reason and the log are inside). A
//!   server that doesn't answer at all gets one retry first.
//! * `disconnected`: the tunnel was torn down cleanly (after `done` appeared).
//!
//! The workflow creates `done` when it has finished measuring.

use deterium_core::{import, ConnectMode, ServerProfile, TunnelStatus};
use deterium_engine::Tunnel;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("set {name}")))
}

fn load_profile(path: &Path) -> ServerProfile {
    let text = std::fs::read_to_string(path).expect("profile file should be readable");
    let is_toml = path.extension().and_then(|e| e.to_str()) == Some("toml");
    let profile = if is_toml {
        ServerProfile::parse(&text).expect("profile should parse")
    } else {
        let hint = path.file_stem().and_then(|s| s.to_str()).unwrap_or("ci");
        import::parse_any(&text, hint)
            .expect("config should import")
            .profile
    };
    let problems = profile.check();
    assert!(problems.is_empty(), "profile has problems: {problems:?}");
    profile
}

fn seconds_from_env(name: &str, default: u64) -> Duration {
    let secs = std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default);
    Duration::from_secs(secs)
}

/// How one connection attempt ended.
enum Attempt {
    Up(Tunnel),
    /// The server never answered at all: no completed handshake and not one
    /// byte back. Cloudflare WARP now and then ignores a device for a while
    /// (seen once in CI on the 4th connection in a minute, while the same
    /// commit passed everywhere else), so this one is worth one more try.
    Silent(String),
    /// Anything else, including a server that answered and then went quiet.
    Failed(String),
}

/// Connects and waits for a completed handshake. A tunnel that doesn't get
/// there is disconnected again before this returns, so the network is back
/// to how it was for a retry.
fn attempt(profile: &ServerProfile, wait: Duration) -> Attempt {
    let tunnel = match deterium_engine::connect(profile, ConnectMode::Full) {
        Ok(tunnel) => tunnel,
        Err(err) => return Attempt::Failed(format!("connect failed: {err}")),
    };

    let connect_deadline = Instant::now() + wait;
    loop {
        let handshake = tunnel.stats().and_then(|s| s.last_handshake).is_some();
        if tunnel.status() == TunnelStatus::Connected && handshake {
            return Attempt::Up(tunnel);
        }
        if Instant::now() > connect_deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    let log = tunnel.log().join("\n");
    let status = tunnel.status();
    let stats = tunnel.stats();
    // What the data plane saw. The byte counters only count traffic carried
    // through the tunnel, not handshake packets; a last handshake of `None`
    // means the server never completed one.
    let seen = stats.as_ref().map_or_else(
        || "no counters".to_string(),
        |s| {
            format!(
                "carried {} bytes out and {} bytes in, last handshake {:?}",
                s.tx_bytes, s.rx_bytes, s.last_handshake
            )
        },
    );
    let silent = stats.is_some_and(|s| s.rx_bytes == 0 && s.last_handshake.is_none());
    let _ = tunnel.disconnect();
    let reason = format!("never connected (status {status:?}; {seen})\n{log}");
    if silent {
        Attempt::Silent(reason)
    } else {
        Attempt::Failed(reason)
    }
}

#[test]
#[ignore = "brings up a real tunnel; run by the CI workflows"]
fn hold_tunnel_open() {
    let profile = load_profile(&env_path("DETERIUM_LIVE_PROFILE"));
    let dir = env_path("DETERIUM_LIVE_DIR");
    std::fs::create_dir_all(&dir).unwrap();

    // Two tries of 45 s and the pause between them stay inside the 120 s the
    // workflows wait for `ready`. A healthy server answers in about a second.
    let wait = seconds_from_env("DETERIUM_LIVE_CONNECT_SECS", 45);
    let fail = |reason: String| -> ! {
        std::fs::write(dir.join("failed"), &reason).unwrap();
        panic!("the tunnel never connected: {reason}");
    };
    let tunnel = match attempt(&profile, wait) {
        Attempt::Up(tunnel) => tunnel,
        Attempt::Failed(reason) => fail(reason),
        Attempt::Silent(reason) => {
            // Visible in the run's summary, so a retry is never silent itself.
            println!(
                "::warning::the server did not answer; retrying once in 8 s. First try: {reason}"
            );
            std::thread::sleep(Duration::from_secs(8));
            match attempt(&profile, wait) {
                Attempt::Up(tunnel) => tunnel,
                Attempt::Silent(again) | Attempt::Failed(again) => {
                    fail(format!("{again}\n(after a retry; first try: {reason})"))
                }
            }
        }
    };
    println!("tunnel is up");
    std::fs::write(dir.join("ready"), "connected\n").unwrap();

    let done = dir.join("done");
    let give_up = Instant::now() + seconds_from_env("DETERIUM_LIVE_MAX_SECS", 300);
    while !done.exists() && Instant::now() < give_up {
        std::thread::sleep(Duration::from_millis(250));
    }

    let stats = tunnel.stats();
    if let Some(stats) = &stats {
        println!(
            "tunnel carried {} bytes out, {} bytes in",
            stats.tx_bytes, stats.rx_bytes
        );
    }
    tunnel.disconnect().expect("disconnect should be clean");
    let report = stats
        .map(|s| format!("tx={} rx={}\n", s.tx_bytes, s.rx_bytes))
        .unwrap_or_default();
    std::fs::write(dir.join("disconnected"), report).unwrap();
}

/// What the app does at start-up when an earlier run died: put routes and
/// adapter settings back. `tunnel-test` kills the process above, then runs this.
#[test]
#[ignore = "changes real network settings; run by the CI workflows"]
fn recover_after_crash() {
    let reverted = deterium_engine::recover_leftovers();
    println!("reverted {reverted} leftover change(s)");
}
