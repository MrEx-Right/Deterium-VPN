//! The armed kill switch against the real Windows Filtering Platform: a
//! "reboot" (a second service process that finds the first one's note on disk)
//! must put the network on hold before anyone connects, and turning the
//! protection off must give it back. The tunnel is a stand-in; the firewall and
//! the note file are real. Ignored by default: it needs administrator rights and
//! it holds this PC's network for about three seconds.
//!
//! ```text
//! cargo test -p deterium-service --test live_armed -- --ignored --nocapture
//! ```
//!
//! The probes use documentation addresses (TEST-NET-1) so what is measured is
//! the firewall's verdict, not the internet.

use deterium_core::import::parse_wireguard_conf;
use deterium_core::{AdapterError, ServerProfile, TunnelStatus};
use deterium_engine::Server;
use deterium_ipc::{Request, Response, WireStats};
use deterium_service::armed::{ArmedStore, FileStore, NetBlocker, FILE_NAME};
use deterium_service::{Connector, Manager, Running};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

const CONF: &str = "[Interface]\nPrivateKey = AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=\nAddress = 10.6.0.2/32\n[Peer]\nPublicKey = hNB8xHQbFgfPavZ3NEhjv5+SRZ6TESr65wrlc71XuxA=\nEndpoint = 192.0.2.1:80\nAllowedIPs = 0.0.0.0/0\n";

struct StandIn;

impl Running for StandIn {
    fn status(&self) -> TunnelStatus {
        TunnelStatus::Connected
    }
    fn stats(&self) -> Option<WireStats> {
        None
    }
    fn leak_protection(&self) -> bool {
        true
    }
    fn log(&self) -> Vec<String> {
        Vec::new()
    }
    fn stop(self: Box<Self>) -> Result<(), AdapterError> {
        Ok(())
    }
}

/// "The VPN server" is a documentation address nothing answers on.
struct StandInConnector;

impl Connector for StandInConnector {
    fn connect(&self, _: &ServerProfile) -> Result<Box<dyn Running>, AdapterError> {
        Ok(Box::new(StandIn))
    }
    fn guard_servers(&self, _: &ServerProfile) -> Vec<Server> {
        vec![Server::tcp("192.0.2.1:80".parse().unwrap())]
    }
}

fn manager(dir: &std::path::Path) -> Manager {
    Manager::with_parts(
        Box::new(StandInConnector),
        Box::new(FileStore::at(dir.join(FILE_NAME))),
        Box::new(NetBlocker),
        Box::new(|line| println!("service | {line}")),
        Duration::from_secs(1),
    )
}

fn refused_by_the_firewall(ip: &str) -> bool {
    let addr: SocketAddr = format!("{ip}:80").parse().unwrap();
    TcpStream::connect_timeout(&addr, Duration::from_millis(700))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
}

#[test]
#[ignore = "needs administrator rights and blocks this PC's network for ~3 s"]
fn a_restarted_service_holds_the_network_until_the_user_turns_it_off() {
    let dir = std::env::temp_dir().join(format!("deterium-live-armed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // First "boot": a tunnel with the kill switch comes up and is remembered.
    let mut profile = parse_wireguard_conf(CONF, "live armed").unwrap().profile;
    profile.security.kill_switch = true;
    let first = manager(&dir);
    assert!(matches!(
        first.handle(Request::Connect {
            profile: Box::new(profile.clone())
        }),
        Response::Ok
    ));
    first.tick();
    assert!(
        FileStore::at(dir.join(FILE_NAME)).load().is_some(),
        "the note is on disk"
    );
    assert!(
        !refused_by_the_firewall("192.0.2.77"),
        "with a tunnel up the manager adds no block of its own"
    );
    // Windows shutting down: the note stays.
    first.shutdown(false);
    drop(first);
    assert!(FileStore::at(dir.join(FILE_NAME)).load().is_some());

    // Second "boot": a new service finds the note before anyone connects.
    let second = manager(&dir);
    assert!(second.restore(), "it was armed");
    assert!(
        refused_by_the_firewall("192.0.2.77"),
        "the network is on hold right after the restart"
    );
    assert!(
        !refused_by_the_firewall("192.0.2.1"),
        "but the VPN server can still be reached"
    );
    let status = second.status();
    assert_eq!(status.active, None);
    assert_eq!(status.armed, Some(profile.id));
    println!("HELD: after the restart traffic is refused except to the VPN server");

    // The user turns the protection off.
    assert!(matches!(second.handle(Request::Disconnect), Response::Ok));
    assert!(
        !refused_by_the_firewall("192.0.2.77"),
        "turning it off gives the network back"
    );
    assert_eq!(FileStore::at(dir.join(FILE_NAME)).load(), None);
    assert_eq!(second.status().armed, None);
    println!("RELEASED: the network is back and the note is gone");

    // And a third start finds nothing to hold.
    let third = manager(&dir);
    assert!(!third.restore());
    assert!(!refused_by_the_firewall("192.0.2.77"));

    let _ = std::fs::remove_dir_all(&dir);
}
