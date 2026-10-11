//! The kill switch's memory across restarts.
//!
//! When a tunnel with the kill switch comes up, the service writes down which
//! servers it must still be able to reach and whether the local network is
//! allowed. If the service then starts again without that tunnel (the PC was
//! rebooted, or the service crashed and Windows restarted it), it reads this
//! note and puts the network on hold *before* it answers anyone: nothing leaves
//! the PC except to the VPN server (and DHCP, and the local network if
//! allowed) until the user connects again or turns the protection off.
//!
//! The hold itself is an ordinary dynamic firewall session owned by the service
//! process, so it can never outlive the service: stopping the service always
//! gives the network back. Only the *note* survives, and it lives in the
//! administrators-only install folder. A missing, damaged or empty note means
//! "not armed", never "block everything".

use deterium_core::Uuid;
use deterium_net::{Protocol, Server};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmedServer {
    pub addr: SocketAddr,
    pub protocol: Protocol,
}

/// What the hold needs to know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmedState {
    pub profile_id: Uuid,
    pub allow_lan: bool,
    pub servers: Vec<ArmedServer>,
}

impl ArmedState {
    pub fn new(profile_id: Uuid, allow_lan: bool, servers: &[Server]) -> Self {
        Self {
            profile_id,
            allow_lan,
            servers: servers
                .iter()
                .map(|s| ArmedServer {
                    addr: s.addr,
                    protocol: s.protocol,
                })
                .collect(),
        }
    }

    pub fn servers(&self) -> Vec<Server> {
        self.servers
            .iter()
            .map(|s| Server {
                addr: s.addr,
                protocol: s.protocol,
            })
            .collect()
    }
}

/// Where the note is kept.
pub trait ArmedStore: Send + Sync {
    /// The saved state, or `None` when there is none or it can't be trusted.
    fn load(&self) -> Option<ArmedState>;
    fn save(&self, state: &ArmedState) -> std::io::Result<()>;
    /// Forgets the state. Succeeds when there is nothing to forget.
    fn clear(&self) -> std::io::Result<()>;
}

/// The note as a file.
pub struct FileStore {
    path: PathBuf,
}

/// The file name inside the install folder.
pub const FILE_NAME: &str = "armed.json";

impl FileStore {
    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    /// `%ProgramFiles%\Deterium\armed.json`: writable only by administrators
    /// (and so by the service), so an ordinary program can neither plant a
    /// note that blocks the network nor remove one.
    pub fn standard() -> Self {
        Self::at(standard_path())
    }
}

pub fn standard_path() -> PathBuf {
    deterium_net::install_dir().join(FILE_NAME)
}

impl ArmedStore for FileStore {
    fn load(&self) -> Option<ArmedState> {
        let text = std::fs::read_to_string(&self.path).ok()?;
        let state: ArmedState = serde_json::from_str(&text).ok()?;
        // A hold with no server to reach would block the VPN itself.
        (!state.servers.is_empty()).then_some(state)
    }

    fn save(&self, state: &ArmedState) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Write beside it and rename, so a crash can't leave half a file.
        let staging = self.path.with_extension("json.new");
        std::fs::write(&staging, json)?;
        std::fs::rename(&staging, &self.path).inspect_err(|_| {
            let _ = std::fs::remove_file(&staging);
        })
    }

    fn clear(&self) -> std::io::Result<()> {
        match std::fs::remove_file(&self.path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

/// Removes the note at the standard place (used when installing or
/// uninstalling the service, so an old one can never block a new install).
pub fn clear_standard() {
    let _ = FileStore::standard().clear();
}

/// Puts the network on hold.
pub trait Blocker: Send + Sync {
    /// Blocks everything except loopback, DHCP, `servers` (and the local
    /// network if `allow_lan`). With `allow_dns_lookup`, plain DNS too, which
    /// a new connection needs to find its server. The block lasts as long as
    /// the returned guard.
    fn block(
        &self,
        servers: Vec<Server>,
        allow_lan: bool,
        allow_dns_lookup: bool,
    ) -> Result<Box<dyn Send>, String>;
}

/// The real thing: Windows Filtering Platform, in a dynamic session.
pub struct NetBlocker;

impl Blocker for NetBlocker {
    fn block(
        &self,
        servers: Vec<Server>,
        allow_lan: bool,
        allow_dns_lookup: bool,
    ) -> Result<Box<dyn Send>, String> {
        deterium_net::guard_blocked(servers, allow_lan, allow_dns_lookup).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("deterium-armed-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn state() -> ArmedState {
        ArmedState::new(
            Uuid::new_v4(),
            false,
            &[
                Server::udp("203.0.113.5:51820".parse().unwrap()),
                Server::tcp("198.51.100.7:443".parse().unwrap()),
            ],
        )
    }

    #[test]
    fn a_saved_state_comes_back_unchanged_and_clear_forgets_it() {
        let dir = dir("round-trip");
        let store = FileStore::at(dir.join(FILE_NAME));
        assert_eq!(store.load(), None);

        let state = state();
        store.save(&state).unwrap();
        assert_eq!(store.load(), Some(state.clone()));
        assert_eq!(store.load().unwrap().servers().len(), 2);
        assert!(!dir.join("armed.json.new").exists());

        store.clear().unwrap();
        assert_eq!(store.load(), None);
        store.clear().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_damaged_note_means_not_armed_never_block_everything() {
        let dir = dir("damaged");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE_NAME);
        let store = FileStore::at(path.clone());
        for junk in ["", "not json", "{}", r#"{"profile_id":"nope"}"#] {
            std::fs::write(&path, junk).unwrap();
            assert_eq!(store.load(), None, "{junk:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_note_with_no_server_is_ignored_because_it_would_cut_the_vpn_off() {
        let dir = dir("no-servers");
        let store = FileStore::at(dir.join(FILE_NAME));
        store
            .save(&ArmedState::new(Uuid::new_v4(), true, &[]))
            .unwrap();
        assert_eq!(store.load(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_standard_note_lives_in_the_install_folder() {
        assert_eq!(
            standard_path(),
            deterium_net::install_dir().join("armed.json")
        );
    }
}
