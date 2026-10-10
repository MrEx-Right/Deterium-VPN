//! Applying a [`NetworkPlan`] to a real system — and, more importantly,
//! *undoing* it. Changing a user's routing table is the riskiest thing this
//! app does, so every change is paired with an `Undo`, recorded in a journal
//! on disk before the next change is made, and reverted by a guard that
//! runs on disconnect, on drop, and (via the journal) after a crash.

use crate::cidr::Cidr;
use crate::plan::{NetworkPlan, Op, PhysicalRoute, PlanError};
use serde::{Deserialize, Serialize};
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("this platform isn't supported yet")]
    Unsupported,
    #[error("administrator rights are required")]
    NotElevated,
    #[error("{0}")]
    DriverMissing(String),
    #[error("{op} failed: {message}")]
    Os { op: &'static str, message: String },
    #[error(transparent)]
    Plan(#[from] PlanError),
    #[error("couldn't write the network journal: {0}")]
    Journal(#[from] io::Error),
}

/// The virtual adapter a plan is applied to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunInfo {
    pub name: String,
    pub interface_index: u32,
    pub luid: u64,
}

/// How to reverse one applied operation. Serializable: it is what the
/// journal stores so a crashed run can be cleaned up by the next one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Undo {
    RemoveRoute {
        dest: Cidr,
        interface_index: u32,
        next_hop: Option<IpAddr>,
    },
}

/// The OS-specific half: knows how to perform and reverse one operation.
pub trait SystemNet {
    /// How the OS currently reaches `dest` (looked up before the tunnel
    /// exists, so the server can be kept off the tunnel).
    fn route_to(&self, dest: IpAddr) -> Result<PhysicalRoute, NetError>;

    /// Performs `op`. Returns what to do to reverse it, or `None` if there is
    /// nothing to reverse (the thing lives on the tunnel adapter and goes away
    /// with it, or already existed and isn't ours).
    fn apply(&mut self, tun: &TunInfo, op: &Op) -> Result<Option<Undo>, NetError>;

    fn undo(&mut self, undo: &Undo) -> Result<(), NetError>;
}

/// Applies a plan and reverts it when dropped.
pub struct NetworkGuard<S: SystemNet> {
    sys: S,
    undos: Vec<Undo>,
    journal: Option<Journal>,
}

impl<S: SystemNet> NetworkGuard<S> {
    /// Applies every op in order. If any step fails, everything applied so
    /// far is reverted before the error is returned — never a half-configured
    /// network.
    pub fn apply(
        mut sys: S,
        tun: &TunInfo,
        plan: &NetworkPlan,
        journal: Option<Journal>,
    ) -> Result<Self, NetError> {
        let mut undos = Vec::new();
        for op in &plan.ops {
            match sys.apply(tun, op) {
                Ok(Some(undo)) => {
                    undos.push(undo);
                    if let Some(journal) = &journal {
                        if let Err(err) = journal.record(&undos) {
                            revert_all(&mut sys, &mut undos, Some(journal));
                            return Err(err.into());
                        }
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    revert_all(&mut sys, &mut undos, journal.as_ref());
                    return Err(err);
                }
            }
        }
        Ok(Self {
            sys,
            undos,
            journal,
        })
    }

    /// Reverts everything now. Safe to call more than once.
    pub fn revert(&mut self) {
        revert_all(&mut self.sys, &mut self.undos, self.journal.as_ref());
    }
}

impl<S: SystemNet> Drop for NetworkGuard<S> {
    fn drop(&mut self) {
        self.revert();
    }
}

/// Best effort, newest first: a failure to undo one step must not stop the
/// others from being undone.
fn revert_all<S: SystemNet>(sys: &mut S, undos: &mut Vec<Undo>, journal: Option<&Journal>) {
    while let Some(undo) = undos.pop() {
        let _ = sys.undo(&undo);
    }
    if let Some(journal) = journal {
        journal.clear();
    }
}

/// On-disk record of what has been applied and not yet reverted.
#[derive(Debug, Clone)]
pub struct Journal {
    path: PathBuf,
}

impl Journal {
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// `%LOCALAPPDATA%\Deterium\net-journal.json` (or the temp dir).
    pub fn default_location() -> Self {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        Self::at(base.join("Deterium").join("net-journal.json"))
    }

    fn record(&self, undos: &[Undo]) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(undos).map_err(io::Error::other)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &self.path)
    }

    fn clear(&self) {
        let _ = std::fs::remove_file(&self.path);
    }

    fn read(&self) -> Vec<Undo> {
        std::fs::read(&self.path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Reverts anything a previous run left behind (crash, power loss, killed
/// process). Returns how many leftovers were reverted.
pub fn recover_stale<S: SystemNet>(sys: &mut S, journal: &Journal) -> usize {
    let mut leftovers = journal.read();
    let count = leftovers.len();
    revert_all(sys, &mut leftovers, Some(journal));
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::PhysicalRoute;
    use crate::testing::{FakeSystemNet, Log};
    use std::sync::{Arc, Mutex};

    fn log() -> Log {
        Arc::new(Mutex::new(Vec::new()))
    }
    fn tun() -> TunInfo {
        TunInfo {
            name: "Deterium".into(),
            interface_index: 99,
            luid: 99,
        }
    }
    fn route(dest: &str) -> Op {
        Op::TunnelRoute {
            dest: Cidr::parse(dest).unwrap(),
        }
    }
    fn plan() -> NetworkPlan {
        NetworkPlan {
            ops: vec![
                Op::AssignAddress(Cidr::parse("10.6.0.2/32").unwrap()),
                Op::BypassRoute {
                    dest: Cidr::parse("203.0.113.10/32").unwrap(),
                    via: PhysicalRoute {
                        interface_index: 7,
                        next_hop: None,
                    },
                },
                route("10.6.0.0/24"),
                route("10.7.0.0/24"),
            ],
        }
    }
    fn journal_path(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("deterium-journal-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("journal.json")
    }
    fn undo_count(log: &Log) -> usize {
        log.lock()
            .unwrap()
            .iter()
            .filter(|e| e.starts_with("undo"))
            .count()
    }

    #[test]
    fn a_failure_midway_reverts_everything_already_applied() {
        let log = log();
        let mut sys = FakeSystemNet::new(log.clone());
        sys.fail_at = Some(3); // the last route fails

        let result = NetworkGuard::apply(sys, &tun(), &plan(), None);
        assert!(result.is_err());
        assert_eq!(undo_count(&log), 2, "bypass and the first tunnel route");
        assert!(
            !log.lock().unwrap().iter().any(|e| e.contains("10.7.0.0")),
            "the failed op must not be recorded as applied"
        );
    }

    #[test]
    fn dropping_the_guard_reverts_and_clears_the_journal() {
        let log = log();
        let path = journal_path("drop");
        let guard = NetworkGuard::apply(
            FakeSystemNet::new(log.clone()),
            &tun(),
            &plan(),
            Some(Journal::at(&path)),
        )
        .unwrap();
        assert!(path.exists(), "journal is written as changes are made");
        assert_eq!(undo_count(&log), 0);

        drop(guard);
        assert_eq!(undo_count(&log), 3);
        assert!(!path.exists(), "journal is removed after a clean revert");
    }

    #[test]
    fn revert_is_idempotent() {
        let log = log();
        let mut guard =
            NetworkGuard::apply(FakeSystemNet::new(log.clone()), &tun(), &plan(), None).unwrap();
        guard.revert();
        guard.revert();
        drop(guard);
        assert_eq!(undo_count(&log), 3, "each route is undone exactly once");
    }

    #[test]
    fn a_crashed_run_is_cleaned_up_from_its_journal() {
        let path = journal_path("crash");

        // Simulate a crash: the guard never gets to run its Drop.
        let crashed_log = log();
        let guard = NetworkGuard::apply(
            FakeSystemNet::new(crashed_log.clone()),
            &tun(),
            &plan(),
            Some(Journal::at(&path)),
        )
        .unwrap();
        std::mem::forget(guard);
        assert!(path.exists());

        // The next run finds the journal and reverts what it lists.
        let recovery_log = log();
        let mut sys = FakeSystemNet::new(recovery_log.clone());
        let reverted = recover_stale(&mut sys, &Journal::at(&path));
        assert_eq!(reverted, 3);
        assert_eq!(undo_count(&recovery_log), 3);
        assert!(!path.exists());

        // Nothing left to do the second time.
        assert_eq!(recover_stale(&mut sys, &Journal::at(&path)), 0);
    }

    #[test]
    fn a_missing_or_corrupt_journal_is_not_fatal() {
        let path = journal_path("corrupt");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{ not json").unwrap();
        let mut sys = FakeSystemNet::new(log());
        assert_eq!(recover_stale(&mut sys, &Journal::at(&path)), 0);
        assert_eq!(
            recover_stale(&mut sys, &Journal::at(journal_path("absent"))),
            0
        );
    }
}
