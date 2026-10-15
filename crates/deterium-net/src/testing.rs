//! A fake operating system for tests: a recording `SystemNet`, an in-memory
//! adapter, and a `Platform` that ties them together. Public (not
//! `cfg(test)`) so other crates' tests can run the whole data plane too.

use crate::leak::{build_hold_rules, build_rules, LeakPolicy, Server};
use crate::plan::{NetworkPlan, Op, PhysicalRoute};
use crate::platform::Platform;
use crate::system::{NetError, NetworkGuard, SystemNet, TunInfo, Undo};
use crate::tun::{FakeTun, FakeTunPeer, TunDevice};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Shared, ordered record of everything the fake OS was asked to do.
pub type Log = Arc<Mutex<Vec<String>>>;

pub struct FakeSystemNet {
    pub log: Log,
    /// Fail the apply of the op at this index (to test rollback).
    pub fail_at: Option<usize>,
    applied: usize,
}

impl FakeSystemNet {
    pub fn new(log: Log) -> Self {
        Self {
            log,
            fail_at: None,
            applied: 0,
        }
    }
}

impl SystemNet for FakeSystemNet {
    fn route_to(&self, _: IpAddr) -> Result<PhysicalRoute, NetError> {
        Ok(PhysicalRoute {
            interface_index: 7,
            next_hop: Some("192.168.1.1".parse().unwrap()),
        })
    }

    fn apply(&mut self, _: &TunInfo, op: &Op) -> Result<Option<Undo>, NetError> {
        let index = self.applied;
        self.applied += 1;
        if self.fail_at == Some(index) {
            return Err(NetError::Os {
                op: "fake",
                message: format!("injected failure at op {index}"),
            });
        }
        self.log.lock().unwrap().push(format!("apply {op:?}"));
        Ok(match op {
            Op::BypassRoute { dest, via } => Some(Undo::RemoveRoute {
                dest: *dest,
                interface_index: via.interface_index,
                next_hop: via.next_hop,
            }),
            Op::TunnelRoute { dest } => Some(Undo::RemoveRoute {
                dest: *dest,
                interface_index: 99,
                next_hop: None,
            }),
            _ => None,
        })
    }

    fn undo(&mut self, undo: &Undo) -> Result<(), NetError> {
        self.log.lock().unwrap().push(format!("undo {undo:?}"));
        Ok(())
    }
}

pub struct FakePlatform {
    pub elevated: bool,
    pub log: Log,
    pub physical: Option<PhysicalRoute>,
    /// Make `guard_leaks` fail, to test that a connection then fails whole.
    pub fail_leak_guard: bool,
    /// Make `guard_hold` fail, to test that a connection then never starts.
    pub fail_hold: bool,
    peer: Mutex<Option<FakeTunPeer>>,
}

impl FakePlatform {
    pub fn new(elevated: bool) -> Self {
        Self {
            elevated,
            log: Arc::new(Mutex::new(Vec::new())),
            physical: Some(PhysicalRoute {
                interface_index: 7,
                next_hop: Some("192.168.1.1".parse().unwrap()),
            }),
            fail_leak_guard: false,
            fail_hold: false,
            peer: Mutex::new(None),
        }
    }

    /// The test's handle to the "OS side" of the adapter, once opened.
    pub fn take_peer(&self) -> Option<FakeTunPeer> {
        self.peer.lock().unwrap().take()
    }

    pub fn entries(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

impl Platform for FakePlatform {
    fn is_elevated(&self) -> bool {
        self.elevated
    }

    fn open_tun(&self, name: &str) -> Result<Arc<dyn TunDevice>, NetError> {
        let (tun, peer) = FakeTun::pair(name);
        *self.peer.lock().unwrap() = Some(peer);
        self.log.lock().unwrap().push(format!("open_tun {name}"));
        Ok(tun)
    }

    fn route_to(&self, _: IpAddr) -> Result<PhysicalRoute, NetError> {
        self.physical.ok_or(NetError::Os {
            op: "route_to",
            message: "no route".into(),
        })
    }

    fn apply_plan(&self, tun: &TunInfo, plan: &NetworkPlan) -> Result<Box<dyn Send>, NetError> {
        let sys = FakeSystemNet::new(self.log.clone());
        Ok(Box::new(NetworkGuard::apply(sys, tun, plan, None)?))
    }

    fn guard_leaks(&self, tun: &TunInfo, policy: &LeakPolicy) -> Result<Box<dyn Send>, NetError> {
        if self.fail_leak_guard {
            return Err(NetError::Os {
                op: "guard_leaks",
                message: "injected failure".into(),
            });
        }
        let rules = build_rules(policy, tun.luid);
        self.log
            .lock()
            .unwrap()
            .push(format!("leak_guard on ({} rules)", rules.len()));
        Ok(Box::new(FakeLeakGuard(self.log.clone())))
    }

    fn guard_hold(&self, servers: Vec<Server>, allow_lan: bool) -> Result<Box<dyn Send>, NetError> {
        if self.fail_hold {
            return Err(NetError::Os {
                op: "guard_hold",
                message: "injected failure".into(),
            });
        }
        let rules = build_hold_rules(servers, allow_lan, 0, false);
        self.log
            .lock()
            .unwrap()
            .push(format!("hold on ({} rules)", rules.len()));
        Ok(Box::new(FakeHold(self.log.clone())))
    }
}

/// Records when the temporary block is lifted.
struct FakeHold(Log);

impl Drop for FakeHold {
    fn drop(&mut self) {
        self.0.lock().unwrap().push("hold off".into());
    }
}

/// Records when the firewall rules are lifted.
struct FakeLeakGuard(Log);

impl Drop for FakeLeakGuard {
    fn drop(&mut self) {
        self.0.lock().unwrap().push("leak_guard off".into());
    }
}
