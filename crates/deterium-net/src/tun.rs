//! A virtual network adapter as the data plane sees it: packets in, packets out.

use crate::system::TunInfo;
use std::io;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub trait TunDevice: Send + Sync {
    fn info(&self) -> &TunInfo;

    /// Waits up to `timeout` for the OS to hand over an outgoing IP packet.
    /// `Ok(None)` means nothing arrived in time (lets callers poll a
    /// shutdown flag).
    fn read_packet(&self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>>;

    /// Delivers a decrypted IP packet to the OS.
    fn write_packet(&self, packet: &[u8]) -> io::Result<()>;
}

/// An in-memory adapter for tests: the "OS side" is a [`FakeTunPeer`].
pub struct FakeTun {
    info: TunInfo,
    from_os: Mutex<Receiver<Vec<u8>>>,
    to_os: Sender<Vec<u8>>,
}

/// The test's stand-in for the operating system's network stack.
pub struct FakeTunPeer {
    to_tun: Sender<Vec<u8>>,
    from_tun: Receiver<Vec<u8>>,
}

impl FakeTun {
    pub fn pair(name: &str) -> (Arc<FakeTun>, FakeTunPeer) {
        let (to_tun, from_os) = channel();
        let (to_os, from_tun) = channel();
        let tun = Arc::new(FakeTun {
            info: TunInfo {
                name: name.to_string(),
                interface_index: 99,
                luid: 99,
            },
            from_os: Mutex::new(from_os),
            to_os,
        });
        (tun, FakeTunPeer { to_tun, from_tun })
    }
}

impl TunDevice for FakeTun {
    fn info(&self) -> &TunInfo {
        &self.info
    }

    fn read_packet(&self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
        let receiver = self.from_os.lock().expect("fake tun poisoned");
        match receiver.recv_timeout(timeout) {
            Ok(packet) => {
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                Ok(Some(n))
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "fake tun closed"))
            }
        }
    }

    fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        self.to_os
            .send(packet.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "fake tun closed"))
    }
}

impl FakeTunPeer {
    /// The OS sends a packet into the tunnel.
    pub fn send(&self, packet: &[u8]) {
        let _ = self.to_tun.send(packet.to_vec());
    }

    /// The next packet the tunnel delivered to the OS, if one arrives in time.
    pub fn recv_timeout(&self, timeout: Duration) -> Option<Vec<u8>> {
        self.from_tun.recv_timeout(timeout).ok()
    }
}
