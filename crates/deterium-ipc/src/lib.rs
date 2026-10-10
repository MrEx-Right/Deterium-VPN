//! Talking to the Deterium background service.
//!
//! * [`proto`] — the messages (portable, plain JSON).
//! * `pipe` — the Windows named-pipe transport: [`serve`] for the service,
//!   [`Client`] for the app. Elsewhere both report "unavailable".
//!
//! See docs/adr/0004-windows-service.md for the reasoning behind the access
//! rules; the short version is that the pipe is the security boundary, so the
//! server restricts who can connect and the client checks who it is talking to.

pub mod proto;

#[cfg(windows)]
mod pipe;
#[cfg(windows)]
pub use pipe::{
    pipe_access_list, serve, serve_with_access_list, service_state, stop_server, wake, Client,
};

#[cfg(not(windows))]
mod other;
#[cfg(not(windows))]
pub use other::{serve, service_state, wake, Client};

pub use proto::*;

/// Whether the background service is installed and running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    NotInstalled,
    Stopped,
    Running,
}

/// Why a call to the service failed.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// Nothing is listening: the service isn't installed or isn't running.
    #[error("the Deterium background service isn't running")]
    Unavailable,
    /// Something is listening, but this account isn't allowed to use it.
    #[error("this Windows account isn't allowed to use the Deterium service")]
    Denied,
    /// Something else is serving the pipe than the real service. Nothing was sent.
    #[error("the pipe isn't served by the Deterium service ({0}); nothing was sent")]
    Untrusted(String),
    #[error("the service speaks protocol {found}, this app speaks {expected}")]
    VersionMismatch { found: u32, expected: u32 },
    #[error("the service sent something unexpected: {0}")]
    Protocol(String),
    #[error("couldn't talk to the service: {0}")]
    Io(#[from] std::io::Error),
}

/// Reads one line of JSON from `reader`, refusing messages over the size limit.
pub(crate) fn read_message<T: serde::de::DeserializeOwned>(
    reader: impl std::io::Read,
) -> Result<T, IpcError> {
    use std::io::{BufRead, BufReader};
    let mut line = String::new();
    BufReader::new(reader.take(MAX_MESSAGE_BYTES + 1)).read_line(&mut line)?;
    if line.len() as u64 > MAX_MESSAGE_BYTES {
        return Err(IpcError::Protocol("message too large".into()));
    }
    if line.trim().is_empty() {
        return Err(IpcError::Protocol("empty message".into()));
    }
    serde_json::from_str(&line).map_err(|e| IpcError::Protocol(e.to_string()))
}

pub(crate) fn write_message(
    mut writer: impl std::io::Write,
    message: &impl serde::Serialize,
) -> Result<(), IpcError> {
    let mut line = serde_json::to_vec(message).map_err(|e| IpcError::Protocol(e.to_string()))?;
    line.push(b'\n');
    writer.write_all(&line)?;
    writer.flush()?;
    Ok(())
}
