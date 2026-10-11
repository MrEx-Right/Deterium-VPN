//! The Deterium background service. See docs/adr/0004-windows-service.md.
//!
//! [`manager`] holds the one tunnel and answers requests (portable and unit
//! tested with a fake connector); the Windows-only modules wrap it in a
//! service (`scm`), install it (`install`) and serve it on the pipe.

pub mod armed;
pub mod manager;
pub use manager::{Connector, EngineConnector, Manager, Running};

#[cfg(windows)]
pub mod cli;
#[cfg(windows)]
pub mod install;
#[cfg(windows)]
pub mod scm;

/// A line in the service's own log, kept where only administrators can read
/// it (the SYSTEM account's local app data), never in a folder users can
/// write to.
pub fn log(message: &str) {
    use std::io::Write;
    let Some(base) = std::env::var_os("LOCALAPPDATA") else {
        return;
    };
    let dir = std::path::PathBuf::from(base).join("Deterium");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("service.log");
    // Keep it small: start over once it passes a megabyte.
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > 1_000_000) {
        let _ = std::fs::remove_file(&path);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{message}");
    }
}
