//! Where Deterium puts the files it needs next to itself on Windows, so the
//! app can be a single `.exe` that runs from anywhere.
//!
//! Wintun's driver DLL is built into the executable and written out to
//! `%ProgramFiles%\Deterium\` the first time an elevated process (the service,
//! or the app restarted as administrator) needs it. That folder is writable
//! only by administrators, so an unprivileged program cannot swap the DLL that
//! a privileged process is about to load. Nothing is ever loaded from the
//! current directory, `PATH`, or a folder the user can write to.

use std::path::{Path, PathBuf};

/// Wintun 0.14.1, amd64, as published (and signed) by WireGuard LLC at
/// <https://www.wintun.net/>. Unmodified.
#[cfg(target_arch = "x86_64")]
pub const WINTUN_DLL: &[u8] = include_bytes!("../assets/wintun.dll");
#[cfg(not(target_arch = "x86_64"))]
pub const WINTUN_DLL: &[u8] = &[];

/// `%ProgramFiles%\Deterium`.
pub fn install_dir() -> PathBuf {
    std::env::var_os("ProgramW6432")
        .or_else(|| std::env::var_os("ProgramFiles"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
        .join("Deterium")
}

/// Makes sure `dir` holds exactly the embedded `wintun.dll` and returns its
/// path. Needs write access to `dir` only when the file is missing or differs.
pub fn ensure_wintun_in(dir: &Path) -> std::io::Result<PathBuf> {
    if WINTUN_DLL.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "this build has no embedded Wintun driver for this CPU",
        ));
    }
    let path = dir.join("wintun.dll");
    if std::fs::read(&path).is_ok_and(|existing| existing == WINTUN_DLL) {
        return Ok(path);
    }
    std::fs::create_dir_all(dir)?;
    // Write beside it and rename, so a crash can't leave half a DLL behind.
    let staging = dir.join("wintun.dll.new");
    std::fs::write(&staging, WINTUN_DLL)?;
    std::fs::rename(&staging, &path).inspect_err(|_| {
        let _ = std::fs::remove_file(&staging);
    })?;
    Ok(path)
}

/// [`ensure_wintun_in`] for the standard install folder.
pub fn ensure_wintun() -> std::io::Result<PathBuf> {
    ensure_wintun_in(&install_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_driver_is_written_once_and_verified_after() {
        let dir = std::env::temp_dir().join(format!("deterium-deploy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let path = ensure_wintun_in(&dir).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), WINTUN_DLL);

        // A damaged copy is replaced, not trusted.
        std::fs::write(&path, b"tampered").unwrap();
        ensure_wintun_in(&dir).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), WINTUN_DLL);

        assert!(!dir.join("wintun.dll.new").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn it_really_is_a_pe_dll() {
        assert_eq!(&WINTUN_DLL[..2], b"MZ");
        assert!(WINTUN_DLL.len() > 100_000);
    }
}
