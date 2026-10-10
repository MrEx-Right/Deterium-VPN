//! The OpenVPN client that ships inside Deterium.
//!
//! The official Windows build of OpenVPN (and the DLLs it needs) is embedded in
//! the executable (see `build.rs`, fetched by `tools/fetch-openvpn.ps1`) and
//! written out to `%ProgramFiles%\Deterium\openvpn\` the first time an
//! elevated process needs it. That folder is administrator-only, so nothing
//! an ordinary program can modify is ever run with elevated rights.
//!
//! OpenVPN is a separate program (GPL-2.0, with the OpenSSL exception) and is
//! run as one; its license text is written next to it.

use std::path::{Path, PathBuf};

include!(concat!(env!("OUT_DIR"), "/bundled_files.rs"));

/// Whether this build contains OpenVPN.
pub fn available() -> bool {
    !FILES.is_empty()
}

/// The bundled OpenVPN version (e.g. `2.7.7-I001`), if there is one.
pub fn version() -> Option<&'static str> {
    available().then_some(VERSION)
}

pub fn deploy_dir() -> PathBuf {
    deterium_net::install_dir().join("openvpn")
}

/// `openvpn.exe` inside `dir`.
pub fn exe_in(dir: &Path) -> PathBuf {
    dir.join("bin").join("openvpn.exe")
}

/// Makes sure `dir` holds exactly the embedded files and returns the path of
/// `openvpn.exe`. Files that already match are left alone (they may be in use
/// by a running tunnel); a missing or different file is rewritten.
pub fn ensure_in(dir: &Path) -> std::io::Result<PathBuf> {
    if !available() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "this build doesn't contain OpenVPN",
        ));
    }
    for (relative, bytes) in FILES {
        let path = dir.join(relative);
        if std::fs::read(&path).is_ok_and(|existing| existing == *bytes) {
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let staging = path.with_extension("new");
        std::fs::write(&staging, bytes)?;
        std::fs::rename(&staging, &path).inspect_err(|_| {
            let _ = std::fs::remove_file(&staging);
        })?;
    }
    Ok(exe_in(dir))
}

pub fn ensure() -> std::io::Result<PathBuf> {
    ensure_in(&deploy_dir())
}

#[cfg(all(test, bundled_openvpn))]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_files_are_unpacked_and_repaired() {
        let dir = std::env::temp_dir().join(format!("deterium-ovpn-bundle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let exe = ensure_in(&dir).unwrap();
        assert!(exe.is_file());
        assert!(dir.join("ssl/modules/legacy.dll").is_file());
        assert!(dir.join("license.txt").is_file());

        std::fs::write(&exe, b"tampered").unwrap();
        ensure_in(&dir).unwrap();
        assert_eq!(&std::fs::read(&exe).unwrap()[..2], b"MZ");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn it_reports_a_version() {
        assert!(version().is_some_and(|v| v.starts_with("2.")));
    }
}
