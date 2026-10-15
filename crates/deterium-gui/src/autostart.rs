//! "Connect when Windows starts".
//!
//! One value under the current user's `Run` key does the whole job: Windows
//! starts the app at sign-in with `--minimized --autostart <server id>`, and
//! the app connects to that server through the background service. The server
//! lives in the command line itself, so the registry is the only place that
//! says whether this is on, and there is no second file that could disagree
//! with it.
//!
//! It is per user and needs no administrator rights. Until the user signs in,
//! the service's kill switch keeps holding the network, as it always does.

use deterium_core::Uuid;
use std::path::Path;

/// The flag the registry command line carries, followed by the server id.
pub const FLAG: &str = "--autostart";

/// `"<exe>" --minimized --autostart <id>`.
pub fn command_line(exe: &Path, id: Uuid) -> String {
    format!("\"{}\" --minimized {FLAG} {id}", exe.display())
}

/// The server id in a command line (the app's own arguments or a registry value).
pub fn server_in<S: AsRef<str>>(args: &[S]) -> Option<Uuid> {
    let at = args.iter().position(|a| a.as_ref() == FLAG)?;
    Uuid::parse_str(args.get(at + 1)?.as_ref()).ok()
}

/// The server id in a registry command line, if it has one.
fn server_in_command_line(command: &str) -> Option<Uuid> {
    let words: Vec<&str> = command.split_whitespace().collect();
    server_in(&words)
}

#[cfg(windows)]
pub use windows::{disable, enable, enabled_for};

#[cfg(not(windows))]
pub fn enabled_for() -> Option<Uuid> {
    None
}
#[cfg(not(windows))]
pub fn enable(_: Uuid) -> Result<(), String> {
    Err("starting with Windows only exists on Windows".into())
}
#[cfg(not(windows))]
pub fn disable() -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
mod windows {
    use super::{command_line, server_in_command_line};
    use deterium_core::Uuid;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_SZ,
    };

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const VALUE: &str = "Deterium";

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The server Windows is set to connect at sign-in, if any.
    pub fn enabled_for() -> Option<Uuid> {
        read(RUN_KEY, VALUE).and_then(|command| server_in_command_line(&command))
    }

    /// Makes Windows start this app at sign-in and connect to `id`.
    pub fn enable(id: Uuid) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        write(RUN_KEY, VALUE, &command_line(&exe, id))
    }

    /// Stops it. Succeeds when it was not on.
    pub fn disable() -> Result<(), String> {
        remove(RUN_KEY, VALUE)
    }

    pub(super) fn write(key: &str, name: &str, text: &str) -> Result<(), String> {
        let (key, name, data) = (wide(key), wide(name), wide(text));
        // SAFETY: every string is NUL-terminated and outlives the call; the size
        // is in bytes and includes the terminator, as REG_SZ requires.
        let code = unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ptr(),
                REG_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            )
        };
        (code == ERROR_SUCCESS)
            .then_some(())
            .ok_or_else(|| format!("Windows registry error {code}"))
    }

    pub(super) fn read(key: &str, name: &str) -> Option<String> {
        let (key, name) = (wide(key), wide(name));
        let mut bytes = 0u32;
        // SAFETY: first call only asks how many bytes the value needs.
        let code = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut bytes,
            )
        };
        if code != ERROR_SUCCESS || bytes == 0 {
            return None;
        }
        let mut buffer = vec![0u16; (bytes as usize).div_ceil(2)];
        // SAFETY: `buffer` holds at least `bytes` bytes.
        let code = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if code != ERROR_SUCCESS {
            return None;
        }
        let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        Some(String::from_utf16_lossy(&buffer[..end]))
    }

    pub(super) fn remove(key: &str, name: &str) -> Result<(), String> {
        let (key, name) = (wide(key), wide(name));
        // SAFETY: NUL-terminated strings that outlive the call.
        let code = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), name.as_ptr()) };
        // "Not found" means it was already off.
        const NOT_FOUND: u32 = 2;
        const PATH_NOT_FOUND: u32 = 3;
        (code == ERROR_SUCCESS || code == NOT_FOUND || code == PATH_NOT_FOUND)
            .then_some(())
            .ok_or_else(|| format!("Windows registry error {code}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::Path;

        /// A key of its own, never the real `Run` key: a test must not make
        /// Windows start anything.
        fn scratch_key() -> String {
            format!(r"Software\DeteriumAutostartTest-{}", std::process::id())
        }

        #[test]
        fn a_value_written_to_the_registry_reads_back_and_goes_away() {
            let key = scratch_key();
            let id = Uuid::new_v4();
            let command = command_line(Path::new(r"C:\Program Files\Deterium\Deterium.exe"), id);

            assert_eq!(read(&key, "Deterium"), None);
            write(&key, "Deterium", &command).unwrap();
            assert_eq!(read(&key, "Deterium").as_deref(), Some(command.as_str()));
            assert_eq!(
                server_in_command_line(&read(&key, "Deterium").unwrap()),
                Some(id)
            );

            remove(&key, "Deterium").unwrap();
            assert_eq!(read(&key, "Deterium"), None);
            // Removing what is not there is fine.
            remove(&key, "Deterium").unwrap();

            // Leave nothing behind: the scratch key itself goes too.
            let wide_key = wide(&key);
            // SAFETY: NUL-terminated key under HKCU that this test created.
            unsafe {
                windows_sys::Win32::System::Registry::RegDeleteKeyW(
                    HKEY_CURRENT_USER,
                    wide_key.as_ptr(),
                )
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_line_quotes_the_path_and_carries_the_server() {
        let id = Uuid::parse_str("0b1d2c3e-4f50-4a61-8b72-93a4b5c6d7e8").unwrap();
        let line = command_line(Path::new(r"C:\Users\Some One\Desktop\Deterium.exe"), id);
        assert_eq!(
            line,
            r#""C:\Users\Some One\Desktop\Deterium.exe" --minimized --autostart 0b1d2c3e-4f50-4a61-8b72-93a4b5c6d7e8"#
        );
    }

    #[test]
    fn the_server_is_found_in_the_app_arguments_and_in_a_registry_command() {
        let id = Uuid::new_v4();
        let args = ["--minimized".to_string(), FLAG.to_string(), id.to_string()];
        assert_eq!(server_in(&args), Some(id));

        let line = command_line(Path::new(r"C:\a b\Deterium.exe"), id);
        assert_eq!(server_in_command_line(&line), Some(id));
    }

    #[test]
    fn a_missing_or_damaged_server_id_means_off() {
        assert_eq!(server_in::<&str>(&[]), None);
        assert_eq!(server_in(&["--minimized"]), None);
        assert_eq!(server_in(&[FLAG]), None);
        assert_eq!(server_in(&[FLAG, "not-a-uuid"]), None);
        assert_eq!(server_in_command_line(r#""C:\x.exe" --minimized"#), None);
    }
}
