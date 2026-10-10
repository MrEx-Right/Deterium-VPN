//! Installing, removing and querying the Windows service. Needs
//! administrator rights except for [`state`].

use deterium_ipc::proto::SERVICE_NAME;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_SERVICE_DOES_NOT_EXIST};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, StartServiceW, SC_ACTION,
    SC_ACTION_RESTART, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
    SC_STATUS_PROCESS_INFO, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW,
    SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONSW, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_START, SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED,
    SERVICE_WIN32_OWN_PROCESS,
};

const DELETE: u32 = 0x0001_0000;
const SERVICE_CHANGE_CONFIG: u32 = 0x0002;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    NotInstalled,
    Stopped,
    Running,
}

fn wide(text: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    text.as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

struct Handle(SC_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by the SCM and is closed once.
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn open_manager(access: u32) -> Result<Handle, String> {
    // SAFETY: null machine/database names mean "this PC, active database".
    let handle = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), access) };
    if handle.is_null() {
        return Err(format!(
            "can't reach the Service Control Manager: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(Handle(handle))
}

fn open_service(manager: &Handle, access: u32) -> Option<Handle> {
    let name = wide(SERVICE_NAME);
    // SAFETY: valid manager handle and NUL-terminated name.
    let handle = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
    (!handle.is_null()).then_some(Handle(handle))
}

fn current_state(service: &Handle) -> Option<u32> {
    // SAFETY: the buffer is a correctly sized SERVICE_STATUS_PROCESS.
    unsafe {
        let mut status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
        let mut needed = 0u32;
        (QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        ) != 0)
            .then_some(status.dwCurrentState)
    }
}

/// Whether the service is installed and running. Works without any rights.
pub fn state() -> State {
    let Ok(manager) = open_manager(SC_MANAGER_CONNECT) else {
        return State::NotInstalled;
    };
    match open_service(&manager, SERVICE_QUERY_STATUS) {
        None => State::NotInstalled,
        Some(service) => match current_state(&service) {
            Some(SERVICE_RUNNING) => State::Running,
            _ => State::Stopped,
        },
    }
}

/// Program Files folders: places a normal user can't write to.
fn protected_roots() -> Vec<PathBuf> {
    ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .collect()
}

/// A service runs as SYSTEM, so the file it starts from must not be
/// replaceable by an ordinary user.
fn is_in_protected_location(exe: &Path) -> bool {
    let exe = exe.to_string_lossy().to_lowercase().replace('/', "\\");
    protected_roots().iter().any(|root| {
        let root = root.to_string_lossy().to_lowercase();
        exe.starts_with(&format!("{}\\", root.trim_end_matches('\\')))
    })
}

fn quote(path: &Path) -> String {
    format!("\"{}\"", path.display())
}

/// The name the deployed copy of the app/service gets in Program Files.
const DEPLOYED_EXE: &str = "Deterium.exe";

/// Copies the running executable into `%ProgramFiles%\Deterium` and returns
/// the new path.
fn deploy(running: &Path) -> Result<PathBuf, String> {
    let dir = deterium_net::install_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("couldn't create {}: {e}", dir.display()))?;
    let target = dir.join(DEPLOYED_EXE);
    let staging = dir.join("Deterium.exe.new");
    std::fs::copy(running, &staging)
        .map_err(|e| format!("couldn't copy the app to {}: {e}", dir.display()))?;
    std::fs::rename(&staging, &target).map_err(|e| {
        let _ = std::fs::remove_file(&staging);
        format!("couldn't replace {}: {e}", target.display())
    })?;
    Ok(target)
}

/// Removes what [`deploy`] and the Wintun deployment left in Program Files.
/// Best effort: the copy may be the running app, which can't delete itself.
fn remove_deployed_files() {
    let dir = deterium_net::install_dir();
    // The service process may still be letting go of its executable for a
    // moment after Windows reports it stopped, so try again for a few seconds.
    for _ in 0..50 {
        for name in [
            DEPLOYED_EXE,
            "wintun.dll",
            "Deterium.exe.new",
            "wintun.dll.new",
        ] {
            let _ = std::fs::remove_file(dir.join(name));
        }
        // The built-in OpenVPN unpacked on first use.
        let _ = std::fs::remove_dir_all(dir.join("openvpn"));
        if std::fs::remove_dir(&dir).is_ok() || !dir.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub struct InstallOptions {
    /// The one user allowed to control the VPN.
    pub allow_sid: String,
    /// Allow installing from a folder ordinary users can write to. Anyone who
    /// can replace that file gets SYSTEM, so this is for development only.
    pub insecure_location: bool,
}

pub fn install(options: &InstallOptions) -> Result<(), String> {
    if !deterium_engine::is_elevated() {
        return Err("installing the service needs administrator rights".into());
    }
    let sid = &options.allow_sid;
    if !(sid.starts_with("S-1-")
        && sid
            .chars()
            .all(|c| c.is_ascii_digit() || c == '-' || c == 'S'))
    {
        return Err(format!("`{sid}` isn't a valid user SID"));
    }

    let running_exe = std::env::current_exe().map_err(|e| e.to_string())?;

    // Replace an older install first, so its files aren't in use.
    if state() != State::NotInstalled {
        uninstall()?;
    }

    let exe = if is_in_protected_location(&running_exe) {
        running_exe
    } else if options.insecure_location {
        println!(
            "WARNING: installing from {} - any program running as your user can replace the \
             service executable. Development only.",
            running_exe.display()
        );
        running_exe
    } else {
        // The app is a single file that may sit anywhere (Desktop, Downloads).
        // A service runs as SYSTEM, so it must start from a folder only
        // administrators can write to: put a copy there. We are elevated, so
        // this is the one moment the copy can't be tampered with by a user.
        deploy(&running_exe)?
    };
    deterium_net::ensure_wintun().map_err(|e| format!("couldn't set up the Wintun driver: {e}"))?;

    let manager = open_manager(SC_MANAGER_CREATE_SERVICE)?;
    let name = wide(SERVICE_NAME);
    let display = wide("Deterium VPN");
    let command = wide(format!("{} service run --allow-sid {}", quote(&exe), sid));
    // SAFETY: all strings are NUL-terminated and outlive the call.
    let service = unsafe {
        CreateServiceW(
            manager.0,
            name.as_ptr(),
            display.as_ptr(),
            DELETE | SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_STATUS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(), // LocalSystem
            std::ptr::null(),
        )
    };
    if service.is_null() {
        return Err(format!(
            "couldn't create the service: {}",
            std::io::Error::last_os_error()
        ));
    }
    let service = Handle(service);

    let mut description =
        wide("Keeps your Deterium VPN tunnel and kill switch running for the app.");
    let info = SERVICE_DESCRIPTIONW {
        lpDescription: description.as_mut_ptr(),
    };
    // Restart by itself after a crash (5 s, 5 s, 30 s), so protection comes back.
    let mut actions = [
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5_000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5_000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 30_000,
        },
    ];
    let failure = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 86_400,
        lpRebootMsg: std::ptr::null_mut(),
        lpCommand: std::ptr::null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    // SAFETY: both structures are fully initialised and live across the calls.
    unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DESCRIPTION,
            &info as *const _ as *const _,
        );
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            &failure as *const _ as *const _,
        );
        if StartServiceW(service.0, 0, std::ptr::null()) == 0 {
            return Err(format!(
                "the service was installed but didn't start: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    wait_for(&service, SERVICE_RUNNING, Duration::from_secs(15))
        .map_err(|_| "the service was installed but didn't reach the running state".to_string())
}

pub fn uninstall() -> Result<(), String> {
    if !deterium_engine::is_elevated() {
        return Err("removing the service needs administrator rights".into());
    }
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let Some(service) = open_service(&manager, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE) else {
        // SAFETY: plain thread-local error query.
        return if unsafe { GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST {
            Ok(())
        } else {
            Err(format!(
                "couldn't open the service: {}",
                std::io::Error::last_os_error()
            ))
        };
    };

    if current_state(&service) != Some(SERVICE_STOPPED) {
        // SAFETY: valid service handle and an out-buffer of the right type.
        unsafe {
            let mut status: SERVICE_STATUS = std::mem::zeroed();
            ControlService(service.0, SERVICE_CONTROL_STOP, &mut status);
        }
        wait_for(&service, SERVICE_STOPPED, Duration::from_secs(20))
            .map_err(|_| "the service didn't stop in time".to_string())?;
    }
    // SAFETY: valid service handle opened with DELETE access.
    if unsafe { DeleteService(service.0) } == 0 {
        return Err(format!(
            "couldn't delete the service: {}",
            std::io::Error::last_os_error()
        ));
    }
    drop(service);
    remove_deployed_files();
    Ok(())
}

fn wait_for(service: &Handle, wanted: u32, timeout: Duration) -> Result<(), ()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if current_state(service) == Some(wanted) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_program_files_counts_as_protected() {
        std::env::set_var("ProgramFiles", r"C:\Program Files");
        assert!(is_in_protected_location(Path::new(
            r"C:\Program Files\Deterium\Deterium.exe"
        )));
        assert!(is_in_protected_location(Path::new(
            r"c:\program files\Deterium\Deterium.exe"
        )));
        assert!(!is_in_protected_location(Path::new(
            r"C:\Users\me\Desktop\Deterium-VPN\target\debug\Deterium.exe"
        )));
        // A look-alike folder must not pass.
        assert!(!is_in_protected_location(Path::new(
            r"C:\Program Files Evil\Deterium.exe"
        )));
    }
}
