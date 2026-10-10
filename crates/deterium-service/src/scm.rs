//! Running as a Windows service: registers with the Service Control Manager,
//! serves the pipe, and shuts the tunnel down cleanly when told to stop.

use crate::manager::{EngineConnector, Manager};
use deterium_ipc::proto::{PIPE_NAME, SERVICE_NAME};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

static STOP: AtomicBool = AtomicBool::new(false);
static STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ALLOWED_SIDS: OnceLock<Vec<String>> = OnceLock::new();
static LAST_STATE: Mutex<u32> = Mutex::new(SERVICE_START_PENDING);

fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Hands control to the Service Control Manager. Returns an error when the
/// program was started from a console instead of by Windows.
pub fn run_as_service(allowed_sids: Vec<String>) -> Result<(), String> {
    let _ = ALLOWED_SIDS.set(allowed_sids);
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: the table is terminated by a null entry and outlives the call,
    // which only returns once the service has stopped.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

fn report(state: u32, exit_code: u32) {
    let handle = STATUS_HANDLE.load(Ordering::SeqCst);
    if handle.is_null() {
        return;
    }
    *LAST_STATE.lock().unwrap_or_else(|e| e.into_inner()) = state;
    let accepted = if state == SERVICE_RUNNING {
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    } else {
        0
    };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: if state == SERVICE_RUNNING || state == SERVICE_STOPPED {
            0
        } else {
            15_000
        },
    };
    // SAFETY: the handle came from RegisterServiceCtrlHandlerExW.
    unsafe { SetServiceStatus(handle as SERVICE_STATUS_HANDLE, &status) };
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            STOP.store(true, Ordering::SeqCst);
            report(SERVICE_STOP_PENDING, 0);
        }
        SERVICE_CONTROL_INTERROGATE => {
            let state = *LAST_STATE.lock().unwrap_or_else(|e| e.into_inner());
            report(state, 0);
        }
        _ => {}
    }
    NO_ERROR
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide(SERVICE_NAME);
    let handle =
        RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), std::ptr::null());
    if handle.is_null() {
        return;
    }
    STATUS_HANDLE.store(handle, Ordering::SeqCst);
    report(SERVICE_START_PENDING, 0);

    let exit_code = match serve_until_stopped(&STOP, || report(SERVICE_RUNNING, 0)) {
        Ok(()) => 0,
        Err(message) => {
            crate::log(&format!("service failed: {message}"));
            1
        }
    };
    report(SERVICE_STOPPED, exit_code);
}

/// The service's whole life: clean up after a crashed predecessor, serve the
/// pipe, and on `stop` take the tunnel down. `on_ready` is called once the
/// pipe is up. Also used by the foreground `console` mode.
pub fn serve_until_stopped(
    stop: &'static AtomicBool,
    on_ready: impl FnOnce(),
) -> Result<(), String> {
    let leftovers = deterium_engine::recover_leftovers();
    if leftovers > 0 {
        crate::log(&format!(
            "cleaned up {leftovers} network change(s) from a previous run"
        ));
    }

    let manager = Arc::new(Manager::new(Box::new(EngineConnector)));
    let allowed = ALLOWED_SIDS.get().cloned().unwrap_or_default();
    let stop_flag = Arc::new(AtomicBool::new(false));

    let server = {
        let manager = manager.clone();
        let stop_flag = stop_flag.clone();
        thread::spawn(move || {
            deterium_ipc::serve(
                PIPE_NAME,
                &allowed,
                stop_flag,
                Arc::new(move |request| manager.handle(request)),
            )
        })
    };

    // Give the server a moment to claim the pipe; if it can't (the name is
    // already taken), it ends immediately and that is a startup failure.
    thread::sleep(Duration::from_millis(300));
    if server.is_finished() {
        return match server.join() {
            Ok(Err(e)) => Err(format!("couldn't create the pipe: {e}")),
            _ => Err("the pipe server stopped unexpectedly".into()),
        };
    }
    crate::log("service started");
    on_ready();

    while !stop.load(Ordering::SeqCst) && !server.is_finished() {
        thread::sleep(Duration::from_millis(200));
    }

    crate::log("service stopping");
    let _ = deterium_ipc::stop_server(PIPE_NAME, &stop_flag, server);
    manager.shutdown();
    crate::log("service stopped");
    Ok(())
}

/// Foreground mode (`console`): the same service loop without the Service
/// Control Manager, for debugging.
pub fn serve_with_sids(allowed_sids: Vec<String>, stop: &'static AtomicBool) -> Result<(), String> {
    let _ = ALLOWED_SIDS.set(allowed_sids);
    serve_until_stopped(stop, || println!("the pipe is up"))
}
