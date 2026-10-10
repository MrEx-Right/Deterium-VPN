//! Windows named-pipe transport. See the crate docs and ADR 0004.

use crate::proto::{PIPE_NAME, PROTOCOL_VERSION, SERVICE_NAME};
use crate::{read_message, write_message, IpcError, Request, Response};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{atomic::AtomicBool, Arc};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeServerProcessId,
    WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
};
use windows_sys::Win32::System::IO::CancelIoEx;

/// Clients get exactly: read data, write data, read attributes, read the
/// security descriptor, synchronize. Notably *not* "append data", which on a
/// pipe means "create another instance of this pipe".
const CLIENT_RIGHTS: u32 = 0x0012_0083;
/// What a client asks for when opening: read + write data + synchronize.
const CLIENT_ACCESS: u32 = 0x0010_0003;
/// The server may learn who we are but may not act as us.
const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

const MAX_CLIENT_THREADS: usize = 32;

fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// The access list for the pipe: SYSTEM and Administrators in full, plus the
/// listed users with [`CLIENT_RIGHTS`]. A SID that isn't well-formed is
/// dropped rather than being allowed to alter the descriptor.
pub fn pipe_access_list(allowed_sids: &[String]) -> String {
    let mut sddl = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    for sid in allowed_sids {
        if is_sid(sid) {
            sddl.push_str(&format!("(A;;0x{CLIENT_RIGHTS:x};;;{sid})"));
        }
    }
    sddl
}

fn is_sid(text: &str) -> bool {
    text.starts_with("S-1-")
        && text.len() < 200
        && text[2..].chars().all(|c| c.is_ascii_digit() || c == '-')
        && !text.ends_with('-')
        && !text.contains("--")
}

fn create_instance(name: &str, sddl: &str, first: bool) -> io::Result<File> {
    let name = wide(name);
    let sddl = wide(sddl);
    let mut descriptor = null_mut();
    // SAFETY: both buffers are NUL-terminated and outlive the call; the
    // descriptor it allocates is freed below.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let mut open_mode = PIPE_ACCESS_DUPLEX;
        if first {
            // Fails if the name is already taken, so nobody can squat it first.
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let handle = CreateNamedPipeW(
            name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            64 * 1024,
            64 * 1024,
            0,
            &attributes,
        );
        let error = io::Error::last_os_error();
        LocalFree(descriptor as _);
        if handle == INVALID_HANDLE_VALUE {
            return Err(error);
        }
        Ok(File::from_raw_handle(handle as RawHandle))
    }
}

/// Serves requests on the pipe until `stop` is set (then call [`wake`]).
/// Every connection is answered on its own thread.
pub fn serve(
    name: &str,
    allowed_sids: &[String],
    stop: Arc<AtomicBool>,
    handler: Arc<dyn Fn(Request) -> Response + Send + Sync>,
) -> io::Result<()> {
    serve_with_access_list(name, &pipe_access_list(allowed_sids), stop, handler)
}

/// [`serve`] with an explicit access list (SDDL). Every new pipe instance
/// needs the "create pipe instance" right for whoever runs the server; the
/// service runs as SYSTEM, which the standard list covers, but a test running
/// as an ordinary user has to grant itself that right.
pub fn serve_with_access_list(
    name: &str,
    sddl: &str,
    stop: Arc<AtomicBool>,
    handler: Arc<dyn Fn(Request) -> Response + Send + Sync>,
) -> io::Result<()> {
    let sddl = sddl.to_string();
    let active = Arc::new(AtomicUsize::new(0));
    let mut first = true;

    loop {
        // Backpressure instead of unbounded threads: with too many clients in
        // flight, new ones simply wait (each is bounded by IO_BUDGET).
        while active.load(Ordering::SeqCst) >= MAX_CLIENT_THREADS && !stop.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(20));
        }
        let pipe = create_instance(name, &sddl, first)?;
        first = false;

        // SAFETY: the handle is valid for as long as `pipe` is alive.
        let connected = unsafe {
            ConnectNamedPipe(pipe.as_raw_handle() as _, null_mut()) != 0
                || GetLastError() == ERROR_PIPE_CONNECTED
        };
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        if !connected {
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let handler = handler.clone();
        let active = active.clone();
        thread::spawn(move || {
            answer(pipe, &*handler);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// How long a client gets to send its request, and then to take the answer.
/// Without a limit, a client that connects and says nothing (or never reads)
/// would hold a server thread forever, and sixteen of them would lock everyone
/// else out. The time the request itself takes to run is not counted.
const IO_BUDGET: Duration = Duration::from_secs(10);

/// Runs `io` and cancels whatever I/O is still pending on `pipe` if it takes
/// longer than [`IO_BUDGET`].
fn within_budget<R>(pipe: &Arc<File>, io: impl FnOnce() -> R) -> R {
    let (done, wait) = std::sync::mpsc::channel::<()>();
    let watched = pipe.clone();
    let watchdog = thread::spawn(move || {
        if wait.recv_timeout(IO_BUDGET).is_err() {
            // SAFETY: `watched` keeps the handle open for this call.
            unsafe { CancelIoEx(watched.as_raw_handle() as _, std::ptr::null()) };
        }
    });
    let result = io();
    let _ = done.send(());
    let _ = watchdog.join();
    result
}

fn answer(pipe: File, handler: &(dyn Fn(Request) -> Response + Send + Sync)) {
    let pipe = Arc::new(pipe);
    let request = within_budget(&pipe, || read_message::<Request>(&*pipe));
    let response = match request {
        Ok(request) => handler(request),
        Err(err) => Response::Error {
            kind: crate::proto::ErrorKind::BadRequest,
            message: err.to_string(),
        },
    };
    within_budget(&pipe, || {
        let _ = write_message(&*pipe, &response);
        let handle = pipe.as_raw_handle() as _;
        // SAFETY: the handle belongs to `pipe`, which is alive. Flushing waits
        // until the client has read the answer; only then is it cut off.
        unsafe {
            FlushFileBuffers(handle);
            DisconnectNamedPipe(handle);
        }
    });
}

/// Unblocks a `serve` loop that is waiting for a client, so it can notice
/// `stop` has been set. A single attempt can miss (every instance may be busy
/// with a client at that instant), so callers repeat it until the server
/// thread has finished; see [`stop_server`].
pub fn wake(name: &str) {
    let _ = OpenOptions::new().read(true).write(true).open(name);
}

/// Sets `stop` and keeps waking the server until its thread has ended.
pub fn stop_server<T>(
    name: &str,
    stop: &AtomicBool,
    thread: thread::JoinHandle<T>,
) -> thread::Result<T> {
    stop.store(true, Ordering::SeqCst);
    let give_up = Instant::now() + Duration::from_secs(10);
    while !thread.is_finished() && Instant::now() < give_up {
        wake(name);
        thread::sleep(Duration::from_millis(50));
    }
    thread.join()
}

/// The app's side. Connects to the service, checks that it really is the
/// service, sends one request and returns the answer.
pub struct Client {
    pipe: String,
    expected_service: Option<String>,
}

impl Client {
    /// The real service: the pipe's server must be the process Windows reports
    /// for the `DeteriumVPN` service.
    pub fn new() -> Self {
        Self {
            pipe: PIPE_NAME.to_string(),
            expected_service: Some(SERVICE_NAME.to_string()),
        }
    }

    /// A client for an arbitrary pipe **without** checking who serves it.
    /// For tests of the transport only; never use it with real profiles.
    pub fn unverified_for_tests(pipe: &str) -> Self {
        Self {
            pipe: pipe.to_string(),
            expected_service: None,
        }
    }

    pub fn call(&self, request: &Request) -> Result<Response, IpcError> {
        let mut pipe = self.open()?;
        if let Some(service) = &self.expected_service {
            verify_server(&pipe, service)?;
        }
        write_message(&mut pipe, request)?;
        read_message(&mut pipe)
    }

    /// Calls `Hello` and checks the protocol version.
    pub fn handshake(&self) -> Result<(), IpcError> {
        match self.call(&Request::Hello)? {
            Response::Hello { protocol, .. } if protocol == PROTOCOL_VERSION => Ok(()),
            Response::Hello { protocol, .. } => Err(IpcError::VersionMismatch {
                found: protocol,
                expected: PROTOCOL_VERSION,
            }),
            other => Err(IpcError::Protocol(format!("unexpected reply {other:?}"))),
        }
    }

    fn open(&self) -> Result<File, IpcError> {
        let name = wide(&self.pipe);
        let give_up = Instant::now() + Duration::from_secs(3);
        loop {
            let opened = OpenOptions::new()
                .access_mode(CLIENT_ACCESS)
                .security_qos_flags(SECURITY_IDENTIFICATION)
                .open(&self.pipe);
            match opened {
                Ok(file) => return Ok(file),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                    if Instant::now() > give_up {
                        return Err(IpcError::Io(e));
                    }
                    // SAFETY: NUL-terminated name that outlives the call.
                    unsafe { WaitNamedPipeW(name.as_ptr(), 500) };
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(IpcError::Unavailable),
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    return Err(IpcError::Denied)
                }
                Err(e) => return Err(IpcError::Io(e)),
            }
        }
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

/// Fails unless the process serving `pipe` is the running Windows service
/// named `service`.
fn verify_server(pipe: &File, service: &str) -> Result<(), IpcError> {
    let mut server_pid = 0u32;
    // SAFETY: valid pipe handle and a valid out-pointer.
    let ok = unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle() as _, &mut server_pid) };
    if ok == 0 {
        return Err(IpcError::Untrusted("can't identify the server".into()));
    }
    match service_process_id(service) {
        Some(pid) if pid == server_pid => Ok(()),
        Some(pid) => Err(IpcError::Untrusted(format!(
            "served by process {server_pid}, but the service runs as {pid}"
        ))),
        None => Err(IpcError::Untrusted("the service isn't running".into())),
    }
}

/// The process id of a running service, if it has one.
pub fn service_process_id(service: &str) -> Option<u32> {
    let name = wide(service);
    // SAFETY: handles are closed on every path; the buffer is a correctly
    // sized SERVICE_STATUS_PROCESS.
    unsafe {
        let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return None;
        }
        let handle = OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS);
        let mut pid = None;
        if !handle.is_null() {
            let mut status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
            let mut needed = 0u32;
            if QueryServiceStatusEx(
                handle,
                SC_STATUS_PROCESS_INFO,
                &mut status as *mut _ as *mut u8,
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            ) != 0
                && status.dwProcessId != 0
            {
                pid = Some(status.dwProcessId);
            }
            CloseServiceHandle(handle);
        }
        CloseServiceHandle(manager);
        pid
    }
}

/// Whether the service is installed and running. Needs no special rights.
pub fn service_state() -> crate::ServiceState {
    use crate::ServiceState;
    use windows_sys::Win32::System::Services::SERVICE_RUNNING;

    let name = wide(SERVICE_NAME);
    // SAFETY: handles are closed on every path; the buffer is a correctly
    // sized SERVICE_STATUS_PROCESS.
    unsafe {
        let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return ServiceState::NotInstalled;
        }
        let handle = OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS);
        let state = if handle.is_null() {
            ServiceState::NotInstalled
        } else {
            let mut status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
            let mut needed = 0u32;
            let ok = QueryServiceStatusEx(
                handle,
                SC_STATUS_PROCESS_INFO,
                &mut status as *mut _ as *mut u8,
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            ) != 0;
            CloseServiceHandle(handle);
            if ok && status.dwCurrentState == SERVICE_RUNNING {
                ServiceState::Running
            } else {
                ServiceState::Stopped
            }
        };
        CloseServiceHandle(manager);
        state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_access_list_names_only_well_formed_sids() {
        let list = pipe_access_list(&[
            "S-1-5-21-1-2-3-1001".into(),
            "S-1-5-21)(A;;GA;;;WD".into(),
            "everyone".into(),
        ]);
        assert!(list.starts_with("D:P(A;;GA;;;SY)(A;;GA;;;BA)"));
        assert!(list.contains(";;;S-1-5-21-1-2-3-1001)"));
        assert!(!list.contains("WD"), "an injected ACE must be dropped");
        assert!(!list.contains("everyone"));
        assert!(
            !list.contains("GA;;;S-1"),
            "users get specific rights, never generic-all"
        );
    }
}
