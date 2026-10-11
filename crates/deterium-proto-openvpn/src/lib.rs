//! OpenVPN `ProtocolAdapter`: drives the system `openvpn` client as a child
//! process (Deterium does not reimplement the protocol).
//!
//! The profile's `.ovpn` text is written to a private temp directory, the
//! client is started against it, and its log output is read to work out the
//! tunnel state ("Initialization Sequence Completed" = connected). Creating
//! the network adapter and routes is OpenVPN's job and usually needs
//! administrator rights; if it can't, its own error ends up in
//! [`OpenVpnTunnelHandle::recent_log`] so the UI can show the real reason.
//!
//! Imported configs are untrusted, so directives that make OpenVPN run
//! programs (`up`, `down`, `script-security 2`, ...) are refused up front.

mod bundled;
mod killswitch;

pub use bundled::{available as bundled_available, version as bundled_version};

/// The servers a `.ovpn` can connect to (names resolved), for callers that
/// need to keep a firewall hole open to them without running OpenVPN.
pub fn configured_servers(raw_config: &str) -> Vec<Server> {
    killswitch::resolve_servers(
        &killswitch::parse_remotes(raw_config),
        killswitch::system_resolver,
    )
}

use deterium_core::validate::risky_openvpn_directives;
use deterium_core::{AdapterError, ProtocolAdapter, SecurityOptions, ServerProfile, TunnelStatus};
use deterium_net::{LeakPolicy, Server};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LOG_CAPACITY: usize = 80;
const EXIT_POLL: Duration = Duration::from_millis(200);

pub struct OpenVpnConnectionConfig {
    raw_config: String,
    /// Username and password for servers that use `auth-user-pass`.
    login: Option<(String, String)>,
    /// Kill switch / DNS-leak settings from the profile.
    security: SecurityOptions,
}

struct Shared {
    status: Mutex<TunnelStatus>,
    log: Mutex<VecDeque<String>>,
    stopping: AtomicBool,
    /// Server addresses OpenVPN reported using, for the firewall rules.
    learned: Mutex<Vec<Server>>,
    /// What the server pushed (DNS servers, full tunnel).
    push: Mutex<killswitch::PushInfo>,
    /// The installed kill-switch rules. Dropping them removes the rules.
    guard: Mutex<Option<Box<dyn Send>>>,
    /// The block that holds from before OpenVPN starts until the full rules
    /// replace it (or the connection fails before it ever came up).
    hold: Mutex<Option<Hold>>,
}

/// The temporary block while OpenVPN is connecting.
struct Hold {
    guard: Box<dyn Send>,
    /// The servers it permits.
    servers: Vec<Server>,
}

type Installer = Box<dyn Fn(&LeakPolicy) -> Result<Box<dyn Send>, String> + Send + Sync>;
/// Installs a hold: the servers to permit, whether the local network is
/// allowed, and whether DNS lookups are (OpenVPN resolving its own `remote`).
type HoldInstaller =
    Box<dyn Fn(Vec<Server>, bool, bool) -> Result<Box<dyn Send>, String> + Send + Sync>;

/// Everything needed to put the kill switch in place once the tunnel is up.
struct Protection {
    security: SecurityOptions,
    /// Servers named in the config (names already resolved).
    configured: Vec<Server>,
    /// The servers the installed rules were built for.
    installed_for: Mutex<Vec<Server>>,
    installer: Installer,
    hold_installer: HoldInstaller,
    /// The config names servers OpenVPN has to look up itself.
    allow_dns_lookup: bool,
}

impl Protection {
    fn new(
        security: SecurityOptions,
        configured: Vec<Server>,
        allow_dns_lookup: bool,
        installer: Installer,
        hold_installer: HoldInstaller,
    ) -> Option<Self> {
        (security.kill_switch || security.block_dns_leaks).then(|| Self {
            security,
            configured,
            installed_for: Mutex::new(Vec::new()),
            installer,
            hold_installer,
            allow_dns_lookup,
        })
    }

    /// Blocks everything except the VPN servers, *before* OpenVPN starts, so
    /// not even the first seconds of the connection are exposed. Only for the
    /// kill switch: DNS-leak blocking alone must not cut off name lookups
    /// while connecting. Fails closed, like [`Protection::install`].
    fn start_hold(&self, shared: &Shared) -> Result<(), String> {
        if !self.security.kill_switch {
            return Ok(());
        }
        let guard = (self.hold_installer)(
            self.configured.clone(),
            self.security.allow_lan,
            self.allow_dns_lookup,
        )?;
        *shared.hold.lock().expect("hold mutex poisoned") = Some(Hold {
            guard,
            servers: self.configured.clone(),
        });
        Ok(())
    }

    /// If OpenVPN is talking to a server the hold doesn't permit yet (a name
    /// that resolved differently, a `<connection>` block), let it through.
    fn widen_hold(&self, shared: &Shared) {
        let mut hold = shared.hold.lock().expect("hold mutex poisoned");
        let Some(current) = hold.as_mut() else {
            return;
        };
        let mut servers = current.servers.clone();
        for learned in shared
            .learned
            .lock()
            .expect("learned mutex poisoned")
            .iter()
        {
            if !servers.contains(learned) {
                servers.push(*learned);
            }
        }
        if servers == current.servers {
            return;
        }
        // New rules first, old ones after: there is never a moment without any.
        match (self.hold_installer)(
            servers.clone(),
            self.security.allow_lan,
            self.allow_dns_lookup,
        ) {
            Ok(guard) => {
                let old = std::mem::replace(&mut current.guard, guard);
                current.servers = servers;
                drop(old);
            }
            Err(why) => shared.push_log(format!(
                "Deterium: couldn't let the connection reach the server OpenVPN is using ({why})"
            )),
        }
    }

    /// Installs (or refreshes) the rules. Fails closed: an error is reported to
    /// the caller, which then ends the connection rather than leaving the user
    /// connected without the protection they asked for.
    fn install(&self, shared: &Shared) -> Result<(), String> {
        let mut servers = self.configured.clone();
        for learned in shared
            .learned
            .lock()
            .expect("learned mutex poisoned")
            .iter()
        {
            if !servers.contains(learned) {
                servers.push(*learned);
            }
        }
        let mut installed = self.installed_for.lock().expect("installed mutex poisoned");
        let mut guard = shared.guard.lock().expect("guard mutex poisoned");
        if guard.is_some() && *installed == servers {
            return Ok(());
        }

        let push = shared.push.lock().expect("push mutex poisoned").clone();
        let Some(policy) = killswitch::build_policy(&self.security, servers.clone(), &push) else {
            return Ok(());
        };
        // New rules first, old ones after: there is never a moment without any.
        let new_guard = (self.installer)(&policy)?;
        let old = guard.replace(new_guard);
        drop(old);
        *installed = servers;
        // The full rules are in force: the temporary block is no longer needed.
        drop(shared.hold.lock().expect("hold mutex poisoned").take());
        Ok(())
    }
}

impl Shared {
    fn new() -> Self {
        Self {
            status: Mutex::new(TunnelStatus::Connecting),
            log: Mutex::new(VecDeque::new()),
            stopping: AtomicBool::new(false),
            learned: Mutex::new(Vec::new()),
            push: Mutex::new(killswitch::PushInfo::default()),
            guard: Mutex::new(None),
            hold: Mutex::new(None),
        }
    }

    /// The connection failed before it ever came up: lift the temporary block
    /// so a failed attempt (wrong password, dead server) doesn't leave the PC
    /// offline. A tunnel that was up keeps its kill switch.
    fn release_hold_if_never_connected(&self) {
        if self.guard.lock().expect("guard mutex poisoned").is_some() {
            return;
        }
        if self
            .hold
            .lock()
            .expect("hold mutex poisoned")
            .take()
            .is_some()
        {
            self.push_log(
                "Deterium: the connection did not come up, so the temporary block was lifted and your internet access is back to normal"
                    .to_string(),
            );
        }
    }

    fn set_status(&self, status: TunnelStatus) {
        *self.status.lock().expect("status mutex poisoned") = status;
    }

    fn push_log(&self, line: String) {
        let mut log = self.log.lock().expect("log mutex poisoned");
        if log.len() == LOG_CAPACITY {
            log.pop_front();
        }
        log.push_back(line);
    }
}

/// A named Windows event OpenVPN watches (`--service`): signalling it makes
/// OpenVPN exit *cleanly*, removing its routes and its adapter. Killing the
/// process instead can leave routes pointing at a dead adapter, which cuts the
/// PC off the network, so that is only the fallback.
#[cfg(windows)]
struct ExitEvent {
    handle: windows_sys::Win32::Foundation::HANDLE,
    name: String,
}

// SAFETY: a kernel event handle may be used from any thread.
#[cfg(windows)]
unsafe impl Send for ExitEvent {}
#[cfg(windows)]
unsafe impl Sync for ExitEvent {}

#[cfg(windows)]
impl ExitEvent {
    fn create() -> Option<Self> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::System::Threading::CreateEventW;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let name = format!(
            "Global\\deterium-openvpn-exit-{}-{nanos}",
            std::process::id()
        );
        let wide: Vec<u16> = std::ffi::OsStr::new(&name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: NUL-terminated name; manual-reset, initially not signalled.
        let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, wide.as_ptr()) };
        (!handle.is_null()).then_some(Self { handle, name })
    }

    fn signal(&self) {
        // SAFETY: the handle is open until `drop`.
        unsafe { windows_sys::Win32::System::Threading::SetEvent(self.handle) };
    }
}

#[cfg(windows)]
impl Drop for ExitEvent {
    fn drop(&mut self) {
        // SAFETY: closed exactly once.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
    }
}

#[cfg(not(windows))]
struct ExitEvent;

#[cfg(not(windows))]
impl ExitEvent {
    fn create() -> Option<Self> {
        None
    }
    fn signal(&self) {}
}

pub struct OpenVpnTunnelHandle {
    shared: Arc<Shared>,
    child: Arc<Mutex<Child>>,
    work_dir: Option<PathBuf>,
    threads: Vec<JoinHandle<()>>,
    exit_event: Option<Arc<ExitEvent>>,
    /// The Wintun adapter OpenVPN uses; removed after OpenVPN has left.
    adapter: Option<deterium_net::HeldAdapter>,
}

/// Waits for the process to end on its own.
fn wait_for_exit(child: &Arc<Mutex<Child>>, limit: Duration) -> bool {
    let deadline = std::time::Instant::now() + limit;
    while std::time::Instant::now() < deadline {
        let done = child
            .lock()
            .ok()
            .is_none_or(|mut c| c.try_wait().ok().flatten().is_some());
        if done {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

impl OpenVpnTunnelHandle {
    /// The most recent lines OpenVPN printed, oldest first.
    pub fn recent_log(&self) -> Vec<String> {
        self.shared
            .log
            .lock()
            .expect("log mutex poisoned")
            .iter()
            .cloned()
            .collect()
    }

    /// Whether the kill switch / DNS-leak rules are currently in place
    /// (including the temporary block that holds while connecting).
    pub fn leak_protection(&self) -> bool {
        self.shared
            .guard
            .lock()
            .expect("guard mutex poisoned")
            .is_some()
            || self
                .shared
                .hold
                .lock()
                .expect("hold mutex poisoned")
                .is_some()
    }

    fn shutdown(&mut self) {
        self.shared.stopping.store(true, Ordering::Relaxed);
        // Ask OpenVPN to leave by itself first so it undoes its own network
        // changes; only force it if it doesn't.
        let left_cleanly = self.exit_event.as_ref().is_some_and(|event| {
            event.signal();
            wait_for_exit(&self.child, Duration::from_secs(10))
        });
        if let Ok(mut child) = self.child.lock() {
            if !left_cleanly {
                kill_process_tree(child.id());
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        self.exit_event = None;
        if self.adapter.take().is_some() {
            // Whatever routes OpenVPN left on its adapter (it was killed, or
            // crashed) would blackhole the PC's traffic: remove them, *then*
            // let the adapter go.
            deterium_net::clear_adapter_routes(deterium_net::OPENVPN_ADAPTER_NAME);
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        if let Some(dir) = self.work_dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
        // The firewall rules go last, after OpenVPN, its routes and its adapter.
        *self.shared.guard.lock().expect("guard mutex poisoned") = None;
        *self.shared.hold.lock().expect("hold mutex poisoned") = None;
        self.shared.set_status(TunnelStatus::Disconnected);
    }
}

impl Drop for OpenVpnTunnelHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Debug)]
pub struct OpenVpnAdapter {
    /// OpenVPN creates its network adapter and routes itself, which needs
    /// administrator rights. Only tests turn this off.
    pub require_elevation: bool,
    /// Stop OpenVPN through its exit event so it removes its own routes and
    /// adapter. Only tests, which use a stand-in program, turn this off.
    pub real_program: bool,
}

impl Default for OpenVpnAdapter {
    fn default() -> Self {
        Self {
            require_elevation: true,
            real_program: true,
        }
    }
}

impl ProtocolAdapter for OpenVpnAdapter {
    type ConnectionConfig = OpenVpnConnectionConfig;
    type TunnelHandle = OpenVpnTunnelHandle;

    fn load_profile(
        &self,
        profile: &ServerProfile,
    ) -> Result<Self::ConnectionConfig, AdapterError> {
        let ovpn = profile
            .openvpn
            .as_ref()
            .ok_or_else(|| AdapterError::InvalidProfile("profile has no [openvpn] table".into()))?;

        if ovpn.raw_config.trim().is_empty() {
            return Err(AdapterError::InvalidProfile(
                "the .ovpn config is empty".into(),
            ));
        }
        if let Some(directive) = risky_openvpn_directives(&ovpn.raw_config).first() {
            return Err(AdapterError::InvalidProfile(format!(
                "the config uses `{directive}`, which can run programs on this PC"
            )));
        }

        let login = ovpn.login().map(|(u, p)| (u.to_string(), p.to_string()));
        if login.is_none() && ovpn.asks_for_login() {
            return Err(AdapterError::InvalidProfile(
                "this server asks for a username and password; enter them in the server's \
                 settings"
                    .into(),
            ));
        }

        Ok(OpenVpnConnectionConfig {
            raw_config: ovpn.raw_config.clone(),
            login,
            security: profile.security.clone(),
        })
    }

    fn connect(&self, config: Self::ConnectionConfig) -> Result<Self::TunnelHandle, AdapterError> {
        if self.require_elevation && !deterium_net::is_elevated() {
            return Err(AdapterError::PermissionRequired(
                "OpenVPN needs administrator rights to create its network adapter and routes"
                    .into(),
            ));
        }
        let binary = resolve_binary()?;

        // OpenVPN 2.6 doesn't create Wintun adapters, it opens an existing one.
        // (Stand-in programs in tests don't need it.)
        let adapter = if self.real_program && cfg!(windows) {
            Some(deterium_net::hold_openvpn_adapter().map_err(|e| {
                AdapterError::ConnectFailed(format!("couldn't prepare the network adapter: {e}"))
            })?)
        } else {
            None
        };

        // The kill switch is in force from *before* OpenVPN starts: a temporary
        // block that permits only the VPN servers (names in the config are
        // resolved now, before any rules exist). The full rules replace it the
        // moment OpenVPN says it is connected. If it can't be installed the
        // connection is refused rather than started unprotected; on any early
        // return below, dropping `shared` lifts it again.
        let shared = Arc::new(Shared::new());
        let protection = if self.real_program && cfg!(windows) {
            let remotes = killswitch::parse_remotes(&config.raw_config);
            let configured = if config.security.kill_switch {
                killswitch::resolve_servers(&remotes, killswitch::system_resolver)
            } else {
                Vec::new()
            };
            Protection::new(
                config.security.clone(),
                configured,
                killswitch::needs_name_lookup(&remotes),
                Box::new(|policy| {
                    deterium_net::guard_openvpn_leaks(policy).map_err(|e| e.to_string())
                }),
                Box::new(|servers, allow_lan, allow_dns| {
                    deterium_net::guard_openvpn_connecting(servers, allow_lan, allow_dns)
                        .map_err(|e| e.to_string())
                }),
            )
            .map(Arc::new)
        } else {
            None
        };
        if let Some(protection) = &protection {
            protection.start_hold(&shared).map_err(|e| {
                AdapterError::ConnectFailed(format!(
                    "couldn't block traffic while connecting ({e}); not connecting unprotected"
                ))
            })?;
        }

        let work_dir = make_work_dir()
            .map_err(|e| AdapterError::ConnectFailed(format!("create temp directory: {e}")))?;
        let config_path = work_dir.join("profile.ovpn");
        std::fs::write(&config_path, &config.raw_config)
            .map_err(|e| AdapterError::ConnectFailed(format!("write temp config: {e}")))
            .inspect_err(|_| {
                let _ = std::fs::remove_dir_all(&work_dir);
            })?;
        restrict_permissions(&config_path);

        // The login goes in its own owner-only file inside the private work
        // directory, which is deleted when the connection ends. It is never put
        // on the command line, where other programs could read it.
        let auth_path = match &config.login {
            Some((user, pass)) => {
                let path = work_dir.join("auth.txt");
                std::fs::write(&path, format!("{user}\n{pass}\n"))
                    .map_err(|e| AdapterError::ConnectFailed(format!("write login file: {e}")))
                    .inspect_err(|_| {
                        let _ = std::fs::remove_dir_all(&work_dir);
                    })?;
                restrict_permissions(&path);
                Some(path)
            }
            None => None,
        };

        let mut command = Command::new(&binary);
        command.arg("--config").arg(&config_path).args([
            "--verb",
            "3",
            "--script-security",
            "1",
            "--auth-nocache",
        ]);
        if cfg!(windows) {
            // Wintun is the one driver Deterium ships; naming it keeps OpenVPN
            // from picking a driver that isn't installed.
            command.args(["--windows-driver", "wintun"]);
            if adapter.is_some() {
                command.args(["--dev-node", deterium_net::OPENVPN_ADAPTER_NAME]);
            }
            if let Some(modules) = binary
                .parent()
                .and_then(Path::parent)
                .map(|root| root.join("ssl").join("modules"))
                .filter(|dir| dir.is_dir())
            {
                // Where OpenSSL finds its optional "legacy" algorithms.
                command.env("OPENSSL_MODULES", modules);
            }
        }
        let exit_event = if self.real_program {
            ExitEvent::create().map(Arc::new)
        } else {
            None
        };
        #[cfg(windows)]
        if let Some(event) = &exit_event {
            command.arg("--service").arg(&event.name).arg("0");
        }
        if let Some(path) = &auth_path {
            // After --config, so it takes precedence over a bare directive in it.
            command.arg("--auth-user-pass").arg(path);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        hide_console_window(&mut command);

        let mut child = command.spawn().map_err(|e| {
            let _ = std::fs::remove_dir_all(&work_dir);
            AdapterError::ConnectFailed(format!("start {}: {e}", binary.display()))
        })?;

        // Reader threads are deliberately detached: they end when OpenVPN's
        // pipes close, and waiting for that on shutdown could hang if a
        // grandchild process keeps a pipe open.
        if let Some(stdout) = child.stdout.take() {
            drop(spawn_reader(
                stdout,
                shared.clone(),
                protection.clone(),
                exit_event.clone(),
            ));
        }
        if let Some(stderr) = child.stderr.take() {
            drop(spawn_reader(
                stderr,
                shared.clone(),
                protection.clone(),
                exit_event.clone(),
            ));
        }

        let child = Arc::new(Mutex::new(child));
        let threads = vec![spawn_exit_watcher(child.clone(), shared.clone())];

        Ok(OpenVpnTunnelHandle {
            shared,
            child,
            work_dir: Some(work_dir),
            threads,
            exit_event,
            adapter,
        })
    }

    fn disconnect(&self, mut handle: Self::TunnelHandle) -> Result<(), AdapterError> {
        handle.shutdown();
        Ok(())
    }

    fn status(&self, handle: &Self::TunnelHandle) -> TunnelStatus {
        *handle.shared.status.lock().expect("status mutex poisoned")
    }
}

fn spawn_reader(
    stream: impl Read + Send + 'static,
    shared: Arc<Shared>,
    protection: Option<Arc<Protection>>,
    exit_event: Option<Arc<ExitEvent>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            handle_line(&line, &shared, protection.as_deref(), exit_event.as_deref());
        }
    })
}

/// Processes one line of OpenVPN output: remembers what the firewall rules
/// need to know, updates the status and, when the tunnel comes up, installs the
/// kill switch. If that fails the connection is ended and reported as an error.
fn handle_line(
    line: &str,
    shared: &Shared,
    protection: Option<&Protection>,
    exit_event: Option<&ExitEvent>,
) {
    {
        let learned = killswitch::servers_from_log(line);
        if !learned.is_empty() {
            {
                let mut known = shared.learned.lock().expect("learned mutex poisoned");
                for server in learned {
                    if !known.contains(&server) {
                        known.push(server);
                    }
                }
            }
            if let Some(protection) = protection {
                protection.widen_hold(shared);
            }
        }
        if let Some(push) = killswitch::push_from_log(line) {
            *shared.push.lock().expect("push mutex poisoned") = push;
        }
    }

    if let Some(status) = interpret_line(line) {
        if status == TunnelStatus::Error {
            shared.release_hold_if_never_connected();
        }
        if status == TunnelStatus::Connected {
            if let Some(protection) = protection {
                if let Err(why) = protection.install(shared) {
                    shared.push_log(format!(
                        "Deterium: couldn't install the kill switch ({why}); disconnecting rather than staying unprotected"
                    ));
                    shared.set_status(TunnelStatus::Error);
                    if let Some(event) = exit_event {
                        event.signal();
                    }
                    shared.push_log(line.to_string());
                    return;
                }
                shared.push_log("Deterium: kill switch / leak protection is active".to_string());
            }
        }
        shared.set_status(status);
    }
    shared.push_log(line.to_string());
}

/// Notices OpenVPN exiting on its own (bad config, missing privileges, ...).
fn spawn_exit_watcher(child: Arc<Mutex<Child>>, shared: Arc<Shared>) -> JoinHandle<()> {
    thread::spawn(move || loop {
        if shared.stopping.load(Ordering::Relaxed) {
            return;
        }
        let exited = child
            .lock()
            .ok()
            .and_then(|mut child| child.try_wait().ok().flatten());

        if let Some(code) = exited {
            if !shared.stopping.load(Ordering::Relaxed) {
                shared.push_log(format!("OpenVPN exited ({code})"));
                shared.release_hold_if_never_connected();
                shared.set_status(TunnelStatus::Error);
            }
            return;
        }
        thread::sleep(EXIT_POLL);
    })
}

/// Maps one line of OpenVPN output to a state change, if it implies one.
pub fn interpret_line(line: &str) -> Option<TunnelStatus> {
    if line.contains("Initialization Sequence Completed") {
        Some(TunnelStatus::Connected)
    } else if line.contains("AUTH_FAILED") || line.contains("Exiting due to fatal error") {
        Some(TunnelStatus::Error)
    } else if line.contains("Restart pause")
        || line.contains("SIGUSR1[soft")
        || line.contains("Inactivity timeout")
        || line.contains("Connection reset, restarting")
    {
        Some(TunnelStatus::Reconnecting)
    } else {
        None
    }
}

/// The `openvpn` program to run: `DETERIUM_OPENVPN` (development), else the
/// copy built into Deterium (unpacked to an administrator-only folder), else
/// one installed on the PC.
fn resolve_binary() -> Result<PathBuf, AdapterError> {
    if let Some(custom) = std::env::var_os("DETERIUM_OPENVPN") {
        let path = PathBuf::from(custom);
        if path.is_file() {
            return Ok(path);
        }
    }
    if bundled::available() {
        return bundled::ensure().map_err(|e| {
            AdapterError::ConnectFailed(format!(
                "couldn't set up the built-in OpenVPN in {}: {e}",
                bundled::deploy_dir().display()
            ))
        });
    }
    find_openvpn().ok_or_else(|| {
        AdapterError::ConnectFailed(
            "OpenVPN isn't installed. Install the OpenVPN client (openvpn.net/community-downloads) or set DETERIUM_OPENVPN to its path"
                .into(),
        )
    })
}

/// Finds an OpenVPN client: `DETERIUM_OPENVPN`, then the built-in copy (once
/// unpacked), then `PATH`, then the usual install locations.
pub fn find_openvpn() -> Option<PathBuf> {
    if let Some(custom) = std::env::var_os("DETERIUM_OPENVPN") {
        let path = PathBuf::from(custom);
        if path.is_file() {
            return Some(path);
        }
    }
    if bundled::available() {
        let path = bundled::exe_in(&bundled::deploy_dir());
        if path.is_file() {
            return Some(path);
        }
    }

    let names: &[&str] = if cfg!(windows) {
        &["openvpn.exe"]
    } else {
        &["openvpn"]
    };

    let from_path = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>());
    let known = [
        r"C:\Program Files\OpenVPN\bin",
        r"C:\Program Files (x86)\OpenVPN\bin",
        "/usr/sbin",
        "/usr/bin",
        "/usr/local/sbin",
        "/usr/local/bin",
        "/opt/homebrew/sbin",
    ]
    .map(PathBuf::from);

    from_path
        .chain(known)
        .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
        .find(|candidate| candidate.is_file())
}

/// Ends the process and everything it started. `openvpn` itself starts
/// nothing, but a launcher or wrapper in front of it does, and its children
/// would otherwise keep running (and keep the tunnel up) after "disconnect".
fn kill_process_tree(pid: u32) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .creation_flags(0x0800_0000)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(windows))]
    let _ = pid;
}

/// Where the per-connection config file lives. It can embed private keys, so
/// it goes in a folder only the current user can read (`%LOCALAPPDATA%` on
/// Windows, `$XDG_RUNTIME_DIR` on Linux) rather than the shared temp folder.
fn run_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(|base| PathBuf::from(base).join("Deterium").join("run"))
        .or_else(|| {
            std::env::var_os("XDG_RUNTIME_DIR").map(|base| PathBuf::from(base).join("deterium"))
        })
        .unwrap_or_else(|| std::env::temp_dir().join("deterium-run"))
}

/// A crash can leave a config file behind; remove ones from earlier runs.
fn purge_stale_work_dirs(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let day = Duration::from_secs(24 * 60 * 60);
    for entry in entries.flatten() {
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > day);
        if stale
            && entry
                .file_name()
                .to_string_lossy()
                .starts_with("deterium-ovpn-")
        {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

fn make_work_dir() -> std::io::Result<PathBuf> {
    let base = run_dir();
    std::fs::create_dir_all(&base)?;
    purge_stale_work_dirs(&base);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = base.join(format!("deterium-ovpn-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// The temp config can embed private keys; keep it owner-only where possible.
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn hide_console_window(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = command;
}

#[cfg(test)]
mod tests {
    use super::*;
    use deterium_core::import::parse_openvpn;
    use std::sync::atomic::AtomicUsize;

    fn profile(config: &str) -> ServerProfile {
        parse_openvpn(config, "test").unwrap().profile
    }

    /// Tests that point `DETERIUM_OPENVPN` at a stand-in must not overlap.
    static FAKE_OPENVPN: Mutex<()> = Mutex::new(());

    #[test]
    fn log_lines_map_to_states() {
        assert_eq!(
            interpret_line("Wed Oct  3 12:00:00 2026 Initialization Sequence Completed"),
            Some(TunnelStatus::Connected)
        );
        assert_eq!(
            interpret_line("AUTH: Received control message: AUTH_FAILED"),
            Some(TunnelStatus::Error)
        );
        assert_eq!(
            interpret_line("TLS: Initial packet from [AF_INET]1.2.3.4"),
            None
        );
    }

    /// Real output of `openvpn 2.6.19` connecting to a real OpenVPN 2.6 server
    /// (captured on 2026-10-04). Guards the log parsing against what the
    /// program actually prints rather than what we assume it prints.
    #[test]
    fn a_real_client_session_log_ends_connected_without_false_alarms() {
        let log = include_str!("../tests/fixtures/real-client-connect.log");
        let states: Vec<TunnelStatus> = log.lines().filter_map(interpret_line).collect();

        assert_eq!(states.last(), Some(&TunnelStatus::Connected));
        assert!(
            !states.contains(&TunnelStatus::Error) && !states.contains(&TunnelStatus::Reconnecting),
            "a healthy session must not produce error/reconnect states: {states:?}"
        );
        assert_eq!(states.len(), 1, "exactly one state change: {states:?}");
    }

    #[test]
    fn load_profile_refuses_programs_in_configs() {
        let bad = profile("client\nremote a 1194\nscript-security 2\nup /tmp/x\n");
        assert!(matches!(
            OpenVpnAdapter::default().load_profile(&bad),
            Err(AdapterError::InvalidProfile(_))
        ));
        let good = profile("client\nremote a 1194\n");
        assert!(OpenVpnAdapter::default().load_profile(&good).is_ok());
    }

    /// A kill switch whose "firewall" just records what it was asked for.
    fn recording_protection(
        kill: bool,
        fail: bool,
    ) -> (Protection, Arc<Mutex<Vec<LeakPolicy>>>, Arc<AtomicBool>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let released = Arc::new(AtomicBool::new(false));
        struct Release(Arc<AtomicBool>);
        impl Drop for Release {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let (log, flag) = (seen.clone(), released.clone());
        let protection = Protection::new(
            SecurityOptions {
                kill_switch: kill,
                allow_lan: true,
                block_dns_leaks: true,
            },
            vec![Server::tcp("203.0.113.5:443".parse().unwrap())],
            false,
            Box::new(move |policy| {
                if fail {
                    return Err("filter refused".into());
                }
                log.lock().unwrap().push(policy.clone());
                Ok(Box::new(Release(flag.clone())) as Box<dyn Send>)
            }),
            Box::new(|_, _, _| Ok(Box::new(()) as Box<dyn Send>)),
        )
        .unwrap();
        (protection, seen, released)
    }

    /// What a hold was asked to permit: servers, local network, DNS lookups.
    type HoldCall = (Vec<Server>, bool, bool);

    /// A protection whose hold "firewall" records its calls and counts how
    /// many holds are alive (a dropped hold is a lifted block).
    fn hold_protection(
        names_in_config: bool,
        fail: bool,
    ) -> (Protection, Arc<Mutex<Vec<HoldCall>>>, Arc<AtomicUsize>) {
        struct Alive(Arc<AtomicUsize>);
        impl Drop for Alive {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let calls = Arc::new(Mutex::new(Vec::new()));
        let alive = Arc::new(AtomicUsize::new(0));
        let (log, count) = (calls.clone(), alive.clone());
        let protection = Protection::new(
            SecurityOptions {
                kill_switch: true,
                allow_lan: false,
                block_dns_leaks: false,
            },
            vec![Server::udp("203.0.113.5:1194".parse().unwrap())],
            names_in_config,
            Box::new(|_| Ok(Box::new(()) as Box<dyn Send>)),
            Box::new(move |servers, lan, dns| {
                if fail {
                    return Err("filter refused".into());
                }
                log.lock().unwrap().push((servers, lan, dns));
                count.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(Alive(count.clone())) as Box<dyn Send>)
            }),
        )
        .unwrap();
        (protection, calls, alive)
    }

    #[test]
    fn the_hold_goes_in_before_openvpn_runs_and_permits_only_the_configured_servers() {
        let (protection, calls, alive) = hold_protection(true, false);
        let shared = Shared::new();
        protection.start_hold(&shared).unwrap();

        assert_eq!(alive.load(Ordering::SeqCst), 1);
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].0,
            vec![Server::udp("203.0.113.5:1194".parse().unwrap())]
        );
        assert!(!calls[0].1, "the local network was not asked for");
        assert!(calls[0].2, "OpenVPN has a name to look up itself");
        assert!(shared.hold.lock().unwrap().is_some());
        // The tunnel is not up yet, but traffic is already being held back.
        assert!(shared.guard.lock().unwrap().is_none());
    }

    #[test]
    fn a_hold_that_cannot_be_installed_is_an_error_not_silence() {
        let (protection, _, alive) = hold_protection(false, true);
        let shared = Shared::new();
        assert!(protection.start_hold(&shared).is_err());
        assert_eq!(alive.load(Ordering::SeqCst), 0);
        assert!(shared.hold.lock().unwrap().is_none());
    }

    #[test]
    fn dns_blocking_alone_does_not_hold_anything() {
        let (mut protection, calls, _) = hold_protection(false, false);
        protection.security.kill_switch = false;
        protection.security.block_dns_leaks = true;
        let shared = Shared::new();
        protection.start_hold(&shared).unwrap();
        assert!(calls.lock().unwrap().is_empty());
        assert!(shared.hold.lock().unwrap().is_none());
    }

    #[test]
    fn a_server_openvpn_turns_out_to_use_is_let_through_without_a_gap() {
        let (protection, calls, alive) = hold_protection(false, false);
        let shared = Shared::new();
        protection.start_hold(&shared).unwrap();

        handle_line(
            "TCP/UDP: Preserving recently used remote address: [AF_INET]192.0.2.77:443",
            &shared,
            Some(&protection),
            None,
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2, "the hold was widened once");
        assert!(calls[1]
            .0
            .contains(&Server::tcp("192.0.2.77:443".parse().unwrap())));
        assert!(calls[1]
            .0
            .contains(&Server::udp("203.0.113.5:1194".parse().unwrap())));
        assert_eq!(
            alive.load(Ordering::SeqCst),
            1,
            "the old hold is released after the new one exists"
        );
    }

    #[test]
    fn a_server_the_hold_already_permits_does_not_reinstall_it() {
        let (protection, calls, _) = hold_protection(false, false);
        let shared = Shared::new();
        protection.start_hold(&shared).unwrap();
        for _ in 0..2 {
            handle_line(
                "UDPv4 link remote: [AF_INET]203.0.113.5:1194",
                &shared,
                Some(&protection),
                None,
            );
        }
        // The log line names both protocols; UDP was configured, TCP is new.
        assert_eq!(calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn the_full_rules_replace_the_hold_when_the_tunnel_comes_up() {
        let (protection, _, alive) = hold_protection(false, false);
        let shared = Shared::new();
        protection.start_hold(&shared).unwrap();
        handle_line(UP, &shared, Some(&protection), None);

        assert_eq!(*shared.status.lock().unwrap(), TunnelStatus::Connected);
        assert!(shared.guard.lock().unwrap().is_some());
        assert!(shared.hold.lock().unwrap().is_none());
        assert_eq!(alive.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_connection_that_fails_before_it_came_up_does_not_leave_the_pc_offline() {
        let (protection, _, alive) = hold_protection(false, false);
        let shared = Shared::new();
        protection.start_hold(&shared).unwrap();
        handle_line(
            "AUTH: Received control message: AUTH_FAILED",
            &shared,
            Some(&protection),
            None,
        );
        assert_eq!(*shared.status.lock().unwrap(), TunnelStatus::Error);
        assert_eq!(alive.load(Ordering::SeqCst), 0, "the block is lifted");
        assert!(shared
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("back to normal")));
    }

    #[test]
    fn a_tunnel_that_was_up_keeps_its_kill_switch_when_it_errors() {
        let (protection, _, _) = hold_protection(false, false);
        let shared = Shared::new();
        protection.start_hold(&shared).unwrap();
        handle_line(UP, &shared, Some(&protection), None);
        handle_line(
            "AUTH: Received control message: AUTH_FAILED",
            &shared,
            Some(&protection),
            None,
        );
        assert!(
            shared.guard.lock().unwrap().is_some(),
            "once connected, an error must not open the floodgates"
        );
    }

    const PUSH: &str = "PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.8.0.1,ifconfig 10.8.0.2 255.255.255.0'";
    const UP: &str = "Initialization Sequence Completed";

    #[test]
    fn the_kill_switch_goes_in_when_the_tunnel_comes_up_and_not_before() {
        let (protection, seen, _) = recording_protection(true, false);
        let shared = Shared::new();

        handle_line(
            "UDPv4 link remote: [AF_INET]198.51.100.9:1194",
            &shared,
            Some(&protection),
            None,
        );
        handle_line(PUSH, &shared, Some(&protection), None);
        assert!(
            seen.lock().unwrap().is_empty(),
            "nothing is blocked before the tunnel is up"
        );
        assert_eq!(*shared.status.lock().unwrap(), TunnelStatus::Connecting);

        handle_line(UP, &shared, Some(&protection), None);
        let policies = seen.lock().unwrap();
        assert_eq!(policies.len(), 1);
        let policy = &policies[0];
        assert!(policy.kill_switch && policy.block_dns_leaks);
        // The configured server and the one OpenVPN actually used are both let through.
        assert!(policy
            .servers
            .contains(&Server::tcp("203.0.113.5:443".parse().unwrap())));
        assert!(policy
            .servers
            .contains(&Server::udp("198.51.100.9:1194".parse().unwrap())));
        assert_eq!(*shared.status.lock().unwrap(), TunnelStatus::Connected);
        assert!(shared.guard.lock().unwrap().is_some());
    }

    #[test]
    fn a_reconnect_to_the_same_servers_keeps_the_rules_it_has() {
        let (protection, seen, released) = recording_protection(true, false);
        let shared = Shared::new();
        handle_line(PUSH, &shared, Some(&protection), None);
        handle_line(UP, &shared, Some(&protection), None);
        handle_line(UP, &shared, Some(&protection), None);
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(!released.load(Ordering::SeqCst));
    }

    #[test]
    fn a_new_server_replaces_the_rules_without_a_gap() {
        let (protection, seen, released) = recording_protection(true, false);
        let shared = Shared::new();
        handle_line(UP, &shared, Some(&protection), None);
        handle_line(
            "TCP/UDP: Preserving recently used remote address: [AF_INET]192.0.2.77:443",
            &shared,
            Some(&protection),
            None,
        );
        handle_line(UP, &shared, Some(&protection), None);
        assert_eq!(seen.lock().unwrap().len(), 2);
        assert!(
            released.load(Ordering::SeqCst),
            "the old rules are released after the new ones exist"
        );
        assert!(shared.guard.lock().unwrap().is_some());
    }

    #[test]
    fn if_the_kill_switch_cannot_be_installed_the_connection_is_an_error() {
        let (protection, _, _) = recording_protection(true, true);
        let shared = Shared::new();
        handle_line(UP, &shared, Some(&protection), None);
        assert_eq!(*shared.status.lock().unwrap(), TunnelStatus::Error);
        assert!(shared
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("couldn't install the kill switch")));
        assert!(shared.guard.lock().unwrap().is_none());
    }

    #[test]
    fn without_protection_the_status_handling_is_unchanged() {
        let shared = Shared::new();
        handle_line(UP, &shared, None, None);
        assert_eq!(*shared.status.lock().unwrap(), TunnelStatus::Connected);
        assert!(shared.guard.lock().unwrap().is_none());
    }

    #[test]
    fn a_profile_with_no_protection_asked_for_gets_none() {
        let off = SecurityOptions {
            kill_switch: false,
            allow_lan: true,
            block_dns_leaks: false,
        };
        assert!(Protection::new(
            off,
            vec![],
            false,
            Box::new(|_| Err("unused".into())),
            Box::new(|_, _, _| Err("unused".into())),
        )
        .is_none());
    }

    #[test]
    fn a_login_is_required_when_the_server_asks_for_one() {
        let mut p = profile("client\nremote a 1194\nauth-user-pass\n");
        let adapter = OpenVpnAdapter::default();
        assert!(matches!(
            adapter.load_profile(&p),
            Err(AdapterError::InvalidProfile(m)) if m.contains("username")
        ));

        let ovpn = p.openvpn.as_mut().unwrap();
        ovpn.username = Some("alice".into());
        ovpn.password = Some("s3cret".into());
        assert!(adapter.load_profile(&p).is_ok());
    }

    #[test]
    fn configs_that_read_a_file_as_the_login_are_refused() {
        let p = profile("client\nremote a 1194\nauth-user-pass /etc/openvpn/secret.txt\n");
        assert!(matches!(
            OpenVpnAdapter::default().load_profile(&p),
            Err(AdapterError::InvalidProfile(_))
        ));
    }

    /// A stand-in for `openvpn` that records its arguments in `args_file`,
    /// prints the success line and then idles.
    fn fake_openvpn_recording_args(dir: &Path, args_file: &Path) -> PathBuf {
        if cfg!(windows) {
            let path = dir.join("fake-openvpn.bat");
            std::fs::write(
                &path,
                format!(
                    "@echo off\r\necho %*> \"{}\"\r\necho Initialization Sequence Completed\r\nping -n 60 127.0.0.1 >nul\r\n",
                    args_file.display()
                ),
            )
            .unwrap();
            path
        } else {
            let path = dir.join("fake-openvpn.sh");
            std::fs::write(
                &path,
                format!(
                    "#!/bin/sh\necho \"$@\" > '{}'\necho Initialization Sequence Completed\nsleep 60\n",
                    args_file.display()
                ),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            path
        }
    }

    /// The login reaches OpenVPN through a private file (never the command
    /// line) and that file disappears with the connection.
    #[test]
    fn the_login_is_passed_as_a_private_file_and_cleaned_up() {
        let _serial = FAKE_OPENVPN.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("fake-ovpn-auth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let args_file = dir.join("args.txt");
        let fake = fake_openvpn_recording_args(&dir, &args_file);

        let mut p = profile("client\nremote a 1194\nauth-user-pass\n");
        let ovpn = p.openvpn.as_mut().unwrap();
        ovpn.username = Some("alice".into());
        ovpn.password = Some("s3cret-pass".into());

        std::env::set_var("DETERIUM_OPENVPN", &fake);
        let adapter = OpenVpnAdapter {
            require_elevation: false,
            real_program: false,
        };
        let handle = adapter.connect(adapter.load_profile(&p).unwrap()).unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while adapter.status(&handle) != TunnelStatus::Connected {
            assert!(std::time::Instant::now() < deadline, "never connected");
            thread::sleep(Duration::from_millis(100));
        }

        let work_dir = handle.work_dir.clone().unwrap();
        assert_eq!(
            std::fs::read_to_string(work_dir.join("auth.txt")).unwrap(),
            "alice\ns3cret-pass\n"
        );
        let args = std::fs::read_to_string(&args_file).unwrap();
        assert!(args.contains("--auth-user-pass"), "args: {args}");
        assert!(args.contains("auth.txt"), "args: {args}");
        assert!(
            !args.contains("s3cret-pass") && !args.contains("alice"),
            "the login must never appear on the command line: {args}"
        );

        adapter.disconnect(handle).unwrap();
        assert!(!work_dir.exists(), "the login file must be removed");

        std::env::remove_var("DETERIUM_OPENVPN");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Full lifecycle against a stand-in `openvpn` that prints the success
    /// line and then idles — exercises spawn, log parsing, kill and cleanup.
    #[test]
    fn lifecycle_with_a_fake_openvpn() {
        let _serial = FAKE_OPENVPN.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("fake-ovpn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let fake = if cfg!(windows) {
            let path = dir.join("fake-openvpn.bat");
            std::fs::write(
                &path,
                "@echo off\r\necho Initialization Sequence Completed\r\nping -n 60 127.0.0.1 >nul\r\n",
            )
            .unwrap();
            path
        } else {
            let path = dir.join("fake-openvpn.sh");
            std::fs::write(
                &path,
                "#!/bin/sh\necho Initialization Sequence Completed\nsleep 60\n",
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            path
        };

        std::env::set_var("DETERIUM_OPENVPN", &fake);
        let adapter = OpenVpnAdapter {
            require_elevation: false,
            real_program: false,
        };
        let config = adapter
            .load_profile(&profile("client\nremote a 1194\n"))
            .unwrap();
        let handle = adapter.connect(config).unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while adapter.status(&handle) != TunnelStatus::Connected {
            assert!(
                std::time::Instant::now() < deadline,
                "never reached Connected"
            );
            thread::sleep(Duration::from_millis(100));
        }
        assert!(handle
            .recent_log()
            .iter()
            .any(|l| l.contains("Initialization Sequence Completed")));

        let work_dir = handle.work_dir.clone().unwrap();
        assert!(work_dir.join("profile.ovpn").exists());
        adapter.disconnect(handle).unwrap();
        assert!(
            !work_dir.exists(),
            "temp config must be removed on disconnect"
        );

        std::env::remove_var("DETERIUM_OPENVPN");
        let _ = std::fs::remove_dir_all(dir);
    }
}
