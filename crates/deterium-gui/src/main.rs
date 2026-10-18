//! `deterium-gui` — native desktop GUI (egui/eframe, no webview). See
//! ARCHITECTURE.md §5a.
//!
//! Everything a user does with servers happens here: add (wizard, import,
//! manual), edit every setting, duplicate, export, delete, connect. Servers
//! are plain `.toml` files in the user's data folder (see `store.rs`); connecting goes
//! through `deterium-engine`, the same engine the background service runs.
//!
//! Everything shown is real state — no placeholder speeds or IPs. WireGuard
//! completes a genuine handshake but no traffic is routed yet (no TUN
//! device), and the UI says so instead of pretending otherwise.

// A release build is a window app: no console box behind it.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod autostart;
mod draft;
mod editor;
mod hero;
mod insights;
mod logo;
mod store;
mod theme;
mod tray;

use deterium_core::export::{to_deterium_toml, to_wireguard_conf};
use deterium_core::{AdapterError, ConnectMode, Protocol, ServerProfile, TunnelStatus, Uuid};
use deterium_engine::{ServiceState, Tunnel};
use draft::Draft;
use editor::{ChooserAction, EditorAction, EditorState, Picked, WizardAction, WizardState};
use eframe::egui::{self, vec2, Align, Align2, Color32, Layout, Margin, RichText};
use hero::{add_row, endpoint_of, format_duration, power_button, server_row, StatusView};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use store::{Store, StoredProfile};
use theme::*;

const SLOW_CONNECT: Duration = Duration::from_secs(8);
const FRAME_INTERVAL: Duration = Duration::from_millis(33);
/// How often the service is asked whether it is holding the network.
const HELD_CHECK_EVERY: Duration = Duration::from_millis(1500);
/// Connecting at sign-in: right after Windows starts the network or the
/// service may not be up yet, so the app tries a few times before giving up.
const AUTOSTART_TRIES: u32 = 8;
const AUTOSTART_EVERY: Duration = Duration::from_secs(10);

/// A connection the app makes by itself when Windows starts it (see
/// [`autostart`]).
struct AutostartJob {
    id: Uuid,
    attempts: u32,
    next_try: Instant,
    /// The app has asked for the connection at least once. After that, being
    /// idle means the user disconnected, and the job ends.
    started: bool,
}

/// What the app's connection looks like from the point of view of an
/// [`AutostartJob`] for one server.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Seen {
    /// Up: the job is done.
    Connected,
    /// Being set up: wait.
    ComingUp,
    /// The server's tunnel gave up.
    Errored,
    /// Another server is connected: the user's choice now.
    Other,
    /// The request itself failed (network not ready yet, service not reachable).
    Failed,
    /// Nothing is happening.
    Idle,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AutostartStep {
    Wait,
    Finish,
    GiveUp,
    /// Connect now, first dropping the failed tunnel if there is one.
    Attempt {
        drop_current: bool,
    },
}

/// What to do next. Pure, so the retry rules are tested without a window.
fn autostart_step(job: &AutostartJob, seen: Seen, now: Instant) -> AutostartStep {
    match seen {
        Seen::Connected | Seen::Other => return AutostartStep::Finish,
        Seen::ComingUp => return AutostartStep::Wait,
        // Idle after the app asked: the user disconnected.
        Seen::Idle if job.started => return AutostartStep::Finish,
        Seen::Idle | Seen::Failed | Seen::Errored => {}
    }
    if now < job.next_try {
        return AutostartStep::Wait;
    }
    if job.attempts >= AUTOSTART_TRIES {
        return AutostartStep::GiveUp;
    }
    AutostartStep::Attempt {
        drop_current: seen == Seen::Errored,
    }
}

enum Connection {
    Idle,
    Active {
        profile: Uuid,
        tunnel: Tunnel,
        status: TunnelStatus,
        started: Instant,
        connected_at: Option<Instant>,
        mode: ConnectMode,
    },
    Failed {
        profile: Uuid,
        message: String,
    },
}

enum Screen {
    Connect,
    Add,
    Edit(Box<EditorState>),
    Wizard(Box<WizardState>),
}

impl Screen {
    fn edit(state: EditorState) -> Self {
        Screen::Edit(Box::new(state))
    }
}

struct DeteriumApp {
    store: Store,
    profiles: Vec<StoredProfile>,
    skipped: Vec<String>,
    selected: Option<Uuid>,
    connection: Connection,
    screen: Screen,
    confirm_delete: Option<Uuid>,
    toast: Option<Toast>,
    elevated: bool,
    /// The server the user tried to connect to without administrator rights.
    elevation_prompt: Option<Uuid>,
    /// Set when this instance was started elevated *by the app itself* to
    /// finish a connection the user asked for (`--connect <id>`).
    auto_connect: Option<Uuid>,
    /// Whether the background service is installed/running (re-checked every
    /// couple of seconds, since it can change outside the app).
    service_state: ServiceState,
    service_checked: Instant,
    service_dialog: bool,
    /// An install/remove that is waiting on the Windows permission prompt.
    service_job: Option<ServiceJob>,
    /// The logo shown in the sidebar header (created on first use).
    logo: Option<egui::TextureHandle>,
    /// The notification-area icon, when the system has one.
    tray: Option<tray::Tray>,
    /// Set by "Quit" so closing the window really ends the app.
    quitting: bool,
    /// The window is hidden in the tray (as opposed to being on screen).
    hidden: bool,
    /// Start with the window hidden in the tray (`--minimized`).
    start_hidden: bool,
    /// The kill switch is holding the network with no tunnel up (the service
    /// restarted or the PC rebooted): the profile it is armed for.
    held: Option<Uuid>,
    held_checked: Instant,
    /// A question to the service that is still being answered.
    held_probe: Option<mpsc::Receiver<Option<Uuid>>>,
    /// "Turn off protection" waiting for the service's answer.
    held_release: Option<mpsc::Receiver<Result<(), String>>>,
    /// Live speed, latency and totals of the current tunnel.
    telemetry: Option<insights::Telemetry>,
    insight_tab: insights::Tab,
    /// The server Windows is set to connect to at sign-in (read from the
    /// registry, which is the only place that says so).
    autostart_server: Option<Uuid>,
    /// Set when Windows started this instance to connect at sign-in.
    autostart_job: Option<AutostartJob>,
}

#[derive(Clone, Copy, PartialEq)]
enum ServiceAction {
    Install,
    Remove,
}

struct ServiceJob {
    action: ServiceAction,
    /// Connect to this server once the install has finished.
    then_connect: Option<Uuid>,
    done: mpsc::Receiver<Result<u32, deterium_engine::ElevateError>>,
}

impl Default for DeteriumApp {
    fn default() -> Self {
        let moved = store::migrate_legacy(std::path::Path::new("profiles"), &store::user_dir());
        let store = Store::new();
        let loaded = store.load();
        let selected = loaded.profiles.first().map(|p| p.profile.id);

        let elevated = deterium_engine::is_elevated();
        let mut toast_on_start = (loaded.upgraded > 0).then(|| {
            toast(
                format!(
                    "Encrypted the saved keys of {} server(s) on this PC",
                    loaded.upgraded
                ),
                GOOD,
            )
        });
        if moved > 0 {
            toast_on_start = Some(toast(
                format!(
                    "Moved {moved} saved server(s) to {}",
                    store.user_dir().display()
                ),
                GOOD,
            ));
        }
        if elevated {
            // A previous run may have crashed with routes still installed.
            let leftovers = deterium_engine::recover_leftovers();
            if leftovers > 0 {
                toast_on_start = Some(toast(
                    format!("Cleaned up {leftovers} network change(s) from a previous run"),
                    WARN,
                ));
            }
        }

        let args: Vec<String> = std::env::args().collect();
        let auto_connect = args
            .iter()
            .position(|a| a == "--connect")
            .and_then(|i| args.get(i + 1))
            .and_then(|id| Uuid::parse_str(id).ok());

        // A tunnel the background service is already holding (the window was
        // closed and reopened): show it instead of pretending nothing is up.
        let adopted = deterium_engine::attach()
            .filter(|(id, _)| loaded.profiles.iter().any(|p| p.profile.id == *id));
        // Windows started this instance to connect at sign-in; not when a
        // tunnel is already up (the window was only reopened).
        let autostart_id = autostart::server_in(&args)
            .filter(|id| adopted.is_none() && loaded.profiles.iter().any(|p| p.profile.id == *id));
        let (connection, selected) = match adopted {
            Some((id, tunnel)) => {
                // The service remembers when the tunnel came up, so the uptime
                // doesn't restart from zero every time the window is opened.
                let already = tunnel.existing_uptime().unwrap_or_default();
                let since = Instant::now()
                    .checked_sub(already)
                    .unwrap_or_else(Instant::now);
                let status = tunnel.status();
                (
                    Connection::Active {
                        profile: id,
                        mode: tunnel.mode(),
                        connected_at: (status == TunnelStatus::Connected).then_some(since),
                        status,
                        tunnel,
                        started: since,
                    },
                    Some(id),
                )
            }
            None => (Connection::Idle, auto_connect.or(autostart_id).or(selected)),
        };

        Self {
            store,
            profiles: loaded.profiles,
            skipped: loaded.skipped,
            selected,
            connection,
            screen: Screen::Connect,
            confirm_delete: None,
            toast: toast_on_start,
            elevated,
            elevation_prompt: None,
            auto_connect,
            service_state: deterium_engine::service_state(),
            service_checked: Instant::now(),
            service_dialog: false,
            service_job: None,
            logo: None,
            tray: None,
            quitting: false,
            hidden: false,
            start_hidden: false,
            held: None,
            held_checked: Instant::now()
                .checked_sub(HELD_CHECK_EVERY)
                .unwrap_or_else(Instant::now),
            held_probe: None,
            held_release: None,
            telemetry: None,
            insight_tab: insights::Tab::default(),
            autostart_server: autostart::enabled_for(),
            autostart_job: autostart_id.map(|id| AutostartJob {
                id,
                attempts: 0,
                next_try: Instant::now(),
                started: false,
            }),
        }
    }
}

impl eframe::App for DeteriumApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &ui.ctx().clone();
        self.handle_tray(ctx);
        self.handle_dropped_files(ctx);
        if let Some(id) = self.auto_connect.take() {
            if self.profile(id).is_some() {
                self.selected = Some(id);
                self.start_connect(id, ConnectMode::Full);
            }
        }
        self.poll_connection(ctx);
        self.poll_service(ctx);
        self.poll_held(ctx);
        self.run_autostart(ctx);

        paint_background(ctx, self.background_target());

        egui::Panel::left("sidebar")
            .resizable(false)
            .exact_size(262.0)
            .frame(
                egui::Frame::NONE
                    .fill(theme::unmultiplied(10, 13, 24, 225))
                    .inner_margin(Margin::symmetric(14, 18)),
            )
            .show(ui, |ui| self.show_sidebar(ui));

        self.show_held_banner(ui);

        let mut screen = std::mem::replace(&mut self.screen, Screen::Connect);
        let mut next: Option<Screen> = None;
        let scroll_id = match &screen {
            Screen::Connect => "connect",
            Screen::Add => "add",
            Screen::Edit(_) => "edit",
            Screen::Wizard(_) => "wizard",
        };

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.inner_margin(Margin::symmetric(36, 26)))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt(scroll_id)
                    .auto_shrink([false, false])
                    .show(ui, |ui| match &mut screen {
                        Screen::Connect => next = self.show_connect(ui),
                        Screen::Add => next = self.show_add(ui),
                        Screen::Edit(state) => next = self.show_edit(ui, state),
                        Screen::Wizard(state) => next = self.show_wizard(ui, state),
                    });
            });

        self.screen = next.unwrap_or(screen);

        self.show_delete_dialog(ctx);
        self.show_elevation_dialog(ctx);
        self.show_service_dialog(ctx);
        show_toast(ctx, &mut self.toast);
        self.sync_tray();
    }
}

// ------------------------------------------------------------ app logic --

impl DeteriumApp {
    fn profile(&self, id: Uuid) -> Option<&StoredProfile> {
        self.profiles.iter().find(|p| p.profile.id == id)
    }

    fn reload(&mut self) {
        let loaded = self.store.load();
        self.profiles = loaded.profiles;
        self.skipped = loaded.skipped;
        if self.selected.and_then(|id| self.profile(id)).is_none() {
            self.selected = self.profiles.first().map(|p| p.profile.id);
        }
    }

    fn is_busy(&self, id: Uuid) -> bool {
        matches!(&self.connection, Connection::Active { profile, .. } if *profile == id)
    }

    fn poll_connection(&mut self, ctx: &egui::Context) {
        if let Connection::Active {
            tunnel,
            status,
            connected_at,
            ..
        } = &mut self.connection
        {
            *status = tunnel.status();
            match (*status == TunnelStatus::Connected, connected_at.is_some()) {
                (true, false) => *connected_at = Some(Instant::now()),
                (false, _) => *connected_at = None,
                (true, true) => {}
            }
            ctx.request_repaint_after(FRAME_INTERVAL);
        }
        self.sync_telemetry();
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        for file in dropped {
            let path = file.path();
            if !path.as_os_str().is_empty() {
                self.handle_import(editor::read_config_file(&path.to_path_buf()));
            }
        }
    }

    /// Opens an imported config in the editor for review (or merges it into
    /// the editor that's already open).
    fn handle_import(&mut self, picked: Picked) {
        if let Screen::Edit(state) = &mut self.screen {
            state.import_picked(picked);
            return;
        }
        if let Some(screen) = self.editor_for_import(picked) {
            self.screen = screen;
        }
    }

    /// A fresh editor pre-filled from an imported file, or a toast if the
    /// file couldn't be read.
    fn editor_for_import(&mut self, picked: Picked) -> Option<Screen> {
        match picked {
            Picked::Cancelled => None,
            Picked::Error(message) => {
                self.toast = Some(toast(message, BAD));
                None
            }
            Picked::Text { text, hint } => {
                let mut state = EditorState::new(Draft::new_wireguard(), true);
                state.import_text(&text, &hint);
                Some(Screen::edit(state))
            }
        }
    }

    fn save_profile(&mut self, profile: ServerProfile) -> bool {
        let existing = self
            .profiles
            .iter()
            .find(|p| p.profile.id == profile.id && !p.builtin)
            .cloned();
        let result = match &existing {
            Some(existing) => self.store.save_existing(existing, profile),
            None => self.store.save_new(profile),
        };
        match result {
            Ok(stored) => {
                self.selected = Some(stored.profile.id);
                self.toast = Some(toast(format!("Saved \"{}\"", stored.profile.name), GOOD));
                self.reload();
                true
            }
            Err(err) => {
                self.toast = Some(toast(format!("Couldn't save: {err}"), BAD));
                false
            }
        }
    }

    fn duplicate(&mut self, id: Uuid) {
        let Some(original) = self.profile(id).map(|p| p.profile.clone()) else {
            return;
        };
        let mut copy = original;
        copy.id = ServerProfile::new_id();
        copy.name = format!("{} (copy)", copy.name);
        copy.companion = None;
        self.save_profile(copy);
    }

    fn delete(&mut self, id: Uuid) {
        if self.is_busy(id) {
            self.disconnect();
        }
        let Some(stored) = self.profile(id).cloned() else {
            return;
        };
        match self.store.delete(&stored) {
            Ok(()) => {
                // Windows must not keep trying to connect to a server that is gone.
                if self.autostart_server == Some(id) {
                    let _ = autostart::disable();
                    self.autostart_server = autostart::enabled_for();
                }
                self.toast = Some(toast(format!("Deleted \"{}\"", stored.profile.name), GOOD));
                self.reload();
            }
            Err(err) => self.toast = Some(toast(format!("Couldn't delete: {err}"), BAD)),
        }
    }

    fn export(&mut self, id: Uuid) {
        let Some(stored) = self.profile(id).cloned() else {
            return;
        };
        let profile = &stored.profile;
        let base: String = profile
            .name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();

        let mut dialog = rfd::FileDialog::new()
            .set_title("Export server")
            .set_file_name(format!("{base}.toml"))
            .add_filter("Deterium profile", &["toml"]);
        dialog = match profile.protocol {
            Protocol::Wireguard => dialog.add_filter("WireGuard config", &["conf"]),
            Protocol::Openvpn => dialog.add_filter("OpenVPN config", &["ovpn"]),
        };
        let Some(path) = dialog.save_file() else {
            return;
        };

        let extension = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let content = match extension.as_str() {
            "conf" => to_wireguard_conf(profile),
            "ovpn" => profile.openvpn.as_ref().map(|o| o.raw_config.clone()),
            _ => None,
        }
        .map(Ok)
        .unwrap_or_else(|| to_deterium_toml(profile).map_err(|e| e.to_string()));

        self.toast = Some(
            match content.and_then(|text| std::fs::write(&path, text).map_err(|e| e.to_string())) {
                Ok(()) => toast("Exported — the file contains your private key", WARN),
                Err(err) => toast(format!("Couldn't export: {err}"), BAD),
            },
        );
    }

    fn start_connect(&mut self, id: Uuid, mode: ConnectMode) {
        let Some(profile) = self.profile(id).map(|p| p.profile.clone()) else {
            return;
        };
        self.connection = match deterium_engine::connect_auto(&profile, mode) {
            Ok(tunnel) => Connection::Active {
                profile: id,
                mode: tunnel.mode(),
                tunnel,
                status: TunnelStatus::Connecting,
                started: Instant::now(),
                connected_at: None,
            },
            // Not a failure: ask the user whether to restart with rights.
            Err(AdapterError::PermissionRequired(_)) => {
                self.elevation_prompt = Some(id);
                Connection::Idle
            }
            Err(err) => Connection::Failed {
                profile: id,
                message: err.to_string(),
            },
        };
    }

    fn disconnect(&mut self) {
        if let Connection::Active {
            profile, tunnel, ..
        } = std::mem::replace(&mut self.connection, Connection::Idle)
        {
            if let Err(err) = tunnel.disconnect() {
                self.connection = Connection::Failed {
                    profile,
                    message: err.to_string(),
                };
            }
        }
    }

    fn background_target(&self) -> Color32 {
        let Some(selected) = self.selected else {
            return Color32::from_rgb(22, 24, 58);
        };
        match &self.connection {
            Connection::Active {
                profile, status, ..
            } if *profile == selected => match status {
                TunnelStatus::Connected => Color32::from_rgb(8, 58, 58),
                TunnelStatus::Error => Color32::from_rgb(64, 22, 30),
                TunnelStatus::Reconnecting => Color32::from_rgb(70, 52, 14),
                _ => Color32::from_rgb(16, 38, 92),
            },
            Connection::Failed { profile, .. } if *profile == selected => {
                Color32::from_rgb(64, 22, 30)
            }
            _ => Color32::from_rgb(22, 24, 58),
        }
    }

    fn describe(&self, stored: &StoredProfile) -> StatusView {
        let id = stored.profile.id;
        // "Leak protection" can be only the DNS part; say exactly what is on.
        let kill_switch = stored.profile.security.kill_switch;
        let idle = |subtitle: &str| StatusView {
            title: "Not connected".into(),
            subtitle: subtitle.into(),
            subtitle_color: DIM,
            accent: ACCENT,
            spinning: false,
            ripples: false,
            warning: None,
            note: None,
        };

        match &self.connection {
            Connection::Active {
                profile,
                tunnel,
                status,
                started,
                connected_at,
                mode,
            } if *profile == id => {
                let uptime = format_duration(connected_at.map(|t| t.elapsed()).unwrap_or_default());
                match status {
                    TunnelStatus::Connected if *mode == ConnectMode::HandshakeOnly => StatusView {
                        title: "Server reachable".into(),
                        subtitle: format!("Handshake complete · test running for {uptime}"),
                        subtitle_color: GOOD,
                        accent: GOOD,
                        spinning: false,
                        ripples: true,
                        warning: None,
                        note: Some(
                            "This was only a test: no traffic is routed. Disconnect, then use \
                             the power button to connect for real.",
                        ),
                    },
                    TunnelStatus::Connected => StatusView {
                        title: "Connected".into(),
                        subtitle: format!("Traffic is flowing through the tunnel · {uptime}"),
                        subtitle_color: GOOD,
                        accent: GOOD,
                        spinning: false,
                        ripples: true,
                        warning: None,
                        note: tunnel.leak_protection().then_some(if kill_switch {
                            "Kill switch is on: traffic outside the tunnel is blocked."
                        } else {
                            "DNS leak protection is on: name lookups outside the tunnel are blocked."
                        }),
                    },
                    TunnelStatus::Error => StatusView {
                        title: "Connection trouble".into(),
                        subtitle: error_detail(&tunnel.log()).unwrap_or_else(|| {
                            "A packet was rejected — the tunnel keeps retrying".into()
                        }),
                        subtitle_color: WARN,
                        accent: WARN,
                        spinning: true,
                        ripples: false,
                        warning: None,
                        note: None,
                    },
                    TunnelStatus::Reconnecting => StatusView {
                        title: "Reconnecting…".into(),
                        subtitle: if kill_switch && tunnel.leak_protection() {
                            "The server stopped answering. The kill switch is holding all traffic until it is back"
                        } else {
                            "The server stopped answering — trying again"
                        }
                        .into(),
                        subtitle_color: WARN,
                        accent: WARN,
                        spinning: true,
                        ripples: false,
                        warning: (!(kill_switch && tunnel.leak_protection())).then_some(
                            "The connection is down and nothing is holding your traffic back: it is NOT protected right now.",
                        ),
                        note: None,
                    },
                    _ => {
                        let slow = started.elapsed() > SLOW_CONNECT;
                        StatusView {
                            title: "Connecting…".into(),
                            subtitle: if slow {
                                "No reply yet — check the server is reachable and the settings match"
                                    .into()
                            } else {
                                "Negotiating a secure connection".into()
                            },
                            subtitle_color: if slow { WARN } else { DIM },
                            accent: ACCENT,
                            spinning: true,
                            ripples: false,
                            warning: (*mode == ConnectMode::Full).then_some(
                                "Wait for \"Connected\" before you open anything: until then your traffic is NOT going through the VPN and your real IP can be visible.",
                            ),
                            note: None,
                        }
                    }
                }
            }
            Connection::Failed { profile, message } if *profile == id => StatusView {
                title: "Couldn't connect".into(),
                subtitle: message.clone(),
                subtitle_color: BAD,
                accent: BAD,
                spinning: false,
                ripples: false,
                warning: None,
                note: None,
            },
            _ => idle("Tap the power button to connect"),
        }
    }
}

/// Picks the most useful single line out of an OpenVPN log for the UI.
fn error_detail(log: &[String]) -> Option<String> {
    let needs_admin = log.iter().any(|line| {
        let line = line.to_lowercase();
        line.contains("administrator") || line.contains("access is denied")
    });
    if needs_admin {
        return Some("OpenVPN needs administrator rights — run Deterium as administrator".into());
    }
    if log.iter().any(|line| line.contains("AUTH_FAILED")) {
        return Some(
            "The server rejected the username or password - check them in Edit (some providers change them regularly)"
                .into(),
        );
    }
    if log
        .iter()
        .any(|line| line.contains("Wintun") && line.contains("not"))
    {
        return Some("The Wintun network driver isn't ready - try connecting a WireGuard server once, or reinstall the background service".into());
    }
    // The last line is often just "OpenVPN exited"; the line before it says why.
    let last = log
        .iter()
        .rev()
        .find(|l| !l.trim().is_empty() && !l.contains("OpenVPN exited"))
        .or_else(|| log.iter().rev().find(|l| !l.trim().is_empty()))?;
    let trimmed: String = last.trim().chars().take(120).collect();
    Some(trimmed)
}

// ---------------------------------------------------------------- views --

impl DeteriumApp {
    fn show_sidebar(&mut self, ui: &mut egui::Ui) {
        let logo = self.logo.get_or_insert_with(|| {
            let size = 128;
            ui.ctx().load_texture(
                "deterium-logo",
                egui::ColorImage::new(
                    [size as usize, size as usize],
                    logo::render(size, None)
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|&[r, g, b, a]| theme::unmultiplied(r, g, b, a))
                        .collect(),
                ),
                egui::TextureOptions::LINEAR,
            )
        });
        ui.horizontal(|ui| {
            ui.add(egui::Image::new((logo.id(), vec2(42.0, 42.0))));
            ui.add_space(6.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                ui.add_space(3.0);
                ui.label(
                    RichText::new("DETERIUM")
                        .size(18.0)
                        .strong()
                        .extra_letter_spacing(2.2)
                        .color(TEXT),
                );
                ui.label(
                    RichText::new("SELF-HOSTED VPN")
                        .size(9.5)
                        .extra_letter_spacing(1.8)
                        .color(ACCENT),
                );
            });
        });

        ui.add_space(24.0);
        sidebar_heading(ui, "YOUR SERVERS");

        let active = match &self.connection {
            Connection::Active {
                profile, status, ..
            } => Some((*profile, *status)),
            _ => None,
        };

        let mut clicked: Option<Uuid> = None;
        let mut add_clicked = false;

        egui::ScrollArea::vertical()
            .id_salt("sidebar_scroll")
            .max_height(ui.available_height() - 52.0)
            .show(ui, |ui| {
                let mut shown_builtin_heading = false;
                for stored in &self.profiles {
                    let id = stored.profile.id;
                    if stored.builtin && !shown_builtin_heading {
                        add_clicked |= add_row(ui).clicked();
                        ui.add_space(14.0);
                        sidebar_heading(ui, "BUILT-IN");
                        shown_builtin_heading = true;
                    }

                    let dot = match active {
                        Some((p, TunnelStatus::Connected)) if p == id => GOOD,
                        Some((p, TunnelStatus::Error)) if p == id => WARN,
                        Some((p, _)) if p == id => ACCENT,
                        _ => Color32::from_rgb(70, 78, 98),
                    };
                    let selected = self.selected == Some(id);
                    if server_row(ui, &stored.profile, selected, dot).clicked() {
                        clicked = Some(id);
                    }
                    ui.add_space(4.0);
                }
                if !shown_builtin_heading {
                    ui.add_space(4.0);
                    add_clicked |= add_row(ui).clicked();
                }
            });

        if let Some(id) = clicked {
            self.selected = Some(id);
            self.screen = Screen::Connect;
        }
        if add_clicked {
            self.screen = Screen::Add;
        }

        ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
            // Bottom-most line: the version of this build.
            ui.label(
                RichText::new(concat!("v", env!("CARGO_PKG_VERSION")))
                    .size(11.5)
                    .color(DIM),
            )
            .on_hover_text(concat!("Deterium VPN ", env!("CARGO_PKG_VERSION")));
            ui.add_space(2.0);
            let (text, color) = match self.service_state {
                ServiceState::Running => ("Background service: running", GOOD),
                ServiceState::Stopped => ("Background service: stopped", WARN),
                ServiceState::NotInstalled => ("Background service: not installed", DIM),
            };
            if ui
                .add(
                    egui::Label::new(RichText::new(text).size(11.5).color(color))
                        .sense(egui::Sense::click()),
                )
                .on_hover_text("Click to manage")
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .clicked()
            {
                self.service_dialog = true;
            }
            if self.elevated {
                ui.label(
                    RichText::new("Running as administrator")
                        .size(11.5)
                        .color(GOOD),
                );
            }
            if !self.skipped.is_empty() {
                ui.label(
                    RichText::new(format!(
                        "{} server file(s) couldn't be read",
                        self.skipped.len()
                    ))
                    .size(11.5)
                    .color(WARN),
                )
                .on_hover_text(self.skipped.join("\n"));
            }
            ui.label(
                RichText::new("Servers are saved on this PC")
                    .size(11.5)
                    .color(DIM),
            )
            .on_hover_text(self.store.user_dir().display().to_string());
        });
    }

    fn show_add(&mut self, ui: &mut egui::Ui) -> Option<Screen> {
        match editor::show_chooser(ui, !self.profiles.is_empty()) {
            ChooserAction::None => None,
            ChooserAction::Cancel => Some(Screen::Connect),
            ChooserAction::Wizard => Some(Screen::Wizard(Box::new(WizardState::new()))),
            ChooserAction::ManualWireGuard => {
                Some(Screen::edit(EditorState::new(Draft::new_wireguard(), true)))
            }
            ChooserAction::ManualOpenVpn => {
                Some(Screen::edit(EditorState::new(Draft::new_openvpn(), true)))
            }
            ChooserAction::Paste => Some(Screen::edit(
                EditorState::new(Draft::new_wireguard(), true).with_paste_open(),
            )),
            ChooserAction::ImportFile => self.editor_for_import(editor::pick_config_file()),
        }
    }

    fn show_edit(&mut self, ui: &mut egui::Ui, state: &mut EditorState) -> Option<Screen> {
        match editor::show_editor(ui, state, &mut self.toast) {
            EditorAction::None => None,
            EditorAction::Cancel => Some(Screen::Connect),
            EditorAction::Save(profile) => self.save_profile(*profile).then_some(Screen::Connect),
        }
    }

    fn show_wizard(&mut self, ui: &mut egui::Ui, state: &mut WizardState) -> Option<Screen> {
        match editor::show_wizard(ui, state, &mut self.toast) {
            WizardAction::None => None,
            WizardAction::Back => Some(Screen::Add),
            WizardAction::Finish(profile) => self.save_profile(*profile).then_some(Screen::Connect),
        }
    }

    fn show_connect(&mut self, ui: &mut egui::Ui) -> Option<Screen> {
        let Some(stored) = self.selected.and_then(|id| self.profile(id)).cloned() else {
            return self.show_empty(ui);
        };
        let profile = &stored.profile;
        let id = profile.id;
        let mut next = None;

        ui.horizontal(|ui| {
            ui.label(RichText::new(&profile.name).size(26.0).strong().color(TEXT));
            badge(
                ui,
                match profile.protocol {
                    Protocol::Wireguard => "WireGuard",
                    Protocol::Openvpn => "OpenVPN",
                },
                ACCENT,
            );
            if stored.builtin {
                badge(ui, "Built-in", GOOD);
            }
        });
        let uptime = match &self.connection {
            Connection::Active {
                profile: p,
                connected_at: Some(t),
                ..
            } if *p == id => Some(format_duration(t.elapsed())),
            _ => None,
        };
        let subtitle = match &uptime {
            Some(up) => format!("{} \u{b7} connected {up}", endpoint_of(profile)),
            None => endpoint_of(profile),
        };
        ui.label(RichText::new(subtitle).size(13.5).color(DIM));

        let busy = self.is_busy(id);
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            if !stored.builtin {
                let edit = ui.add_enabled(!busy, ghost_button("Edit", ACCENT));
                if edit.clicked() {
                    next = Some(Screen::edit(EditorState::new(
                        Draft::from_profile(profile),
                        false,
                    )));
                }
                edit.on_disabled_hover_text("Disconnect before editing this server");
            }
            if ui.add(ghost_button("Duplicate", DIM)).clicked() {
                self.duplicate(id);
            }
            let on_here = self.autostart_server == Some(id);
            let service_up = self.service_state == ServiceState::Running;
            let start_button = ui
                .add_enabled(
                    service_up || on_here,
                    ghost_button(
                        if on_here {
                            "Start with Windows: on"
                        } else {
                            "Start with Windows: off"
                        },
                        if on_here { GOOD } else { DIM },
                    ),
                )
                .on_hover_text(match (on_here, self.autostart_server) {
                    (true, _) => "Deterium starts hidden when you sign in and connects to this server. Click to stop.",
                    (false, Some(_)) => "Another server connects at sign-in. Click to connect to this one instead.",
                    (false, None) => "Starts Deterium hidden when you sign in to Windows and connects to this server. Until then the kill switch keeps holding your internet.",
                })
                .on_disabled_hover_text("Needs the background service. Install it from the sidebar first.");
            if start_button.clicked() {
                self.toggle_autostart(id);
            }
            if ui.add(ghost_button("Export…", DIM)).clicked() {
                self.export(id);
            }
            if profile.protocol == Protocol::Wireguard {
                let any_active = matches!(self.connection, Connection::Active { .. });
                let test = ui
                    .add_enabled(!any_active, ghost_button("Test connection", ACCENT))
                    .on_hover_text("Checks the server answers. Changes no network settings.");
                if test.clicked() {
                    self.start_connect(id, ConnectMode::HandshakeOnly);
                }
            }
            if !stored.builtin && ui.add(ghost_button("Delete", BAD)).clicked() {
                self.confirm_delete = Some(id);
            }
        });

        let view = self.describe(&stored);
        let (enabled, reason) = self.power_availability(&stored);
        let time = ui.input(|i| i.time);

        ui.add_space(2.0);
        ui.vertical_centered(|ui| {
            let response = power_button(ui, &view, enabled, time);
            if enabled && response.clicked() {
                if busy {
                    self.disconnect();
                } else {
                    self.start_connect(id, ConnectMode::Full);
                }
            } else if !enabled {
                response.on_hover_text(reason);
            }

            ui.add_space(2.0);
            ui.label(RichText::new(&view.title).size(28.0).strong().color(TEXT));
            ui.add_space(2.0);
            ui.label(
                RichText::new(&view.subtitle)
                    .size(14.0)
                    .color(view.subtitle_color),
            );
            if let Some(warning) = view.warning {
                ui.add_space(8.0);
                ui.add(
                    egui::Label::new(RichText::new(warning).size(13.0).strong().color(WARN)).wrap(),
                );
            }
            if let Some(note) = view.note {
                ui.add_space(8.0);
                ui.label(RichText::new(note).size(12.0).color(DIM));
            }
        });

        ui.add_space(22.0);

        self.show_insights(ui, &stored);

        ui.add_space(30.0);
        next
    }

    fn show_empty(&mut self, ui: &mut egui::Ui) -> Option<Screen> {
        let mut next = None;
        ui.add_space(90.0);
        ui.vertical_centered(|ui| {
            ui.label(
                RichText::new("Add your first server")
                    .size(30.0)
                    .strong()
                    .color(TEXT),
            );
            ui.add_space(6.0);
            ui.label(dim(
                "Deterium connects you to a server you control or subscribe to.",
            ));
            ui.label(dim("No accounts, no tracking, nothing hosted by us."));
            ui.add_space(24.0);
            ui.horizontal(|ui| {
                ui.add_space((ui.available_width() - 440.0).max(0.0) / 2.0);
                if ui.add(primary_button("Set up my own server")).clicked() {
                    next = Some(Screen::Wizard(Box::new(WizardState::new())));
                }
                if ui.add(ghost_button("Import a config", ACCENT)).clicked() {
                    next = Some(Screen::Add);
                }
            });
        });
        next
    }

    /// Only one tunnel at a time.
    fn power_availability(&self, stored: &StoredProfile) -> (bool, String) {
        if let Connection::Active { profile, .. } = &self.connection {
            if *profile != stored.profile.id {
                let other = self
                    .profile(*profile)
                    .map(|p| p.profile.name.as_str())
                    .unwrap_or("the other server");
                return (false, format!("Disconnect {other} first"));
            }
        }
        (true, String::new())
    }

    /// Reacts to the tray icon and keeps "close" from ending the app while the
    /// tray is there to bring it back.
    fn handle_tray(&mut self, ctx: &egui::Context) {
        if self.start_hidden {
            self.start_hidden = false;
            if let Some(tray) = &self.tray {
                self.hidden = true;
                tray.hide_window();
            }
        }

        let actions = self
            .tray
            .as_ref()
            .map(|tray| tray.take_actions())
            .unwrap_or_default();
        for action in actions {
            match action {
                tray::Action::Open => {
                    self.hidden = false;
                    self.bring_back(ctx);
                }
                tray::Action::Toggle => {
                    if matches!(self.connection, Connection::Active { .. }) {
                        self.disconnect();
                    } else if let Some(id) = self.selected {
                        self.start_connect(id, ConnectMode::Full);
                    }
                    // A permission prompt or an error needs to be seen.
                    if self.elevation_prompt.is_some()
                        || matches!(self.connection, Connection::Failed { .. })
                    {
                        self.hidden = false;
                        self.bring_back(ctx);
                    }
                }
                tray::Action::Quit => {
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }

        if self.tray.is_some()
            && !self.quitting
            && ctx.input(|input| input.viewport().close_requested())
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            if let Some(tray) = &self.tray {
                self.hidden = true;
                tray.hide_window();
            }
        }
    }

    /// Brings the window back from the tray.
    fn bring_back(&self, ctx: &egui::Context) {
        if let Some(tray) = &self.tray {
            tray.show_window();
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    /// Tells the tray icon what is going on.
    fn sync_tray(&mut self) {
        let Some(tray) = self.tray.as_mut() else {
            return;
        };
        let selected_name = self
            .selected
            .and_then(|id| self.profiles.iter().find(|p| p.profile.id == id))
            .map(|p| p.profile.name.clone());

        let summary = match &self.connection {
            Connection::Active {
                profile, status, ..
            } => {
                let name = self
                    .profiles
                    .iter()
                    .find(|p| p.profile.id == *profile)
                    .map(|p| p.profile.name.clone())
                    .or(selected_name);
                tray::Summary {
                    look: match status {
                        TunnelStatus::Connected => tray::Look::Connected,
                        TunnelStatus::Connecting | TunnelStatus::Disconnected => {
                            tray::Look::Connecting
                        }
                        TunnelStatus::Reconnecting | TunnelStatus::Error => tray::Look::Warning,
                    },
                    server: name,
                    connected: true,
                }
            }
            _ => tray::Summary {
                look: tray::Look::Idle,
                server: selected_name,
                connected: false,
            },
        };
        tray.show(summary);
    }

    /// Connects by itself when Windows started this app for that (see
    /// [`autostart`]). It stops as soon as the connection is up, or the user
    /// takes over by connecting elsewhere or disconnecting, and gives up after
    /// a few tries so a server that is down never makes it loop forever.
    fn run_autostart(&mut self, ctx: &egui::Context) {
        let Some(job) = self.autostart_job.as_ref() else {
            return;
        };
        let id = job.id;
        // Keeps ticking while the window is parked in the tray.
        ctx.request_repaint_after(Duration::from_secs(1));

        let seen = match &self.connection {
            Connection::Active {
                profile, status, ..
            } if *profile == id => match status {
                TunnelStatus::Connected => Seen::Connected,
                TunnelStatus::Error => Seen::Errored,
                _ => Seen::ComingUp,
            },
            Connection::Active { .. } => Seen::Other,
            Connection::Failed { .. } => Seen::Failed,
            Connection::Idle => Seen::Idle,
        };
        match autostart_step(job, seen, Instant::now()) {
            AutostartStep::Wait => {}
            AutostartStep::Finish => self.autostart_job = None,
            AutostartStep::GiveUp => {
                self.autostart_job = None;
                self.toast = Some(toast(
                    "Couldn't connect automatically. Connect from the app when you're ready",
                    WARN,
                ));
            }
            AutostartStep::Attempt { drop_current } => {
                if let Some(job) = self.autostart_job.as_mut() {
                    job.attempts += 1;
                    job.next_try = Instant::now() + AUTOSTART_EVERY;
                }
                // Without the service a connection needs a permission prompt,
                // which nobody wants at sign-in: wait for the service instead.
                if self.service_state != ServiceState::Running {
                    return;
                }
                if drop_current {
                    self.disconnect();
                }
                if self.profile(id).is_none() {
                    self.autostart_job = None;
                    return;
                }
                self.selected = Some(id);
                self.start_connect(id, ConnectMode::Full);
                if let Some(job) = self.autostart_job.as_mut() {
                    job.started = true;
                }
            }
        }
    }

    /// Turns "connect when Windows starts" on for `id`, or off if it already
    /// is for that server.
    fn toggle_autostart(&mut self, id: Uuid) {
        let turning_off = self.autostart_server == Some(id);
        let result = if turning_off {
            autostart::disable()
        } else {
            autostart::enable(id)
        };
        self.autostart_server = autostart::enabled_for();
        self.toast = Some(match result {
            Ok(()) if turning_off => toast("Deterium will no longer start with Windows", GOOD),
            Ok(()) => {
                let name = self
                    .profile(id)
                    .map_or_else(String::new, |p| p.profile.name.clone());
                toast(
                    format!("Deterium will connect to \"{name}\" when you sign in to Windows"),
                    GOOD,
                )
            }
            Err(why) => toast(format!("Couldn't change this: {why}"), BAD),
        });
    }

    /// Keeps `held` up to date: asks the service, off the UI thread, whether
    /// its kill switch is holding the network while no tunnel is up.
    fn poll_held(&mut self, ctx: &egui::Context) {
        if let Some(release) = &self.held_release {
            ctx.request_repaint_after(Duration::from_millis(150));
            if let Ok(result) = release.try_recv() {
                self.held_release = None;
                match result {
                    Ok(()) => {
                        self.held = None;
                        self.toast = Some(toast(
                            "Protection turned off - your internet access is back",
                            GOOD,
                        ));
                    }
                    Err(why) => {
                        self.toast = Some(toast(
                            format!("Couldn't turn the protection off: {why}"),
                            BAD,
                        ));
                    }
                }
                self.held_checked = Instant::now()
                    .checked_sub(HELD_CHECK_EVERY)
                    .unwrap_or_else(Instant::now);
            }
            return;
        }
        if matches!(self.connection, Connection::Active { .. }) {
            // A tunnel is up (or coming up): the service is not holding a bare network.
            self.held = None;
            self.held_probe = None;
            return;
        }
        if let Some(probe) = &self.held_probe {
            ctx.request_repaint_after(Duration::from_millis(150));
            if let Ok(answer) = probe.try_recv() {
                self.held = answer;
                self.held_probe = None;
                self.held_checked = Instant::now();
            }
            return;
        }
        ctx.request_repaint_after(HELD_CHECK_EVERY);
        if self.service_state == ServiceState::Running
            && self.held_checked.elapsed() >= HELD_CHECK_EVERY
        {
            let (sender, receiver) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = sender.send(deterium_engine::service_armed());
            });
            self.held_probe = Some(receiver);
        } else if self.service_state != ServiceState::Running {
            self.held = None;
        }
    }

    /// The notice that explains why there is no internet and how to get it
    /// back. Without it, a kill switch that outlives a reboot would look like
    /// a broken PC.
    fn show_held_banner(&mut self, ui: &mut egui::Ui) {
        let Some(armed_for) = self.held else {
            return;
        };
        let name = self
            .profile(armed_for)
            .map_or_else(|| "your VPN".to_string(), |p| p.profile.name.clone());
        egui::Panel::top("held")
            .frame(
                egui::Frame::NONE
                    .fill(theme::unmultiplied(70, 28, 28, 235))
                    .inner_margin(Margin::symmetric(24, 12)),
            )
            .show(ui, |ui| {
                ui.label(
                    RichText::new("Kill switch is holding your internet")
                        .size(15.0)
                        .strong()
                        .color(TEXT),
                );
                ui.add_space(2.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "The VPN isn't connected, so nothing leaves this PC except to the server of \"{name}\". Connect to {name} to get online again, or turn the protection off."
                        ))
                        .size(13.0)
                        .color(TEXT),
                    )
                    .wrap(),
                );
                ui.add_space(6.0);
                let waiting = self.held_release.is_some();
                if ui
                    .add_enabled(!waiting, ghost_button("Turn protection off", BAD))
                    .on_hover_text("Lifts the block now. The kill switch arms again the next time you connect.")
                    .clicked()
                {
                    let (sender, receiver) = mpsc::channel();
                    std::thread::spawn(move || {
                        let _ = sender.send(deterium_engine::service_disarm());
                    });
                    self.held_release = Some(receiver);
                }
            });
    }

    fn poll_service(&mut self, ctx: &egui::Context) {
        if self.service_checked.elapsed() > Duration::from_secs(2) {
            self.service_state = deterium_engine::service_state();
            self.service_checked = Instant::now();
        }
        let Some(job) = &self.service_job else {
            return;
        };
        ctx.request_repaint_after(Duration::from_millis(200));
        let Ok(result) = job.done.try_recv() else {
            return;
        };
        let (action, then_connect) = (job.action, job.then_connect);
        self.service_job = None;
        self.service_state = deterium_engine::service_state();
        self.service_checked = Instant::now();

        match (action, result) {
            (ServiceAction::Install, Ok(0)) => {
                self.toast = Some(toast("Background service installed", GOOD));
                if let Some(id) = then_connect {
                    self.start_connect(id, ConnectMode::Full);
                }
            }
            (ServiceAction::Remove, Ok(0)) => {
                // The service took any tunnel down with it.
                if matches!(self.connection, Connection::Active { .. }) {
                    self.connection = Connection::Idle;
                }
                self.toast = Some(toast("Background service removed", GOOD));
            }
            (_, Ok(code)) => {
                self.toast = Some(toast(
                    format!(
                        "The service setup didn't finish (code {code}). Run \
                         `deterium-service install` in an administrator terminal to see why."
                    ),
                    BAD,
                ));
            }
            (_, Err(deterium_engine::ElevateError::Declined)) => {
                self.toast = Some(toast("Cancelled - nothing was changed", WARN));
            }
            (_, Err(err)) => self.toast = Some(toast(err.to_string(), BAD)),
        }
    }

    /// Runs `deterium-service install|uninstall` through the Windows permission
    /// prompt without freezing the window.
    fn start_service_job(&mut self, action: ServiceAction, then_connect: Option<Uuid>) {
        // The app is a single file: it re-runs itself, elevated, as the
        // installer. (That run copies the app to Program Files for the service.)
        let Ok(exe) = std::env::current_exe() else {
            self.toast = Some(toast("Couldn't locate the app", BAD));
            return;
        };

        let mut args = vec![
            "service".to_string(),
            match action {
                ServiceAction::Install => "install".to_string(),
                ServiceAction::Remove => "uninstall".to_string(),
            },
        ];
        if action == ServiceAction::Install {
            let Some(sid) = deterium_engine::current_user_sid() else {
                self.toast = Some(toast(
                    "Couldn't work out which Windows account you use",
                    BAD,
                ));
                return;
            };
            args.extend(["--allow-sid".to_string(), sid]);
        }
        // The app has no console; failures are shown in a message box.
        args.push("--gui-errors".to_string());

        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(deterium_engine::run_elevated_and_wait(&exe, &args));
        });
        self.service_job = Some(ServiceJob {
            action,
            then_connect,
            done: receiver,
        });
    }

    fn show_service_dialog(&mut self, ctx: &egui::Context) {
        if !self.service_dialog {
            return;
        }
        let busy = self.service_job.is_some();
        let state = self.service_state;
        let mut close = false;
        let mut action = None;

        egui::Window::new("Background service")
            .anchor(Align2::CENTER_CENTER, vec2(0.0, 0.0))
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.set_max_width(460.0);
                let (text, color) = match state {
                    ServiceState::Running => ("Installed and running", GOOD),
                    ServiceState::Stopped => ("Installed, but not running", WARN),
                    ServiceState::NotInstalled => ("Not installed", DIM),
                };
                ui.label(RichText::new(text).color(color).strong());
                ui.add_space(6.0);
                ui.label(
                    "The service runs the VPN in the background. With it, Deterium never \
                     asks for administrator rights again, the VPN stays up when you close this \
                     window, and the kill switch keeps protecting you even if the app crashes.",
                );
                ui.add_space(4.0);
                ui.label(dim(
                    "Installing needs one Windows permission prompt. Only your Windows \
                     account can control it.",
                ));
                ui.add_space(10.0);
                ui.horizontal_wrapped(|ui| {
                    if busy {
                        ui.spinner();
                        ui.label(dim("Waiting for the Windows permission prompt..."));
                    } else if state == ServiceState::NotInstalled {
                        if ui.add(primary_button("Install")).clicked() {
                            action = Some(ServiceAction::Install);
                        }
                    } else {
                        if state == ServiceState::Stopped
                            && ui.add(primary_button("Repair")).clicked()
                        {
                            action = Some(ServiceAction::Install);
                        }
                        if ui.add(ghost_button("Remove", BAD)).clicked() {
                            action = Some(ServiceAction::Remove);
                        }
                    }
                    if ui.add(ghost_button("Close", DIM)).clicked() {
                        close = true;
                    }
                });
            });

        if close {
            self.service_dialog = false;
        }
        if let Some(action) = action {
            self.start_service_job(action, None);
        }
    }

    fn show_elevation_dialog(&mut self, ctx: &egui::Context) {
        let Some(id) = self.elevation_prompt else {
            return;
        };
        let Some(stored) = self.profile(id).cloned() else {
            self.elevation_prompt = None;
            return;
        };

        enum Choice {
            InstallService,
            Restart,
            Test,
            Cancel,
        }
        let mut choice = None;

        egui::Window::new("Administrator rights needed")
            .anchor(Align2::CENTER_CENTER, vec2(0.0, 0.0))
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.set_max_width(430.0);
                ui.label(
                    "Creating the VPN adapter and routing traffic through it needs \
                     administrator rights on Windows.",
                );
                ui.add_space(4.0);
                ui.label(dim(format!(
                    "Deterium will restart with a Windows permission prompt and connect to \
                     \"{}\" for you.",
                    stored.profile.name
                )));
                ui.add_space(10.0);
                if self.service_state == ServiceState::NotInstalled {
                    ui.label(
                        RichText::new("Recommended: install the background service")
                            .color(GOOD)
                            .strong(),
                    );
                    ui.label(dim(
                        "One Windows permission prompt, once. After that Deterium needs no \
                         administrator rights, and the kill switch keeps working even if the \
                         window is closed.",
                    ));
                    ui.add_space(6.0);
                    if self.service_job.is_some() {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(dim("Waiting for the Windows permission prompt..."));
                        });
                    } else if ui
                        .add(primary_button("Install background service"))
                        .clicked()
                    {
                        choice = Some(Choice::InstallService);
                    }
                    ui.add_space(10.0);
                    ui.label(dim("Or, just for now:"));
                }
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add(if self.service_state == ServiceState::NotInstalled {
                            ghost_button("Restart as administrator", ACCENT)
                        } else {
                            primary_button("Restart as administrator")
                        })
                        .clicked()
                    {
                        choice = Some(Choice::Restart);
                    }
                    if stored.profile.protocol == Protocol::Wireguard
                        && ui
                            .add(ghost_button("Test connection only", ACCENT))
                            .on_hover_text("Checks the server answers without changing anything")
                            .clicked()
                    {
                        choice = Some(Choice::Test);
                    }
                    if ui.add(ghost_button("Cancel", DIM)).clicked() {
                        choice = Some(Choice::Cancel);
                    }
                });
            });

        match choice {
            None => {}
            Some(Choice::InstallService) => {
                self.start_service_job(ServiceAction::Install, Some(id));
                self.elevation_prompt = None;
            }
            Some(Choice::Cancel) => self.elevation_prompt = None,
            Some(Choice::Test) => {
                self.elevation_prompt = None;
                self.start_connect(id, ConnectMode::HandshakeOnly);
            }
            Some(Choice::Restart) => {
                self.elevation_prompt = None;
                match deterium_engine::relaunch_elevated(&["--connect".into(), id.to_string()]) {
                    Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                    Err(deterium_engine::ElevateError::Declined) => {
                        self.toast = Some(toast(
                            "Cancelled — still running without administrator rights",
                            WARN,
                        ));
                    }
                    Err(err) => self.toast = Some(toast(err.to_string(), BAD)),
                }
            }
        }
    }

    fn show_delete_dialog(&mut self, ctx: &egui::Context) {
        let Some(id) = self.confirm_delete else {
            return;
        };
        let Some(name) = self.profile(id).map(|p| p.profile.name.clone()) else {
            self.confirm_delete = None;
            return;
        };

        let mut decision = None;
        egui::Window::new("Delete server?")
            .anchor(Align2::CENTER_CENTER, vec2(0.0, 0.0))
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(format!("\"{name}\" will be removed from this PC."));
                ui.label(dim(
                    "Its saved keys go with it. The server itself is not touched.",
                ));
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.add(ghost_button("Delete", BAD)).clicked() {
                        decision = Some(true);
                    }
                    if ui.add(ghost_button("Keep it", DIM)).clicked() {
                        decision = Some(false);
                    }
                });
            });

        match decision {
            Some(true) => {
                self.confirm_delete = None;
                self.delete(id);
            }
            Some(false) => self.confirm_delete = None,
            None => {}
        }
    }
}

fn sidebar_heading(ui: &mut egui::Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .size(11.0)
            .color(DIM)
            .extra_letter_spacing(1.2),
    );
    ui.add_space(8.0);
}

/// The native window handle, which the tray uses to wake a hidden window.
#[cfg(windows)]
fn native_window(cc: &eframe::CreationContext<'_>) -> Option<isize> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match cc.window_handle().ok()?.as_raw() {
        RawWindowHandle::Win32(handle) => Some(handle.hwnd.get()),
        _ => None,
    }
}

#[cfg(not(windows))]
fn native_window(_cc: &eframe::CreationContext<'_>) -> Option<isize> {
    None
}

fn main() -> eframe::Result<()> {
    // The same file is also the installer and the background service:
    // `Deterium.exe service install|uninstall|run ...` never opens a window.
    #[cfg(windows)]
    {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.first().map(String::as_str) == Some("service") {
            std::process::exit(deterium_service::cli::run(args));
        }
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Deterium VPN")
            .with_icon(std::sync::Arc::new(egui::IconData {
                rgba: logo::render(256, None),
                width: 256,
                height: 256,
            }))
            .with_inner_size([1040.0, 760.0])
            .with_min_inner_size([860.0, 640.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };

    eframe::run_native(
        "Deterium VPN",
        options,
        Box::new(|cc| {
            apply_style(&cc.egui_ctx);
            Ok(Box::new(DeteriumApp {
                tray: tray::Tray::new(&cc.egui_ctx, native_window(cc)),
                start_hidden: std::env::args().any(|arg| arg == "--minimized"),
                ..Default::default()
            }))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(attempts: u32, started: bool, due_in: Option<Duration>) -> AutostartJob {
        AutostartJob {
            id: Uuid::new_v4(),
            attempts,
            next_try: Instant::now() + due_in.unwrap_or_default(),
            started,
        }
    }

    fn step(job: &AutostartJob, seen: Seen) -> AutostartStep {
        // A moment after `next_try` for a due job, well before it for a waiting one.
        autostart_step(job, seen, Instant::now() + Duration::from_millis(1))
    }

    #[test]
    fn the_first_try_happens_right_away_and_needs_no_drop() {
        assert_eq!(
            step(&job(0, false, None), Seen::Idle),
            AutostartStep::Attempt {
                drop_current: false
            }
        );
    }

    #[test]
    fn a_connection_that_is_up_or_coming_up_ends_or_pauses_the_job() {
        assert_eq!(
            step(&job(1, true, None), Seen::Connected),
            AutostartStep::Finish
        );
        assert_eq!(
            step(&job(1, true, None), Seen::ComingUp),
            AutostartStep::Wait
        );
    }

    #[test]
    fn the_user_taking_over_ends_the_job() {
        // Another server was connected.
        assert_eq!(
            step(&job(0, false, None), Seen::Other),
            AutostartStep::Finish
        );
        // Disconnected after the app had already asked.
        assert_eq!(step(&job(1, true, None), Seen::Idle), AutostartStep::Finish);
    }

    #[test]
    fn a_failed_or_errored_attempt_is_retried_only_when_it_is_time() {
        let waiting = job(1, true, Some(Duration::from_secs(10)));
        assert_eq!(step(&waiting, Seen::Failed), AutostartStep::Wait);
        assert_eq!(step(&waiting, Seen::Errored), AutostartStep::Wait);

        let due = job(1, true, None);
        assert_eq!(
            step(&due, Seen::Failed),
            AutostartStep::Attempt {
                drop_current: false
            }
        );
        assert_eq!(
            step(&due, Seen::Errored),
            AutostartStep::Attempt { drop_current: true }
        );
    }

    #[test]
    fn it_gives_up_after_a_few_tries_instead_of_looping_for_ever() {
        let spent = job(AUTOSTART_TRIES, true, None);
        assert_eq!(step(&spent, Seen::Failed), AutostartStep::GiveUp);
        assert_eq!(step(&spent, Seen::Errored), AutostartStep::GiveUp);
        // One try left is still a try.
        assert_eq!(
            step(&job(AUTOSTART_TRIES - 1, true, None), Seen::Failed),
            AutostartStep::Attempt {
                drop_current: false
            }
        );
    }
}
