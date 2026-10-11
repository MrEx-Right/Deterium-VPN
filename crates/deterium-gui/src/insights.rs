//! Live numbers and the detail panel on the connect screen: download and
//! upload speed, latency, totals, a two-minute traffic graph, and the
//! Traffic / Connection / Protection / Log tabs.
//!
//! Everything shown is measured, never made up. Speed and totals are the byte
//! counters of the tunnel adapter (Windows keeps them, no administrator rights
//! needed, same for WireGuard and OpenVPN). Latency is a real ICMP echo to an
//! address *inside* the tunnel (the server's tunnel address, else the DNS server
//! the tunnel carries); with none to ask, the card says so instead of guessing.
//! The exit IP is only looked up when the user presses the button.

use super::DeteriumApp;
use crate::hero::{detail_rows, format_bytes, format_duration, host_of};
use crate::store::StoredProfile;
use crate::theme::*;
use deterium_core::{Protocol, ServerProfile, TunnelStatus, Uuid};
use eframe::egui::{self, pos2, vec2, Color32, Margin, RichText, Shape, Stroke};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Seconds of history kept (one sample per second).
pub const HISTORY: usize = 120;
const SAMPLE_EVERY: Duration = Duration::from_secs(1);
const PING_EVERY: Duration = Duration::from_secs(2);
const PING_TIMEOUT: Duration = Duration::from_millis(1500);
const TARGET_RETRY: Duration = Duration::from_secs(5);
/// A flat graph still needs a scale: 10 KB/s.
const MIN_SCALE: f64 = 10.0 * 1024.0;
const DOWN: Color32 = Color32::from_rgb(52, 211, 153);
const UP: Color32 = Color32::from_rgb(86, 140, 255);
const EVENT_CAPACITY: usize = 60;

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Traffic,
    Connection,
    Protection,
    Log,
}

// ------------------------------------------------------------ pure parts --

/// Bytes per second between two readings of a counter. A counter that went
/// backwards (the adapter was recreated) counts as no traffic, not as a huge
/// negative number.
pub fn rate(before: u64, after: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return 0.0;
    }
    after.saturating_sub(before) as f64 / secs
}

/// "4.8" and "MB/s" for a speed in bytes per second.
pub fn format_rate(bytes_per_second: f64) -> (String, &'static str) {
    const UNITS: [&str; 4] = ["B/s", "KB/s", "MB/s", "GB/s"];
    let mut value = bytes_per_second.max(0.0);
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    let text = if unit == 0 || value >= 100.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
    };
    (text, UNITS[unit])
}

/// Round trips seen so far.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Latency {
    pub last: Option<Duration>,
    pub best: Option<Duration>,
    pub worst: Option<Duration>,
    pub sent: u32,
    pub lost: u32,
}

impl Latency {
    pub fn record(&mut self, answer: Option<Duration>) {
        self.sent += 1;
        match answer {
            Some(rtt) => {
                self.last = Some(rtt);
                self.best = Some(self.best.map_or(rtt, |b| b.min(rtt)));
                self.worst = Some(self.worst.map_or(rtt, |w| w.max(rtt)));
            }
            None => {
                self.lost += 1;
                self.last = None;
            }
        }
    }

    pub fn loss_percent(&self) -> Option<f64> {
        (self.sent > 0).then(|| f64::from(self.lost) * 100.0 / f64::from(self.sent))
    }
}

/// The address inside the tunnel to measure latency against: the server's
/// tunnel address OpenVPN was given (`route-gateway`), else the first IPv4 DNS
/// server the tunnel carries. `None` when there is nothing inside the tunnel
/// to ask; the app never pings an outside address on its own.
pub fn latency_target(profile: &ServerProfile, log: &[String]) -> Option<IpAddr> {
    if let Some(wg) = &profile.wireguard {
        return wg
            .interface
            .dns
            .iter()
            .flatten()
            .filter_map(|d| d.trim().parse::<IpAddr>().ok())
            .find(IpAddr::is_ipv4);
    }
    let reply = log.iter().rev().find(|l| l.contains("PUSH_REPLY"))?;
    let after = |key: &str| {
        reply.split(',').find_map(|part| {
            part.trim()
                .strip_prefix(key)
                .and_then(|ip| ip.trim().trim_end_matches('\'').parse::<IpAddr>().ok())
                .filter(IpAddr::is_ipv4)
        })
    };
    after("route-gateway ").or_else(|| after("dhcp-option DNS "))
}

fn adapter_for(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Wireguard => deterium_proto_wireguard::ADAPTER_NAME,
        Protocol::Openvpn => deterium_engine::OPENVPN_ADAPTER_NAME,
    }
}

/// Asks a public "what is my address" service over plain HTTP. Only called
/// when the user presses the button; through a full tunnel the answer is the
/// server's address.
fn fetch_exit_ip() -> Result<String, String> {
    const HOST: &str = "api.ipify.org";
    let timeout = Duration::from_secs(6);
    let addr = (HOST, 80)
        .to_socket_addrs()
        .map_err(|e| format!("couldn't look up {HOST}: {e}"))?
        .next()
        .ok_or_else(|| format!("{HOST} has no address"))?;
    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("couldn't connect: {e}"))?;
    let _ = stream.set_read_timeout(Some(timeout));
    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: Deterium\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .map_err(|e| format!("couldn't ask: {e}"))?;
    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .map_err(|e| format!("no answer: {e}"))?;
    parse_exit_ip(&reply)
}

fn parse_exit_ip(reply: &str) -> Result<String, String> {
    let body = reply.split_once("\r\n\r\n").map_or("", |(_, body)| body);
    let candidate = body.trim();
    candidate
        .parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|_| "the answer wasn't an IP address".to_string())
}

// -------------------------------------------------------------- telemetry --

pub enum ExitIp {
    NotAsked,
    Asking(mpsc::Receiver<Result<String, String>>),
    Known(String),
    Failed(String),
}

/// What has been measured since the connection started.
pub struct Telemetry {
    pub profile: Uuid,
    adapter: &'static str,
    started: Instant,
    last_reading: Option<(Instant, u64, u64)>,
    /// Bytes per second, one per second, oldest first.
    pub down: VecDeque<f64>,
    pub up: VecDeque<f64>,
    pub rx_total: u64,
    pub tx_total: u64,
    pub peak_down: f64,
    pub peak_up: f64,
    down_sum: f64,
    samples: u32,
    pub latency: Latency,
    pub target: Option<IpAddr>,
    target_checked: Option<Instant>,
    ping: Option<mpsc::Receiver<Option<Duration>>>,
    last_ping: Option<Instant>,
    pub exit_ip: ExitIp,
    /// Things that happened, newest last, with the time since connecting.
    pub events: VecDeque<(Duration, String)>,
    last_status: Option<TunnelStatus>,
}

fn push_capped<T>(queue: &mut VecDeque<T>, value: T, capacity: usize) {
    if queue.len() == capacity {
        queue.pop_front();
    }
    queue.push_back(value);
}

impl Telemetry {
    pub fn new(profile: Uuid, protocol: Protocol) -> Self {
        Self {
            profile,
            adapter: adapter_for(protocol),
            started: Instant::now(),
            last_reading: None,
            down: VecDeque::new(),
            up: VecDeque::new(),
            rx_total: 0,
            tx_total: 0,
            peak_down: 0.0,
            peak_up: 0.0,
            down_sum: 0.0,
            samples: 0,
            latency: Latency::default(),
            target: None,
            target_checked: None,
            ping: None,
            last_ping: None,
            exit_ip: ExitIp::NotAsked,
            events: VecDeque::new(),
            last_status: None,
        }
    }

    pub fn average_down(&self) -> f64 {
        if self.samples == 0 {
            0.0
        } else {
            self.down_sum / f64::from(self.samples)
        }
    }

    pub fn current_down(&self) -> f64 {
        self.down.back().copied().unwrap_or(0.0)
    }

    pub fn current_up(&self) -> f64 {
        self.up.back().copied().unwrap_or(0.0)
    }

    pub fn note(&mut self, text: impl Into<String>) {
        push_capped(
            &mut self.events,
            (self.started.elapsed(), text.into()),
            EVENT_CAPACITY,
        );
    }

    /// Feeds one reading of the adapter's counters taken at `now`.
    pub fn record_counters(&mut self, now: Instant, rx: u64, tx: u64) {
        self.rx_total = rx;
        self.tx_total = tx;
        if let Some((then, rx_before, tx_before)) = self.last_reading {
            let elapsed = now.saturating_duration_since(then);
            let (down, up) = (rate(rx_before, rx, elapsed), rate(tx_before, tx, elapsed));
            push_capped(&mut self.down, down, HISTORY);
            push_capped(&mut self.up, up, HISTORY);
            self.peak_down = self.peak_down.max(down);
            self.peak_up = self.peak_up.max(up);
            self.down_sum += down;
            self.samples += 1;
        }
        self.last_reading = Some((now, rx, tx));
    }

    /// Called every frame while a tunnel exists. Cheap unless a sample or a
    /// ping is due.
    pub fn poll(
        &mut self,
        status: TunnelStatus,
        profile: &ServerProfile,
        log: impl Fn() -> Vec<String>,
    ) {
        let now = Instant::now();

        if self.last_status != Some(status) {
            self.note(match status {
                TunnelStatus::Connecting => "Connecting",
                TunnelStatus::Connected => "Connected",
                TunnelStatus::Reconnecting => "Connection lost, reconnecting",
                TunnelStatus::Disconnected => "Disconnected",
                TunnelStatus::Error => "Connection failed",
            });
            self.last_status = Some(status);
        }

        if let ExitIp::Asking(answer) = &self.exit_ip {
            if let Ok(result) = answer.try_recv() {
                match &result {
                    Ok(ip) => self.note(format!("Exit IP is {ip}")),
                    Err(why) => self.note(format!("Couldn't check the exit IP: {why}")),
                }
                self.exit_ip = match result {
                    Ok(ip) => ExitIp::Known(ip),
                    Err(why) => ExitIp::Failed(why),
                };
            }
        }

        if status != TunnelStatus::Connected {
            return;
        }

        let due = self
            .last_reading
            .is_none_or(|(then, _, _)| now.duration_since(then) >= SAMPLE_EVERY);
        if due {
            if let Some(counters) = deterium_engine::adapter_counters(self.adapter) {
                self.record_counters(now, counters.rx_bytes, counters.tx_bytes);
            }
        }

        if let Some(answer) = &self.ping {
            if let Ok(rtt) = answer.try_recv() {
                self.latency.record(rtt);
                self.ping = None;
            }
        }

        if self.target.is_none()
            && self
                .target_checked
                .is_none_or(|t| now.duration_since(t) >= TARGET_RETRY)
        {
            self.target_checked = Some(now);
            self.target = latency_target(profile, &log());
        }

        if let (Some(target), None) = (self.target, &self.ping) {
            if self
                .last_ping
                .is_none_or(|t| now.duration_since(t) >= PING_EVERY)
            {
                self.last_ping = Some(now);
                let (sender, receiver) = mpsc::channel();
                std::thread::spawn(move || {
                    let _ = sender.send(deterium_engine::ping(target, PING_TIMEOUT));
                });
                self.ping = Some(receiver);
            }
        }
    }

    fn ask_exit_ip(&mut self) {
        if matches!(self.exit_ip, ExitIp::Asking(_)) {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(fetch_exit_ip());
        });
        self.exit_ip = ExitIp::Asking(receiver);
    }
}

// ---------------------------------------------------------------- drawing --

fn polyline(rect: egui::Rect, values: &VecDeque<f64>, scale: f64) -> Vec<egui::Pos2> {
    let slots = (HISTORY - 1) as f32;
    let first = HISTORY - values.len().min(HISTORY);
    values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = rect.left() + (first + i) as f32 / slots * rect.width();
            let y = rect.bottom() - ((*v / scale).clamp(0.0, 1.0) as f32) * rect.height();
            pos2(x, y)
        })
        .collect()
}

fn scale_of(series: &[&VecDeque<f64>]) -> f64 {
    series
        .iter()
        .flat_map(|s| s.iter())
        .copied()
        .fold(MIN_SCALE, f64::max)
}

fn sparkline(ui: &mut egui::Ui, values: &VecDeque<f64>, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 22.0), egui::Sense::hover());
    if values.len() >= 2 && ui.is_rect_visible(rect) {
        let points = polyline(rect, values, scale_of(&[values]));
        ui.painter()
            .add(Shape::line(points, Stroke::new(1.5, color)));
    }
}

fn traffic_chart(ui: &mut egui::Ui, telemetry: Option<&Telemetry>) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 96.0), egui::Sense::hover());
    if !ui.is_rect_visible(rect) {
        return;
    }
    let painter = ui.painter();
    painter.rect_filled(rect, 8.0, with_alpha(BORDER, 70));
    for fraction in [0.5_f32, 0.0] {
        let y = rect.bottom() - fraction * rect.height();
        painter.line_segment(
            [pos2(rect.left(), y), pos2(rect.right(), y)],
            Stroke::new(1.0, with_alpha(DIM, 40)),
        );
    }
    let Some(t) = telemetry.filter(|t| t.down.len() >= 2) else {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "Waiting for traffic",
            egui::FontId::proportional(13.0),
            DIM,
        );
        return;
    };
    let scale = scale_of(&[&t.down, &t.up]);
    painter.add(Shape::line(
        polyline(rect, &t.down, scale),
        Stroke::new(1.8, DOWN),
    ));
    painter.add(Shape::line(
        polyline(rect, &t.up, scale),
        Stroke::new(1.8, UP),
    ));
    let (top, unit) = format_rate(scale);
    painter.text(
        rect.left_top() + vec2(8.0, 5.0),
        egui::Align2::LEFT_TOP,
        format!("{top} {unit}"),
        egui::FontId::proportional(11.0),
        DIM,
    );
}

fn metric_tile(
    ui: &mut egui::Ui,
    label: &str,
    value: &str,
    unit: &str,
    footer: &str,
    spark: Option<(&VecDeque<f64>, Color32)>,
) {
    // Tighter than the shared card: four of these share one row, and the
    // window can be as narrow as 860 px.
    egui::Frame::none()
        .fill(with_alpha(CARD, 215))
        .stroke(Stroke::new(1.0_f32, BORDER))
        .rounding(12.0)
        .inner_margin(Margin::symmetric(12.0, 10.0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.set_min_height(84.0);
            ui.spacing_mut().item_spacing.y = 3.0;
            ui.label(
                RichText::new(label)
                    .size(10.5)
                    .color(DIM)
                    .extra_letter_spacing(1.2),
            );
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(RichText::new(value).size(22.0).strong().color(TEXT));
                if !unit.is_empty() {
                    ui.label(RichText::new(unit).size(12.0).color(DIM));
                }
            });
            match spark {
                Some((values, color)) => sparkline(ui, values, color),
                None => {
                    ui.label(RichText::new(footer).size(11.5).color(DIM));
                }
            }
        });
}

fn rows(ui: &mut egui::Ui, id: &str, content: impl FnOnce(&mut Vec<(String, String)>)) {
    let mut list = Vec::new();
    content(&mut list);
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([30.0, 9.0])
        .show(ui, |ui| {
            for (key, value) in list {
                ui.label(RichText::new(key).size(13.0).color(DIM));
                ui.add(egui::Label::new(RichText::new(value).size(13.5).color(TEXT)).wrap());
                ui.end_row();
            }
        });
}

// -------------------------------------------------------------- the panel --

impl DeteriumApp {
    /// Keeps `telemetry` in step with the connection: created when a tunnel
    /// appears, dropped when it goes, fed while it is up.
    pub(crate) fn sync_telemetry(&mut self) {
        let active = match &self.connection {
            super::Connection::Active {
                profile,
                tunnel,
                status,
                ..
            } => Some((*profile, tunnel, *status)),
            _ => None,
        };
        let Some((id, tunnel, status)) = active else {
            self.telemetry = None;
            return;
        };
        let Some(stored) = self.profiles.iter().find(|p| p.profile.id == id) else {
            return;
        };
        let profile = &stored.profile;
        if self.telemetry.as_ref().is_none_or(|t| t.profile != id) {
            self.telemetry = Some(Telemetry::new(id, profile.protocol));
        }
        if let Some(t) = self.telemetry.as_mut() {
            t.poll(status, profile, || tunnel.log());
        }
    }

    pub(crate) fn show_insights(&mut self, ui: &mut egui::Ui, stored: &StoredProfile) {
        let profile = &stored.profile;
        let id = profile.id;
        let live = self.telemetry.as_ref().filter(|t| t.profile == id);

        ui.columns(4, |cols| {
            let dash = "-".to_string();
            let (down, down_unit) = live.map_or((dash.clone(), ""), |t| {
                let (v, u) = format_rate(t.current_down());
                (v, u)
            });
            metric_tile(
                &mut cols[0],
                "DOWNLOAD",
                &down,
                down_unit,
                "Connect to see speed",
                live.map(|t| (&t.down, DOWN)),
            );
            let (up, up_unit) = live.map_or((dash.clone(), ""), |t| {
                let (v, u) = format_rate(t.current_up());
                (v, u)
            });
            metric_tile(
                &mut cols[1],
                "UPLOAD",
                &up,
                up_unit,
                "Connect to see speed",
                live.map(|t| (&t.up, UP)),
            );
            let (latency, latency_unit, latency_note) = match live {
                Some(t) => match (t.latency.last, t.target) {
                    (Some(rtt), _) => (
                        rtt.as_millis().to_string(),
                        "ms",
                        match (t.latency.best, t.latency.worst) {
                            (Some(b), Some(w)) => {
                                format!("best {} / worst {}", b.as_millis(), w.as_millis())
                            }
                            _ => String::new(),
                        },
                    ),
                    (None, Some(_)) if t.latency.sent > 0 => {
                        (dash.clone(), "", "no answer from the server".to_string())
                    }
                    (None, Some(_)) => (dash.clone(), "", "measuring...".to_string()),
                    (None, None) => (
                        dash.clone(),
                        "",
                        "nothing inside the tunnel to ask".to_string(),
                    ),
                },
                None => (dash.clone(), "", "Connect to measure".to_string()),
            };
            metric_tile(
                &mut cols[2],
                "LATENCY",
                &latency,
                latency_unit,
                &latency_note,
                None,
            );
            let (total, total_note) = match live {
                Some(t) => (
                    format_bytes(t.rx_total + t.tx_total),
                    format!(
                        "down {} / up {}",
                        format_bytes(t.rx_total),
                        format_bytes(t.tx_total)
                    ),
                ),
                None => (dash.clone(), "Connect to count".to_string()),
            };
            metric_tile(&mut cols[3], "TOTAL", &total, "", &total_note, None);
        });

        ui.add_space(14.0);
        ui.horizontal(|ui| {
            for (tab, label) in [
                (Tab::Traffic, "Traffic"),
                (Tab::Connection, "Connection"),
                (Tab::Protection, "Protection"),
                (Tab::Log, "Log"),
            ] {
                let color = if self.insight_tab == tab { ACCENT } else { DIM };
                if ui.add(ghost_button(label, color)).clicked() {
                    self.insight_tab = tab;
                }
            }
        });
        ui.add_space(8.0);

        match self.insight_tab {
            Tab::Traffic => self.traffic_tab(ui, id),
            Tab::Connection => self.connection_tab(ui, stored),
            Tab::Protection => self.protection_tab(ui, profile),
            Tab::Log => self.log_tab(ui, id),
        }
    }

    fn traffic_tab(&mut self, ui: &mut egui::Ui, id: Uuid) {
        let live = self.telemetry.as_ref().filter(|t| t.profile == id);
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Last two minutes").size(12.0).color(DIM));
                ui.label(RichText::new("download").size(12.0).color(DOWN));
                ui.label(RichText::new("upload").size(12.0).color(UP));
            });
            ui.add_space(4.0);
            traffic_chart(ui, live);
            ui.add_space(8.0);
            let fmt = |v: f64| {
                let (n, u) = format_rate(v);
                format!("{n} {u}")
            };
            let (peak, avg, peak_up, loss) = match live {
                Some(t) => (
                    fmt(t.peak_down),
                    fmt(t.average_down()),
                    fmt(t.peak_up),
                    t.latency
                        .loss_percent()
                        .map_or("-".to_string(), |p| format!("{p:.0}%")),
                ),
                None => ("-".into(), "-".into(), "-".into(), "-".into()),
            };
            ui.columns(4, |cols| {
                for (col, (label, value)) in cols.iter_mut().zip([
                    ("Peak download", peak),
                    ("Average download", avg),
                    ("Peak upload", peak_up),
                    ("Lost pings", loss),
                ]) {
                    col.label(RichText::new(label).size(11.5).color(DIM));
                    col.label(RichText::new(value).size(14.0).strong().color(TEXT));
                }
            });
        });
    }

    fn connection_tab(&mut self, ui: &mut egui::Ui, stored: &StoredProfile) {
        let profile = &stored.profile;
        let id = profile.id;
        let handshake = match &self.connection {
            super::Connection::Active {
                profile: p, tunnel, ..
            } if *p == id => tunnel.stats().and_then(|s| s.last_handshake),
            _ => None,
        };
        let live = self.telemetry.as_ref().filter(|t| t.profile == id);
        let target = live.and_then(|t| t.target);
        let mut ask = false;
        card(ui, |ui| {
            rows(ui, "live_rows", |list| {
                list.push(("Server".into(), host_of(profile)));
                list.push((
                    "Protocol".into(),
                    match profile.protocol {
                        Protocol::Wireguard => "WireGuard".into(),
                        Protocol::Openvpn => "OpenVPN".into(),
                    },
                ));
                if live.is_some() {
                    list.push((
                        "Tunnel adapter".into(),
                        adapter_for(profile.protocol).to_string(),
                    ));
                    list.push((
                        "Latency measured against".into(),
                        target.map_or("nothing inside the tunnel".to_string(), |t| {
                            format!("{t} (inside the tunnel)")
                        }),
                    ));
                }
                if let Some(age) = handshake {
                    list.push((
                        "Last handshake".into(),
                        format!("{} ago", format_duration(age)),
                    ));
                }
            });
            if let Some(t) = live {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Exit IP").size(13.0).color(DIM));
                    match &t.exit_ip {
                        ExitIp::Known(ip) => {
                            ui.label(RichText::new(ip).size(13.5).strong().color(TEXT));
                        }
                        ExitIp::Asking(_) => {
                            ui.label(RichText::new("checking...").size(13.0).color(DIM));
                        }
                        ExitIp::Failed(why) => {
                            ui.label(RichText::new(why).size(12.5).color(BAD));
                        }
                        ExitIp::NotAsked => {}
                    }
                    let asking = matches!(t.exit_ip, ExitIp::Asking(_));
                    if ui
                        .add_enabled(!asking, ghost_button("Check exit IP", ACCENT))
                        .on_hover_text(
                            "Asks api.ipify.org once, now, over the tunnel. Deterium never does this by itself.",
                        )
                        .clicked()
                    {
                        ask = true;
                    }
                });
            }
            ui.add_space(10.0);
            ui.separator();
            ui.add_space(8.0);
            detail_rows(ui, profile);
        });
        if ask {
            if let Some(t) = self.telemetry.as_mut() {
                t.ask_exit_ip();
            }
        }
    }

    fn protection_tab(&mut self, ui: &mut egui::Ui, profile: &ServerProfile) {
        let id = profile.id;
        let active =
            matches!(&self.connection, super::Connection::Active { profile: p, .. } if *p == id);
        let rules = match &self.connection {
            super::Connection::Active {
                profile: p, tunnel, ..
            } if *p == id => Some(tunnel.leak_protection()),
            _ => None,
        };
        let sec = &profile.security;
        let on_off = |on: bool| if on { "on" } else { "off" };
        card(ui, |ui| {
            rows(ui, "protection_rows", |list| {
                list.push(("Kill switch".into(), on_off(sec.kill_switch).into()));
                list.push((
                    "Local network".into(),
                    if !sec.kill_switch {
                        "not restricted".into()
                    } else if sec.allow_lan {
                        "reachable while protected".into()
                    } else {
                        "blocked while protected".into()
                    },
                ));
                list.push((
                    "DNS leak blocking".into(),
                    format!(
                        "{} (applied when the tunnel carries your DNS)",
                        on_off(sec.block_dns_leaks)
                    ),
                ));
                list.push((
                    "Firewall rules right now".into(),
                    match (active, rules) {
                        (true, Some(true)) => "in force".into(),
                        (true, _) => "none".into(),
                        _ => "not connected".into(),
                    },
                ));
            });
            if active && sec.kill_switch && rules == Some(false) {
                ui.add_space(8.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "The kill switch is on for this server but its rules aren't in force yet. Until they are, traffic isn't held back.",
                        )
                        .size(12.5)
                        .strong()
                        .color(WARN),
                    )
                    .wrap(),
                );
            }
            ui.add_space(8.0);
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "With the kill switch on and the background service installed, a restart of the PC keeps the network blocked (except to your VPN server) until you connect again or turn the protection off.",
                    )
                    .size(12.0)
                    .color(DIM),
                )
                .wrap(),
            );
        });
    }

    fn log_tab(&mut self, ui: &mut egui::Ui, id: Uuid) {
        let lines = match &self.connection {
            super::Connection::Active {
                profile: p, tunnel, ..
            } if *p == id => tunnel.log(),
            _ => Vec::new(),
        };
        let events: Vec<(Duration, String)> = self
            .telemetry
            .as_ref()
            .filter(|t| t.profile == id)
            .map(|t| t.events.iter().cloned().collect())
            .unwrap_or_default();
        card(ui, |ui| {
            ui.label(RichText::new("Events").size(12.0).color(DIM));
            if events.is_empty() {
                ui.label(
                    RichText::new("Nothing yet. Connect to start.")
                        .size(12.5)
                        .color(DIM),
                );
            }
            for (at, text) in events.iter().rev().take(12) {
                ui.label(
                    RichText::new(format!("+{}  {text}", format_duration(*at)))
                        .monospace()
                        .size(11.5)
                        .color(TEXT),
                );
            }
            if !lines.is_empty() {
                ui.add_space(8.0);
                ui.label(RichText::new("OpenVPN").size(12.0).color(DIM));
                egui::ScrollArea::vertical()
                    .max_height(180.0)
                    .id_source("openvpn_log")
                    .show(ui, |ui| {
                        for line in lines.iter().rev().take(40).rev() {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(line).monospace().size(11.0).color(DIM),
                                )
                                .wrap(),
                            );
                        }
                    });
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deterium_core::import::{parse_openvpn, parse_wireguard_conf};

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn a_rate_is_bytes_over_time_and_never_negative() {
        assert_eq!(rate(1_000, 3_048, secs(2)), 1_024.0);
        assert_eq!(rate(5_000, 100, secs(1)), 0.0, "a recreated adapter");
        assert_eq!(rate(1, 2, Duration::ZERO), 0.0);
    }

    #[test]
    fn speeds_are_shown_in_a_readable_unit() {
        assert_eq!(format_rate(0.0), ("0".into(), "B/s"));
        assert_eq!(format_rate(512.0), ("512".into(), "B/s"));
        assert_eq!(format_rate(1536.0), ("1.5".into(), "KB/s"));
        assert_eq!(format_rate(4.8 * 1024.0 * 1024.0), ("4.8".into(), "MB/s"));
        assert_eq!(format_rate(250.0 * 1024.0 * 1024.0), ("250".into(), "MB/s"));
        assert_eq!(format_rate(-3.0), ("0".into(), "B/s"));
    }

    #[test]
    fn counters_become_a_history_with_peak_and_average() {
        let mut t = Telemetry::new(Uuid::nil(), Protocol::Wireguard);
        let start = Instant::now();
        t.record_counters(start, 1_000, 100);
        assert!(t.down.is_empty(), "one reading is not a rate yet");
        t.record_counters(start + secs(1), 3_000, 100);
        t.record_counters(start + secs(2), 4_000, 600);
        assert_eq!(t.down, VecDeque::from([2_000.0, 1_000.0]));
        assert_eq!(t.up, VecDeque::from([0.0, 500.0]));
        assert_eq!(t.peak_down, 2_000.0);
        assert_eq!(t.average_down(), 1_500.0);
        assert_eq!((t.rx_total, t.tx_total), (4_000, 600));
    }

    #[test]
    fn the_history_never_grows_past_two_minutes() {
        let mut t = Telemetry::new(Uuid::nil(), Protocol::Openvpn);
        let start = Instant::now();
        for i in 0..(HISTORY as u64 + 50) {
            t.record_counters(start + secs(i), i * 10, i);
        }
        assert_eq!(t.down.len(), HISTORY);
        assert_eq!(t.up.len(), HISTORY);
    }

    #[test]
    fn latency_keeps_best_worst_and_counts_losses() {
        let mut l = Latency::default();
        assert_eq!(l.loss_percent(), None);
        l.record(Some(Duration::from_millis(50)));
        l.record(Some(Duration::from_millis(40)));
        l.record(None);
        l.record(Some(Duration::from_millis(70)));
        assert_eq!(l.last, Some(Duration::from_millis(70)));
        assert_eq!(l.best, Some(Duration::from_millis(40)));
        assert_eq!(l.worst, Some(Duration::from_millis(70)));
        assert_eq!(l.loss_percent(), Some(25.0));
    }

    const WG: &str = "[Interface]\nPrivateKey = AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=\nAddress = 10.6.0.2/32\nDNS = 10.6.0.1, 1.1.1.1\n[Peer]\nPublicKey = hNB8xHQbFgfPavZ3NEhjv5+SRZ6TESr65wrlc71XuxA=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n";

    #[test]
    fn wireguard_measures_against_the_first_ipv4_dns_server_in_the_tunnel() {
        let profile = parse_wireguard_conf(WG, "t").unwrap().profile;
        assert_eq!(
            latency_target(&profile, &[]),
            Some("10.6.0.1".parse().unwrap())
        );
        let no_dns = parse_wireguard_conf(&WG.replace("DNS = 10.6.0.1, 1.1.1.1\n", ""), "t")
            .unwrap()
            .profile;
        assert_eq!(latency_target(&no_dns, &[]), None);
    }

    #[test]
    fn openvpn_measures_against_the_pushed_gateway_else_the_pushed_dns() {
        let profile = parse_openvpn("client\nremote a.example 1194\n", "t")
            .unwrap()
            .profile;
        assert_eq!(latency_target(&profile, &["unrelated".into()]), None);

        let both = "PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 8.8.8.8,route-gateway 10.8.0.1,ifconfig 10.8.0.2 255.255.255.0'".to_string();
        assert_eq!(
            latency_target(&profile, &[both]),
            Some("10.8.0.1".parse().unwrap())
        );
        let dns_only =
            "PUSH_REPLY,dhcp-option DNS 10.9.0.1,ifconfig 10.9.0.2 255.255.255.0".to_string();
        assert_eq!(
            latency_target(&profile, &[dns_only]),
            Some("10.9.0.1".parse().unwrap())
        );
    }

    #[test]
    fn the_exit_ip_is_only_trusted_when_it_is_an_ip() {
        let ok = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n203.0.113.9\n";
        assert_eq!(parse_exit_ip(ok).unwrap(), "203.0.113.9");
        assert!(parse_exit_ip("HTTP/1.1 200 OK\r\n\r\n<html>blocked</html>").is_err());
        assert!(parse_exit_ip("no headers at all").is_err());
    }

    #[test]
    fn every_tab_draws_with_and_without_a_live_tunnel() {
        let dir = std::env::temp_dir().join(format!("deterium-insights-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("DETERIUM_DATA_DIR", &dir);

        let profile = parse_wireguard_conf(WG, "draw test").unwrap().profile;
        let id = profile.id;
        let stored = StoredProfile {
            path: dir.join("draw-test.toml"),
            profile,
            builtin: false,
        };

        let mut app = DeteriumApp::default();
        let ctx = egui::Context::default();
        let draw = |app: &mut DeteriumApp| {
            for tab in [Tab::Traffic, Tab::Connection, Tab::Protection, Tab::Log] {
                app.insight_tab = tab;
                let _ = ctx.run(egui::RawInput::default(), |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| app.show_insights(ui, &stored));
                });
            }
        };

        app.telemetry = None;
        draw(&mut app);

        let mut live = Telemetry::new(id, Protocol::Wireguard);
        let start = Instant::now();
        for i in 0..30u64 {
            live.record_counters(start + secs(i), i * 40_000 + (i % 7) * 9_000, i * 4_000);
        }
        live.latency.record(Some(Duration::from_millis(48)));
        live.latency.record(None);
        live.target = Some("10.6.0.1".parse().unwrap());
        live.exit_ip = ExitIp::Known("203.0.113.9".into());
        live.note("Connected");
        app.telemetry = Some(live);
        draw(&mut app);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
