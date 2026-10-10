//! Everything for adding and configuring servers from the UI: the "add a
//! server" chooser, the full editor form, and the "set up my own server"
//! wizard. These are pure views — they edit state and return an action; the
//! app decides what to save, connect or delete.

use crate::draft::{Draft, ROUTE_ALL, ROUTE_PRIVATE_ONLY};
use crate::theme::*;
use deterium_core::import::parse_any;
use deterium_core::provision::{wireguard_server_script, WireGuardServerSetup};
use deterium_core::{Problem, Protocol, ServerProfile};
use deterium_proto_wireguard::{
    generate_preshared_key, generate_private_key, public_key_from_private,
};
use eframe::egui::{self, vec2, Align, Color32, Layout, RichText, TextEdit};
use std::path::PathBuf;

// ---------------------------------------------------------------- shared --

struct Fields<'a> {
    problems: &'a [Problem],
    show_all: bool,
}

impl Fields<'_> {
    /// Label, input, then that field's problems (only once the user has
    /// typed something there, or tried to save) and an optional hint.
    fn field(
        &self,
        ui: &mut egui::Ui,
        label: &str,
        id: &str,
        empty: bool,
        hint: Option<&str>,
        add: impl FnOnce(&mut egui::Ui),
    ) {
        ui.label(RichText::new(label).size(12.5).color(DIM));
        add(ui);
        if !empty || self.show_all {
            for problem in self.problems.iter().filter(|p| p.field == id) {
                ui.label(RichText::new(&problem.message).size(12.0).color(BAD));
            }
        }
        if let Some(hint) = hint {
            ui.label(RichText::new(hint).size(11.5).color(DIM));
        }
        ui.add_space(6.0);
    }
}

fn text_input(ui: &mut egui::Ui, value: &mut String, hint: &str) {
    ui.add(
        TextEdit::singleline(value)
            .hint_text(hint)
            .desired_width(f32::INFINITY),
    );
}

fn copy(ui: &egui::Ui, text: String, toast_slot: &mut Option<Toast>, what: &str) {
    ui.ctx().copy_text(text);
    *toast_slot = Some(toast(format!("{what} copied"), GOOD));
}

pub enum Picked {
    Cancelled,
    Text { text: String, hint: String },
    Error(String),
}

/// Native file picker for configs; reads the chosen file as text.
pub fn pick_config_file() -> Picked {
    let Some(path) = rfd::FileDialog::new()
        .set_title("Choose a VPN config")
        .add_filter("VPN configs", &["conf", "ovpn", "toml", "txt"])
        .add_filter("All files", &["*"])
        .pick_file()
    else {
        return Picked::Cancelled;
    };
    read_config_file(&path)
}

pub fn read_config_file(path: &PathBuf) -> Picked {
    let hint = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    match std::fs::read_to_string(path) {
        Ok(text) => Picked::Text { text, hint },
        Err(err) => Picked::Error(format!("Couldn't read {}: {err}", path.display())),
    }
}

// --------------------------------------------------------------- chooser --

pub enum ChooserAction {
    None,
    Cancel,
    ImportFile,
    Paste,
    Wizard,
    ManualWireGuard,
    ManualOpenVpn,
}

pub fn show_chooser(ui: &mut egui::Ui, can_cancel: bool) -> ChooserAction {
    let mut action = ChooserAction::None;

    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Add a server")
                .size(26.0)
                .strong()
                .color(TEXT),
        );
        if can_cancel {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(ghost_button("Cancel", DIM)).clicked() {
                    action = ChooserAction::Cancel;
                }
            });
        }
    });
    ui.label(dim(
        "Deterium never hosts servers. Use one you rent, one you run, or one from a VPN subscription.",
    ));
    ui.add_space(16.0);

    ui.columns(2, |cols| {
        if choice_card(
            &mut cols[0],
            "Set up my own server",
            "Rent any VPS, paste one generated script into it, and Deterium creates \
             the keys and the profile for you.",
            "RECOMMENDED",
        ) {
            action = ChooserAction::Wizard;
        }
        if choice_card(
            &mut cols[1],
            "Import a config file",
            "A WireGuard .conf, OpenVPN .ovpn or Deterium .toml from your VPN \
             provider or an existing server.",
            "",
        ) {
            action = ChooserAction::ImportFile;
        }
    });
    ui.add_space(4.0);
    ui.columns(2, |cols| {
        if choice_card(
            &mut cols[0],
            "Paste a config",
            "Copied a config from an email or a dashboard? Paste the text and review it \
             before saving.",
            "",
        ) {
            action = ChooserAction::Paste;
        }
        if choice_card(
            &mut cols[1],
            "Create WireGuard manually",
            "Fill in every setting yourself: keys, addresses, DNS, routes, keepalive, \
             port, MTU and more.",
            "",
        ) {
            action = ChooserAction::ManualWireGuard;
        }
    });
    ui.add_space(4.0);
    ui.columns(2, |cols| {
        if choice_card(
            &mut cols[0],
            "Create OpenVPN manually",
            "Paste or write an .ovpn config. Needs the OpenVPN client installed on this PC.",
            "",
        ) {
            action = ChooserAction::ManualOpenVpn;
        }
    });

    ui.add_space(16.0);
    ui.label(dim(
        "Tip: you can also drop a config file anywhere on this window.",
    ));
    action
}

// ---------------------------------------------------------------- editor --

pub struct Notice {
    pub text: String,
    pub color: Color32,
}

pub struct EditorState {
    pub draft: Draft,
    pub is_new: bool,
    show_private: bool,
    show_psk: bool,
    show_all_errors: bool,
    notice: Option<Notice>,
    paste: Option<String>,
    openvpn_found: Option<PathBuf>,
}

pub enum EditorAction {
    None,
    Save(Box<ServerProfile>),
    Cancel,
}

impl EditorState {
    pub fn new(draft: Draft, is_new: bool) -> Self {
        Self {
            draft,
            is_new,
            show_private: false,
            show_psk: false,
            show_all_errors: false,
            notice: None,
            paste: None,
            openvpn_found: deterium_engine::find_openvpn(),
        }
    }

    pub fn with_paste_open(mut self) -> Self {
        self.paste = Some(String::new());
        self
    }

    pub fn import_text(&mut self, text: &str, hint: &str) {
        match parse_any(text, hint) {
            Ok(imported) => {
                let name = imported.profile.name.clone();
                let notes = imported.warnings.len();
                let mut message = format!("Imported \"{name}\". Review the settings, then save.");
                if notes > 0 {
                    message.push_str(&format!(
                        "\n{notes} thing(s) weren't carried over: {}",
                        imported.warnings.join("; ")
                    ));
                }
                self.notice = Some(Notice {
                    text: message,
                    color: if notes > 0 { WARN } else { GOOD },
                });
                self.draft.apply_import(imported);
                self.show_all_errors = false;
            }
            Err(err) => {
                self.notice = Some(Notice {
                    text: err.to_string(),
                    color: BAD,
                });
            }
        }
    }

    pub fn import_picked(&mut self, picked: Picked) {
        match picked {
            Picked::Cancelled => {}
            Picked::Text { text, hint } => self.import_text(&text, &hint),
            Picked::Error(message) => {
                self.notice = Some(Notice {
                    text: message,
                    color: BAD,
                })
            }
        }
    }
}

pub fn show_editor(
    ui: &mut egui::Ui,
    st: &mut EditorState,
    toast_slot: &mut Option<Toast>,
) -> EditorAction {
    let problems = st.draft.problems();
    let mut save = false;
    let mut cancel = false;

    ui.horizontal(|ui| {
        ui.label(
            RichText::new(if st.is_new {
                "New server"
            } else {
                "Edit server"
            })
            .size(26.0)
            .strong()
            .color(TEXT),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            save = ui.add(primary_button("Save")).clicked();
            cancel = ui.add(ghost_button("Cancel", DIM)).clicked();
        });
    });
    if save {
        if problems.is_empty() {
            return match st.draft.build() {
                Ok(profile) => EditorAction::Save(Box::new(profile)),
                Err(_) => EditorAction::None,
            };
        }
        st.show_all_errors = true;
    }
    if !problems.is_empty() && st.show_all_errors {
        ui.label(
            RichText::new(format!(
                "{} setting(s) need attention — highlighted below",
                problems.len()
            ))
            .size(13.0)
            .color(BAD),
        );
    }
    ui.add_space(6.0);

    import_bar(ui, st);
    ui.add_space(10.0);

    let fields = Fields {
        problems: &problems,
        show_all: st.show_all_errors,
    };

    general_card(ui, st, &fields);
    ui.add_space(12.0);

    match st.draft.protocol {
        Protocol::Wireguard => {
            interface_card(ui, st, &fields, toast_slot);
            ui.add_space(12.0);
            peer_card(ui, st, &fields);
            ui.add_space(12.0);
            protection_card(ui, st);
            ui.add_space(12.0);
            snippet_card(ui, st, toast_slot);
        }
        Protocol::Openvpn => {
            openvpn_card(ui, st, &fields);
            ui.add_space(12.0);
            protection_card(ui, st);
        }
    }

    ui.add_space(16.0);
    ui.horizontal(|ui| {
        if ui.add(primary_button("Save")).clicked() {
            if problems.is_empty() {
                save = true;
            } else {
                st.show_all_errors = true;
            }
        }
        if ui.add(ghost_button("Cancel", DIM)).clicked() {
            cancel = true;
        }
    });
    ui.add_space(30.0);

    if cancel {
        return EditorAction::Cancel;
    }
    if save {
        if let Ok(profile) = st.draft.build() {
            return EditorAction::Save(Box::new(profile));
        }
    }
    EditorAction::None
}

fn import_bar(ui: &mut egui::Ui, st: &mut EditorState) {
    ui.horizontal(|ui| {
        if ui.add(ghost_button("Import file…", ACCENT)).clicked() {
            st.import_picked(pick_config_file());
        }
        if ui.add(ghost_button("Paste config…", ACCENT)).clicked() {
            st.paste = if st.paste.is_some() {
                None
            } else {
                Some(String::new())
            };
        }
    });
    ui.label(dim(
        "Fill the form from a WireGuard .conf, OpenVPN .ovpn or Deterium .toml.",
    ));

    let mut import_now = None;
    let mut close = false;
    if let Some(text) = st.paste.as_mut() {
        ui.add_space(6.0);
        card(ui, |ui| {
            ui.label(dim("Paste the config text:"));
            ui.add(
                TextEdit::multiline(text)
                    .code_editor()
                    .desired_rows(8)
                    .desired_width(f32::INFINITY)
                    .hint_text("[Interface]\nPrivateKey = …\n…"),
            );
            ui.horizontal(|ui| {
                if ui.add(primary_button("Import")).clicked() {
                    import_now = Some(text.clone());
                }
                if ui.add(ghost_button("Close", DIM)).clicked() {
                    close = true;
                }
            });
        });
    }
    if let Some(text) = import_now {
        st.import_text(&text, "");
        st.paste = None;
    } else if close {
        st.paste = None;
    }

    if let Some(notice) = &st.notice {
        ui.add_space(6.0);
        ui.label(RichText::new(&notice.text).size(13.0).color(notice.color));
    }
}

fn general_card(ui: &mut egui::Ui, st: &mut EditorState, fields: &Fields) {
    card(ui, |ui| {
        section_title(ui, "General");

        fields.field(
            ui,
            "Name",
            "name",
            st.draft.name.trim().is_empty(),
            None,
            |ui| {
                text_input(ui, &mut st.draft.name, "e.g. Frankfurt VPS");
            },
        );

        ui.label(RichText::new("Protocol").size(12.5).color(DIM));
        ui.horizontal(|ui| {
            for (protocol, label) in [
                (Protocol::Wireguard, "WireGuard"),
                (Protocol::Openvpn, "OpenVPN"),
            ] {
                let selected = st.draft.protocol == protocol;
                let button =
                    egui::Button::new(RichText::new(label).size(14.0).color(if selected {
                        Color32::from_rgb(8, 14, 32)
                    } else {
                        TEXT
                    }))
                    .fill(if selected {
                        ACCENT
                    } else {
                        Color32::TRANSPARENT
                    })
                    .min_size(vec2(120.0, 32.0));
                if ui.add(button).clicked() && !selected {
                    st.draft.switch_to(protocol);
                }
            }
        });
        ui.add_space(8.0);

        fields.field(
            ui,
            "Tags",
            "tags",
            true,
            Some("Optional, comma-separated — e.g. work, europe"),
            |ui| text_input(ui, &mut st.draft.tags, "home, travel"),
        );

        fields.field(ui, "Notes", "notes", true, None, |ui| {
            ui.add(
                TextEdit::multiline(&mut st.draft.notes)
                    .desired_rows(2)
                    .desired_width(f32::INFINITY)
                    .hint_text("Anything you want to remember about this server"),
            );
        });
    });
}

fn secret_row(
    ui: &mut egui::Ui,
    value: &mut String,
    visible: &mut bool,
    hint: &str,
    extra: impl FnOnce(&mut egui::Ui, &mut String),
) {
    ui.horizontal(|ui| {
        ui.add(
            TextEdit::singleline(value)
                .password(!*visible)
                .hint_text(hint)
                .desired_width((ui.available_width() - 210.0).max(120.0)),
        );
        if ui
            .add(ghost_button(if *visible { "Hide" } else { "Show" }, DIM))
            .clicked()
        {
            *visible = !*visible;
        }
        extra(ui, value);
    });
}

fn interface_card(
    ui: &mut egui::Ui,
    st: &mut EditorState,
    fields: &Fields,
    toast_slot: &mut Option<Toast>,
) {
    card(ui, |ui| {
        section_title(ui, "This device");
        ui.label(dim(
            "Your end of the tunnel. The private key never leaves this PC.",
        ));
        ui.add_space(8.0);

        fields.field(
            ui,
            "Private key",
            "private_key",
            st.draft.private_key.trim().is_empty(),
            None,
            |ui| {
                secret_row(
                    ui,
                    &mut st.draft.private_key,
                    &mut st.show_private,
                    "44-character base64 key",
                    |ui, value| {
                        if ui
                            .add(ghost_button("Generate", ACCENT))
                            .on_hover_text(
                                "Create a brand-new key pair. The old key is discarded, so \
                                 the server must be given the new public key.",
                            )
                            .clicked()
                        {
                            if let Ok(key) = generate_private_key() {
                                *value = key;
                            }
                        }
                    },
                );
            },
        );

        ui.label(
            RichText::new("Public key (give this to your server)")
                .size(12.5)
                .color(DIM),
        );
        ui.horizontal(|ui| match public_key_from_private(&st.draft.private_key) {
            Ok(public) => {
                ui.label(RichText::new(&public).monospace().size(13.0).color(TEXT));
                if ui.add(ghost_button("Copy", ACCENT)).clicked() {
                    copy(ui, public, toast_slot, "Public key");
                }
            }
            Err(_) => {
                ui.label(
                    RichText::new("— enter a valid private key —")
                        .size(13.0)
                        .color(DIM),
                );
            }
        });
        ui.add_space(10.0);

        fields.field(
            ui,
            "Tunnel address",
            "address",
            st.draft.address.trim().is_empty(),
            Some("This device's address inside the tunnel. Comma-separate for IPv4 + IPv6."),
            |ui| text_input(ui, &mut st.draft.address, "10.66.66.2/32"),
        );

        fields.field(
            ui,
            "DNS servers",
            "dns",
            true,
            Some("Optional. Used while the tunnel is up."),
            |ui| text_input(ui, &mut st.draft.dns, "1.1.1.1, 9.9.9.9"),
        );

        ui.columns(2, |cols| {
            fields.field(
                &mut cols[0],
                "MTU",
                "mtu",
                true,
                Some("Empty = automatic (1420 typical)"),
                |ui| text_input(ui, &mut st.draft.mtu, "1420"),
            );
            fields.field(
                &mut cols[1],
                "Local listen port",
                "listen_port",
                true,
                Some("Empty = pick a random port"),
                |ui| text_input(ui, &mut st.draft.listen_port, "51000"),
            );
        });
    });
}

fn peer_card(ui: &mut egui::Ui, st: &mut EditorState, fields: &Fields) {
    card(ui, |ui| {
        section_title(ui, "The server");
        ui.label(dim("The WireGuard server you're connecting to."));
        ui.add_space(8.0);

        fields.field(
            ui,
            "Server address",
            "endpoint",
            st.draft.endpoint.trim().is_empty(),
            Some("Host or IP and port. IPv6 goes in brackets: [fd00::1]:51820"),
            |ui| text_input(ui, &mut st.draft.endpoint, "vpn.example.com:51820"),
        );

        fields.field(
            ui,
            "Server public key",
            "peer_public_key",
            st.draft.peer_public_key.trim().is_empty(),
            None,
            |ui| text_input(ui, &mut st.draft.peer_public_key, "44-character base64 key"),
        );

        fields.field(
            ui,
            "Preshared key (optional)",
            "preshared_key",
            st.draft.preshared_key.trim().is_empty(),
            Some("Extra symmetric key shared with the server for added protection."),
            |ui| {
                secret_row(
                    ui,
                    &mut st.draft.preshared_key,
                    &mut st.show_psk,
                    "leave empty to skip",
                    |ui, value| {
                        if ui.add(ghost_button("Generate", ACCENT)).clicked() {
                            if let Ok(key) = generate_preshared_key() {
                                *value = key;
                            }
                        }
                        if ui.add(ghost_button("Clear", DIM)).clicked() {
                            value.clear();
                        }
                    },
                );
            },
        );

        fields.field(
            ui,
            "Routed networks (Allowed IPs)",
            "allowed_ips",
            st.draft.allowed_ips.trim().is_empty(),
            Some("Which traffic goes through the tunnel. 0.0.0.0/0 sends everything."),
            |ui| {
                text_input(ui, &mut st.draft.allowed_ips, "0.0.0.0/0, ::/0");
                ui.horizontal(|ui| {
                    if ui.add(ghost_button("Route all traffic", ACCENT)).clicked() {
                        st.draft.allowed_ips = ROUTE_ALL.into();
                    }
                    if ui
                        .add(ghost_button("Private networks only", ACCENT))
                        .clicked()
                    {
                        st.draft.allowed_ips = ROUTE_PRIVATE_ONLY.into();
                    }
                });
            },
        );

        fields.field(
            ui,
            "Keepalive (seconds)",
            "keepalive",
            true,
            Some("Keeps NAT/firewall mappings open. 25 is the usual value; empty disables it."),
            |ui| {
                text_input(ui, &mut st.draft.keepalive, "25");
                ui.horizontal(|ui| {
                    if ui.add(ghost_button("25", ACCENT)).clicked() {
                        st.draft.keepalive = "25".into();
                    }
                    if ui.add(ghost_button("Off", DIM)).clicked() {
                        st.draft.keepalive.clear();
                    }
                });
            },
        );
    });
}

fn protection_card(ui: &mut egui::Ui, st: &mut EditorState) {
    card(ui, |ui| {
        section_title(ui, "Leak protection");
        ui.label(dim(
            "Firewall rules that keep traffic inside the tunnel. They exist only while \
             connected, and Windows removes them by itself if Deterium ever closes or crashes.",
        ));
        ui.add_space(8.0);

        ui.checkbox(
            &mut st.draft.kill_switch,
            "Kill switch: block all traffic outside the tunnel",
        );
        ui.label(dim(
            "If the tunnel drops, nothing leaves this PC until it is back or you disconnect.",
        ));
        ui.add_space(6.0);

        ui.add_enabled(
            st.draft.kill_switch,
            egui::Checkbox::new(
                &mut st.draft.allow_lan,
                "Allow the local network (printers, NAS, router)",
            ),
        );
        ui.add_space(6.0);

        ui.checkbox(
            &mut st.draft.block_dns_leaks,
            "Block DNS requests that bypass the tunnel",
        );
        ui.label(dim(if st.draft.protocol == Protocol::Openvpn {
            "Applies when the server sends all traffic and its own DNS servers through the \
             tunnel; otherwise it would cut off name lookups for the whole PC."
        } else {
            "Applies when the tunnel carries the DNS servers set above (a full tunnel, or DNS \
             inside the routed networks); otherwise it would cut off name lookups for the whole PC."
        }));
    });
}

fn snippet_card(ui: &mut egui::Ui, st: &mut EditorState, toast_slot: &mut Option<Toast>) {
    let Some(mut snippet) = st.draft.server_peer_snippet() else {
        return;
    };
    card(ui, |ui| {
        section_title(ui, "Allow this device on your server");
        ui.label(dim(
            "Add this block to the server's WireGuard config (e.g. /etc/wireguard/wg0.conf) \
             and reload it.",
        ));
        ui.add_space(6.0);
        ui.add(
            TextEdit::multiline(&mut snippet)
                .code_editor()
                .interactive(false)
                .desired_rows(4)
                .desired_width(f32::INFINITY),
        );
        if ui.add(ghost_button("Copy block", ACCENT)).clicked() {
            copy(ui, snippet.clone(), toast_slot, "Peer block");
        }
    });
}

fn openvpn_card(ui: &mut egui::Ui, st: &mut EditorState, fields: &Fields) {
    card(ui, |ui| {
        section_title(ui, "OpenVPN configuration");

        match &st.openvpn_found {
            _ if deterium_engine::bundled_available() => {
                ui.label(
                    RichText::new(format!(
                        "OpenVPN {} is built into Deterium - nothing to install.",
                        deterium_engine::bundled_version().unwrap_or_default()
                    ))
                    .size(12.5)
                    .color(GOOD),
                );
            }
            Some(path) => {
                ui.label(
                    RichText::new(format!("OpenVPN client found: {}", path.display()))
                        .size(12.5)
                        .color(GOOD),
                );
            }
            None => {
                ui.label(
                    RichText::new(
                        "OpenVPN client not found. Install it from openvpn.net/community-downloads \
                         to connect — you can still save this server.",
                    )
                    .size(12.5)
                    .color(WARN),
                );
            }
        }
        ui.add_space(8.0);

        fields.field(
            ui,
            "Config (.ovpn)",
            "raw_config",
            st.draft.raw_config.trim().is_empty(),
            Some("Certificates and keys can be embedded inline (<ca>, <cert>, <key>)."),
            |ui| {
                ui.add(
                    TextEdit::multiline(&mut st.draft.raw_config)
                        .code_editor()
                        .desired_rows(16)
                        .desired_width(f32::INFINITY)
                        .hint_text("client\ndev tun\nproto udp\nremote vpn.example.com 1194\n…"),
                );
            },
        );

        ui.add_space(4.0);
        section_title(ui, "Login");
        ui.label(dim(
            "Only needed when the server asks for a username and password. The password is \
             stored encrypted on this PC.",
        ));
        ui.add_space(6.0);
        let needs_login = st.draft.asks_for_login();
        fields.field(
            ui,
            "Username",
            "username",
            needs_login && st.draft.username.trim().is_empty(),
            None,
            |ui| {
                ui.add(
                    TextEdit::singleline(&mut st.draft.username)
                        .desired_width(f32::INFINITY)
                        .hint_text("optional"),
                );
            },
        );
        fields.field(
            ui,
            "Password",
            "password",
            needs_login && st.draft.password.is_empty(),
            None,
            |ui| {
                ui.add(
                    TextEdit::singleline(&mut st.draft.password)
                        .password(true)
                        .desired_width(f32::INFINITY)
                        .hint_text("optional"),
                );
            },
        );

        for warning in st.draft.warnings() {
            ui.label(RichText::new(warning).size(12.5).color(WARN));
        }
    });
}

// ---------------------------------------------------------------- wizard --

pub struct WizardState {
    name: String,
    host: String,
    port: String,
    server_cidr: String,
    client_address: String,
    dns: String,
    client_private: String,
    server_public: String,
    tried: bool,
}

pub enum WizardAction {
    None,
    Back,
    Finish(Box<ServerProfile>),
}

impl WizardState {
    pub fn new() -> Self {
        Self {
            name: String::new(),
            host: String::new(),
            port: "51820".into(),
            server_cidr: "10.66.66.1/24".into(),
            client_address: "10.66.66.2/32".into(),
            dns: "1.1.1.1".into(),
            client_private: generate_private_key().unwrap_or_default(),
            server_public: String::new(),
            tried: false,
        }
    }

    fn endpoint(&self) -> String {
        let host = self.host.trim();
        let port = self.port.trim();
        if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    }

    fn draft(&self) -> Draft {
        let mut draft = Draft::blank();
        draft.name = self.name.clone();
        draft.private_key = self.client_private.clone();
        draft.address = self.client_address.clone();
        draft.dns = self.dns.clone();
        draft.peer_public_key = self.server_public.clone();
        draft.endpoint = self.endpoint();
        draft
    }

    fn script(&self) -> Result<String, String> {
        let client_public = public_key_from_private(&self.client_private)?;
        let listen_port = self
            .port
            .trim()
            .parse::<u16>()
            .map_err(|_| "enter a port number (1-65535)".to_string())?;
        wireguard_server_script(&WireGuardServerSetup {
            listen_port,
            server_cidr: self.server_cidr.clone(),
            client_address: self.client_address.clone(),
            client_public_key: client_public,
        })
    }
}

pub fn show_wizard(
    ui: &mut egui::Ui,
    st: &mut WizardState,
    toast_slot: &mut Option<Toast>,
) -> WizardAction {
    let mut action = WizardAction::None;

    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Set up my own server")
                .size(26.0)
                .strong()
                .color(TEXT),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.add(ghost_button("Back", DIM)).clicked() {
                action = WizardAction::Back;
            }
        });
    });
    ui.label(dim(
        "Works with any Debian/Ubuntu VPS you rent. Your device's private key stays on this PC; \
         the script only gets its public key.",
    ));
    ui.add_space(12.0);

    let problems = st.draft().problems();
    let fields = Fields {
        problems: &problems,
        show_all: st.tried,
    };

    card(ui, |ui| {
        section_title(ui, "1 · Your server");
        fields.field(ui, "Name", "name", st.name.trim().is_empty(), None, |ui| {
            text_input(ui, &mut st.name, "e.g. Frankfurt VPS");
        });
        ui.columns(2, |cols| {
            cols[0].label(RichText::new("Server IP or domain").size(12.5).color(DIM));
            text_input(&mut cols[0], &mut st.host, "203.0.113.10");
            cols[1].label(RichText::new("WireGuard port").size(12.5).color(DIM));
            text_input(&mut cols[1], &mut st.port, "51820");
        });
        if st.tried || !st.host.trim().is_empty() {
            for problem in problems.iter().filter(|p| p.field == "endpoint") {
                ui.label(RichText::new(&problem.message).size(12.0).color(BAD));
            }
        }

        ui.add_space(6.0);
        egui::CollapsingHeader::new(
            RichText::new("Advanced network settings")
                .size(13.0)
                .color(DIM),
        )
        .default_open(false)
        .show(ui, |ui| {
            ui.add_space(4.0);
            ui.label(dim(
                "Defaults are fine unless they clash with a network you already use.",
            ));
            fields.field(
                ui,
                "Tunnel subnet (server side)",
                "none",
                true,
                None,
                |ui| {
                    text_input(ui, &mut st.server_cidr, "10.66.66.1/24");
                },
            );
            fields.field(
                ui,
                "This device's tunnel address",
                "address",
                true,
                None,
                |ui| {
                    text_input(ui, &mut st.client_address, "10.66.66.2/32");
                },
            );
            fields.field(ui, "DNS servers", "dns", true, None, |ui| {
                text_input(ui, &mut st.dns, "1.1.1.1");
            });
        });
    });
    ui.add_space(12.0);

    card(ui, |ui| {
        section_title(ui, "2 · Run this on your server");
        ui.label(dim(
            "Open a terminal on the server (SSH), paste the script, and run it as root. \
             It installs WireGuard, creates the server key, and allows this device.",
        ));
        ui.add_space(6.0);

        match st.script() {
            Ok(script) => {
                let mut shown = script.clone();
                egui::ScrollArea::vertical()
                    .max_height(230.0)
                    .id_source("wizard_script")
                    .show(ui, |ui| {
                        ui.add(
                            TextEdit::multiline(&mut shown)
                                .code_editor()
                                .interactive(false)
                                .desired_width(f32::INFINITY),
                        );
                    });
                ui.horizontal(|ui| {
                    if ui.add(primary_button("Copy script")).clicked() {
                        copy(ui, script, toast_slot, "Setup script");
                    }
                    ui.label(dim(
                        "Also open UDP port in your provider's firewall if it has one.",
                    ));
                });
            }
            Err(message) => {
                ui.label(
                    RichText::new(format!("Can't build the script yet: {message}")).color(WARN),
                );
            }
        }
    });
    ui.add_space(12.0);

    card(ui, |ui| {
        section_title(ui, "3 · Paste the server's public key");
        ui.label(dim(
            "The script prints a line starting with SERVER PUBLIC KEY when it finishes.",
        ));
        ui.add_space(6.0);
        fields.field(
            ui,
            "Server public key",
            "peer_public_key",
            st.server_public.trim().is_empty(),
            None,
            |ui| text_input(ui, &mut st.server_public, "44-character base64 key"),
        );

        if ui.add(primary_button("Create server")).clicked() {
            st.tried = true;
            if let Ok(profile) = st.draft().build() {
                action = WizardAction::Finish(Box::new(profile));
            }
        }
    });
    ui.add_space(30.0);

    action
}
