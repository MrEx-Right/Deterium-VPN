//! The system tray (notification area) icon: shows whether the VPN is on at a
//! glance, lets the window be closed without ending the app, and offers
//! connect / disconnect / switch server / quit from a right-click menu.
//!
//! Windows only. Elsewhere [`Tray::new`] returns `None` and the window simply
//! closes as usual.

use deterium_core::Uuid;
use eframe::egui;

/// What the icon should show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Look {
    Idle,
    Connecting,
    Connected,
    /// Reconnecting, or an error: something needs the user's attention.
    Warning,
}

/// What the user asked for through the tray.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Open,
    Toggle,
    /// A server picked from the "Connect to" submenu.
    ConnectTo(Uuid),
    Quit,
}

/// Everything the tray needs to describe the current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub look: Look,
    /// Name of the connected (or selected) server.
    pub server: Option<String>,
    /// Whether the toggle item would disconnect (true) or connect (false).
    pub connected: bool,
    /// Every saved server, in the app's order, for the "Connect to" submenu.
    pub servers: Vec<(Uuid, String)>,
    /// The server a tunnel is up (or coming up) on: ticked in the submenu.
    pub active: Option<Uuid>,
}

impl Summary {
    pub fn status_line(&self) -> String {
        let name = self.server.as_deref().unwrap_or("no server");
        match self.look {
            Look::Idle => "Not connected".to_string(),
            Look::Connecting => format!("Connecting to {name}..."),
            Look::Connected => format!("Connected: {name}"),
            Look::Warning => format!("Connection trouble: {name}"),
        }
    }

    pub fn toggle_label(&self) -> String {
        if self.connected {
            "Disconnect".to_string()
        } else {
            match &self.server {
                Some(name) => format!("Connect to {name}"),
                None => "Connect".to_string(),
            }
        }
    }
}

/// Menu id of a server's item in the "Connect to" submenu. The id carries the
/// server, so the click handler needs no shared lookup table.
#[cfg(any(windows, test))]
fn server_item_id(id: Uuid) -> String {
    format!("server:{id}")
}

/// The server behind a menu id made by [`server_item_id`].
#[cfg(any(windows, test))]
fn server_of_item(menu_id: &str) -> Option<Uuid> {
    menu_id.strip_prefix("server:")?.parse().ok()
}

/// A server name as a Windows menu label: `&` would underline the next letter
/// instead of showing, and a tab starts the shortcut column.
#[cfg(any(windows, test))]
fn menu_label(name: &str) -> String {
    name.replace('&', "&&").replace('\t', " ")
}

/// The icon's pixels: the Deterium logo with a small dot in the colour of the
/// connection state. Drawn in code (see `logo.rs`), so there are no image files.
pub fn icon_pixels(look: Look, size: u32) -> Vec<u8> {
    use crate::logo::Status;
    crate::logo::render(
        size,
        Some(match look {
            Look::Idle => Status::Idle,
            Look::Connecting => Status::Connecting,
            Look::Connected => Status::Connected,
            Look::Warning => Status::Warning,
        }),
    )
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
    use tray_icon::{
        Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
    };

    pub struct Tray {
        icon: TrayIcon,
        status: MenuItem,
        toggle: MenuItem,
        servers: Submenu,
        /// The submenu's items and the list they were built from.
        server_items: Vec<(Uuid, CheckMenuItem)>,
        listed: Vec<(Uuid, String)>,
        shown: Option<Summary>,
        actions: Arc<Mutex<Vec<Action>>>,
    }

    impl Tray {
        /// The window may be hidden when the user clicks: eframe still runs the
        /// app's `logic` then, so queueing the click and asking for a repaint
        /// is enough for the app to see it and show itself.
        pub fn new(ctx: &egui::Context) -> Option<Self> {
            let actions: Arc<Mutex<Vec<Action>>> = Arc::default();

            let open = MenuItem::new("Open Deterium VPN", true, None);
            let status = MenuItem::new("Not connected", false, None);
            let toggle = MenuItem::new("Connect", true, None);
            let servers = Submenu::new("Connect to", false);
            let quit = MenuItem::new("Quit Deterium VPN", true, None);
            let menu = Menu::new();
            menu.append_items(&[
                &open,
                &PredefinedMenuItem::separator(),
                &status,
                &toggle,
                &servers,
                &PredefinedMenuItem::separator(),
                &quit,
            ])
            .ok()?;

            let icon = Icon::from_rgba(icon_pixels(Look::Idle, 32), 32, 32).ok()?;
            let tray = TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_menu_on_left_click(false)
                .with_tooltip("Deterium VPN")
                .with_icon(icon)
                .build()
                .ok()?;

            // Both handlers run on the tray's own thread: just queue what
            // happened and wake the window so it can react.
            let (open_id, toggle_id, quit_id) =
                (open.id().clone(), toggle.id().clone(), quit.id().clone());
            {
                let (queue, ctx) = (actions.clone(), ctx.clone());
                MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                    let action = if event.id == open_id {
                        Action::Open
                    } else if event.id == toggle_id {
                        Action::Toggle
                    } else if event.id == quit_id {
                        Action::Quit
                    } else if let Some(id) = server_of_item(event.id.as_ref()) {
                        Action::ConnectTo(id)
                    } else {
                        return;
                    };
                    queue.lock().unwrap_or_else(|e| e.into_inner()).push(action);
                    ctx.request_repaint();
                }));
            }
            {
                let (queue, ctx) = (actions.clone(), ctx.clone());
                TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
                    let clicked = matches!(
                        event,
                        TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } | TrayIconEvent::DoubleClick {
                            button: MouseButton::Left,
                            ..
                        }
                    );
                    if clicked {
                        queue
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(Action::Open);
                        ctx.request_repaint();
                    }
                }));
            }

            Some(Self {
                icon: tray,
                status,
                toggle,
                servers,
                server_items: Vec::new(),
                listed: Vec::new(),
                shown: None,
                actions,
            })
        }

        /// What the user did since the last call.
        pub fn take_actions(&mut self) -> Vec<Action> {
            let actions =
                std::mem::take(&mut *self.actions.lock().unwrap_or_else(|e| e.into_inner()));
            // Windows flips a check item's tick by itself when it is clicked;
            // put the ticks back to what is really going on.
            if actions.iter().any(|a| matches!(a, Action::ConnectTo(_))) {
                self.shown = None;
            }
            actions
        }

        /// Rebuilds the "Connect to" submenu when servers were added, removed,
        /// renamed or reordered.
        fn list_servers(&mut self, servers: &[(Uuid, String)]) {
            if self.listed == servers {
                return;
            }
            for (_, item) in self.server_items.drain(..) {
                let _ = self.servers.remove(&item);
            }
            for (id, name) in servers {
                let item = CheckMenuItem::with_id(
                    server_item_id(*id),
                    menu_label(name),
                    true,
                    false,
                    None,
                );
                if self.servers.append(&item).is_ok() {
                    self.server_items.push((*id, item));
                }
            }
            self.servers.set_enabled(!self.server_items.is_empty());
            self.listed = servers.to_vec();
        }

        /// Updates the icon, tooltip and menu, only when something changed.
        pub fn show(&mut self, summary: Summary) {
            if self.shown.as_ref() == Some(&summary) {
                return;
            }
            if let Ok(icon) = Icon::from_rgba(icon_pixels(summary.look, 32), 32, 32) {
                let _ = self.icon.set_icon(Some(icon));
            }
            let _ = self
                .icon
                .set_tooltip(Some(format!("Deterium VPN - {}", summary.status_line())));
            self.status.set_text(summary.status_line());
            self.toggle.set_text(summary.toggle_label());
            self.list_servers(&summary.servers);
            for (id, item) in &self.server_items {
                item.set_checked(summary.active == Some(*id));
            }
            self.shown = Some(summary);
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub struct Tray;

    impl Tray {
        pub fn new(_ctx: &egui::Context) -> Option<Self> {
            None
        }
        pub fn take_actions(&mut self) -> Vec<Action> {
            Vec::new()
        }
        pub fn show(&mut self, _summary: Summary) {}
    }
}

pub use imp::Tray;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_icon_is_the_logo_with_a_dot_in_the_state_colour() {
        let size = 32;
        let at = |look: Look| {
            let px = icon_pixels(look, size);
            assert_eq!(px.len(), (size * size * 4) as usize);
            // Centre of the status dot (bottom right).
            let i = ((25 * size + 25) * 4) as usize;
            (px[i], px[i + 1], px[i + 2], px[i + 3])
        };
        assert_eq!(at(Look::Connected), (52, 211, 153, 255));
        assert_eq!(at(Look::Warning), (251, 191, 36, 255));
        assert_eq!(at(Look::Connecting), (86, 140, 255, 255));
    }

    #[test]
    fn every_state_has_its_own_colour() {
        let colours: Vec<_> = [Look::Idle, Look::Connecting, Look::Connected, Look::Warning]
            .iter()
            .map(|look| {
                let px = icon_pixels(*look, 32);
                let i = ((25 * 32 + 25) * 4) as usize;
                (px[i], px[i + 1], px[i + 2])
            })
            .collect();
        for (i, a) in colours.iter().enumerate() {
            for b in &colours[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn the_menu_texts_follow_the_state() {
        let idle = Summary {
            look: Look::Idle,
            server: Some("US".into()),
            connected: false,
            servers: Vec::new(),
            active: None,
        };
        assert_eq!(idle.status_line(), "Not connected");
        assert_eq!(idle.toggle_label(), "Connect to US");

        let up = Summary {
            look: Look::Connected,
            server: Some("US".into()),
            connected: true,
            servers: Vec::new(),
            active: None,
        };
        assert_eq!(up.status_line(), "Connected: US");
        assert_eq!(up.toggle_label(), "Disconnect");

        let none = Summary {
            look: Look::Idle,
            server: None,
            connected: false,
            servers: Vec::new(),
            active: None,
        };
        assert_eq!(none.toggle_label(), "Connect");
    }

    #[test]
    fn a_server_item_id_leads_back_to_its_server() {
        let id = Uuid::new_v4();
        assert_eq!(server_of_item(&server_item_id(id)), Some(id));
        // The other items' ids are never mistaken for a server.
        assert_eq!(server_of_item("1"), None);
        assert_eq!(server_of_item("server:not-a-uuid"), None);
        assert_eq!(server_of_item(&id.to_string()), None);
    }

    #[test]
    fn server_names_show_as_written_in_the_menu() {
        assert_eq!(menu_label("US East"), "US East");
        assert_eq!(menu_label("R&D"), "R&&D");
        assert_eq!(menu_label("a\tb"), "a b");
    }
}
