//! The system tray (notification area) icon: shows whether the VPN is on at a
//! glance, lets the window be closed without ending the app, and offers
//! connect / disconnect / quit from a right-click menu.
//!
//! Windows only. Elsewhere [`Tray::new`] returns `None` and the window simply
//! closes as usual.

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
    use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{
        Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
    };

    use std::sync::atomic::{AtomicI32, Ordering};
    use windows_sys::Win32::Foundation::RECT;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetWindowLongPtrW, GetWindowRect, SetForegroundWindow, SetWindowLongPtrW, SetWindowPos,
        ShowWindow, GWL_EXSTYLE, SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOSIZE, SWP_NOZORDER,
        SW_HIDE, SW_RESTORE, SW_SHOWNOACTIVATE, WS_EX_APPWINDOW, WS_EX_TOOLWINDOW,
    };

    /// Where the window was before it went to the tray.
    static SAVED_X: AtomicI32 = AtomicI32::new(100);
    static SAVED_Y: AtomicI32 = AtomicI32::new(100);
    const OFF_SCREEN: i32 = -32_000;

    fn raw(hwnd: isize) -> *mut std::ffi::c_void {
        hwnd as *mut std::ffi::c_void
    }

    /// Puts the window "in the tray": no taskbar button, no Alt+Tab entry,
    /// parked off screen. It is deliberately still a visible window, because
    /// Windows doesn't redraw hidden or minimised ones and the app would then
    /// stop noticing connection changes (and tray clicks).
    fn hide_window(hwnd: isize) {
        // SAFETY: plain Win32 calls on this process's own window; safe from any thread.
        unsafe {
            let h = raw(hwnd);
            let mut rect: RECT = std::mem::zeroed();
            if GetWindowRect(h, &mut rect) != 0 && rect.left > OFF_SCREEN / 2 {
                SAVED_X.store(rect.left, Ordering::Relaxed);
                SAVED_Y.store(rect.top, Ordering::Relaxed);
            }
            ShowWindow(h, SW_RESTORE);
            // The taskbar button only goes away if the window is hidden while
            // its style changes.
            ShowWindow(h, SW_HIDE);
            let style = GetWindowLongPtrW(h, GWL_EXSTYLE);
            SetWindowLongPtrW(
                h,
                GWL_EXSTYLE,
                (style | WS_EX_TOOLWINDOW as isize) & !(WS_EX_APPWINDOW as isize),
            );
            SetWindowPos(
                h,
                std::ptr::null_mut(),
                OFF_SCREEN,
                OFF_SCREEN,
                0,
                0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
            );
            ShowWindow(h, SW_SHOWNOACTIVATE);
        }
    }

    /// Brings the window back where it was, with its taskbar button.
    fn show_window(hwnd: isize) {
        // SAFETY: as in `hide_window`.
        unsafe {
            let h = raw(hwnd);
            ShowWindow(h, SW_HIDE);
            let style = GetWindowLongPtrW(h, GWL_EXSTYLE);
            SetWindowLongPtrW(
                h,
                GWL_EXSTYLE,
                (style & !(WS_EX_TOOLWINDOW as isize)) | WS_EX_APPWINDOW as isize,
            );
            SetWindowPos(
                h,
                std::ptr::null_mut(),
                SAVED_X.load(Ordering::Relaxed),
                SAVED_Y.load(Ordering::Relaxed),
                0,
                0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED,
            );
            ShowWindow(h, SW_RESTORE);
            SetForegroundWindow(h);
        }
    }

    pub struct Tray {
        window: Option<isize>,
        icon: TrayIcon,
        status: MenuItem,
        toggle: MenuItem,
        shown: Option<Summary>,
        actions: Arc<Mutex<Vec<Action>>>,
    }

    impl Tray {
        /// `window` is the native handle of the app window. A window hidden in
        /// the tray is not redrawn, so egui would never see the user's click:
        /// the tray's own thread wakes it with the Windows API first.
        pub fn new(ctx: &egui::Context, window: Option<isize>) -> Option<Self> {
            let actions: Arc<Mutex<Vec<Action>>> = Arc::default();

            let open = MenuItem::new("Open Deterium", true, None);
            let status = MenuItem::new("Not connected", false, None);
            let toggle = MenuItem::new("Connect", true, None);
            let quit = MenuItem::new("Quit Deterium", true, None);
            let menu = Menu::new();
            menu.append_items(&[
                &open,
                &PredefinedMenuItem::separator(),
                &status,
                &toggle,
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
                    } else {
                        return;
                    };
                    if let (Action::Open, Some(hwnd)) = (action, window) {
                        show_window(hwnd);
                    }
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
                        if let Some(hwnd) = window {
                            show_window(hwnd);
                        }
                        queue
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(Action::Open);
                        ctx.request_repaint();
                    }
                }));
            }

            Some(Self {
                window,
                icon: tray,
                status,
                toggle,
                shown: None,
                actions,
            })
        }

        /// Sends the window to the tray (see `hide_window`).
        pub fn hide_window(&self) {
            if let Some(hwnd) = self.window {
                hide_window(hwnd);
            }
        }

        /// Brings the window back from the tray.
        pub fn show_window(&self) {
            if let Some(hwnd) = self.window {
                show_window(hwnd);
            }
        }

        /// What the user did since the last call.
        pub fn take_actions(&self) -> Vec<Action> {
            std::mem::take(&mut *self.actions.lock().unwrap_or_else(|e| e.into_inner()))
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
            self.shown = Some(summary);
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub struct Tray;

    impl Tray {
        pub fn new(_ctx: &egui::Context, _window: Option<isize>) -> Option<Self> {
            None
        }
        pub fn hide_window(&self) {}
        pub fn show_window(&self) {}
        pub fn take_actions(&self) -> Vec<Action> {
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
        };
        assert_eq!(idle.status_line(), "Not connected");
        assert_eq!(idle.toggle_label(), "Connect to US");

        let up = Summary {
            look: Look::Connected,
            server: Some("US".into()),
            connected: true,
        };
        assert_eq!(up.status_line(), "Connected: US");
        assert_eq!(up.toggle_label(), "Disconnect");

        let none = Summary {
            look: Look::Idle,
            server: None,
            connected: false,
        };
        assert_eq!(none.toggle_label(), "Connect");
    }
}
