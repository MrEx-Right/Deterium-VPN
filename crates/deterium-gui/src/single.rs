//! One Deterium per Windows sign-in: starting the app again while it runs
//! (hidden in the tray or not) brings the running copy to the front instead of
//! opening a second window with a second tray icon.
//!
//! A named event in the session's `Local\` namespace is both the lock (it
//! exists as long as the first copy runs) and the doorbell (a second copy sets
//! it; the first one wakes up and shows itself).

use eframe::egui;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Held by the copy that runs. Dropping it does not let go of the name: that
/// happens when the process ends.
pub struct Instance {
    /// The event's handle as a number (handles aren't `Send`); 0 when the
    /// check couldn't be made and this copy runs unguarded.
    #[cfg(windows)]
    event: usize,
    wanted: Arc<AtomicBool>,
}

#[cfg(windows)]
const NAME: &str = r"Local\Deterium-VPN-window";

/// Takes the name, or finds another copy running and returns `None`: this copy
/// should then exit. With `show_running` the running copy is asked to come to
/// the front. `patience` is how long to wait for a running copy to finish
/// closing first (used when the app restarts itself with administrator rights).
#[cfg(windows)]
pub fn claim(show_running: bool, patience: Duration) -> Option<Instance> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS,
    };
    use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent};
    use windows_sys::Win32::UI::WindowsAndMessaging::{AllowSetForegroundWindow, ASFW_ANY};

    let name: Vec<u16> = NAME.encode_utf16().chain(Some(0)).collect();
    let deadline = std::time::Instant::now() + patience;
    loop {
        // SAFETY: a NUL-terminated name, default security; auto-reset, not set.
        let (event, error) = unsafe {
            let event = CreateEventW(std::ptr::null(), 0, 0, name.as_ptr());
            (event, GetLastError())
        };
        if !event.is_null() && error != ERROR_ALREADY_EXISTS {
            return Some(Instance {
                event: event as usize,
                wanted: Arc::default(),
            });
        }
        // Access denied means the running copy has administrator rights: it
        // is there, it just can't be rung from here.
        if event.is_null() && error != ERROR_ACCESS_DENIED {
            return Some(Instance {
                event: 0,
                wanted: Arc::default(),
            });
        }

        let waiting = std::time::Instant::now() < deadline;
        // SAFETY: `event` is a handle we own (or null), closed once.
        unsafe {
            if !event.is_null() {
                if show_running && !waiting {
                    // Let it take the foreground, which Windows gave to us.
                    AllowSetForegroundWindow(ASFW_ANY);
                    SetEvent(event);
                }
                CloseHandle(event);
            }
        }
        if !waiting {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(not(windows))]
pub fn claim(_show_running: bool, _patience: Duration) -> Option<Instance> {
    Some(Instance {
        wanted: Arc::default(),
    })
}

impl Instance {
    /// Waits for another copy's knock on a thread of its own and wakes the
    /// app (even while hidden) when it comes.
    pub fn listen(&self, ctx: &egui::Context) {
        #[cfg(windows)]
        if self.event != 0 {
            use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
            use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};

            let (event, wanted, ctx) = (self.event, self.wanted.clone(), ctx.clone());
            std::thread::spawn(move || loop {
                // SAFETY: the handle stays open for the life of the process.
                if unsafe { WaitForSingleObject(event as _, INFINITE) } != WAIT_OBJECT_0 {
                    break;
                }
                wanted.store(true, Ordering::SeqCst);
                ctx.request_repaint();
            });
        }
        #[cfg(not(windows))]
        let _ = ctx;
    }

    /// Whether another copy asked to see the window since the last call.
    pub fn show_requested(&self) -> bool {
        self.wanted.swap(false, Ordering::SeqCst)
    }
}
