//! The service's command line. The app is a single file that re-runs itself as
//! `Deterium.exe service ...` (elevated for install/uninstall, started by
//! Windows for `run`); there is no separate service program.
//!
//! * `run --allow-sid <SID>`: what Windows starts. Not for typing by hand.
//! * `install --allow-sid <SID>` / `uninstall` / `status`: manage the service
//!   (install and uninstall need an elevated prompt).
//! * `console --allow-sid <SID>`: run in the foreground for debugging.
//!
//! `--pause-on-error` waits for Enter after a failure (console windows);
//! `--gui-errors` shows the failure in a message box (the app has no console).

use crate::{install, scm};
use std::sync::atomic::{AtomicBool, Ordering};

/// Runs one service command and returns the process exit code. `args` are the
/// arguments after the program name; a leading `service` word is accepted.
pub fn run(mut args: Vec<String>) -> i32 {
    if args.first().map(String::as_str) == Some("service") {
        args.remove(0);
    }
    let command = args.first().map(String::as_str).unwrap_or("");
    let allowed: Vec<String> = args
        .windows(2)
        .filter(|w| w[0] == "--allow-sid")
        .map(|w| w[1].clone())
        .collect();
    let flag = |name: &str| args.iter().any(|a| a == name);

    let result: Result<(), String> = match command {
        "run" => scm::run_as_service(allowed).map_err(|e| {
            format!(
                "{e}\nThis command is started by Windows. To try the service from a prompt, \
                 use `console`."
            )
        }),
        "console" => {
            static STOP: AtomicBool = AtomicBool::new(false);
            wait_for_enter(&STOP);
            scm::serve_with_sids(allowed, &STOP)
        }
        "install" => match allowed.first() {
            Some(sid) => install::install(&install::InstallOptions {
                allow_sid: sid.clone(),
                insecure_location: flag("--dev-insecure-location"),
            })
            .map(|()| println!("Deterium service installed and running.")),
            None => Err("install needs --allow-sid <the user's SID>".into()),
        },
        "uninstall" => install::uninstall().map(|()| println!("Deterium service removed.")),
        "status" => {
            println!(
                "{}",
                match install::state() {
                    install::State::NotInstalled => "not installed",
                    install::State::Stopped => "installed, stopped",
                    install::State::Running => "installed, running",
                }
            );
            Ok(())
        }
        _ => Err("usage: service install --allow-sid <SID> | uninstall | status | console".into()),
    };

    match result {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("{message}");
            if flag("--gui-errors") {
                message_box("Deterium VPN", &message);
            } else if flag("--pause-on-error") {
                // Started through a UAC prompt, the window would vanish with the message.
                eprintln!("\nPress Enter to close this window.");
                let _ = std::io::stdin().read_line(&mut String::new());
            }
            1
        }
    }
}

/// Stops the console mode when Enter is pressed.
fn wait_for_enter(stop: &'static AtomicBool) {
    std::thread::spawn(move || {
        println!("Deterium service running in the foreground. Press Enter to stop.");
        let _ = std::io::stdin().read_line(&mut String::new());
        stop.store(true, Ordering::SeqCst);
    });
}

fn message_box(title: &str, text: &str) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

    let wide = |s: &str| -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    let (title, text) = (wide(title), wide(text));
    // SAFETY: both strings are NUL-terminated and outlive the call.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}
