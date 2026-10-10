//! Administrator rights. Creating a virtual adapter and changing routes
//! needs them; the rest of the app does not. See docs/adr/0003 for why the
//! app re-launches itself elevated (on request) instead of always running
//! as administrator.

#[derive(Debug, thiserror::Error)]
pub enum ElevateError {
    /// The user closed or declined the Windows UAC prompt.
    #[error("the administrator prompt was declined")]
    Declined,
    #[error("couldn't restart as administrator: {0}")]
    Failed(String),
}

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: plain Win32 calls with correctly sized, initialized buffers;
    // the token handle is closed on every path that opened it.
    unsafe {
        let mut token: HANDLE = std::mem::zeroed();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut TOKEN_ELEVATION as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(unix)]
pub fn is_elevated() -> bool {
    extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { geteuid() == 0 }
}

#[cfg(not(any(windows, unix)))]
pub fn is_elevated() -> bool {
    false
}

/// Starts this same executable again with administrator rights (the user sees
/// the Windows UAC prompt) and the given arguments, in the current working
/// directory. The caller should exit once this returns `Ok`.
#[cfg(windows)]
pub fn relaunch_elevated(args: &[String]) -> Result<(), ElevateError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
        text.encode_wide().chain(std::iter::once(0)).collect()
    }

    let exe = std::env::current_exe().map_err(|e| ElevateError::Failed(e.to_string()))?;
    let dir = std::env::current_dir().map_err(|e| ElevateError::Failed(e.to_string()))?;
    let parameters = args
        .iter()
        .map(|a| quote_arg(a))
        .collect::<Vec<_>>()
        .join(" ");

    let verb = wide("runas".as_ref());
    let exe = wide(exe.as_os_str());
    let parameters = wide(parameters.as_ref());
    let dir = wide(dir.as_os_str());

    // SAFETY: all pointers are NUL-terminated UTF-16 buffers that outlive the call.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            exe.as_ptr(),
            parameters.as_ptr(),
            dir.as_ptr(),
            SW_SHOWNORMAL,
        )
    } as usize;

    match result {
        // Values above 32 mean the process was started.
        r if r > 32 => Ok(()),
        // SE_ERR_ACCESSDENIED: what ShellExecute reports for a declined UAC prompt.
        5 => Err(ElevateError::Declined),
        other => Err(ElevateError::Failed(format!(
            "ShellExecute returned code {other}"
        ))),
    }
}

#[cfg(not(windows))]
pub fn relaunch_elevated(_args: &[String]) -> Result<(), ElevateError> {
    Err(ElevateError::Failed(
        "restarting with elevated rights is only implemented on Windows".into(),
    ))
}

/// The Windows user this process runs as, as an SID string such as
/// `S-1-5-21-...-1001`. Used to tell the background service which account may
/// control it.
#[cfg(windows)]
pub fn current_user_sid() -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: buffers are sized by the first GetTokenInformation call; the
    // token handle and the string Windows allocates are released on every path.
    unsafe {
        let mut token: HANDLE = std::mem::zeroed();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let mut needed = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        let mut buffer = vec![0u8; needed as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr() as *mut _,
            needed,
            &mut needed,
        ) != 0;
        CloseHandle(token);
        if !ok {
            return None;
        }
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut text: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
            return None;
        }
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text as _);
        Some(sid)
    }
}

#[cfg(not(windows))]
pub fn current_user_sid() -> Option<String> {
    None
}

/// Runs `exe` elevated (the user sees the Windows UAC prompt), waits for it to
/// finish and returns its exit code.
#[cfg(windows)]
pub fn run_elevated_and_wait(exe: &std::path::Path, args: &[String]) -> Result<u32, ElevateError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, WaitForSingleObject, INFINITE,
    };
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
        text.encode_wide().chain(std::iter::once(0)).collect()
    }

    let verb = wide("runas".as_ref());
    let file = wide(exe.as_os_str());
    let parameters = wide(
        args.iter()
            .map(|a| quote_arg(a))
            .collect::<Vec<_>>()
            .join(" ")
            .as_ref(),
    );

    // SAFETY: the structure is fully initialised, every string is NUL-terminated
    // and outlives the call, and the process handle is closed afterwards.
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = parameters.as_ptr();
        info.nShow = SW_SHOWNORMAL;
        if ShellExecuteExW(&mut info) == 0 {
            return match std::io::Error::last_os_error().raw_os_error() {
                // ERROR_CANCELLED: the user declined the UAC prompt.
                Some(1223) => Err(ElevateError::Declined),
                _ => Err(ElevateError::Failed(
                    std::io::Error::last_os_error().to_string(),
                )),
            };
        }
        if info.hProcess.is_null() {
            return Err(ElevateError::Failed("no process handle".into()));
        }
        let waited = WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 1u32;
        if waited == WAIT_OBJECT_0 {
            GetExitCodeProcess(info.hProcess, &mut code);
        }
        CloseHandle(info.hProcess);
        Ok(code)
    }
}

#[cfg(not(windows))]
pub fn run_elevated_and_wait(
    _exe: &std::path::Path,
    _args: &[String],
) -> Result<u32, ElevateError> {
    Err(ElevateError::Failed(
        "running elevated is only implemented on Windows".into(),
    ))
}

/// Quotes one argument for a Windows command line.
#[cfg_attr(not(windows), allow(dead_code))]
fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_arguments_are_left_alone() {
        assert_eq!(quote_arg("--connect"), "--connect");
        assert_eq!(quote_arg("b3f1b1a0-7e34"), "b3f1b1a0-7e34");
    }

    #[test]
    fn arguments_with_spaces_or_quotes_are_quoted_safely() {
        assert_eq!(quote_arg("my server"), "\"my server\"");
        assert_eq!(quote_arg(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg(r"C:\dir with space\"), r#""C:\dir with space\\""#);
    }
}
