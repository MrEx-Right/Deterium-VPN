//! "A newer Deterium is out": once per start the app asks GitHub for the
//! project's release tags and compares them with its own version.
//!
//! There are no binary downloads (Deterium is built from source on the user's
//! PC), so all this does is say so; updating means running
//! `Install-Deterium.bat` again from a fresh copy of the source. Nothing is
//! sent except the request itself, and a failed check stays silent.

use serde::Deserialize;

/// Where the source (and its tags) lives.
pub const REPO_URL: &str = "https://github.com/MrEx-Right/Deterium-VPN";
const API_HOST: &str = "api.github.com";
const TAGS_PATH: &str = "/repos/MrEx-Right/Deterium-VPN/tags?per_page=100";
/// The tag list is a few kilobytes; anything far bigger is not GitHub's answer.
const MAX_BODY: usize = 1 << 20;

/// A release number like `0.4.0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(u64, u64, u64);

impl Version {
    /// Reads `0.4.0` or `v0.4.0`. Anything else (pre-releases, other tags)
    /// is not a release and gives `None`.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let text = text
            .strip_prefix('v')
            .or_else(|| text.strip_prefix('V'))
            .unwrap_or(text);
        let mut parts = text.split('.');
        let mut next = || -> Option<u64> {
            let part = parts.next()?;
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            part.parse().ok()
        };
        let version = Version(next()?, next()?, next()?);
        parts.next().is_none().then_some(version)
    }

    /// The version of this build.
    pub fn current() -> Self {
        Self::parse(env!("CARGO_PKG_VERSION")).unwrap_or(Version(0, 0, 0))
    }
}

/// Whether `other` (the background service's version) is older than this
/// build. A version that can't be read is not called older: every build of
/// the service reports a plain `x.y.z`.
pub fn is_older(other: &str) -> bool {
    older_than(other, Version::current())
}

fn older_than(other: &str, this: Version) -> bool {
    Version::parse(other).is_some_and(|other| other < this)
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

#[derive(Deserialize)]
struct Tag {
    name: String,
}

/// The newest release in GitHub's tag list, if it is newer than `current`.
pub fn newer_in(tags_json: &str, current: Version) -> Result<Option<Version>, String> {
    let tags: Vec<Tag> =
        serde_json::from_str(tags_json).map_err(|e| format!("unexpected answer: {e}"))?;
    Ok(tags
        .iter()
        .filter_map(|tag| Version::parse(&tag.name))
        .max()
        .filter(|newest| *newest > current))
}

/// Asks GitHub, now, whether there is a newer release than this build.
/// Blocks for up to a few seconds: run it off the UI thread.
pub fn check() -> Result<Option<Version>, String> {
    let body = fetch(API_HOST, TAGS_PATH)?;
    newer_in(&body, Version::current())
}

#[cfg(windows)]
fn fetch(host: &str, path: &str) -> Result<String, String> {
    use windows_sys::Win32::Networking::WinHttp::{
        WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders,
        WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetTimeouts,
        INTERNET_DEFAULT_HTTPS_PORT, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE,
        WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
    };

    /// Closes a WinHTTP handle however the function returns.
    struct Handle(*mut std::ffi::c_void);
    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: a handle WinHTTP gave us, closed once.
            unsafe { WinHttpCloseHandle(self.0) };
        }
    }
    fn open(raw: *mut std::ffi::c_void, what: &str) -> Result<Handle, String> {
        if raw.is_null() {
            Err(format!(
                "{what} failed: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(Handle(raw))
        }
    }
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    let agent = wide(concat!("Deterium-VPN/", env!("CARGO_PKG_VERSION")));
    let host = wide(host);
    let verb = wide("GET");
    let path = wide(path);
    let headers = wide("Accept: application/vnd.github+json");
    let none = std::ptr::null();

    // SAFETY: plain WinHTTP calls; every string is NUL-terminated and outlives
    // the call, and every handle is closed by `Handle`.
    unsafe {
        let session = open(
            WinHttpOpen(
                agent.as_ptr(),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                none,
                none,
                0,
            ),
            "opening WinHTTP",
        )?;
        WinHttpSetTimeouts(session.0, 5_000, 5_000, 5_000, 10_000);
        let connection = open(
            WinHttpConnect(session.0, host.as_ptr(), INTERNET_DEFAULT_HTTPS_PORT, 0),
            "connecting",
        )?;
        let request = open(
            WinHttpOpenRequest(
                connection.0,
                verb.as_ptr(),
                path.as_ptr(),
                none,
                none,
                std::ptr::null(),
                WINHTTP_FLAG_SECURE,
            ),
            "opening the request",
        )?;
        if WinHttpSendRequest(
            request.0,
            headers.as_ptr(),
            u32::MAX, // the headers are NUL-terminated
            std::ptr::null(),
            0,
            0,
            0,
        ) == 0
            || WinHttpReceiveResponse(request.0, std::ptr::null_mut()) == 0
        {
            return Err(format!(
                "couldn't reach {API_HOST}: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut status: u32 = 0;
        let mut size = std::mem::size_of::<u32>() as u32;
        if WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            none,
            (&mut status as *mut u32).cast(),
            &mut size,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err("no status in the answer".to_string());
        }
        if status != 200 {
            return Err(format!("{API_HOST} answered {status}"));
        }

        let mut body = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let mut read: u32 = 0;
            if WinHttpReadData(
                request.0,
                chunk.as_mut_ptr().cast(),
                chunk.len() as u32,
                &mut read,
            ) == 0
            {
                return Err(format!(
                    "the answer broke off: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read as usize]);
            if body.len() > MAX_BODY {
                return Err("the answer is too big".to_string());
            }
        }
        String::from_utf8(body).map_err(|_| "the answer isn't text".to_string())
    }
}

#[cfg(not(windows))]
fn fetch(_host: &str, _path: &str) -> Result<String, String> {
    Err("update checks are only built for Windows".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_numbers_are_read_with_or_without_a_v() {
        assert_eq!(Version::parse("0.4.0"), Some(Version(0, 4, 0)));
        assert_eq!(Version::parse("v0.3.0"), Some(Version(0, 3, 0)));
        assert_eq!(Version::parse(" V1.10.2 "), Some(Version(1, 10, 2)));
    }

    #[test]
    fn only_an_older_service_needs_an_update() {
        let app = Version(0, 6, 1);
        assert!(older_than("0.1.0", app));
        assert!(older_than("0.6.0", app));
        assert!(!older_than("0.6.1", app));
        // A newer service (an older app build was started) works fine.
        assert!(!older_than("0.7.0", app));
        assert!(!older_than("", app));
        assert!(!older_than("0.6", app));
    }

    #[test]
    fn other_tags_are_not_releases() {
        for tag in [
            "",
            "v",
            "0.4",
            "0.4.0.1",
            "0.5.0-beta",
            "1.x.0",
            "latest",
            "v+1.0.0",
        ] {
            assert_eq!(Version::parse(tag), None, "{tag:?}");
        }
    }

    #[test]
    fn numbers_compare_as_numbers_not_text() {
        assert!(Version(0, 10, 0) > Version(0, 9, 9));
        assert!(Version(1, 0, 0) > Version(0, 99, 99));
    }

    #[test]
    fn the_newest_tag_counts_only_when_it_is_newer() {
        // The real list, in GitHub's order (which is not by version).
        let json = r#"[{"name":"v0.3.0"},{"name":"v0.2.0"},{"name":"0.4.0"},{"name":"nightly"}]"#;
        assert_eq!(newer_in(json, Version(0, 3, 0)), Ok(Some(Version(0, 4, 0))));
        assert_eq!(newer_in(json, Version(0, 4, 0)), Ok(None));
        assert_eq!(newer_in(json, Version(0, 5, 0)), Ok(None));
        assert_eq!(newer_in("[]", Version(0, 5, 0)), Ok(None));
    }

    #[test]
    fn an_answer_that_is_not_a_tag_list_is_an_error() {
        assert!(newer_in(r#"{"message":"API rate limit exceeded"}"#, Version(0, 5, 0)).is_err());
        assert!(newer_in("<html>", Version(0, 5, 0)).is_err());
    }

    #[test]
    fn this_build_has_a_release_number() {
        assert_ne!(Version::current(), Version(0, 0, 0));
    }

    /// Asks the real GitHub: `cargo test -p deterium-gui update -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs the internet"]
    fn github_answers_with_a_tag_list() {
        let body = fetch(API_HOST, TAGS_PATH).expect("GitHub should answer");
        let newest = newer_in(&body, Version(0, 0, 0)).expect("a tag list");
        println!("newest release on GitHub: {newest:?}");
        assert!(newest.is_some());
    }
}
