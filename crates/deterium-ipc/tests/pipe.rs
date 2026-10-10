//! The named-pipe transport against a real pipe, as an ordinary (non-admin)
//! user: the access list must let this user in, requests and answers must
//! survive the round trip, and the server must keep working after bad input.

#![cfg(windows)]

use deterium_ipc::{
    pipe_access_list, serve_with_access_list, stop_server, Client, ErrorKind, IpcError, Request,
    Response,
};
use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn my_sid() -> String {
    let out = std::process::Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .expect("whoami");
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim()
        .rsplit(',')
        .next()
        .unwrap()
        .trim_matches('"')
        .to_string()
}

struct TestServer {
    name: String,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TestServer {
    fn start(tag: &str, allowed: Vec<String>) -> Self {
        Self::start_as(tag, allowed, true)
    }

    /// `creator_may_connect = false` leaves the test user off the list, so the
    /// server can't be woken (or joined) from here when it is dropped.
    fn start_as(tag: &str, allowed: Vec<String>, creator_may_connect: bool) -> Self {
        let name = format!(r"\\.\pipe\deterium-test-{tag}-{}", std::process::id());
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<dyn Fn(Request) -> Response + Send + Sync> =
            Arc::new(|request| match request {
                Request::Hello => Response::Hello {
                    protocol: deterium_ipc::PROTOCOL_VERSION,
                    service_version: "test".into(),
                },
                Request::Status => Response::Status(deterium_ipc::ServiceStatus { active: None }),
                _ => Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: "unsupported in this test".into(),
                },
            });
        let thread = {
            let (name, stop) = (name.clone(), stop.clone());
            thread::spawn(move || {
                // The test server runs as an ordinary user, so it also grants
                // itself the right to create further pipe instances (SYSTEM has
                // it already in the real service).
                let creator = if creator_may_connect {
                    format!("(A;;GA;;;{})", my_sid())
                } else {
                    String::new()
                };
                let sddl = pipe_access_list(&allowed) + &creator;
                serve_with_access_list(&name, &sddl, stop, handler).expect("serve");
            })
        };
        thread::sleep(Duration::from_millis(300));
        Self {
            name,
            stop,
            thread: Some(thread),
        }
    }

    fn client(&self) -> Client {
        Client::unverified_for_tests(&self.name)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(t) = self.thread.take() {
            let _ = stop_server(&self.name, &self.stop, t);
        }
    }
}

#[test]
fn the_allowed_user_can_talk_to_the_server() {
    let server = TestServer::start("ok", vec![my_sid()]);
    server.client().handshake().expect("handshake");
    match server.client().call(&Request::Status).unwrap() {
        Response::Status(s) => assert!(s.active.is_none()),
        other => panic!("{other:?}"),
    }
}

#[test]
fn many_clients_at_once_all_get_answers() {
    let server = TestServer::start("many", vec![my_sid()]);
    let name = server.name.clone();
    let handles: Vec<_> = (0..12)
        .map(|_| {
            let name = name.clone();
            thread::spawn(move || {
                for _ in 0..5 {
                    Client::unverified_for_tests(&name).handshake().unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn a_user_who_is_not_on_the_list_is_turned_away() {
    // The list names only the built-in "Guest" SID, not this user. (This test
    // process isn't an administrator or SYSTEM either, or the ACE for those
    // would let it in; skip in that case.)
    let mut server = TestServer::start_as("denied", vec!["S-1-5-21-1-2-3-501".into()], false);
    let result = server.client().call(&Request::Hello);
    // The server thread stays blocked waiting for a client we aren't allowed
    // to be; let it end with the test process.
    server.thread.take();
    match result {
        Err(IpcError::Denied) => {}
        Ok(_) if deterium_engine_is_admin() => {}
        other => panic!("expected access denied, got {other:?}"),
    }
}

fn deterium_engine_is_admin() -> bool {
    std::process::Command::new("net")
        .arg("session")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn garbage_gets_an_error_and_the_server_carries_on() {
    let server = TestServer::start("garbage", vec![my_sid()]);

    let mut raw = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&server.name)
        .unwrap();
    raw.write_all(b"{\"type\":\"format_disk\"}\n").unwrap();
    let mut answer = String::new();
    BufReader::new(&raw).read_line(&mut answer).unwrap();
    assert!(answer.contains("bad_request"), "got: {answer}");

    server.client().handshake().expect("still serving");
}

#[test]
fn a_message_over_the_size_limit_is_refused() {
    let server = TestServer::start("big", vec![my_sid()]);

    let raw = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&server.name)
        .unwrap();
    // 5 MiB without a newline, then close the write side by dropping after reading.
    let chunk = vec![b'a'; 64 * 1024];
    let writer = {
        let mut w = raw.try_clone().unwrap();
        thread::spawn(move || {
            for _ in 0..80 {
                if w.write_all(&chunk).is_err() {
                    break;
                }
            }
        })
    };
    let mut answer = String::new();
    let _ = BufReader::new(&raw).read_line(&mut answer);
    drop(raw);
    let _ = writer.join();
    assert!(
        answer.contains("too large") || answer.contains("bad_request"),
        "got: {}",
        &answer[..answer.len().min(200)]
    );

    server.client().handshake().expect("still serving");
}

#[test]
fn nothing_listening_means_unavailable() {
    let client = Client::unverified_for_tests(r"\\.\pipe\deterium-test-nobody-here");
    assert!(matches!(
        client.call(&Request::Hello),
        Err(IpcError::Unavailable)
    ));
}

#[test]
fn the_real_client_refuses_an_impostor() {
    // A pipe with the real name served by this test process, while no service
    // is running: the real client must send nothing.
    let probe = Client::new();
    if deterium_ipc::service_state() != deterium_ipc::ServiceState::NotInstalled {
        return; // a real service is installed on this PC; the check would pass for it
    }
    let _ = probe; // (see below: serving the real name needs the first-instance right)
    let impostor_name = deterium_ipc::PIPE_NAME;
    let stop = Arc::new(AtomicBool::new(false));
    let handler: Arc<dyn Fn(Request) -> Response + Send + Sync> = Arc::new(|_| Response::Ok);
    let t = {
        let stop = stop.clone();
        let sid = my_sid();
        thread::spawn(move || {
            let sddl = pipe_access_list(std::slice::from_ref(&sid)) + &format!("(A;;GA;;;{sid})");
            let _ = serve_with_access_list(impostor_name, &sddl, stop, handler);
        })
    };
    thread::sleep(Duration::from_millis(300));
    let result = Client::new().call(&Request::Hello);
    let _ = stop_server(impostor_name, &stop, t);
    assert!(
        matches!(result, Err(IpcError::Untrusted(_))),
        "the client must not talk to an impostor: {result:?}"
    );
}
