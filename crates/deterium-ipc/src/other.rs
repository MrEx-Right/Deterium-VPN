//! Platforms without a service: every call reports the service as unavailable.

use crate::{IpcError, Request, Response, ServiceState};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub struct Client;

impl Client {
    pub fn new() -> Self {
        Client
    }

    pub fn call(&self, _request: &Request) -> Result<Response, IpcError> {
        Err(IpcError::Unavailable)
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

pub fn serve(
    _name: &str,
    _allowed_sids: &[String],
    _stop: Arc<AtomicBool>,
    _handler: Arc<dyn Fn(Request) -> Response + Send + Sync>,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the background service is only implemented on Windows",
    ))
}

pub fn wake(_name: &str) {}

pub fn service_state() -> ServiceState {
    ServiceState::NotInstalled
}
