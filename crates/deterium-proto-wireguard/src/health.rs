//! Is the tunnel actually alive? WireGuard has no "connected" state: a quiet
//! peer is indistinguishable from a dead one except by *handshake age*. A
//! live peer keeps completing handshakes as long as we keep sending (our
//! keepalives count), so a handshake that stops being renewed means the
//! server stopped answering — Wi-Fi dropped, the machine slept, the server
//! went away. This module turns that observation into a status; it is pure
//! so every rule is a unit test.

use std::time::Duration;

/// Timing knobs. The defaults suit a real network; tests shrink them.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// While healthy with keepalives on, start our own handshake if the last
    /// one is older than this — proves liveness well before WireGuard's own
    /// 2-minute rekey would.
    pub probe_after: Duration,
    /// Handshake older than this (with keepalives on) = the server is not
    /// answering.
    pub stale_after: Duration,
    /// How often to retry a handshake once the server stopped answering.
    pub retry_every: Duration,
    /// How often to replace the UDP socket while the server is silent, so a
    /// network change (new Wi-Fi, resume from sleep) can't leave us sending
    /// into a dead socket forever.
    pub rebind_every: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            probe_after: Duration::from_secs(45),
            stale_after: Duration::from_secs(90),
            retry_every: Duration::from_secs(10),
            rebind_every: Duration::from_secs(20),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// No handshake has ever completed on this connection.
    Connecting,
    Healthy,
    /// It worked, and the server has stopped answering.
    Reconnecting,
}

pub struct Observation {
    /// Age of the current session's handshake, if there is a session.
    pub handshake_age: Option<Duration>,
    pub ever_connected: bool,
    pub keepalive: bool,
    /// The protocol library gave up on a handshake attempt.
    pub expired: bool,
}

pub fn assess(observation: &Observation, policy: &Policy) -> Health {
    let lost = if observation.ever_connected {
        Health::Reconnecting
    } else {
        Health::Connecting
    };

    if observation.expired {
        return lost;
    }
    match observation.handshake_age {
        None => lost,
        // Without keepalives an idle connection legitimately stops
        // handshaking, so age alone proves nothing there.
        Some(age) if observation.keepalive && age > policy.stale_after => Health::Reconnecting,
        Some(_) => Health::Healthy,
    }
}

/// Should we start a liveness handshake now?
pub fn should_probe(
    health: Health,
    keepalive: bool,
    handshake_age: Option<Duration>,
    since_last_probe: Duration,
    policy: &Policy,
) -> bool {
    match health {
        Health::Reconnecting => since_last_probe >= policy.retry_every,
        Health::Healthy => {
            keepalive
                && handshake_age.is_some_and(|age| age > policy.probe_after)
                && since_last_probe >= policy.probe_after
        }
        Health::Connecting => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: Policy = Policy {
        probe_after: Duration::from_secs(45),
        stale_after: Duration::from_secs(90),
        retry_every: Duration::from_secs(10),
        rebind_every: Duration::from_secs(20),
    };
    fn obs(age: Option<u64>, ever: bool, keepalive: bool, expired: bool) -> Observation {
        Observation {
            handshake_age: age.map(Duration::from_secs),
            ever_connected: ever,
            keepalive,
            expired,
        }
    }

    #[test]
    fn before_the_first_handshake_it_is_connecting() {
        assert_eq!(
            assess(&obs(None, false, true, false), &P),
            Health::Connecting
        );
        assert_eq!(
            assess(&obs(None, false, true, true), &P),
            Health::Connecting
        );
    }

    #[test]
    fn a_fresh_handshake_is_healthy() {
        assert_eq!(
            assess(&obs(Some(3), false, true, false), &P),
            Health::Healthy
        );
    }

    #[test]
    fn a_handshake_that_stops_being_renewed_means_reconnecting() {
        assert_eq!(
            assess(&obs(Some(89), true, true, false), &P),
            Health::Healthy
        );
        assert_eq!(
            assess(&obs(Some(91), true, true, false), &P),
            Health::Reconnecting
        );
    }

    #[test]
    fn an_idle_connection_without_keepalives_is_not_called_dead() {
        assert_eq!(
            assess(&obs(Some(3_000), true, false, false), &P),
            Health::Healthy
        );
    }

    #[test]
    fn losing_the_session_after_having_connected_is_reconnecting_not_connecting() {
        assert_eq!(
            assess(&obs(None, true, true, false), &P),
            Health::Reconnecting
        );
        assert_eq!(
            assess(&obs(Some(1), true, true, true), &P),
            Health::Reconnecting
        );
    }

    #[test]
    fn probing_is_rate_limited_and_only_when_it_helps() {
        let s = Duration::from_secs;
        // Healthy with keepalives: probe once the handshake is old, not before.
        assert!(!should_probe(
            Health::Healthy,
            true,
            Some(s(30)),
            s(100),
            &P
        ));
        assert!(should_probe(Health::Healthy, true, Some(s(50)), s(60), &P));
        assert!(!should_probe(Health::Healthy, true, Some(s(50)), s(10), &P));
        assert!(!should_probe(
            Health::Healthy,
            false,
            Some(s(500)),
            s(500),
            &P
        ));
        // Reconnecting: retry on the retry cadence.
        assert!(!should_probe(Health::Reconnecting, true, None, s(5), &P));
        assert!(should_probe(Health::Reconnecting, true, None, s(10), &P));
        // Never before the first handshake: boringtun already retries that.
        assert!(!should_probe(Health::Connecting, true, None, s(999), &P));
    }
}
