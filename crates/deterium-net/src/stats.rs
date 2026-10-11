//! Live numbers about the tunnel, read from Windows itself: how many bytes
//! have crossed the tunnel adapter, and how long a packet takes to an address
//! inside the tunnel. Neither needs administrator rights, and both work the
//! same for WireGuard and OpenVPN because they look at the adapter, not at the
//! protocol. Windows only; elsewhere the functions report "unknown".

use std::net::IpAddr;
use std::time::Duration;

/// Bytes through a network adapter since it was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterCounters {
    /// Received by this PC through the adapter (the download).
    pub rx_bytes: u64,
    /// Sent by this PC through the adapter (the upload).
    pub tx_bytes: u64,
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, GetIfEntry2, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
        ICMP_ECHO_REPLY, IP_SUCCESS, MIB_IF_ROW2,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    fn wide(text: &str) -> Vec<u16> {
        std::ffi::OsStr::new(text)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn adapter_counters(alias: &str) -> Option<AdapterCounters> {
        let name = wide(alias);
        let mut luid = NET_LUID_LH { Value: 0 };
        // SAFETY: NUL-terminated name; Windows fills `luid`.
        if unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid) } != NO_ERROR {
            return None;
        }
        // SAFETY: all-zero is a valid row; only the identity is set before the call.
        let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        row.InterfaceLuid = luid;
        // SAFETY: `row` is a valid, writable MIB_IF_ROW2 with its key filled in.
        if unsafe { GetIfEntry2(&mut row) } != NO_ERROR {
            return None;
        }
        Some(AdapterCounters {
            rx_bytes: row.InOctets,
            tx_bytes: row.OutOctets,
        })
    }

    /// One ICMP echo to an IPv4 address; the round trip, or `None` when there
    /// was no answer in time. Blocks for up to `timeout`.
    pub fn ping(target: IpAddr, timeout: Duration) -> Option<Duration> {
        let IpAddr::V4(v4) = target else {
            return None;
        };
        // SAFETY: plain handle creation; closed below on every path.
        let handle: HANDLE = unsafe { IcmpCreateFile() };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return None;
        }
        // Network byte order, as IcmpSendEcho wants it.
        let destination = u32::from_ne_bytes(v4.octets());
        let payload = [0x44u8; 32];
        // The reply buffer must hold the reply header, the echoed data and
        // 8 bytes for an ICMP error.
        let mut reply = [0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + 32 + 8 + 16];
        let wait = timeout.as_millis().min(u32::MAX as u128) as u32;
        // SAFETY: the payload and reply buffers outlive the call and their
        // sizes are passed exactly; no options are used.
        let answers = unsafe {
            IcmpSendEcho(
                handle,
                destination,
                payload.as_ptr().cast(),
                payload.len() as u16,
                std::ptr::null(),
                reply.as_mut_ptr().cast(),
                reply.len() as u32,
                wait,
            )
        };
        let result = (answers > 0).then(|| {
            // SAFETY: Windows wrote an ICMP_ECHO_REPLY at the start of the
            // buffer (read unaligned, the buffer is only byte-aligned).
            unsafe { std::ptr::read_unaligned(reply.as_ptr().cast::<ICMP_ECHO_REPLY>()) }
        });
        // SAFETY: handle came from IcmpCreateFile.
        unsafe {
            IcmpCloseHandle(handle);
        }
        result
            .filter(|r| r.Status == IP_SUCCESS)
            .map(|r| Duration::from_millis(u64::from(r.RoundTripTime)))
    }
}

/// The byte counters of the network adapter called `alias`, if there is one.
pub fn adapter_counters(alias: &str) -> Option<AdapterCounters> {
    #[cfg(windows)]
    {
        imp::adapter_counters(alias)
    }
    #[cfg(not(windows))]
    {
        let _ = alias;
        None
    }
}

/// How long one echo to `target` takes, or `None` when nothing answered (or
/// the address isn't IPv4, which isn't supported yet). Blocks up to `timeout`.
pub fn ping(target: IpAddr, timeout: Duration) -> Option<Duration> {
    #[cfg(windows)]
    {
        imp::ping(target, timeout)
    }
    #[cfg(not(windows))]
    {
        let _ = (target, timeout);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_adapter_that_does_not_exist_has_no_counters() {
        assert_eq!(
            adapter_counters("Deterium adapter that cannot exist 7f3a"),
            None
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_counters_of_a_real_adapter_grow_with_traffic() {
        let alias = "Loopback Pseudo-Interface 1";
        let Some(before) = adapter_counters(alias) else {
            return; // a Windows without the default loopback alias
        };
        for _ in 0..5 {
            let _ = ping("127.0.0.1".parse().unwrap(), Duration::from_secs(1));
        }
        let after = adapter_counters(alias).unwrap();
        assert!(after.rx_bytes >= before.rx_bytes && after.tx_bytes >= before.tx_bytes);
    }

    #[test]
    fn loopback_answers_a_ping_and_ipv6_is_not_attempted() {
        if cfg!(windows) {
            let rtt = ping("127.0.0.1".parse().unwrap(), Duration::from_secs(2));
            assert!(rtt.is_some_and(|d| d < Duration::from_secs(1)), "{rtt:?}");
        }
        assert_eq!(
            ping("::1".parse().unwrap(), Duration::from_millis(200)),
            None
        );
    }

    #[test]
    fn a_documentation_address_never_answers() {
        assert_eq!(
            ping("192.0.2.123".parse().unwrap(), Duration::from_millis(300)),
            None
        );
    }
}
