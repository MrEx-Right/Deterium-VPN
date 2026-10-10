//! IP prefixes and the "which source addresses may this peer use" matcher.

use deterium_core::validate::parse_cidr;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Self> {
        (prefix <= max_prefix(addr)).then_some(Self { addr, prefix })
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let (addr, prefix) = parse_cidr(text)?;
        Ok(Self { addr, prefix })
    }

    /// A single host: `/32` or `/128`.
    pub fn host(addr: IpAddr) -> Self {
        Self {
            addr,
            prefix: max_prefix(addr),
        }
    }

    pub fn is_default(&self) -> bool {
        self.prefix == 0
    }

    /// The same prefix with the host bits cleared (`10.6.0.7/24` -> `10.6.0.0/24`).
    pub fn network(&self) -> Self {
        let addr = match self.addr {
            IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask32(self.prefix))),
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask128(self.prefix))),
        };
        Self {
            addr,
            prefix: self.prefix,
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                u32::from(net) & mask32(self.prefix) == u32::from(ip) & mask32(self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                u128::from(net) & mask128(self.prefix) == u128::from(ip) & mask128(self.prefix)
            }
            _ => false,
        }
    }

    /// Splits into the two prefixes one bit longer; `None` for a host route.
    pub fn halves(&self) -> Option<[Cidr; 2]> {
        let net = self.network();
        if net.prefix >= max_prefix(net.addr) {
            return None;
        }
        let next = net.prefix + 1;
        let low = Cidr {
            addr: net.addr,
            prefix: next,
        };
        let high_addr = match net.addr {
            IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4) | (1u32 << (32 - next)))),
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) | (1u128 << (128 - next)))),
        };
        Some([
            low,
            Cidr {
                addr: high_addr,
                prefix: next,
            },
        ])
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn max_prefix(addr: IpAddr) -> u8 {
    if addr.is_ipv4() {
        32
    } else {
        128
    }
}

fn mask32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

fn mask128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix as u32)
    }
}

/// WireGuard's cryptokey routing for one peer: decrypted packets whose
/// *source* address isn't in this set are dropped, so a compromised or
/// misbehaving server can't inject traffic that claims to come from
/// somewhere it shouldn't.
#[derive(Debug, Clone, Default)]
pub struct AllowedIps(Vec<Cidr>);

impl AllowedIps {
    pub fn new(cidrs: Vec<Cidr>) -> Self {
        Self(cidrs)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn contains_respects_prefix_and_family() {
        assert!(c("10.6.0.0/24").contains(ip("10.6.0.200")));
        assert!(!c("10.6.0.0/24").contains(ip("10.6.1.1")));
        assert!(c("0.0.0.0/0").contains(ip("8.8.8.8")));
        assert!(!c("0.0.0.0/0").contains(ip("::1")));
        assert!(c("fd00::/8").contains(ip("fdab::1")));
        assert!(c("10.6.0.2/32").contains(ip("10.6.0.2")));
        assert!(!c("10.6.0.2/32").contains(ip("10.6.0.3")));
    }

    #[test]
    fn network_clears_host_bits() {
        assert_eq!(c("10.6.0.7/24").network(), c("10.6.0.0/24"));
        assert_eq!(c("1.2.3.4/0").network(), c("0.0.0.0/0"));
    }

    #[test]
    fn default_routes_split_into_halves() {
        let [a, b] = c("0.0.0.0/0").halves().unwrap();
        assert_eq!((a, b), (c("0.0.0.0/1"), c("128.0.0.0/1")));
        let [a, b] = c("::/0").halves().unwrap();
        assert_eq!((a, b), (c("::/1"), c("8000::/1")));
        let [a, b] = c("10.0.0.0/8").halves().unwrap();
        assert_eq!((a, b), (c("10.0.0.0/9"), c("10.128.0.0/9")));
        assert!(c("1.2.3.4/32").halves().is_none());
    }

    #[test]
    fn allowed_ips_match_any_member() {
        let allowed = AllowedIps::new(vec![c("10.6.0.0/24"), c("192.168.1.5/32")]);
        assert!(allowed.contains(ip("10.6.0.9")));
        assert!(allowed.contains(ip("192.168.1.5")));
        assert!(!allowed.contains(ip("192.168.1.6")));
        assert!(!AllowedIps::default().contains(ip("10.6.0.9")));
    }
}
