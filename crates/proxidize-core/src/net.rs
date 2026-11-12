//! Addresses, networks and connection targets.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// An IPv4 or IPv6 address as one 128-bit value (IPv4 is stored IPv4-mapped, `::ffff:a.b.c.d`), cheap to copy,
/// hash and compare. Used everywhere on the packet path.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Ip(u128);

const V4_MAPPED: u128 = 0xFFFF << 32;

impl Ip {
    pub const UNSPECIFIED_V4: Ip = Ip(V4_MAPPED);

    pub fn v4(octets: [u8; 4]) -> Ip {
        Ip(V4_MAPPED | u32::from_be_bytes(octets) as u128)
    }

    pub fn v4_u32(value: u32) -> Ip {
        Ip(V4_MAPPED | value as u128)
    }

    pub fn v6(octets: [u8; 16]) -> Ip {
        Ip(u128::from_be_bytes(octets))
    }

    pub fn from_slice_v4(bytes: &[u8]) -> Ip {
        Ip::v4([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    pub fn from_slice_v6(bytes: &[u8]) -> Ip {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&bytes[..16]);
        Ip::v6(octets)
    }

    pub fn raw(self) -> u128 {
        self.0
    }

    pub fn from_raw(value: u128) -> Ip {
        Ip(value)
    }

    pub fn is_v4(self) -> bool {
        self.0 >> 32 == 0xFFFF
    }

    /// The IPv4 value (only meaningful when [`is_v4`](Self::is_v4)).
    pub fn v4_value(self) -> u32 {
        self.0 as u32
    }

    pub fn write_v4(self, destination: &mut [u8]) {
        destination[..4].copy_from_slice(&self.v4_value().to_be_bytes());
    }

    pub fn write_v6(self, destination: &mut [u8]) {
        destination[..16].copy_from_slice(&self.0.to_be_bytes());
    }

    pub fn is_unspecified(self) -> bool {
        if self.is_v4() {
            self.v4_value() == 0
        } else {
            self.0 == 0
        }
    }

    pub fn is_loopback(self) -> bool {
        if self.is_v4() {
            self.v4_value() >> 24 == 127
        } else {
            self.0 == 1
        }
    }

    pub fn is_multicast_or_broadcast(self) -> bool {
        if self.is_v4() {
            let v = self.v4_value();
            v >> 28 == 0xE || v == u32::MAX
        } else {
            self.0 >> 120 == 0xFF
        }
    }

    pub fn to_std(self) -> IpAddr {
        if self.is_v4() {
            IpAddr::V4(Ipv4Addr::from(self.v4_value()))
        } else {
            IpAddr::V6(Ipv6Addr::from(self.0))
        }
    }

    pub fn from_std(address: IpAddr) -> Ip {
        match address {
            IpAddr::V4(v4) => Ip::v4(v4.octets()),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Ip::v4(v4.octets()),
                None => Ip::v6(v6.octets()),
            },
        }
    }
}

impl From<IpAddr> for Ip {
    fn from(value: IpAddr) -> Self {
        Ip::from_std(value)
    }
}

impl From<Ip> for IpAddr {
    fn from(value: Ip) -> Self {
        value.to_std()
    }
}

impl FromStr for Ip {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IpAddr::from_str(s.trim().trim_matches(|c| c == '[' || c == ']')).map(Ip::from_std)
    }
}

impl fmt::Display for Ip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_std().fmt(f)
    }
}

impl fmt::Debug for Ip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// An IPv4 or IPv6 network (`10.0.0.0/8`, `2001:db8::/32`). A bare address is a /32 or /128.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Cidr {
    network: Ip,
    prefix128: u32,
    is_v4: bool,
}

impl Cidr {
    pub fn parse(text: &str) -> Option<Cidr> {
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        let mut parts = text.splitn(2, '/');
        let address: Ip = parts.next()?.parse().ok()?;
        let max = if address.is_v4() { 32 } else { 128 };
        let prefix = match parts.next() {
            Some(p) => p.trim().parse::<u32>().ok().filter(|p| *p <= max)?,
            None => max,
        };
        let prefix128 = if address.is_v4() { prefix + 96 } else { prefix };
        Some(Cidr { network: mask(address, prefix128), prefix128, is_v4: address.is_v4() })
    }

    pub fn single(address: Ip) -> Cidr {
        Cidr { network: address, prefix128: 128, is_v4: address.is_v4() }
    }

    pub fn network(&self) -> Ip {
        self.network
    }

    pub fn is_v4(&self) -> bool {
        self.is_v4
    }

    pub fn prefix_len(&self) -> u32 {
        if self.is_v4 {
            self.prefix128 - 96
        } else {
            self.prefix128
        }
    }

    pub fn contains(&self, address: Ip) -> bool {
        address.is_v4() == self.is_v4 && mask(address, self.prefix128) == self.network
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len())
    }
}

fn mask(address: Ip, prefix128: u32) -> Ip {
    let m = if prefix128 == 0 {
        0
    } else if prefix128 >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix128)
    };
    Ip(address.0 & m)
}

/// `1.2.3.4-1.2.3.9`: an inclusive range of addresses of one family.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IpRange {
    pub first: Ip,
    pub last: Ip,
}

impl IpRange {
    pub fn parse(text: &str) -> Option<IpRange> {
        let dash = text.find('-')?;
        if dash == 0 || dash == text.len() - 1 {
            return None;
        }
        let a: Ip = text[..dash].parse().ok()?;
        let b: Ip = text[dash + 1..].parse().ok()?;
        if a.is_v4() != b.is_v4() {
            return None;
        }
        Some(IpRange { first: a.min(b), last: a.max(b) })
    }

    pub fn contains(&self, address: Ip) -> bool {
        address >= self.first && address <= self.last
    }
}

/// Where a connection goes: a host name (resolved by the proxy) or an address, plus a port.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Target {
    Host(String, u16),
    Addr(Ip, u16),
}

impl Target {
    /// A literal IP becomes [`Target::Addr`]; names are normalised (IDN to ASCII, lower case, no trailing dot).
    pub fn host(host: &str, port: u16) -> Target {
        match host.parse::<Ip>() {
            Ok(ip) => Target::Addr(ip, port),
            Err(_) => Target::Host(normalize_host(host), port),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Target::Host(_, p) | Target::Addr(_, p) => *p,
        }
    }

    pub fn is_host(&self) -> bool {
        matches!(self, Target::Host(..))
    }

    /// `host:port` or `[v6]:port`.
    pub fn authority(&self) -> String {
        match self {
            Target::Host(h, p) => format!("{h}:{p}"),
            Target::Addr(a, p) if a.is_v4() => format!("{a}:{p}"),
            Target::Addr(a, p) => format!("[{a}]:{p}"),
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.authority())
    }
}

pub fn normalize_host(host: &str) -> String {
    let host = host.trim().trim_end_matches('.');
    match idna::domain_to_ascii(host) {
        Ok(ascii) if !ascii.is_empty() => ascii.to_ascii_lowercase(),
        _ => host.to_ascii_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_round_trips() {
        let v4: Ip = "192.168.1.20".parse().unwrap();
        assert!(v4.is_v4());
        assert_eq!(v4.to_string(), "192.168.1.20");
        let v6: Ip = "2001:db8::1".parse().unwrap();
        assert!(!v6.is_v4());
        assert_eq!(v6.to_string(), "2001:db8::1");
        let mapped: Ip = "::ffff:10.0.0.1".parse().unwrap();
        assert!(mapped.is_v4());
        assert!(Ip::v4([127, 0, 0, 1]).is_loopback());
        assert!(Ip::v4([224, 0, 0, 251]).is_multicast_or_broadcast());
        assert!(Ip::v4([0, 0, 0, 0]).is_unspecified());
    }

    #[test]
    fn cidr_and_ranges() {
        let c = Cidr::parse("10.1.2.3/8").unwrap();
        assert_eq!(c.to_string(), "10.0.0.0/8");
        assert!(c.contains("10.200.1.1".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        assert!(!c.contains("::a01:203".parse().unwrap()), "families don't mix");
        let six = Cidr::parse("2001:db8::/32").unwrap();
        assert!(six.contains("2001:db8:1::5".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.4/33").is_none());
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains("8.8.8.8".parse().unwrap()));
        assert_eq!(Cidr::parse("1.2.3.4").unwrap().prefix_len(), 32);

        let r = IpRange::parse("1.2.3.9-1.2.3.4").unwrap();
        assert!(r.contains("1.2.3.5".parse().unwrap()));
        assert!(!r.contains("1.2.3.10".parse().unwrap()));
        assert!(IpRange::parse("1.2.3.4-::1").is_none());
    }

    #[test]
    fn targets() {
        assert_eq!(Target::host("Example.COM.", 80), Target::Host("example.com".into(), 80));
        assert!(matches!(Target::host("1.2.3.4", 80), Target::Addr(..)));
        assert_eq!(Target::host("bücher.de", 443).authority(), "xn--bcher-kva.de:443");
        assert_eq!(Target::Addr("::1".parse().unwrap(), 53).authority(), "[::1]:53");
    }
}
