//! The packet diversion interface the redirectors are written against. On Windows it is WinDivert
//! ([`crate::windivert`]); tests use an in-memory implementation, so all of the redirection logic runs on any OS.

use std::fmt;

use proxidize_core::net::Ip;
use proxidize_core::packet;

/// Largest packet WinDivert hands out.
pub const MTU_MAX: usize = 40 + 0xFFFF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Layer {
    Network = 0,
    NetworkForward = 1,
    Flow = 2,
    Socket = 3,
    Reflect = 4,
}

pub mod flags {
    pub const SNIFF: u64 = 0x0001;
    pub const DROP: u64 = 0x0002;
    pub const RECV_ONLY: u64 = 0x0004;
    pub const SEND_ONLY: u64 = 0x0008;
    pub const NO_INSTALL: u64 = 0x0010;
    pub const FRAGMENTS: u64 = 0x0020;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Event {
    NetworkPacket = 0,
    FlowEstablished = 1,
    FlowDeleted = 2,
    SocketBind = 3,
    SocketConnect = 4,
    SocketListen = 5,
    SocketAccept = 6,
    SocketClose = 7,
    ReflectOpen = 8,
    ReflectClose = 9,
    Other = 255,
}

/// `WINDIVERT_ADDRESS` (80 bytes). Bit fields of the u32 at offset 8 (MSVC allocates from the LSB): Layer:8,
/// Event:8, Sniffed, Outbound, Loopback, Impostor, IPv6, IPChecksum, TCPChecksum, UDPChecksum. The 64-byte union
/// at offset 16 is the network data (interface indexes) or the socket/flow data.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Address {
    pub timestamp: i64,
    pub bits: u32,
    reserved: u32,
    data: [u8; 64],
}

const _: () = assert!(std::mem::size_of::<Address>() == 80);

impl Default for Address {
    fn default() -> Self {
        Address { timestamp: 0, bits: 0, reserved: 0, data: [0; 64] }
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Address").field("outbound", &self.outbound()).field("ipv6", &self.ipv6()).finish()
    }
}

const BIT_OUTBOUND: u32 = 17;
const BIT_LOOPBACK: u32 = 18;
const BIT_IMPOSTOR: u32 = 19;
const BIT_IPV6: u32 = 20;
const BIT_IP_CHECKSUM: u32 = 21;
const BIT_TCP_CHECKSUM: u32 = 22;
const BIT_UDP_CHECKSUM: u32 = 23;

impl Address {
    fn bit(&self, b: u32) -> bool {
        self.bits & (1 << b) != 0
    }

    fn set_bit(&mut self, b: u32, on: bool) {
        if on {
            self.bits |= 1 << b;
        } else {
            self.bits &= !(1 << b);
        }
    }

    fn u32_at(&self, o: usize) -> u32 {
        u32::from_le_bytes(self.data[o..o + 4].try_into().unwrap())
    }

    pub fn event(&self) -> Event {
        match (self.bits >> 8) & 0xFF {
            0 => Event::NetworkPacket,
            1 => Event::FlowEstablished,
            2 => Event::FlowDeleted,
            3 => Event::SocketBind,
            4 => Event::SocketConnect,
            5 => Event::SocketListen,
            6 => Event::SocketAccept,
            7 => Event::SocketClose,
            8 => Event::ReflectOpen,
            9 => Event::ReflectClose,
            _ => Event::Other,
        }
    }

    pub fn outbound(&self) -> bool {
        self.bit(BIT_OUTBOUND)
    }

    pub fn set_outbound(&mut self, on: bool) {
        self.set_bit(BIT_OUTBOUND, on);
    }

    pub fn loopback(&self) -> bool {
        self.bit(BIT_LOOPBACK)
    }

    pub fn impostor(&self) -> bool {
        self.bit(BIT_IMPOSTOR)
    }

    pub fn ipv6(&self) -> bool {
        self.bit(BIT_IPV6)
    }

    pub fn set_ipv6(&mut self, on: bool) {
        self.set_bit(BIT_IPV6, on);
    }

    /// Marks the IP/TCP/UDP checksums as valid (after computing them).
    pub fn set_checksums_valid(&mut self) {
        self.set_bit(BIT_IP_CHECKSUM, true);
        self.set_bit(BIT_TCP_CHECKSUM, true);
        self.set_bit(BIT_UDP_CHECKSUM, true);
    }

    pub fn if_idx(&self) -> u32 {
        self.u32_at(0)
    }

    // Socket / flow layer data.

    pub fn endpoint_id(&self) -> u64 {
        u64::from_le_bytes(self.data[0..8].try_into().unwrap())
    }

    pub fn process_id(&self) -> u32 {
        self.u32_at(16)
    }

    /// Socket/flow addresses are UINT32[4] with the most significant word last; IPv4 is IPv4-mapped.
    fn ip_at(&self, o: usize) -> Ip {
        let w = |i: usize| self.u32_at(o + 4 * i) as u128;
        Ip::from_raw((w(3) << 96) | (w(2) << 64) | (w(1) << 32) | w(0))
    }

    pub fn local_address(&self) -> Ip {
        self.ip_at(20)
    }

    pub fn remote_address(&self) -> Ip {
        self.ip_at(36)
    }

    pub fn local_port(&self) -> u16 {
        u16::from_le_bytes([self.data[52], self.data[53]])
    }

    pub fn remote_port(&self) -> u16 {
        u16::from_le_bytes([self.data[54], self.data[55]])
    }

    pub fn protocol(&self) -> u8 {
        self.data[56]
    }

    /// Builds a socket-layer event (tests).
    #[allow(clippy::too_many_arguments)]
    pub fn socket_event(
        event: Event,
        pid: u32,
        endpoint: u64,
        protocol: u8,
        local: Ip,
        lport: u16,
        remote: Ip,
        rport: u16,
    ) -> Address {
        let mut a = Address { bits: (Layer::Socket as u32) | ((event as u32) << 8), ..Default::default() };
        a.data[0..8].copy_from_slice(&endpoint.to_le_bytes());
        a.data[16..20].copy_from_slice(&pid.to_le_bytes());
        for (o, ip) in [(20, local), (36, remote)] {
            let raw = ip.raw();
            for i in 0..4 {
                a.data[o + 4 * i..o + 4 * i + 4].copy_from_slice(&((raw >> (32 * i)) as u32).to_le_bytes());
            }
        }
        a.data[52..54].copy_from_slice(&lport.to_le_bytes());
        a.data[54..56].copy_from_slice(&rport.to_le_bytes());
        a.data[56] = protocol;
        a
    }

    /// An outbound network-layer address (tests).
    pub fn outbound_packet(ipv6: bool) -> Address {
        let mut a = Address::default();
        a.set_outbound(true);
        a.set_ipv6(ipv6);
        a
    }
}

/// A WinDivert error code with a hint about what to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DivertError {
    pub code: u32,
    pub context: String,
}

impl fmt::Display for DivertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hint = match self.code {
            2 => "WinDivert64.sys / WinDivert.dll not found.".to_string(),
            5 => "Access denied. Proxidize must run as Administrator.".to_string(),
            87 => "Invalid parameter (bad filter string or layer).".to_string(),
            126 => "WinDivert.dll could not be loaded.".to_string(),
            577 => "The WinDivert driver signature could not be verified (Secure Boot / driver signing policy).".to_string(),
            654 => "An incompatible WinDivert driver is already loaded. Close other WinDivert-based tools or reboot.".to_string(),
            1060 => "The WinDivert service is marked for deletion. Reboot and try again.".to_string(),
            1275 => "The WinDivert driver was blocked (anti-virus, HVCI / Memory Integrity).".to_string(),
            1753 => "The Base Filtering Engine service is not running.".to_string(),
            other => std::io::Error::from_raw_os_error(other as i32).to_string(),
        };
        write!(f, "WinDivert error {} ({}): {hint}", self.code, self.context)
    }
}

impl std::error::Error for DivertError {}

/// Receive errors that mean the handle was shut down or closed: the loop ends.
pub fn is_shutdown_error(code: u32) -> bool {
    matches!(code, 232 | 6 | 995)
}

/// One open diversion handle.
pub trait Divert: Send + Sync {
    /// Blocks until a packet or event arrives. `Err(code)` when the handle fails or is shut down.
    fn recv(&self, buffer: &mut [u8], address: &mut Address) -> Result<usize, u32>;

    /// Injects a packet unchanged.
    fn send(&self, packet: &[u8], address: &Address) -> bool;

    /// Recomputes the checksums and injects.
    fn reinject(&self, packet: &mut [u8], address: &mut Address) -> bool {
        if let Some(info) = packet::parse(packet) {
            packet::update_checksums(packet, &info);
        }
        address.set_checksums_valid();
        self.send(packet, address)
    }

    /// Makes blocked and future `recv` calls fail, so the capture loop ends.
    fn shutdown(&self);

    fn set_queue(&self, _length: u64, _size: u64) {}
}

/// Opens diversion handles.
pub trait DivertOpener: Send + Sync {
    fn open(&self, filter: &str, layer: Layer, priority: i16, flags: u64) -> Result<std::sync::Arc<dyn Divert>, DivertError>;
}

#[cfg(test)]
pub mod mock {
    //! In-memory diversion for tests: packets are pushed in, injected packets are recorded.

    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Condvar, Mutex};

    type Queue = (VecDeque<(Vec<u8>, Address)>, bool);

    #[derive(Default)]
    pub struct MockDivert {
        incoming: Mutex<Queue>,
        ready: Condvar,
        pub sent: Mutex<Vec<(Vec<u8>, Address)>>,
        pub filter: String,
    }

    impl MockDivert {
        pub fn push(&self, packet: Vec<u8>, address: Address) {
            self.incoming.lock().unwrap().0.push_back((packet, address));
            self.ready.notify_all();
        }

        pub fn take_sent(&self) -> Vec<(Vec<u8>, Address)> {
            std::mem::take(&mut *self.sent.lock().unwrap())
        }
    }

    impl Divert for MockDivert {
        fn recv(&self, buffer: &mut [u8], address: &mut Address) -> Result<usize, u32> {
            let mut guard = self.incoming.lock().unwrap();
            loop {
                if guard.1 {
                    return Err(232);
                }
                if let Some((p, a)) = guard.0.pop_front() {
                    buffer[..p.len()].copy_from_slice(&p);
                    *address = a;
                    return Ok(p.len());
                }
                guard = self.ready.wait(guard).unwrap();
            }
        }

        fn send(&self, packet: &[u8], address: &Address) -> bool {
            self.sent.lock().unwrap().push((packet.to_vec(), *address));
            true
        }

        fn shutdown(&self) {
            self.incoming.lock().unwrap().1 = true;
            self.ready.notify_all();
        }
    }

    /// Hands out mock handles and remembers them by filter.
    #[derive(Default)]
    pub struct MockOpener {
        pub opened: Mutex<Vec<(String, Layer, Arc<MockDivert>)>>,
    }

    impl MockOpener {
        pub fn handle(&self, contains: &str) -> Arc<MockDivert> {
            self.opened
                .lock()
                .unwrap()
                .iter()
                .find(|(f, _, _)| f.contains(contains))
                .map(|(_, _, d)| d.clone())
                .expect("handle opened")
        }
    }

    impl DivertOpener for MockOpener {
        fn open(&self, filter: &str, layer: Layer, _priority: i16, _flags: u64) -> Result<Arc<dyn Divert>, DivertError> {
            let d = Arc::new(MockDivert { filter: filter.into(), ..Default::default() });
            self.opened.lock().unwrap().push((filter.into(), layer, d.clone()));
            Ok(d)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_layout() {
        let local: Ip = "10.0.0.2".parse().unwrap();
        let remote: Ip = "2001:db8::5".parse().unwrap();
        let a = Address::socket_event(Event::SocketConnect, 4242, 77, 6, local, 50000, remote, 443);
        assert_eq!(a.event(), Event::SocketConnect);
        assert_eq!((a.process_id(), a.endpoint_id(), a.protocol()), (4242, 77, 6));
        assert_eq!((a.local_address(), a.local_port()), (local, 50000));
        assert_eq!((a.remote_address(), a.remote_port()), (remote, 443));
        let mut b = Address::outbound_packet(true);
        assert!(b.outbound() && b.ipv6());
        b.set_outbound(false);
        assert!(!b.outbound() && b.ipv6());
    }
}
