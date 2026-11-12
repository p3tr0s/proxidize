//! IPv4/IPv6 + TCP/UDP header parsing, in-place rewriting and packet construction.

use crate::net::Ip;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketInfo {
    pub is_v6: bool,
    pub ip_header_len: usize,
    pub total_len: usize,
    pub protocol: u8,
    pub transport_offset: usize,
    pub payload_offset: usize,
    pub payload_len: usize,
    pub source: Ip,
    pub destination: Ip,
    pub source_port: u16,
    pub destination_port: u16,
    pub tcp_flags: u8,
}

impl PacketInfo {
    pub fn is_tcp(&self) -> bool {
        self.protocol == PROTO_TCP
    }
    pub fn is_udp(&self) -> bool {
        self.protocol == PROTO_UDP
    }
    pub fn is_syn(&self) -> bool {
        self.tcp_flags & TCP_SYN != 0
    }
    pub fn is_ack(&self) -> bool {
        self.tcp_flags & TCP_ACK != 0
    }
    pub fn is_rst(&self) -> bool {
        self.tcp_flags & TCP_RST != 0
    }
    pub fn is_fin(&self) -> bool {
        self.tcp_flags & TCP_FIN != 0
    }
}

/// An IPv4 or IPv6 fragment. Offsets are in bytes; `data_*` locate the fragment's payload in the packet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FragmentInfo {
    pub is_v6: bool,
    pub source: Ip,
    pub destination: Ip,
    pub identification: u32,
    pub protocol: u8,
    pub offset: usize,
    pub more_fragments: bool,
    pub header_len: usize,
    pub data_offset: usize,
    pub data_len: usize,
}

fn be16(p: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([p[at], p[at + 1]])
}

fn be32(p: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]])
}

fn put16(p: &mut [u8], at: usize, v: u16) {
    p[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

fn put32(p: &mut [u8], at: usize, v: u32) {
    p[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

/// Walks hop-by-hop / routing / destination-options headers. Returns (next header, offset).
fn skip_v6_extensions(packet: &[u8], total: usize) -> Option<(u8, usize)> {
    let mut next = packet[6];
    let mut offset = 40usize;
    while matches!(next, 0 | 43 | 60) {
        if offset + 8 > total {
            return None;
        }
        let following = packet[offset];
        offset += (packet[offset + 1] as usize + 1) * 8;
        next = following;
        if offset > total {
            return None;
        }
    }
    Some((next, offset))
}

/// Parses an unfragmented TCP or UDP packet. Fragments and other protocols return `None`.
pub fn parse(packet: &[u8]) -> Option<PacketInfo> {
    if packet.len() < 20 {
        return None;
    }
    let mut info = PacketInfo::default();
    let total;
    let transport_offset = match packet[0] >> 4 {
        4 => {
            let ihl = (packet[0] & 0x0F) as usize * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            total = be16(packet, 2) as usize;
            if total < ihl || total > packet.len() {
                return None;
            }
            if be16(packet, 6) & 0x3FFF != 0 {
                return None; // fragment: ports are not reliably present
            }
            info.ip_header_len = ihl;
            info.protocol = packet[9];
            info.source = Ip::from_slice_v4(&packet[12..16]);
            info.destination = Ip::from_slice_v4(&packet[16..20]);
            ihl
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let payload_len = be16(packet, 4) as usize;
            total = 40 + payload_len;
            if payload_len == 0 || total > packet.len() {
                return None;
            }
            let (next, offset) = skip_v6_extensions(packet, total)?;
            if next == 44 {
                return None;
            }
            info.is_v6 = true;
            info.ip_header_len = 40;
            info.protocol = next;
            info.source = Ip::from_slice_v6(&packet[8..24]);
            info.destination = Ip::from_slice_v6(&packet[24..40]);
            offset
        }
        _ => return None,
    };

    info.total_len = total;
    info.transport_offset = transport_offset;
    let segment = total - transport_offset;
    match info.protocol {
        PROTO_TCP => {
            if segment < 20 {
                return None;
            }
            let data_offset = (packet[transport_offset + 12] >> 4) as usize * 4;
            if data_offset < 20 || data_offset > segment {
                return None;
            }
            info.source_port = be16(packet, transport_offset);
            info.destination_port = be16(packet, transport_offset + 2);
            info.tcp_flags = packet[transport_offset + 13];
            info.payload_offset = transport_offset + data_offset;
            info.payload_len = total - info.payload_offset;
            Some(info)
        }
        PROTO_UDP => {
            if segment < 8 {
                return None;
            }
            info.source_port = be16(packet, transport_offset);
            info.destination_port = be16(packet, transport_offset + 2);
            let udp_len = be16(packet, transport_offset + 4) as usize;
            info.payload_offset = transport_offset + 8;
            info.payload_len = (if (8..=segment).contains(&udp_len) { udp_len } else { segment }) - 8;
            Some(info)
        }
        _ => None,
    }
}

pub fn swap_addresses(packet: &mut [u8], info: &PacketInfo) {
    if info.is_v6 {
        let (a, b) = packet[8..40].split_at_mut(16);
        a.swap_with_slice(b);
    } else {
        let (a, b) = packet[12..20].split_at_mut(4);
        a.swap_with_slice(b);
    }
}

pub fn set_source(packet: &mut [u8], info: &PacketInfo, address: Ip) {
    if info.is_v6 {
        address.write_v6(&mut packet[8..]);
    } else {
        address.write_v4(&mut packet[12..]);
    }
}

pub fn set_destination(packet: &mut [u8], info: &PacketInfo, address: Ip) {
    if info.is_v6 {
        address.write_v6(&mut packet[24..]);
    } else {
        address.write_v4(&mut packet[16..]);
    }
}

pub fn set_source_port(packet: &mut [u8], info: &PacketInfo, port: u16) {
    put16(packet, info.transport_offset, port);
}

pub fn set_destination_port(packet: &mut [u8], info: &PacketInfo, port: u16) {
    put16(packet, info.transport_offset + 2, port);
}

/// Recomputes the IPv4 header checksum and the TCP/UDP checksum.
pub fn update_checksums(packet: &mut [u8], info: &PacketInfo) {
    if !info.is_v6 {
        packet[10] = 0;
        packet[11] = 0;
        let c = fold(sum(&packet[..info.ip_header_len], 0));
        put16(packet, 10, c);
    }
    let at = if info.protocol == PROTO_TCP { info.transport_offset + 16 } else { info.transport_offset + 6 };
    packet[at] = 0;
    packet[at + 1] = 0;
    let mut c = transport_checksum(packet, info);
    if info.protocol == PROTO_UDP && c == 0 {
        c = 0xFFFF;
    }
    put16(packet, at, c);
}

/// True when the IPv4 header checksum (if any) and the transport checksum are valid.
pub fn verify_checksums(packet: &[u8], info: &PacketInfo) -> bool {
    if !info.is_v6 && fold(sum(&packet[..info.ip_header_len], 0)) != 0 {
        return false;
    }
    transport_checksum(packet, info) == 0
}

/// One's complement checksum over pseudo header + segment (including the current checksum field).
pub fn transport_checksum(packet: &[u8], info: &PacketInfo) -> u16 {
    let segment_len = info.total_len - info.transport_offset;
    let mut s: u64 = if info.is_v6 {
        sum(&packet[8..40], 0) + (segment_len >> 16) as u64 + (segment_len & 0xFFFF) as u64 + info.protocol as u64
    } else {
        sum(&packet[12..20], 0) + info.protocol as u64 + segment_len as u64
    };
    s = sum(&packet[info.transport_offset..info.total_len], s);
    fold(s)
}

/// Builds an IPv4 or IPv6 UDP packet with checksums. Returns `None` when the families differ or it doesn't fit.
pub fn build_udp(source: Ip, source_port: u16, target: Ip, target_port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    if source.is_v4() != target.is_v4() {
        return None;
    }
    let ip_header = if source.is_v4() { 20 } else { 40 };
    let udp_len = 8 + payload.len();
    let total = ip_header + udp_len;
    if total > 0xFFFF {
        return None;
    }
    let mut p = vec![0u8; total];
    if source.is_v4() {
        p[0] = 0x45;
        put16(&mut p, 2, total as u16);
        p[8] = 64;
        p[9] = PROTO_UDP;
        source.write_v4(&mut p[12..]);
        target.write_v4(&mut p[16..]);
    } else {
        p[0] = 0x60;
        put16(&mut p, 4, udp_len as u16);
        p[6] = PROTO_UDP;
        p[7] = 64;
        source.write_v6(&mut p[8..]);
        target.write_v6(&mut p[24..]);
    }
    put16(&mut p, ip_header, source_port);
    put16(&mut p, ip_header + 2, target_port);
    put16(&mut p, ip_header + 4, udp_len as u16);
    p[ip_header + 8..].copy_from_slice(payload);
    let info = parse(&p)?;
    update_checksums(&mut p, &info);
    Some(p)
}

/// Describes an IP fragment: IPv4 with MF set or a non-zero offset, or IPv6 with a fragment header.
pub fn fragment_info(packet: &[u8]) -> Option<FragmentInfo> {
    if packet.len() < 20 {
        return None;
    }
    match packet[0] >> 4 {
        4 => {
            let ihl = (packet[0] & 0x0F) as usize * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            let total = be16(packet, 2) as usize;
            let flags = be16(packet, 6);
            let more = flags & 0x2000 != 0;
            let offset = (flags & 0x1FFF) as usize * 8;
            if (!more && offset == 0) || total < ihl || total > packet.len() {
                return None;
            }
            Some(FragmentInfo {
                is_v6: false,
                source: Ip::from_slice_v4(&packet[12..16]),
                destination: Ip::from_slice_v4(&packet[16..20]),
                identification: be16(packet, 4) as u32,
                protocol: packet[9],
                offset,
                more_fragments: more,
                header_len: ihl,
                data_offset: ihl,
                data_len: total - ihl,
            })
        }
        6 if packet.len() >= 40 => {
            let total = 40 + be16(packet, 4) as usize;
            if total > packet.len() {
                return None;
            }
            let (next, offset) = skip_v6_extensions(packet, total)?;
            if next != 44 || offset + 8 > total {
                return None;
            }
            let offset_and_flags = be16(packet, offset + 2);
            Some(FragmentInfo {
                is_v6: true,
                source: Ip::from_slice_v6(&packet[8..24]),
                destination: Ip::from_slice_v6(&packet[24..40]),
                identification: be32(packet, offset + 4),
                protocol: packet[offset],
                offset: (offset_and_flags >> 3) as usize * 8,
                more_fragments: offset_and_flags & 1 != 0,
                header_len: 40,
                data_offset: offset + 8,
                data_len: total - (offset + 8),
            })
        }
        _ => None,
    }
}

/// The RST the application's stack accepts for an established connection seen in `segment` (an outbound packet of
/// it): addresses and ports swapped, sequence = the segment's ACK number. `None` without an ACK to build from.
pub fn tcp_reset_for_segment(segment: &[u8], info: &PacketInfo) -> Option<Vec<u8>> {
    if !info.is_ack() {
        return None;
    }
    let ack_number = be32(segment, info.transport_offset + 8);
    Some(build_reset(info, ack_number, 0, TCP_RST))
}

/// The RST+ACK a remote host would send in reply to `syn` (addresses and ports swapped). Fails blocked connections
/// immediately instead of letting them time out.
pub fn tcp_reset_for_syn(syn: &[u8], info: &PacketInfo) -> Vec<u8> {
    let sequence = be32(syn, info.transport_offset + 4);
    let ack = sequence.wrapping_add(1).wrapping_add(info.payload_len as u32);
    build_reset(info, 0, ack, TCP_RST | TCP_ACK)
}

fn build_reset(info: &PacketInfo, sequence: u32, ack: u32, flags: u8) -> Vec<u8> {
    let ip_header = if info.is_v6 { 40 } else { 20 };
    let total = ip_header + 20;
    let mut p = vec![0u8; total];
    if info.is_v6 {
        p[0] = 0x60;
        put16(&mut p, 4, 20);
        p[6] = PROTO_TCP;
        p[7] = 64;
        info.destination.write_v6(&mut p[8..]);
        info.source.write_v6(&mut p[24..]);
    } else {
        p[0] = 0x45;
        put16(&mut p, 2, total as u16);
        p[8] = 64;
        p[9] = PROTO_TCP;
        info.destination.write_v4(&mut p[12..]);
        info.source.write_v4(&mut p[16..]);
    }
    put16(&mut p, ip_header, info.destination_port);
    put16(&mut p, ip_header + 2, info.source_port);
    put32(&mut p, ip_header + 4, sequence);
    put32(&mut p, ip_header + 8, ack);
    p[ip_header + 12] = 0x50;
    p[ip_header + 13] = flags;
    let rst = parse(&p).expect("built RST parses");
    update_checksums(&mut p, &rst);
    p
}

fn sum(data: &[u8], mut s: u64) -> u64 {
    let (pairs, rest) = data.as_chunks::<2>();
    for c in pairs {
        s += u16::from_be_bytes(*c) as u64;
    }
    if let [last] = rest {
        s += (*last as u64) << 8;
    }
    s
}

fn fold(mut s: u64) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    !(s as u16)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn tcp_packet(src: &str, sport: u16, dst: &str, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let s: Ip = src.parse().unwrap();
        let d: Ip = dst.parse().unwrap();
        let ip_header = if s.is_v4() { 20 } else { 40 };
        let total = ip_header + 20 + payload.len();
        let mut p = vec![0u8; total];
        if s.is_v4() {
            p[0] = 0x45;
            put16(&mut p, 2, total as u16);
            p[8] = 64;
            p[9] = PROTO_TCP;
            s.write_v4(&mut p[12..]);
            d.write_v4(&mut p[16..]);
        } else {
            p[0] = 0x60;
            put16(&mut p, 4, (20 + payload.len()) as u16);
            p[6] = PROTO_TCP;
            p[7] = 64;
            s.write_v6(&mut p[8..]);
            d.write_v6(&mut p[24..]);
        }
        put16(&mut p, ip_header, sport);
        put16(&mut p, ip_header + 2, dport);
        put32(&mut p, ip_header + 4, 1000);
        put32(&mut p, ip_header + 8, 5000);
        p[ip_header + 12] = 0x50;
        p[ip_header + 13] = flags;
        p[ip_header + 20..].copy_from_slice(payload);
        let info = parse(&p).unwrap();
        update_checksums(&mut p, &info);
        p
    }

    #[test]
    fn tcp_v4_parse_rewrite_checksum() {
        let mut p = tcp_packet("192.168.1.20", 50000, "203.0.113.5", 443, TCP_SYN, b"");
        let info = parse(&p).unwrap();
        assert!(info.is_tcp() && info.is_syn() && !info.is_ack());
        assert_eq!(info.source.to_string(), "192.168.1.20");
        assert_eq!(info.destination_port, 443);
        assert!(verify_checksums(&p, &info));

        swap_addresses(&mut p, &info);
        set_destination_port(&mut p, &info, 34010);
        let info2 = parse(&p).unwrap();
        assert_eq!(info2.destination.to_string(), "192.168.1.20");
        assert!(!verify_checksums(&p, &info2), "stale checksum");
        update_checksums(&mut p, &info2);
        assert!(verify_checksums(&p, &info2));
        assert_eq!(info2.destination_port, 34010);
    }

    #[test]
    fn udp_build_v4_and_v6() {
        let p = build_udp("10.0.0.1".parse().unwrap(), 53, "10.0.0.2".parse().unwrap(), 5353, b"hello").unwrap();
        let info = parse(&p).unwrap();
        assert!(info.is_udp());
        assert_eq!(&p[info.payload_offset..info.payload_offset + info.payload_len], b"hello");
        assert!(verify_checksums(&p, &info));

        let p6 = build_udp("2001:db8::1".parse().unwrap(), 1, "2001:db8::2".parse().unwrap(), 2, b"x").unwrap();
        let info6 = parse(&p6).unwrap();
        assert!(info6.is_v6 && info6.payload_len == 1);
        assert!(verify_checksums(&p6, &info6));
        assert!(build_udp("10.0.0.1".parse().unwrap(), 1, "::1".parse().unwrap(), 2, b"").is_none());
    }

    #[test]
    fn v6_extension_headers_are_followed() {
        // hop-by-hop options header (8 bytes) in front of TCP
        let base = tcp_packet("2001:db8::1", 1234, "2001:db8::2", 80, TCP_SYN, b"");
        let mut p = base[..40].to_vec();
        p[6] = 0; // next = hop-by-hop
        put16(&mut p, 4, 28);
        p.extend_from_slice(&[PROTO_TCP, 0, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(&base[40..]);
        let info = parse(&p).unwrap();
        assert_eq!(info.transport_offset, 48);
        assert_eq!(info.destination_port, 80);
    }

    #[test]
    fn resets() {
        let syn = tcp_packet("192.168.1.20", 50000, "203.0.113.5", 443, TCP_SYN, b"");
        let info = parse(&syn).unwrap();
        let rst = tcp_reset_for_syn(&syn, &info);
        let r = parse(&rst).unwrap();
        assert!(r.is_rst() && r.is_ack());
        assert_eq!(r.source.to_string(), "203.0.113.5");
        assert_eq!(r.destination_port, 50000);
        assert_eq!(be32(&rst, 28), 1001);
        assert!(verify_checksums(&rst, &r));

        let seg = tcp_packet("192.168.1.20", 50000, "203.0.113.5", 443, TCP_ACK, b"data");
        let si = parse(&seg).unwrap();
        let rst2 = tcp_reset_for_segment(&seg, &si).unwrap();
        let r2 = parse(&rst2).unwrap();
        assert!(r2.is_rst() && !r2.is_ack());
        assert_eq!(be32(&rst2, 24), 5000, "sequence = their ack");
        assert!(tcp_reset_for_segment(&syn, &info).is_none());
    }

    #[test]
    fn fragments_detected() {
        let mut p = tcp_packet("10.0.0.1", 1, "10.0.0.2", 2, TCP_ACK, &[0u8; 40]);
        assert!(fragment_info(&p).is_none());
        put16(&mut p, 6, 0x2000); // MF
        put16(&mut p, 4, 77);
        assert!(parse(&p).is_none());
        let f = fragment_info(&p).unwrap();
        assert!(f.more_fragments && f.offset == 0 && f.identification == 77 && f.data_len == 60);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Reference vectors shared with the C# self-tests.
    #[test]
    fn reference_vectors() {
        let p = build_udp("192.168.1.10".parse().unwrap(), 5353, "8.8.8.8".parse().unwrap(), 53, b"hello").unwrap();
        assert_eq!(p.len(), 33);
        assert_eq!((p[10], p[11], p[26], p[27]), (0xA9, 0x0A, 0xD5, 0x21));
        let p6 = build_udp("2001:db8::1".parse().unwrap(), 1234, "2001:db8::2".parse().unwrap(), 53, b"hi").unwrap();
        assert_eq!(p6.len(), 50);
        assert_eq!((p6[46], p6[47]), (0x36, 0xF5));

        let mut syn = hex("45000028123440008006a8bf0a0000025db8d822c35001bb01020304000000005002faf0ac030000");
        let info = parse(&syn).unwrap();
        assert!(verify_checksums(&syn, &info));
        let rst = tcp_reset_for_syn(&syn, &info);
        assert_eq!((rst[28], rst[31]), (0x01, 0x05), "ack = seq + 1");
        swap_addresses(&mut syn, &info);
        set_destination_port(&mut syn, &info, 34010);
        update_checksums(&mut syn, &info);
        assert_eq!(to_hex(&syn), "45000028123440008006a8bf5db8d8220a000002c35084da01020304000000005002faf028e40000");
        let reflected = parse(&syn).unwrap();
        assert_eq!(
            (info.source, info.destination, info.source_port),
            (reflected.destination, reflected.source, reflected.source_port)
        );

        let mut seg = hex("45000028123440008006a8bf0a0000025db8d822c35001bb010203040a0b0c0d5010faf000000000");
        let si = parse(&seg).unwrap();
        update_checksums(&mut seg, &si);
        let r = tcp_reset_for_segment(&seg, &si).unwrap();
        assert_eq!(to_hex(&r[24..28]), "0a0b0c0d");
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45; 19]).is_none());
        let mut p = tcp_packet("10.0.0.1", 1, "10.0.0.2", 2, TCP_ACK, b"");
        put16(&mut p, 2, 2000);
        assert!(parse(&p).is_none(), "total length beyond buffer");
    }
}
