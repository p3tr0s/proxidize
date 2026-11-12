//! IPv4/IPv6 fragment reassembly. Programs can split UDP datagrams (and in theory TCP segments) into IP
//! fragments; only the first one carries ports, so without reassembly the later fragments would slip past the
//! rules. Overlapping or oversized datagrams are discarded and incomplete ones expire.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::net::Ip;
use crate::packet::FragmentInfo;

const MAX_DATAGRAM: usize = 0xFFFF;

/// A complete datagram rebuilt from fragments, plus the original fragments in arrival order.
#[derive(Debug)]
pub struct Reassembled<T> {
    /// Unfragmented IPv4/IPv6 packet (IPv6 extension headers dropped). May exceed the link MTU.
    pub packet: Vec<u8>,
    /// The fragments as captured, to re-send unchanged when the datagram is allowed out directly.
    pub fragments: Vec<(Vec<u8>, T)>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    is_v6: bool,
    source: Ip,
    destination: Ip,
    identification: u32,
    protocol: u8,
}

struct Pending<T> {
    created_ms: u64,
    header: Option<Vec<u8>>,
    total_len: Option<usize>,
    pieces: Vec<(usize, Vec<u8>)>,
    fragments: Vec<(Vec<u8>, T)>,
}

/// Thread-safe; `T` carries per-fragment capture metadata (the WinDivert address, for example).
pub struct Reassembler<T> {
    pending: Mutex<HashMap<Key, Pending<T>>>,
    max_pending: usize,
}

impl<T> Default for Reassembler<T> {
    fn default() -> Self {
        Reassembler::new(256)
    }
}

impl<T> Reassembler<T> {
    pub fn new(max_pending: usize) -> Self {
        Reassembler { pending: Mutex::new(HashMap::new()), max_pending: max_pending.max(1) }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// Adds a fragment. Returns the datagram once every fragment is present; otherwise `None` (held, or the
    /// datagram was discarded as invalid).
    pub fn add(&self, packet: &[u8], fragment: &FragmentInfo, tag: T, now_ms: u64) -> Option<Reassembled<T>> {
        let limit = if fragment.is_v6 { MAX_DATAGRAM } else { MAX_DATAGRAM - fragment.header_len };
        if fragment.offset + fragment.data_len > limit || fragment.data_offset + fragment.data_len > packet.len() {
            return None;
        }
        let key = Key {
            is_v6: fragment.is_v6,
            source: fragment.source,
            destination: fragment.destination,
            identification: fragment.identification,
            protocol: fragment.protocol,
        };
        let mut map = self.pending.lock().unwrap();
        if !map.contains_key(&key) && map.len() >= self.max_pending {
            if let Some(oldest) = map.iter().min_by_key(|(_, p)| p.created_ms).map(|(k, _)| *k) {
                map.remove(&oldest);
            }
        }
        let pending = map.entry(key).or_insert_with(|| Pending {
            created_ms: now_ms,
            header: None,
            total_len: None,
            pieces: Vec::new(),
            fragments: Vec::new(),
        });

        let start = fragment.offset;
        let stop = fragment.offset + fragment.data_len;
        if pending.pieces.iter().any(|(o, d)| start < o + d.len() && *o < stop) {
            map.remove(&key); // overlap or duplicate: never reassemble ambiguous data
            return None;
        }
        if fragment.offset == 0 {
            pending.header = Some(packet[..fragment.header_len].to_vec());
        }
        if !fragment.more_fragments {
            if pending.total_len.is_some_and(|t| t != stop) {
                map.remove(&key);
                return None;
            }
            pending.total_len = Some(stop);
        }
        pending.pieces.push((fragment.offset, packet[fragment.data_offset..fragment.data_offset + fragment.data_len].to_vec()));
        pending.fragments.push((packet.to_vec(), tag));

        let total = pending.total_len?;
        pending.header.as_ref()?;
        pending.pieces.sort_by_key(|(o, _)| *o);
        let mut covered = 0usize;
        for (offset, data) in &pending.pieces {
            if *offset > covered {
                return None; // gap: wait for more
            }
            covered += data.len();
        }
        if covered != total {
            if covered > total {
                map.remove(&key);
            }
            return None;
        }
        let done = map.remove(&key)?;
        let packet = build(fragment.is_v6, fragment.protocol, done.header.as_deref()?, &done.pieces, covered);
        Some(Reassembled { packet, fragments: done.fragments })
    }

    /// Drops datagrams older than `max_age_ms`. Returns how many were dropped.
    pub fn expire(&self, now_ms: u64, max_age_ms: u64) -> usize {
        let mut map = self.pending.lock().unwrap();
        let before = map.len();
        map.retain(|_, p| now_ms.saturating_sub(p.created_ms) <= max_age_ms);
        before - map.len()
    }
}

fn build(is_v6: bool, protocol: u8, header: &[u8], pieces: &[(usize, Vec<u8>)], data_len: usize) -> Vec<u8> {
    let header_len = if is_v6 { 40 } else { header.len() };
    let mut packet = Vec::with_capacity(header_len + data_len);
    packet.extend_from_slice(&header[..header_len]);
    for (_, data) in pieces {
        packet.extend_from_slice(data);
    }
    if is_v6 {
        packet[4..6].copy_from_slice(&(data_len as u16).to_be_bytes());
        packet[6] = protocol;
    } else {
        let total = (header_len + data_len).min(0xFFFF) as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[6] = 0;
        packet[7] = 0; // clear MF and offset
        packet[10] = 0;
        packet[11] = 0;
        let mut sum: u64 = packet[..header_len].as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c) as u64).sum();
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    }
    packet
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{build_udp, fragment_info, parse, verify_checksums};

    /// Splits an IPv4 packet into fragments with `chunk`-byte payloads (multiple of 8).
    fn split_v4(packet: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        let data = &packet[20..];
        let mut out = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + chunk).min(data.len());
            let mut f = packet[..20].to_vec();
            f.extend_from_slice(&data[offset..end]);
            let total = f.len() as u16;
            f[2..4].copy_from_slice(&total.to_be_bytes());
            let more = if end < data.len() { 0x2000 } else { 0 };
            f[6..8].copy_from_slice(&(more | (offset / 8) as u16).to_be_bytes());
            f[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
            out.push(f);
            offset = end;
        }
        out
    }

    #[test]
    fn reassembles_out_of_order() {
        let payload: Vec<u8> = (0..100u8).collect();
        let whole = build_udp("10.0.0.1".parse().unwrap(), 5000, "10.0.0.2".parse().unwrap(), 3074, &payload).unwrap();
        let mut frags = split_v4(&whole, 32);
        assert_eq!(frags.len(), 4);
        frags.swap(0, 3);
        let r: Reassembler<u32> = Reassembler::default();
        let mut result = None;
        for (i, f) in frags.iter().enumerate() {
            let info = fragment_info(f).unwrap();
            result = r.add(f, &info, i as u32, 0);
            if i < 3 {
                assert!(result.is_none());
            }
        }
        let done = result.unwrap();
        assert_eq!(done.fragments.len(), 4);
        let info = parse(&done.packet).unwrap();
        assert_eq!(info.destination_port, 3074);
        assert_eq!(&done.packet[info.payload_offset..], &payload[..]);
        assert!(verify_checksums(&done.packet, &info));
        assert_eq!(r.pending_count(), 0);
    }

    #[test]
    fn overlap_discards_and_expiry() {
        let whole = build_udp("10.0.0.1".parse().unwrap(), 1, "10.0.0.2".parse().unwrap(), 2, &[7u8; 64]).unwrap();
        let frags = split_v4(&whole, 32);
        let r: Reassembler<()> = Reassembler::default();
        let first = fragment_info(&frags[0]).unwrap();
        assert!(r.add(&frags[0], &first, (), 0).is_none());
        assert!(r.add(&frags[0], &first, (), 0).is_none(), "duplicate drops the datagram");
        assert_eq!(r.pending_count(), 0);

        assert!(r.add(&frags[0], &first, (), 0).is_none());
        assert_eq!(r.expire(10_000, 5_000), 1);
        assert_eq!(r.pending_count(), 0);
    }

    #[test]
    fn bounded() {
        let r: Reassembler<()> = Reassembler::new(2);
        for id in 0..5u16 {
            let whole = build_udp("10.0.0.1".parse().unwrap(), 1, "10.0.0.2".parse().unwrap(), 2, &[0u8; 64]).unwrap();
            let mut f = split_v4(&whole, 32).remove(0);
            f[4..6].copy_from_slice(&id.to_be_bytes());
            let info = fragment_info(&f).unwrap();
            r.add(&f, &info, (), id as u64);
        }
        assert_eq!(r.pending_count(), 2);
    }
}
