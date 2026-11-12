//! Fake-IP DNS: host names get addresses from a reserved IPv4 range (default 198.18.0.0/15) so a connection to
//! one can be sent to the proxy by name. Plus the reverse cache built from sniffed DNS answers.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::clock::now_ms;
use crate::net::{normalize_host, Cidr, Ip};

struct PoolState {
    by_host: HashMap<String, u32>,
    by_slot: Vec<Option<String>>,
    next: u32,
}

/// Round-robin allocation; when the range is exhausted the oldest slot is recycled.
pub struct FakeIpPool {
    range: Cidr,
    base: u32,
    size: u32,
    state: Mutex<PoolState>,
}

impl FakeIpPool {
    /// `None` unless `cidr` is an IPv4 network of /30 or larger.
    pub fn new(cidr: &str) -> Option<FakeIpPool> {
        let range = Cidr::parse(cidr)?;
        if !range.is_v4() || range.prefix_len() > 30 {
            return None;
        }
        let size = (1u64 << (32 - range.prefix_len())).min(1 << 20) as u32; // cap memory at ~1M slots
        Some(FakeIpPool {
            range,
            base: range.network().v4_value(),
            size,
            state: Mutex::new(PoolState { by_host: HashMap::new(), by_slot: vec![None; size as usize], next: 1 }),
        })
    }

    pub fn range(&self) -> Cidr {
        self.range
    }

    pub fn len(&self) -> usize {
        self.state.lock().unwrap().by_host.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, address: Ip) -> bool {
        self.range.contains(address)
    }

    pub fn get_or_allocate(&self, host: &str) -> Ip {
        let host = normalize_host(host);
        let mut s = self.state.lock().unwrap();
        if let Some(slot) = s.by_host.get(&host) {
            return Ip::v4_u32(self.base + slot);
        }
        let slot = s.next;
        s.next += 1;
        if s.next >= self.size - 1 {
            s.next = 1; // skip network (0) and broadcast (size-1)
        }
        if let Some(previous) = s.by_slot[slot as usize].take() {
            s.by_host.remove(&previous);
        }
        s.by_slot[slot as usize] = Some(host.clone());
        s.by_host.insert(host, slot);
        Ip::v4_u32(self.base + slot)
    }

    pub fn host_for(&self, address: Ip) -> Option<String> {
        if !self.range.contains(address) {
            return None;
        }
        let slot = address.v4_value().wrapping_sub(self.base);
        if slot >= self.size {
            return None;
        }
        self.state.lock().unwrap().by_slot[slot as usize].clone()
    }
}

const MAX_CACHE: usize = 100_000;
const MAX_NAMES: usize = 8;

/// Reverse DNS cache (address to names) built from sniffed answers. Rules match destinations by name through it.
#[derive(Default)]
pub struct DnsCache {
    entries: Mutex<HashMap<Ip, (Vec<String>, u64)>>,
}

impl DnsCache {
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn add(&self, address: Ip, name: &str, ttl_seconds: u32) {
        self.add_at(address, name, ttl_seconds, now_ms());
    }

    pub fn add_at(&self, address: Ip, name: &str, ttl_seconds: u32, now: u64) {
        if name.is_empty() || address.is_unspecified() {
            return;
        }
        let expires = now + (ttl_seconds as u64).clamp(120, 3600) * 1000;
        let mut map = self.entries.lock().unwrap();
        let entry = map.entry(address).or_insert_with(|| (Vec::new(), 0));
        if !entry.0.iter().any(|n| n.eq_ignore_ascii_case(name)) {
            if entry.0.len() >= MAX_NAMES {
                entry.0.remove(0);
            }
            entry.0.push(name.to_string());
        }
        entry.1 = entry.1.max(expires);
        if map.len() > MAX_CACHE {
            map.retain(|_, (_, e)| *e >= now);
            if map.len() > MAX_CACHE {
                // still full of live entries: drop the ones expiring soonest
                let mut by_expiry: Vec<(Ip, u64)> = map.iter().map(|(k, (_, e))| (*k, *e)).collect();
                by_expiry.sort_by_key(|(_, e)| *e);
                for (k, _) in by_expiry.into_iter().take(MAX_CACHE / 4) {
                    map.remove(&k);
                }
            }
        }
    }

    /// Stale names are still returned: long-lived connections outlive TTLs and a hint beats nothing.
    pub fn names(&self, address: Ip) -> Option<Vec<String>> {
        self.entries.lock().unwrap().get(&address).map(|(n, _)| n.clone())
    }

    pub fn sweep(&self) {
        let now = now_ms();
        self.entries.lock().unwrap().retain(|_, (_, e)| *e >= now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_ips() {
        let pool = FakeIpPool::new("198.18.0.0/15").unwrap();
        let a = pool.get_or_allocate("World.Realm.Example.");
        assert!(pool.contains(a));
        assert_eq!(a.to_string(), "198.18.0.1");
        assert_eq!(pool.get_or_allocate("world.realm.example"), a, "same name, same address");
        assert_eq!(pool.host_for(a).as_deref(), Some("world.realm.example"));
        assert!(pool.host_for("198.18.0.99".parse().unwrap()).is_none());
        assert!(pool.host_for("8.8.8.8".parse().unwrap()).is_none());
        assert!(FakeIpPool::new("2001:db8::/64").is_none());
        assert!(FakeIpPool::new("10.0.0.0/31").is_none());
    }

    #[test]
    fn fake_ip_recycles() {
        let pool = FakeIpPool::new("10.0.0.0/30").unwrap(); // usable slots: 1, 2 (3 is broadcast)
        let a = pool.get_or_allocate("a.example");
        let _b = pool.get_or_allocate("b.example");
        let c = pool.get_or_allocate("c.example");
        assert_eq!(a, c, "oldest slot reused");
        assert!(pool.host_for(a).as_deref() == Some("c.example"));
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn dns_cache() {
        let cache = DnsCache::default();
        let ip: Ip = "203.0.113.5".parse().unwrap();
        cache.add_at(ip, "a.example", 30, 0);
        cache.add_at(ip, "A.example", 30, 0);
        cache.add_at(ip, "b.example", 30, 0);
        assert_eq!(cache.names(ip).unwrap(), vec!["a.example", "b.example"]);
        for i in 0..10 {
            cache.add_at(ip, &format!("n{i}.example"), 30, 0);
        }
        assert_eq!(cache.names(ip).unwrap().len(), MAX_NAMES);
        cache.add_at(Ip::UNSPECIFIED_V4, "x", 30, 0);
        assert_eq!(cache.len(), 1);
    }
}
