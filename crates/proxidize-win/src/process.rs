//! Which program owns a connection. Primary source: WinDivert socket-layer events (connect/bind/accept/listen),
//! sniffed as they happen. Fallback: the system TCP/UDP owner tables (rate limited).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;

use proxidize_core::clock::now_ms;
use proxidize_core::log::LogHub;
use proxidize_core::net::Ip;

use crate::divert::{flags, is_shutdown_error, Address, Divert, DivertOpener, Event, Layer};

/// The owner of a connection. `alive` is false when the process had already exited (or is unknown).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessDetails {
    pub pid: Option<u32>,
    pub name: String,
    pub path: Option<String>,
    pub alive: bool,
}

impl ProcessDetails {
    pub fn unknown() -> ProcessDetails {
        ProcessDetails { pid: None, name: "(unknown)".into(), path: None, alive: false }
    }

    /// Pid for display and the rule engine (-1 when unknown).
    pub fn pid_i64(&self) -> i64 {
        self.pid.map(|p| p as i64).unwrap_or(-1)
    }

    pub fn pid_u32(&self) -> u32 {
        self.pid.unwrap_or(0)
    }
}

/// Owner lookups the redirectors need.
pub trait Processes: Send + Sync {
    /// Owner of an outbound TCP connection. Consults the system table only when `allow_refresh`.
    fn resolve_tcp(&self, local: Ip, local_port: u16, remote: Ip, remote_port: u16, allow_refresh: bool) -> Option<u32>;
    /// The connection was accepted by a local listener (inbound), not opened by the program.
    fn is_accepted_tcp(&self, local_port: u16, remote: Ip, remote_port: u16) -> bool;
    fn resolve_udp(&self, local_port: u16, allow_refresh: bool) -> Option<u32>;
    fn details(&self, pid: Option<u32>) -> ProcessDetails;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpRow {
    pub local: Ip,
    pub local_port: u16,
    pub remote: Ip,
    pub remote_port: u16,
    pub pid: u32,
    pub listening: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpRow {
    pub local: Ip,
    pub local_port: u16,
    pub pid: u32,
}

/// What the operating system provides.
pub trait SystemInfo: Send + Sync {
    fn tcp_table(&self) -> Vec<TcpRow>;
    fn udp_table(&self) -> Vec<UdpRow>;
    /// Image path and creation time of a live process; `None` when it can't be opened or has exited.
    fn identity(&self, pid: u32) -> Option<(Option<String>, u64)>;
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct TcpKey {
    local_port: u16,
    remote: Ip,
    remote_port: u16,
}

#[derive(Clone, Copy)]
struct Owner {
    pid: u32,
    endpoint: u64,
    at_ms: u64,
    accepted: bool,
}

#[derive(Default)]
struct Tables {
    tcp: HashMap<TcpKey, Owner>,
    udp: HashMap<u16, Owner>,
    listening: HashMap<u16, u32>,
}

pub struct ProcessResolver {
    system: Arc<dyn SystemInfo>,
    log: Arc<LogHub>,
    tables: RwLock<Tables>,
    processes: Mutex<HashMap<u32, (ProcessDetails, u64, u64)>>,
    refresh: Mutex<(u64, u64)>,
    last_trim: AtomicU64,
}

/// Runs the socket-event monitor thread; dropping it stops the thread.
pub struct SocketMonitor {
    handle: Option<Arc<dyn Divert>>,
    thread: Option<JoinHandle<()>>,
    stopping: Arc<AtomicBool>,
}

impl Drop for SocketMonitor {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(h) = &self.handle {
            h.shutdown();
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl ProcessResolver {
    pub fn new(system: Arc<dyn SystemInfo>, log: Arc<LogHub>) -> Arc<ProcessResolver> {
        Arc::new(ProcessResolver {
            system,
            log,
            tables: RwLock::default(),
            processes: Mutex::default(),
            refresh: Mutex::new((0, 0)),
            last_trim: AtomicU64::new(0),
        })
    }

    /// Starts sniffing socket events. Without them (driver refused the socket layer) the tables still work.
    pub fn start_monitor(self: &Arc<Self>, opener: &dyn DivertOpener) -> SocketMonitor {
        let stopping = Arc::new(AtomicBool::new(false));
        match opener.open("true", Layer::Socket, 1000, flags::SNIFF | flags::RECV_ONLY) {
            Ok(handle) => {
                let me = self.clone();
                let h = handle.clone();
                let stop = stopping.clone();
                let thread = std::thread::Builder::new()
                    .name("proxidize socket monitor".into())
                    .spawn(move || {
                        let mut empty = [0u8; 0];
                        let mut addr = Address::default();
                        while !stop.load(Ordering::Acquire) {
                            match h.recv(&mut empty, &mut addr) {
                                Ok(_) => me.on_socket_event(&addr),
                                Err(code) if stop.load(Ordering::Acquire) || is_shutdown_error(code) => break,
                                Err(_) => {}
                            }
                        }
                    })
                    .ok();
                SocketMonitor { handle: Some(handle), thread, stopping }
            }
            Err(e) => {
                self.log.warning(format!("Socket event monitor unavailable, using the system tables only: {e}"));
                SocketMonitor { handle: None, thread: None, stopping }
            }
        }
    }

    pub fn on_socket_event(&self, addr: &Address) {
        let now = now_ms();
        let pid = addr.process_id();
        let event = addr.event();
        let mut t = self.tables.write().unwrap();
        match addr.protocol() {
            6 => {
                let key =
                    TcpKey { local_port: addr.local_port(), remote: addr.remote_address(), remote_port: addr.remote_port() };
                match event {
                    Event::SocketConnect | Event::SocketAccept => {
                        t.tcp.insert(
                            key,
                            Owner { pid, endpoint: addr.endpoint_id(), at_ms: now, accepted: event == Event::SocketAccept },
                        );
                    }
                    Event::SocketListen => {
                        t.listening.insert(addr.local_port(), pid);
                    }
                    Event::SocketClose => {
                        if t.tcp.get(&key).is_some_and(|o| o.endpoint == addr.endpoint_id()) {
                            t.tcp.remove(&key);
                        }
                        if t.listening.get(&addr.local_port()) == Some(&pid) && addr.remote_port() == 0 {
                            t.listening.remove(&addr.local_port());
                        }
                    }
                    _ => {}
                }
            }
            17 => match event {
                Event::SocketBind | Event::SocketConnect => {
                    t.udp.insert(addr.local_port(), Owner { pid, endpoint: addr.endpoint_id(), at_ms: now, accepted: false });
                }
                Event::SocketClose if t.udp.get(&addr.local_port()).is_some_and(|o| o.endpoint == addr.endpoint_id()) => {
                    t.udp.remove(&addr.local_port());
                }
                _ => {}
            },
            _ => {}
        }
        drop(t);
        self.trim_if_large();
    }

    fn refresh_tcp(&self) {
        {
            let mut r = self.refresh.lock().unwrap();
            let now = now_ms();
            if now.saturating_sub(r.0) < 2 && r.0 != 0 {
                return;
            }
            r.0 = now;
        }
        let rows = self.system.tcp_table();
        let now = now_ms();
        let mut t = self.tables.write().unwrap();
        let mut listening = HashMap::new();
        for row in rows {
            if row.listening {
                listening.insert(row.local_port, row.pid);
            } else if row.remote_port != 0 {
                let key = TcpKey { local_port: row.local_port, remote: row.remote, remote_port: row.remote_port };
                t.tcp.entry(key).or_insert(Owner { pid: row.pid, endpoint: 0, at_ms: now, accepted: false });
            }
        }
        t.listening = listening;
        drop(t);
        self.trim_if_large();
    }

    fn refresh_udp(&self) {
        {
            let mut r = self.refresh.lock().unwrap();
            let now = now_ms();
            if now.saturating_sub(r.1) < 20 && r.1 != 0 {
                return;
            }
            r.1 = now;
        }
        let rows = self.system.udp_table();
        let now = now_ms();
        let mut t = self.tables.write().unwrap();
        for row in rows {
            // Table rows win over stale event entries (port reuse), but never over a fresher event.
            let replace = match t.udp.get(&row.local_port) {
                None => true,
                Some(o) => o.endpoint == 0 || now.saturating_sub(o.at_ms) > 5000,
            };
            if replace {
                t.udp.insert(row.local_port, Owner { pid: row.pid, endpoint: 0, at_ms: now, accepted: false });
            }
        }
    }

    fn trim_if_large(&self) {
        let now = now_ms();
        let last = self.last_trim.load(Ordering::Relaxed);
        if now.saturating_sub(last) < 10_000 || self.tables.read().unwrap().tcp.len() <= 50_000 {
            return;
        }
        self.last_trim.store(now, Ordering::Relaxed);
        self.tables.write().unwrap().tcp.retain(|_, o| now.saturating_sub(o.at_ms) <= 5 * 60_000);
    }
}

impl Processes for ProcessResolver {
    fn resolve_tcp(&self, _local: Ip, local_port: u16, remote: Ip, remote_port: u16, allow_refresh: bool) -> Option<u32> {
        let key = TcpKey { local_port, remote, remote_port };
        if let Some(o) = self.tables.read().unwrap().tcp.get(&key) {
            return Some(o.pid);
        }
        if !allow_refresh {
            return None;
        }
        self.refresh_tcp();
        self.tables.read().unwrap().tcp.get(&key).map(|o| o.pid)
    }

    fn is_accepted_tcp(&self, local_port: u16, remote: Ip, remote_port: u16) -> bool {
        let t = self.tables.read().unwrap();
        t.tcp.get(&TcpKey { local_port, remote, remote_port }).is_some_and(|o| o.accepted)
            || t.listening.contains_key(&local_port)
    }

    fn resolve_udp(&self, local_port: u16, allow_refresh: bool) -> Option<u32> {
        if let Some(o) = self.tables.read().unwrap().udp.get(&local_port) {
            return Some(o.pid);
        }
        if !allow_refresh {
            return None;
        }
        self.refresh_udp();
        self.tables.read().unwrap().udp.get(&local_port).map(|o| o.pid)
    }

    fn details(&self, pid: Option<u32>) -> ProcessDetails {
        let Some(pid) = pid else { return ProcessDetails::unknown() };
        match pid {
            0 => return ProcessDetails { pid: Some(0), name: "System Idle".into(), path: None, alive: true },
            4 => return ProcessDetails { pid: Some(4), name: "System".into(), path: None, alive: true },
            _ => {}
        }
        // Always re-check the identity: a cached entry is reused only while the creation time still matches, so a
        // recycled pid never inherits another program's route.
        let Some((path, created)) = self.system.identity(pid) else {
            return ProcessDetails { pid: Some(pid), name: format!("pid {pid} (exited)"), path: None, alive: false };
        };
        let now = now_ms();
        let mut cache = self.processes.lock().unwrap();
        if let Some((details, _, cached_created)) = cache.get(&pid) {
            let same_path = path.as_ref().is_none_or(|p| details.path.as_ref().is_some_and(|d| d.eq_ignore_ascii_case(p)));
            if created != 0 && *cached_created == created && same_path {
                return details.clone();
            }
        }
        let name =
            path.as_deref().and_then(|p| p.rsplit(['\\', '/']).next()).map(String::from).unwrap_or_else(|| format!("pid {pid}"));
        let details = ProcessDetails { pid: Some(pid), name, path, alive: true };
        cache.insert(pid, (details.clone(), now, created));
        if cache.len() > 4096 {
            cache.retain(|_, (_, at, _)| now.saturating_sub(*at) <= 60_000);
        }
        details
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A fake operating system: a table of live processes and connection rows.
    #[derive(Default)]
    pub struct FakeSystem {
        pub processes: Mutex<HashMap<u32, (String, u64)>>,
        pub tcp: Mutex<Vec<TcpRow>>,
        pub udp: Mutex<Vec<UdpRow>>,
    }

    impl FakeSystem {
        pub fn spawn(&self, pid: u32, path: &str) {
            self.processes.lock().unwrap().insert(pid, (path.into(), now_ms() + pid as u64));
        }
    }

    impl SystemInfo for FakeSystem {
        fn tcp_table(&self) -> Vec<TcpRow> {
            self.tcp.lock().unwrap().clone()
        }
        fn udp_table(&self) -> Vec<UdpRow> {
            self.udp.lock().unwrap().clone()
        }
        fn identity(&self, pid: u32) -> Option<(Option<String>, u64)> {
            self.processes.lock().unwrap().get(&pid).map(|(p, c)| (Some(p.clone()), *c))
        }
    }

    #[test]
    fn events_tables_and_recycled_pids() {
        let system = Arc::new(FakeSystem::default());
        system.spawn(100, r"F:\Wow1\Wow.exe");
        let r = ProcessResolver::new(system.clone(), Arc::new(LogHub::default()));
        let local: Ip = "10.0.0.2".parse().unwrap();
        let remote: Ip = "203.0.113.5".parse().unwrap();
        r.on_socket_event(&Address::socket_event(Event::SocketConnect, 100, 1, 6, local, 50000, remote, 8085));
        assert_eq!(r.resolve_tcp(local, 50000, remote, 8085, false), Some(100));
        r.on_socket_event(&Address::socket_event(Event::SocketClose, 100, 2, 6, local, 50000, remote, 8085));
        assert_eq!(r.resolve_tcp(local, 50000, remote, 8085, false), Some(100), "other endpoint's close ignored");
        r.on_socket_event(&Address::socket_event(Event::SocketClose, 100, 1, 6, local, 50000, remote, 8085));
        assert_eq!(r.resolve_tcp(local, 50000, remote, 8085, false), None);

        system.tcp.lock().unwrap().push(TcpRow {
            local,
            local_port: 50001,
            remote,
            remote_port: 443,
            pid: 100,
            listening: false,
        });
        assert_eq!(r.resolve_tcp(local, 50001, remote, 443, false), None, "no refresh allowed");
        assert_eq!(r.resolve_tcp(local, 50001, remote, 443, true), Some(100));

        let d = r.details(Some(100));
        assert_eq!((d.name.as_str(), d.alive), ("Wow.exe", true));
        // pid recycled by another program: new creation time, new path
        system.processes.lock().unwrap().insert(100, (r"C:\x\other.exe".into(), 1));
        assert_eq!(r.details(Some(100)).name, "other.exe");
        system.processes.lock().unwrap().clear();
        assert!(!r.details(Some(100)).alive);
        assert!(!r.details(None).alive);
        assert!(r.details(Some(4)).alive);

        r.on_socket_event(&Address::socket_event(Event::SocketBind, 100, 9, 17, local, 5353, Ip::UNSPECIFIED_V4, 0));
        assert_eq!(r.resolve_udp(5353, false), Some(100));
        r.on_socket_event(&Address::socket_event(Event::SocketAccept, 7, 3, 6, local, 80, remote, 1234));
        assert!(r.is_accepted_tcp(80, remote, 1234));
    }
}
