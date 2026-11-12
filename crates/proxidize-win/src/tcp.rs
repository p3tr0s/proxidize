//! Diverts outbound TCP. New connections are matched against the rules; redirected flows are reflected to the
//! local relay port (addresses swapped, re-injected as inbound) and the relay's replies are reflected back, so the
//! program believes it talks to its original destination.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use proxidize_core::clock::now_ms;
use proxidize_core::config::RuleAction;
use proxidize_core::net::Ip;
use proxidize_core::packet::{self, PacketInfo};
use proxidize_core::relay::{NatEntry, NatKey};
use proxidize_core::rules::Protocol;

use crate::context::{format_destination, EngineContext};
use crate::divert::{is_shutdown_error, Address, Divert, MTU_MAX};

pub const FILTER: &str = "outbound and !loopback and tcp";
pub const PRIORITY: i16 = 0;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    local: Ip,
    local_port: u16,
    remote: Ip,
    remote_port: u16,
}

impl FlowKey {
    fn of(info: &PacketInfo) -> FlowKey {
        FlowKey { local: info.source, local_port: info.source_port, remote: info.destination, remote_port: info.destination_port }
    }
}

struct Inner {
    ctx: Arc<EngineContext>,
    handle: Arc<dyn Divert>,
    allowed: Mutex<HashMap<FlowKey, u64>>,
    killed: Mutex<HashMap<FlowKey, u64>>,
    unknown_until: Mutex<HashMap<FlowKey, u64>>,
    dropped: AtomicU64,
    stopping: AtomicBool,
}

pub struct TcpRedirector {
    inner: Arc<Inner>,
    pending: Option<SyncSender<(Vec<u8>, Address)>>,
    threads: Vec<JoinHandle<()>>,
}

impl TcpRedirector {
    pub fn start(ctx: Arc<EngineContext>, handle: Arc<dyn Divert>) -> TcpRedirector {
        handle.set_queue(8192, 8 * 1024 * 1024);
        let inner = Arc::new(Inner {
            ctx,
            handle,
            allowed: Mutex::default(),
            killed: Mutex::default(),
            unknown_until: Mutex::default(),
            dropped: AtomicU64::new(0),
            stopping: AtomicBool::new(false),
        });
        let (tx, rx) = sync_channel::<(Vec<u8>, Address)>(4096);
        let capture = {
            let inner = inner.clone();
            let tx = tx.clone();
            std::thread::Builder::new().name("proxidize tcp capture".into()).spawn(move || inner.capture_loop(tx)).unwrap()
        };
        let deferred = {
            let inner = inner.clone();
            std::thread::Builder::new().name("proxidize tcp deferred syn".into()).spawn(move || inner.deferred_loop(rx)).unwrap()
        };
        TcpRedirector { inner, pending: Some(tx), threads: vec![capture, deferred] }
    }

    /// Packets dropped by strict mode (unknown owner, unparseable, errors, pre-existing proxied flows).
    pub fn dropped(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }

    pub fn sweep(&self) {
        let now = now_ms();
        self.inner.allowed.lock().unwrap().retain(|_, t| now.saturating_sub(*t) <= 10 * 60_000);
        self.inner.unknown_until.lock().unwrap().retain(|_, until| now <= *until);
        self.inner.killed.lock().unwrap().retain(|_, t| now.saturating_sub(*t) <= 2 * 60_000);
    }
}

impl Drop for TcpRedirector {
    fn drop(&mut self) {
        self.inner.stopping.store(true, Ordering::Release);
        self.inner.handle.shutdown();
        self.pending.take(); // the capture thread holds the other sender; it exits on shutdown
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Inner {
    fn capture_loop(&self, pending: SyncSender<(Vec<u8>, Address)>) {
        let mut buffer = vec![0u8; MTU_MAX];
        let mut addr = Address::default();
        while !self.stopping.load(Ordering::Acquire) {
            let len = match self.handle.recv(&mut buffer, &mut addr) {
                Ok(n) => n,
                Err(code) if self.stopping.load(Ordering::Acquire) || is_shutdown_error(code) => break,
                Err(code) => {
                    self.ctx.log.debug(format!("TCP capture receive error {code}"));
                    continue;
                }
            };
            let packet = &mut buffer[..len];
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.process(packet, &mut addr, &pending)));
            if result.is_err() {
                self.ctx.log.error("TCP redirector: internal error while handling a packet.");
                if self.ctx.strict() {
                    self.dropped.fetch_add(1, Ordering::Relaxed); // fail closed: TCP retransmits
                } else {
                    self.handle.send(&buffer[..len], &addr);
                }
            }
        }
    }

    fn process(&self, packet: &mut [u8], addr: &mut Address, pending: &SyncSender<(Vec<u8>, Address)>) {
        let Some(info) = packet::parse(packet).filter(|i| i.is_tcp()) else {
            // Fragmented TCP or an unknown header chain: Windows doesn't send these for normal connections and the
            // owner/ports can't be checked, so strict mode drops them.
            if self.ctx.strict() {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                self.ctx.log.debug("TCP: dropped a packet that could not be parsed (fragment or unknown IPv6 header).");
            } else {
                self.handle.send(packet, addr);
            }
            return;
        };
        let relay_port = self.ctx.relay_port();

        // Relay -> program: L:relay -> R:sp becomes R:dp -> L:sp (inbound).
        if info.source_port == relay_port {
            let key = NatKey { local: info.source, remote: info.destination, client_port: info.destination_port };
            if let Some(entry) = self.ctx.nat.get(&key) {
                packet::swap_addresses(packet, &info);
                packet::set_source_port(packet, &info, entry.original_port);
                addr.set_outbound(false);
                self.handle.reinject(packet, addr);
            } else {
                self.handle.send(packet, addr);
            }
            return;
        }

        let key = NatKey { local: info.source, remote: info.destination, client_port: info.source_port };
        let is_new = info.is_syn() && !info.is_ack();
        if let Some(entry) = self.ctx.nat.get(&key) {
            if entry.original_port == info.destination_port && (!is_new || !entry.is_closed()) {
                self.reflect(packet, &info, addr, relay_port);
                return;
            }
        }

        if self.ctx.is_proxy_endpoint(info.destination, info.destination_port) {
            self.handle.send(packet, addr);
            return;
        }

        if !is_new {
            // Not a connection set up here. In strict mode the owner is checked once per flow: flows a proxied
            // program opened before redirection started (or across an engine restart) are reset instead of being
            // allowed to continue directly.
            if !self.ctx.strict() || self.allow_untracked(packet, &info, addr) {
                self.handle.send(packet, addr);
            }
            return;
        }

        match self.ctx.processes.resolve_tcp(info.source, info.source_port, info.destination, info.destination_port, false) {
            Some(pid) => self.new_connection(packet, addr, Some(pid)),
            // The socket event may still be in flight: resolve on the deferred thread.
            None => match pending.try_send((packet.to_vec(), *addr)) {
                Ok(()) => {}
                Err(TrySendError::Full((mut p, mut a))) | Err(TrySendError::Disconnected((mut p, mut a))) => {
                    self.new_connection(&mut p, &mut a, None)
                }
            },
        }
    }

    fn deferred_loop(&self, rx: Receiver<(Vec<u8>, Address)>) {
        while let Ok((mut p, mut addr)) = rx.recv() {
            if self.stopping.load(Ordering::Acquire) {
                break;
            }
            let Some(info) = packet::parse(&p) else {
                self.handle.send(&p, &addr);
                continue;
            };
            let mut pid = None;
            for attempt in 0..15 {
                if self.stopping.load(Ordering::Acquire) {
                    break;
                }
                pid = self.ctx.processes.resolve_tcp(
                    info.source,
                    info.source_port,
                    info.destination,
                    info.destination_port,
                    attempt >= 1,
                );
                if pid.is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            if pid.is_none() {
                self.ctx.log.debug(format!(
                    "TCP {}:{} -> {}:{}: owning process not found{}",
                    info.source,
                    info.source_port,
                    info.destination,
                    info.destination_port,
                    if self.ctx.strict() { "; SYN dropped (the program will retry)" } else { "" }
                ));
            }
            self.new_connection(&mut p, &mut addr, pid);
        }
    }

    fn new_connection(&self, packet: &mut [u8], addr: &mut Address, pid: Option<u32>) {
        let Some(info) = packet::parse(packet) else {
            self.handle.send(packet, addr);
            return;
        };
        let nat_key = NatKey { local: info.source, remote: info.destination, client_port: info.source_port };
        if let Some(stale) = self.ctx.nat.get(&nat_key) {
            self.ctx.nat.remove(&stale); // port reuse: the old flow is gone
        }
        if pid == Some(self.ctx.self_pid) {
            self.handle.send(packet, addr);
            return;
        }
        let process = self.ctx.processes.details(pid);
        if self.ctx.must_drop_unidentified(&process) {
            // Unknown or exited owner: the rules can't be applied, so the SYN stays in. TCP retransmits it after
            // about a second, by when the owner is normally known.
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let (hostname, hostnames, is_fake) = self.ctx.names_for(info.destination);
        if is_fake && hostname.is_none() {
            self.ctx.log.warning(format!(
                "TCP {} -> {}:{}: unknown fake IP (stale DNS cache?), resetting.",
                process.name, info.destination, info.destination_port
            ));
            self.send_reset(packet, &info, addr);
            return;
        }

        let decision = self.ctx.evaluate(Protocol::Tcp, &process, info.destination, &hostnames, info.destination_port);
        let destination = format_destination(hostname.as_deref(), info.destination, info.destination_port);
        let flow = FlowKey::of(&info);
        self.allowed.lock().unwrap().remove(&flow);
        self.killed.lock().unwrap().remove(&flow);
        self.ctx.notify_routed(&process, &decision);

        match decision.action {
            RuleAction::Block => {
                self.ctx.tracker.record_event(
                    "TCP",
                    process.pid_u32(),
                    &process.name,
                    &destination,
                    RuleAction::Block,
                    &decision.route_name,
                    &decision.rule_name,
                    "Blocked",
                );
                self.ctx.log.debug(format!(
                    "TCP {}({}) -> {destination} blocked by '{}'",
                    process.name,
                    process.pid_i64(),
                    decision.rule_name
                ));
                self.send_reset(packet, &info, addr);
            }
            RuleAction::Direct if !is_fake => {
                if self.ctx.log_direct() {
                    self.ctx.tracker.record_event(
                        "TCP",
                        process.pid_u32(),
                        &process.name,
                        &destination,
                        RuleAction::Direct,
                        "Direct",
                        &decision.rule_name,
                        "Direct",
                    );
                }
                self.allowed.lock().unwrap().insert(flow, now_ms());
                self.handle.send(packet, addr);
            }
            _ => {
                let entry = NatEntry::new(
                    nat_key,
                    info.destination_port,
                    Arc::new(decision),
                    process.pid_u32(),
                    process.name.clone(),
                    process.path.clone(),
                    hostname,
                    is_fake,
                );
                self.ctx.nat.add(Arc::new(entry));
                self.reflect(packet, &info, addr, self.ctx.relay_port());
            }
        }
    }

    /// Strict-mode check for a packet of a flow without a NAT entry: true when it may go out unchanged. Owners are
    /// checked once per flow; flows whose program must not connect directly are reset.
    fn allow_untracked(&self, packet: &[u8], info: &PacketInfo, addr: &Address) -> bool {
        let key = FlowKey::of(info);
        if self.allowed.lock().unwrap().contains_key(&key) {
            return true;
        }
        if self.killed.lock().unwrap().contains_key(&key) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if info.is_syn() && info.is_ack() {
            self.allowed.lock().unwrap().insert(key, now_ms()); // SYN-ACK: accepted by a local server
            return true;
        }
        if self.unknown_until.lock().unwrap().get(&key).is_some_and(|until| now_ms() < *until) {
            self.dropped.fetch_add(1, Ordering::Relaxed); // looked up moments ago and not found
            return false;
        }
        if self.ctx.fake_ips.as_ref().is_some_and(|f| f.contains(info.destination)) {
            self.kill(packet, info, addr, key, "(fake IP)", "flow to a fake IP without a relay entry");
            return false;
        }

        let pid = self.ctx.processes.resolve_tcp(info.source, info.source_port, info.destination, info.destination_port, true);
        if pid == Some(self.ctx.self_pid)
            || self.ctx.processes.is_accepted_tcp(info.source_port, info.destination, info.destination_port)
        {
            self.allowed.lock().unwrap().insert(key, now_ms());
            return true;
        }
        let Some(pid) = pid.filter(|p| *p != 0) else {
            // Closed socket (TIME_WAIT rows have no owner) or not in the table: nothing legitimate needs this packet
            // badly enough to risk sending it from the real address.
            self.unknown_until.lock().unwrap().insert(key, now_ms() + 1000);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        self.unknown_until.lock().unwrap().remove(&key);

        let process = self.ctx.processes.details(Some(pid));
        if self.ctx.must_drop_unidentified(&process) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let (_, hostnames, _) = self.ctx.names_for(info.destination);
        let decision = self.ctx.evaluate(Protocol::Tcp, &process, info.destination, &hostnames, info.destination_port);
        if decision.action == RuleAction::Direct {
            self.allowed.lock().unwrap().insert(key, now_ms());
            return true;
        }
        self.kill(packet, info, addr, key, &process.name, &format!("opened before redirection ({})", decision.rule_name));
        false
    }

    fn kill(&self, packet: &[u8], info: &PacketInfo, addr: &Address, key: FlowKey, process: &str, reason: &str) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        self.killed.lock().unwrap().insert(key, now_ms());
        self.ctx.log.info(format!(
            "TCP {process} {}:{} -> {}:{}: reset, {reason}. The program will reconnect through its rule.",
            info.source, info.source_port, info.destination, info.destination_port
        ));
        if info.is_rst() {
            return;
        }
        if let Some(mut rst) = packet::tcp_reset_for_segment(packet, info) {
            let mut a = *addr;
            a.set_outbound(false);
            self.handle.reinject(&mut rst, &mut a);
        }
    }

    /// Program -> destination: L:sp -> R:dp becomes R:sp -> L:relay (inbound).
    fn reflect(&self, packet: &mut [u8], info: &PacketInfo, addr: &mut Address, relay_port: u16) {
        packet::swap_addresses(packet, info);
        packet::set_destination_port(packet, info, relay_port);
        addr.set_outbound(false);
        self.handle.reinject(packet, addr);
    }

    fn send_reset(&self, syn: &[u8], info: &PacketInfo, addr: &Address) {
        let mut rst = packet::tcp_reset_for_syn(syn, info);
        let mut a = *addr;
        a.set_outbound(false);
        self.handle.reinject(&mut rst, &mut a);
    }
}
