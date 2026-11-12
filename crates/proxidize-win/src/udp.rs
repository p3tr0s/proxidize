//! Diverts outbound UDP. Datagrams that match a Proxy rule leave the network path and are re-sent through a SOCKS5
//! UDP association owned by Proxidize; replies are injected back as inbound packets. UDP that a rule's route can't
//! carry is blocked, never sent directly.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use proxidize_core::clock::now_ms;
use proxidize_core::config::{ProxyServer, RuleAction};
use proxidize_core::fragments::Reassembler;
use proxidize_core::net::{Ip, Target};
use proxidize_core::packet::{self, FragmentInfo, PacketInfo};
use proxidize_core::proxy::{endpoint_of, socks5_handshake, udp as socks_udp, SOCKS5_UDP_ASSOCIATE};
use proxidize_core::relay::ConnectionRecord;
use proxidize_core::rules::{Decision, Protocol};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::context::{format_destination, EngineContext};
use crate::divert::{is_shutdown_error, Address, Divert, MTU_MAX};

pub const PRIORITY: i16 = -100;
/// DNS, DHCP, NetBIOS, DHCPv6, SSDP, mDNS, LLMNR: never redirected.
pub const EXCLUDED_PORTS: [u16; 10] = [53, 67, 68, 137, 138, 546, 547, 1900, 5353, 5355];

fn udp_filter(resolver_port: u16) -> String {
    let exclusions: Vec<String> = EXCLUDED_PORTS.iter().map(|p| format!("udp.DstPort != {p}")).collect();
    format!("udp and udp.SrcPort != {resolver_port} and {}", exclusions.join(" and "))
}

/// IP fragments carry no UDP header after the first one, so they are captured too and reassembled; otherwise a
/// fragmented datagram from a proxied program would leave directly.
pub fn filter_with_fragments(resolver_port: u16) -> String {
    format!(
        "outbound and !loopback and (({}) or (ip and (ip.MF or ip.FragOff != 0)) or (ipv6 and ipv6.NextHdr == 44))",
        udp_filter(resolver_port)
    )
}

pub fn filter_plain(resolver_port: u16) -> String {
    format!("outbound and !loopback and {}", udp_filter(resolver_port))
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    local: Ip,
    local_port: u16,
    remote: Ip,
    remote_port: u16,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct AssociationKey {
    client: Ip,
    client_port: u16,
    route: String,
}

struct Flow {
    decision: Decision,
    pid: Option<u32>,
    process_name: String,
    hostname: Option<String>,
    is_fake: bool,
    last_seen: AtomicU64,
    record: Mutex<Option<Arc<ConnectionRecord>>>,
}

struct Outbound {
    target: Target,
    visible: Ip,
    payload: Vec<u8>,
}

struct Association {
    key: AssociationKey,
    is_v6: bool,
    decision: Decision,
    template: Mutex<Address>,
    tx: mpsc::Sender<Outbound>,
    cancel: CancellationToken,
    last_activity: AtomicU64,
    disposed: AtomicBool,
    visible_by_host: Mutex<HashMap<(String, u16), Ip>>,
    visible_by_address: Mutex<HashMap<(Ip, u16), Ip>>,
}

impl Association {
    fn healthy(&self) -> bool {
        !self.disposed.load(Ordering::Acquire)
    }

    fn uses_proxy(&self) -> bool {
        !self.decision.route.is_empty()
    }

    fn dispose(&self) {
        if !self.disposed.swap(true, Ordering::AcqRel) {
            self.cancel.cancel();
        }
    }
}

struct Inner {
    ctx: Arc<EngineContext>,
    handle: Arc<dyn Divert>,
    flows: Mutex<HashMap<FlowKey, Arc<Flow>>>,
    associations: Mutex<HashMap<AssociationKey, Arc<Association>>>,
    own_ports: Mutex<HashSet<u16>>,
    warned_rules: Mutex<HashSet<String>>,
    failed_until: Mutex<HashMap<AssociationKey, u64>>,
    reassembler: Reassembler<Address>,
    stopping: AtomicBool,
    shutdown: CancellationToken,
}

pub struct UdpRedirector {
    inner: Arc<Inner>,
    thread: Option<JoinHandle<()>>,
}

impl UdpRedirector {
    pub fn start(ctx: Arc<EngineContext>, handle: Arc<dyn Divert>) -> UdpRedirector {
        handle.set_queue(8192, 4 * 1024 * 1024);
        let inner = Arc::new(Inner {
            ctx,
            handle,
            flows: Mutex::default(),
            associations: Mutex::default(),
            own_ports: Mutex::default(),
            warned_rules: Mutex::default(),
            failed_until: Mutex::default(),
            reassembler: Reassembler::default(),
            stopping: AtomicBool::new(false),
            shutdown: CancellationToken::new(),
        });
        let worker = inner.clone();
        let thread =
            std::thread::Builder::new().name("proxidize udp capture".into()).spawn(move || worker.capture_loop()).unwrap();
        UdpRedirector { inner, thread: Some(thread) }
    }

    pub fn sweep(&self) {
        let inner = &self.inner;
        let now = now_ms();
        let expired = inner.reassembler.expire(now, 5000);
        if expired > 0 {
            inner.ctx.log.debug(format!("UDP: dropped {expired} incomplete fragmented datagram(s)."));
        }
        let idle = inner.ctx.udp_idle_ms();
        let stale: Vec<Arc<Flow>> = {
            let mut flows = inner.flows.lock().unwrap();
            let keys: Vec<FlowKey> = flows
                .iter()
                .filter(|(_, f)| now.saturating_sub(f.last_seen.load(Ordering::Relaxed)) > idle)
                .map(|(k, _)| *k)
                .collect();
            keys.iter().filter_map(|k| flows.remove(k)).collect()
        };
        for flow in stale {
            if let Some(record) = flow.record.lock().unwrap().take() {
                inner.ctx.tracker.close(&record, None);
            }
        }
        let mut associations = inner.associations.lock().unwrap();
        associations.retain(|_, a| {
            let keep = a.healthy() && now.saturating_sub(a.last_activity.load(Ordering::Relaxed)) <= idle;
            if !keep {
                a.dispose();
            }
            keep
        });
        inner.failed_until.lock().unwrap().retain(|_, until| *until > now);
    }
}

impl Drop for UdpRedirector {
    fn drop(&mut self) {
        let inner = &self.inner;
        inner.stopping.store(true, Ordering::Release);
        inner.shutdown.cancel();
        inner.handle.shutdown();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        for (_, a) in inner.associations.lock().unwrap().drain() {
            a.dispose();
        }
        for (_, flow) in inner.flows.lock().unwrap().drain() {
            if let Some(record) = flow.record.lock().unwrap().take() {
                inner.ctx.tracker.close(&record, None);
            }
        }
    }
}

impl Inner {
    fn capture_loop(self: &Arc<Self>) {
        let mut buffer = vec![0u8; MTU_MAX];
        let mut addr = Address::default();
        while !self.stopping.load(Ordering::Acquire) {
            let len = match self.handle.recv(&mut buffer, &mut addr) {
                Ok(n) => n,
                Err(code) if self.stopping.load(Ordering::Acquire) || is_shutdown_error(code) => break,
                Err(_) => continue,
            };
            let packet = &buffer[..len];
            let consumed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.process(packet, &addr)));
            match consumed {
                Ok(true) => {}
                Ok(false) => {
                    self.handle.send(packet, &addr);
                }
                Err(_) => {
                    self.ctx.log.error("UDP redirector: internal error while handling a datagram.");
                    if !self.ctx.strict() {
                        self.handle.send(packet, &addr); // strict mode drops: UDP senders cope with loss
                    }
                }
            }
        }
    }

    /// True when the datagram was consumed (proxied or blocked).
    fn process(self: &Arc<Self>, packet: &[u8], addr: &Address) -> bool {
        let Some(info) = packet::parse(packet).filter(|i| i.is_udp()) else {
            if let Some(fragment) = packet::fragment_info(packet) {
                self.handle_fragment(packet, &fragment, *addr);
                return true;
            }
            return self.ctx.strict(); // unparseable: pass in normal mode, drop in strict mode
        };
        if self.own_ports.lock().unwrap().contains(&info.source_port)
            || info.destination.is_multicast_or_broadcast()
            || self.ctx.is_proxy_endpoint(info.destination, info.destination_port)
        {
            return false;
        }

        let key = FlowKey {
            local: info.source,
            local_port: info.source_port,
            remote: info.destination,
            remote_port: info.destination_port,
        };
        let now = now_ms();
        let existing = self.flows.lock().unwrap().get(&key).cloned();
        let flow = match existing {
            Some(f) => f,
            None => {
                let Some(f) = self.create_flow(&info) else { return false };
                let f = Arc::new(f);
                if f.pid.is_some() {
                    self.flows.lock().unwrap().insert(key, f.clone()); // unknown owner: decide again next time
                }
                f
            }
        };
        flow.last_seen.store(now, Ordering::Relaxed);
        match flow.decision.action {
            RuleAction::Direct if !flow.is_fake => return false,
            RuleAction::Block => return true,
            _ => {}
        }
        if self.ctx.guard.check(&flow.decision.route).is_some() {
            return true; // proxy flagged unsafe by the health check: drop, never send directly
        }

        let akey = AssociationKey { client: info.source, client_port: info.source_port, route: flow.decision.route_key() };
        {
            let mut failed = self.failed_until.lock().unwrap();
            if let Some(retry_at) = failed.get(&akey) {
                if *retry_at > now {
                    return true; // the proxy refused UDP moments ago: drop instead of hammering it
                }
                failed.remove(&akey);
            }
        }
        let association = {
            let mut map = self.associations.lock().unwrap();
            match map.get(&akey).filter(|a| a.healthy()) {
                Some(a) => a.clone(),
                None => {
                    let a = self.create_association(akey.clone(), &flow, *addr, info.is_v6);
                    map.insert(akey, a.clone());
                    a
                }
            }
        };
        *association.template.lock().unwrap() = *addr; // interface index changes after VPN / Wi-Fi reconnects

        let mut record = flow.record.lock().unwrap();
        if record.is_none() && association.healthy() {
            let destination = format_destination(flow.hostname.as_deref(), info.destination, info.destination_port);
            let r = self.ctx.tracker.open(
                "UDP",
                flow.pid.unwrap_or(0),
                &flow.process_name,
                &destination,
                flow.decision.action,
                &flow.decision.route_name,
                &flow.decision.rule_name,
            );
            r.set_state("Established");
            *record = Some(r);
        }
        let payload = packet[info.payload_offset..info.payload_offset + info.payload_len].to_vec();
        let n = payload.len() as u64;
        let target = match (&flow.hostname, flow.is_fake) {
            (Some(host), true) => Target::host(host, info.destination_port),
            _ => Target::Addr(info.destination, info.destination_port),
        };
        association.last_activity.store(now, Ordering::Relaxed);
        if association.healthy() && association.tx.try_send(Outbound { target, visible: info.destination, payload }).is_ok() {
            if let Some(r) = record.as_ref() {
                r.add_up(n);
            }
        }
        true
    }

    /// Holds fragments until the datagram is complete, then decides on the whole: proxied/blocked datagrams are
    /// consumed, allowed ones are re-sent as the original fragments. Incomplete datagrams expire.
    fn handle_fragment(self: &Arc<Self>, packet: &[u8], fragment: &FragmentInfo, addr: Address) {
        let Some(done) = self.reassembler.add(packet, fragment, addr, now_ms()) else { return };
        let template = done.fragments[0].1;
        let consumed = match packet::parse(&done.packet).filter(|i| i.is_udp()) {
            None => self.ctx.strict(), // reassembled TCP or other protocols: strict mode drops them
            Some(info) if info.source_port == self.ctx.resolver_port || EXCLUDED_PORTS.contains(&info.destination_port) => false,
            Some(_) => self.process(&done.packet, &template),
        };
        if !consumed {
            for (original, tag) in &done.fragments {
                self.handle.send(original, tag);
            }
        }
    }

    fn create_flow(&self, info: &PacketInfo) -> Option<Flow> {
        let mut pid = self.ctx.processes.resolve_udp(info.source_port, true);
        let mut attempt = 0;
        while pid.is_none() && attempt < 5 {
            // the bind event may still be in flight
            std::thread::sleep(Duration::from_millis(2));
            pid = self.ctx.processes.resolve_udp(info.source_port, attempt >= 2);
            attempt += 1;
        }
        if pid == Some(self.ctx.self_pid) {
            return None;
        }
        let process = self.ctx.processes.details(pid);
        let flow = |decision: Decision, pid: Option<u32>, hostname: Option<String>, is_fake: bool| Flow {
            decision,
            pid,
            process_name: process.name.clone(),
            hostname,
            is_fake,
            last_seen: AtomicU64::new(now_ms()),
            record: Mutex::new(None),
        };
        if self.ctx.must_drop_unidentified(&process) {
            // Unknown/exited owner: drop without caching the flow, so the next datagram is decided again.
            return Some(flow(Decision::block("Block (unknown program)", "Block"), None, None, false));
        }
        let (hostname, hostnames, is_fake) = self.ctx.names_for(info.destination);
        if is_fake && hostname.is_none() {
            return Some(flow(Decision::block("Block (unknown fake IP)", "Block"), pid, None, false));
        }
        let mut decision = self.ctx.evaluate(Protocol::Udp, &process, info.destination, &hostnames, info.destination_port);
        let destination = format_destination(hostname.as_deref(), info.destination, info.destination_port);
        self.ctx.notify_routed(&process, &decision);
        if decision.action == RuleAction::Proxy && !decision.supports_udp() {
            if self.warned_rules.lock().unwrap().insert(decision.rule_name.clone()) {
                self.ctx.log.warning(format!(
                    "Rule '{}': UDP needs a single SOCKS5 proxy; matching UDP traffic is blocked.",
                    decision.rule_name
                ));
            }
            decision = Decision {
                rule_id: decision.rule_id.clone(),
                ..Decision::block(decision.rule_name.clone(), "Block (UDP unsupported)")
            };
        }
        if decision.action == RuleAction::Block {
            self.ctx.tracker.record_event(
                "UDP",
                process.pid_u32(),
                &process.name,
                &destination,
                RuleAction::Block,
                &decision.route_name,
                &decision.rule_name,
                "Blocked",
            );
        } else if decision.action == RuleAction::Direct && !is_fake && pid.is_some() && self.ctx.log_direct() {
            self.ctx.tracker.record_event(
                "UDP",
                process.pid_u32(),
                &process.name,
                &destination,
                RuleAction::Direct,
                "Direct",
                &decision.rule_name,
                "Direct",
            );
        }
        Some(flow(decision, pid, hostname, is_fake))
    }

    fn create_association(
        self: &Arc<Self>,
        key: AssociationKey,
        flow: &Flow,
        template: Address,
        is_v6: bool,
    ) -> Arc<Association> {
        let (tx, rx) = mpsc::channel(1024);
        let association = Arc::new(Association {
            key,
            is_v6,
            decision: flow.decision.clone(),
            template: Mutex::new(template),
            tx,
            cancel: self.shutdown.child_token(),
            last_activity: AtomicU64::new(now_ms()),
            disposed: AtomicBool::new(false),
            visible_by_host: Mutex::default(),
            visible_by_address: Mutex::default(),
        });
        let me = self.clone();
        let a = association.clone();
        self.ctx.runtime.spawn(async move {
            let cancel = a.cancel.clone();
            let result = tokio::select! {
                _ = cancel.cancelled() => Ok(()),
                r = me.run_association(&a, rx) => r,
            };
            if let Err(message) = result {
                me.ctx.log.warning(format!(
                    "UDP association {} via {} failed: {message}",
                    Target::Addr(a.key.client, a.key.client_port),
                    a.decision.route_name
                ));
                me.failed_until.lock().unwrap().insert(a.key.clone(), now_ms() + 15_000);
            }
            a.dispose();
            me.associations.lock().unwrap().retain(|_, other| !Arc::ptr_eq(other, &a));
        });
        association
    }

    async fn run_association(self: &Arc<Self>, a: &Arc<Association>, mut rx: mpsc::Receiver<Outbound>) -> Result<(), String> {
        let socket = Arc::new(bind_dual().map_err(|e| e.to_string())?);
        let local = socket.local_addr().map_err(|e| e.to_string())?;
        let (port, dual) = (local.port(), local.is_ipv6());
        self.own_ports.lock().unwrap().insert(port);
        let _unregister = Unregister(self.clone(), port);

        let mut relay: Option<SocketAddr> = None;
        if let Some(proxy) = a.decision.route.first() {
            let (control, relay_ip, relay_port) = self.associate(proxy).await?;
            let endpoint = socket_addr(relay_ip, relay_port, dual);
            relay = Some(endpoint);
            self.ctx.log.debug(format!(
                "UDP association for {} via {}, relay {endpoint}",
                Target::Addr(a.key.client, a.key.client_port),
                proxy.name
            ));
            let watch = a.clone();
            let log = self.ctx.log.clone();
            tokio::spawn(async move {
                // The association lives as long as its control connection.
                let mut control = control;
                let mut buf = [0u8; 256];
                loop {
                    tokio::select! {
                        _ = watch.cancel.cancelled() => return,
                        n = control.read(&mut buf) => if !matches!(n, Ok(n) if n > 0) { break },
                    }
                }
                log.debug(format!(
                    "UDP association control connection closed for {}",
                    Target::Addr(watch.key.client, watch.key.client_port)
                ));
                watch.dispose();
            });
        }

        let receiver = {
            let me = self.clone();
            let a = a.clone();
            let socket = socket.clone();
            tokio::spawn(async move { me.receive_loop(&a, &socket).await })
        };
        let _abort = AbortOnDrop(receiver);

        let mut buffer = Vec::with_capacity(socks_udp::MAX_HEADER + 65536);
        while let Some(item) = rx.recv().await {
            let sent = match relay {
                Some(relay) => {
                    let mut target = item.target;
                    match &target {
                        Target::Host(host, port) if !a.decision.resolve_remotely => {
                            let Some(ip) = self.ctx.resolver.resolve(host).await else { continue };
                            a.visible_by_address.lock().unwrap().insert((ip, *port), item.visible);
                            target = Target::Addr(ip, *port);
                        }
                        Target::Host(host, port) => {
                            a.visible_by_host.lock().unwrap().insert((host.clone(), *port), item.visible);
                        }
                        Target::Addr(ip, port) => {
                            a.visible_by_address.lock().unwrap().insert((*ip, *port), item.visible);
                        }
                    }
                    buffer.clear();
                    if socks_udp::write_header(&mut buffer, &target).is_err() {
                        continue;
                    }
                    buffer.extend_from_slice(&item.payload);
                    socket.send_to(&buffer, relay).await
                }
                None => {
                    // Direct relay: only for fake-IP destinations with a Direct decision.
                    let (ip, port) = match &item.target {
                        Target::Addr(ip, port) => (*ip, *port),
                        Target::Host(host, port) => match self.ctx.resolver.resolve(host).await {
                            Some(ip) => (ip, *port),
                            None => continue,
                        },
                    };
                    a.visible_by_address.lock().unwrap().insert((ip, port), item.visible);
                    socket.send_to(&item.payload, socket_addr(ip, port, dual)).await
                }
            };
            match sent {
                Ok(_) => a.last_activity.store(now_ms(), Ordering::Relaxed),
                Err(e) => self.ctx.log.debug(format!("UDP send failed: {e}")),
            }
        }
        Ok(())
    }

    /// SOCKS5 UDP ASSOCIATE. Returns the control connection (kept open) and the relay endpoint.
    async fn associate(&self, proxy: &ProxyServer) -> Result<(tokio::net::TcpStream, Ip, u16), String> {
        let mut control = self.ctx.connector.connect(&[], &endpoint_of(proxy)).await.map_err(|e| e.0)?;
        let bound = tokio::time::timeout(
            self.ctx.connector.timeout(),
            socks5_handshake(&mut control, proxy, &Target::Addr(Ip::UNSPECIFIED_V4, 0), SOCKS5_UDP_ASSOCIATE),
        )
        .await
        .map_err(|_| format!("{}: timed out during UDP ASSOCIATE.", proxy.name))?
        .map_err(|e| e.0)?;
        let peer = control.peer_addr().map_err(|e| e.to_string())?;
        let (ip, port) = match bound {
            Target::Addr(ip, port) if !ip.is_unspecified() => (ip, port),
            Target::Addr(_, port) | Target::Host(_, port) => (Ip::from_std(peer.ip()), port),
        };
        Ok((control, ip, port))
    }

    async fn receive_loop(&self, a: &Arc<Association>, socket: &UdpSocket) {
        let mut buffer = vec![0u8; 65536 + socks_udp::MAX_HEADER];
        loop {
            let (n, from) = match socket.recv_from(&mut buffer).await {
                Ok(r) => r,
                // ICMP port unreachable surfaces as ConnectionReset on Windows UDP sockets.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                Err(_) => break,
            };
            let data = &buffer[..n];
            let (source, source_port, offset) = if a.uses_proxy() {
                let Some((origin, offset)) = socks_udp::parse(data) else { continue };
                let port = origin.port();
                let source = match &origin {
                    Target::Host(host, _) => match a.visible_by_host.lock().unwrap().get(&(host.clone(), port)) {
                        Some(ip) => *ip,
                        None => continue,
                    },
                    Target::Addr(ip, _) => {
                        let by_address = a.visible_by_address.lock().unwrap().get(&(*ip, port)).copied();
                        match by_address {
                            Some(visible) => visible,
                            None => {
                                // A reply from a real address to a host-name request: map it back to the fake IP used
                                // for that port.
                                let by_host = a.visible_by_host.lock().unwrap();
                                by_host.iter().find(|((_, p), _)| *p == port).map(|(_, v)| *v).unwrap_or(*ip)
                            }
                        }
                    }
                };
                (source, port, offset)
            } else {
                let remote = Ip::from_std(from.ip());
                let source = a.visible_by_address.lock().unwrap().get(&(remote, from.port())).copied().unwrap_or(remote);
                (source, from.port(), 0)
            };
            if source.is_v4() != a.key.client.is_v4() {
                continue; // an IPv6 reply can't reach an IPv4 socket (or the other way round)
            }
            let payload = &data[offset..];
            let Some(mut reply) = packet::build_udp(source, source_port, a.key.client, a.key.client_port, payload) else {
                continue;
            };
            if !self.stopping.load(Ordering::Acquire) {
                let mut addr = *a.template.lock().unwrap();
                addr.set_outbound(false);
                addr.set_ipv6(a.is_v6);
                self.handle.reinject(&mut reply, &mut addr);
            }
            let key = FlowKey { local: a.key.client, local_port: a.key.client_port, remote: source, remote_port: source_port };
            if let Some(flow) = self.flows.lock().unwrap().get(&key) {
                flow.last_seen.store(now_ms(), Ordering::Relaxed);
                if let Some(r) = flow.record.lock().unwrap().as_ref() {
                    r.add_down(payload.len() as u64);
                }
            }
            a.last_activity.store(now_ms(), Ordering::Relaxed);
        }
    }
}

struct Unregister(Arc<Inner>, u16);

impl Drop for Unregister {
    fn drop(&mut self) {
        self.0.own_ports.lock().unwrap().remove(&self.1);
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn bind_dual() -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
    let socket = match Socket::new(Domain::IPV6, Type::DGRAM, Some(SockProtocol::UDP)).and_then(|s| {
        s.set_only_v6(false)?;
        s.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).into())?;
        Ok(s)
    }) {
        Ok(s) => s,
        Err(_) => {
            let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(SockProtocol::UDP))?;
            s.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())?;
            s
        }
    };
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// Dual-stack sockets need IPv4 destinations as IPv4-mapped IPv6.
fn socket_addr(ip: Ip, port: u16, dual: bool) -> SocketAddr {
    match ip.to_std() {
        IpAddr::V4(v4) if dual => SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), port),
        other => SocketAddr::new(other, port),
    }
}
