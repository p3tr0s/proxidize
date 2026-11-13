//! The TCP relay: redirected connections arrive here (the packet layer reflects each SYN back to us), get looked up
//! in the NAT table, connected through their route and piped both ways. Plus the bookkeeping around it: the NAT
//! table, the route guard (proxies that must not carry traffic right now) and the connection list for the UI.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use chrono::{DateTime, Local};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::clock::now_ms;
use crate::config::{ProxyServer, RuleAction};
use crate::log::LogHub;
use crate::net::{Ip, Target};
use crate::proxy::{Connector, ProxyError};
use crate::resolve::HostResolver;
use crate::rules::Decision;

// ---------------------------------------------------------------------------------------------------------------
// NAT

/// A redirected flow as the relay sees it. The program's SYN (L:sp to R:dp) is reflected so the relay accepts a
/// connection from R:sp on local address L; (L, R, sp) is visible on both sides.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NatKey {
    pub local: Ip,
    pub remote: Ip,
    pub client_port: u16,
}

const PENDING: u8 = 0;
const ACCEPTED: u8 = 1;
const CLOSED: u8 = 2;

#[derive(Debug)]
pub struct NatEntry {
    pub key: NatKey,
    pub original_port: u16,
    pub decision: Arc<Decision>,
    pub process_id: u32,
    pub process_name: String,
    pub process_path: Option<String>,
    pub hostname: Option<String>,
    pub is_fake_ip: bool,
    pub created_ms: u64,
    closed_ms: AtomicU64,
    state: AtomicU8,
}

impl NatEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: NatKey,
        original_port: u16,
        decision: Arc<Decision>,
        process_id: u32,
        process_name: String,
        process_path: Option<String>,
        hostname: Option<String>,
        is_fake_ip: bool,
    ) -> NatEntry {
        NatEntry {
            key,
            original_port,
            decision,
            process_id,
            process_name,
            process_path,
            hostname,
            is_fake_ip,
            created_ms: now_ms(),
            closed_ms: AtomicU64::new(0),
            state: AtomicU8::new(PENDING),
        }
    }

    /// The address the program connected to (may be a fake IP).
    pub fn original_address(&self) -> Ip {
        self.key.remote
    }

    pub fn is_accepted(&self) -> bool {
        self.state.load(Ordering::Acquire) >= ACCEPTED
    }

    pub fn is_closed(&self) -> bool {
        self.state.load(Ordering::Acquire) == CLOSED
    }

    pub fn mark_accepted(&self) {
        let _ = self.state.compare_exchange(PENDING, ACCEPTED, Ordering::AcqRel, Ordering::Acquire);
    }

    pub fn mark_closed(&self) {
        self.closed_ms.store(now_ms(), Ordering::Release);
        self.state.store(CLOSED, Ordering::Release);
    }

    /// `host:port` when the name is known, else the address.
    pub fn destination(&self) -> String {
        match &self.hostname {
            Some(h) => format!("{h}:{}", self.original_port),
            None => Target::Addr(self.original_address(), self.original_port).to_string(),
        }
    }
}

#[derive(Default)]
pub struct NatTable {
    entries: RwLock<HashMap<NatKey, Arc<NatEntry>>>,
}

impl NatTable {
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn add(&self, entry: Arc<NatEntry>) {
        self.entries.write().unwrap().insert(entry.key, entry);
    }

    pub fn get(&self, key: &NatKey) -> Option<Arc<NatEntry>> {
        self.entries.read().unwrap().get(key).cloned()
    }

    /// Removes `entry` only if it is still the one stored under its key.
    pub fn remove(&self, entry: &Arc<NatEntry>) {
        let mut map = self.entries.write().unwrap();
        if map.get(&entry.key).is_some_and(|e| Arc::ptr_eq(e, entry)) {
            map.remove(&entry.key);
        }
    }

    /// Drops closed flows after a grace period (late FIN/ACKs) and SYNs the relay never accepted.
    pub fn sweep(&self, closed_grace_ms: u64, pending_timeout_ms: u64) {
        let now = now_ms();
        self.entries.write().unwrap().retain(|_, e| {
            if e.is_closed() {
                now.saturating_sub(e.closed_ms.load(Ordering::Acquire)) <= closed_grace_ms
            } else {
                e.is_accepted() || now.saturating_sub(e.created_ms) <= pending_timeout_ms
            }
        });
    }

    pub fn clear(&self) {
        self.entries.write().unwrap().clear();
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Route guard

/// Proxies that must not carry traffic right now (the health check found their exit IP is your own, say).
/// Connections through them are refused; the block lifts when a later check is clean.
#[derive(Default)]
pub struct RouteGuard {
    blocked: RwLock<HashMap<String, String>>,
}

impl RouteGuard {
    pub fn len(&self) -> usize {
        self.blocked.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The reason the route can't be used, if any hop is blocked.
    pub fn check(&self, route: &[ProxyServer]) -> Option<String> {
        let map = self.blocked.read().unwrap();
        route.iter().find_map(|hop| map.get(&hop.id).map(|why| format!("{} is blocked: {why}", hop.name)))
    }

    pub fn is_blocked(&self, proxy_id: &str) -> bool {
        self.blocked.read().unwrap().contains_key(proxy_id)
    }

    /// Replaces the blocked set. Returns the ids that were not blocked before.
    pub fn set(&self, blocked: HashMap<String, String>) -> Vec<String> {
        let mut map = self.blocked.write().unwrap();
        let added = blocked.keys().filter(|k| !map.contains_key(*k)).cloned().collect();
        *map = blocked;
        added
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Connection list

#[derive(Debug)]
pub struct ConnectionRecord {
    pub id: u64,
    pub started: DateTime<Local>,
    pub protocol: &'static str,
    pub process_id: u32,
    pub process_name: String,
    pub destination: String,
    pub action: RuleAction,
    pub route_name: String,
    pub rule_name: String,
    ended: Mutex<Option<DateTime<Local>>>,
    state: Mutex<String>,
    error: Mutex<Option<String>>,
    up: AtomicU64,
    down: AtomicU64,
}

impl ConnectionRecord {
    pub fn state(&self) -> String {
        self.state.lock().unwrap().clone()
    }

    pub fn set_state(&self, state: &str) {
        *self.state.lock().unwrap() = state.to_string();
    }

    pub fn error(&self) -> Option<String> {
        self.error.lock().unwrap().clone()
    }

    pub fn set_error(&self, error: impl Into<String>) {
        *self.error.lock().unwrap() = Some(error.into());
    }

    pub fn ended(&self) -> Option<DateTime<Local>> {
        *self.ended.lock().unwrap()
    }

    pub fn bytes_up(&self) -> u64 {
        self.up.load(Ordering::Relaxed)
    }

    pub fn bytes_down(&self) -> u64 {
        self.down.load(Ordering::Relaxed)
    }

    pub fn add_up(&self, n: u64) {
        self.up.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_down(&self, n: u64) {
        self.down.fetch_add(n, Ordering::Relaxed);
    }
}

const CLOSED_CAPACITY: usize = 500;

/// Active and recently closed connections, for display.
#[derive(Default)]
pub struct ConnectionTracker {
    active: Mutex<HashMap<u64, Arc<ConnectionRecord>>>,
    closed: Mutex<VecDeque<Arc<ConnectionRecord>>>,
    next_id: AtomicU64,
}

impl ConnectionTracker {
    pub fn active_count(&self) -> usize {
        self.active.lock().unwrap().len()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &self,
        protocol: &'static str,
        process_id: u32,
        process_name: &str,
        destination: &str,
        action: RuleAction,
        route_name: &str,
        rule_name: &str,
    ) -> Arc<ConnectionRecord> {
        let record = Arc::new(ConnectionRecord {
            id: self.next_id.fetch_add(1, Ordering::Relaxed) + 1,
            started: Local::now(),
            protocol,
            process_id,
            process_name: process_name.to_string(),
            destination: destination.to_string(),
            action,
            route_name: route_name.to_string(),
            rule_name: rule_name.to_string(),
            ended: Mutex::new(None),
            state: Mutex::new("Connecting".into()),
            error: Mutex::new(None),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
        });
        self.active.lock().unwrap().insert(record.id, record.clone());
        record
    }

    pub fn close(&self, record: &Arc<ConnectionRecord>, state: Option<&str>) {
        if self.active.lock().unwrap().remove(&record.id).is_none() {
            return;
        }
        *record.ended.lock().unwrap() = Some(Local::now());
        let state = state.unwrap_or(if record.error().is_none() { "Closed" } else { "Failed" });
        record.set_state(state);
        let mut closed = self.closed.lock().unwrap();
        closed.push_back(record.clone());
        while closed.len() > CLOSED_CAPACITY {
            closed.pop_front();
        }
    }

    /// An instantaneous event (a blocked or direct connection).
    #[allow(clippy::too_many_arguments)]
    pub fn record_event(
        &self,
        protocol: &'static str,
        process_id: u32,
        process_name: &str,
        destination: &str,
        action: RuleAction,
        route_name: &str,
        rule_name: &str,
        state: &str,
    ) {
        let record = self.open(protocol, process_id, process_name, destination, action, route_name, rule_name);
        self.close(&record, Some(state));
    }

    /// Newest first.
    pub fn snapshot(&self, include_closed: bool) -> Vec<Arc<ConnectionRecord>> {
        let mut list: Vec<_> = self.active.lock().unwrap().values().cloned().collect();
        if include_closed {
            list.extend(self.closed.lock().unwrap().iter().cloned());
        }
        list.sort_by_key(|r| std::cmp::Reverse(r.id));
        list
    }

    pub fn clear_closed(&self) {
        self.closed.lock().unwrap().clear();
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Relay server

pub struct RelayDeps {
    pub nat: Arc<NatTable>,
    pub connector: Connector,
    pub resolver: Arc<dyn HostResolver>,
    pub tracker: Arc<ConnectionTracker>,
    pub log: Arc<LogHub>,
    pub guard: Arc<RouteGuard>,
}

struct Client {
    route: Vec<String>,
    reset: CancellationToken,
}

struct Inner {
    deps: RelayDeps,
    clients: Mutex<HashMap<u64, Client>>,
    next_client: AtomicU64,
    shutdown: CancellationToken,
}

/// Accepts reflected connections. Dropping it (or [`stop`](Self::stop)) stops accepting; open connections are
/// left alone unless [`abort_all`](Self::abort_all) is called first.
pub struct RelayServer {
    inner: Arc<Inner>,
    port: u16,
    accept: JoinHandle<()>,
}

#[derive(Debug)]
pub enum RelayStartError {
    PortInUse(u16),
    Io(std::io::Error),
}

impl std::fmt::Display for RelayStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayStartError::PortInUse(p) => write!(f, "Relay port {p} is already in use. Choose another port in Settings."),
            RelayStartError::Io(e) => write!(f, "Relay could not start: {e}"),
        }
    }
}

impl std::error::Error for RelayStartError {}

impl RelayServer {
    /// Must be called inside a tokio runtime. `bind = None` listens on every address (dual stack).
    pub fn start(port: u16, bind: Option<IpAddr>, deps: RelayDeps) -> Result<RelayServer, RelayStartError> {
        let listener = listen(port, bind).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                RelayStartError::PortInUse(port)
            } else {
                RelayStartError::Io(e)
            }
        })?;
        let port = listener.local_addr().map_err(RelayStartError::Io)?.port();
        let inner = Arc::new(Inner {
            deps,
            clients: Mutex::default(),
            next_client: AtomicU64::new(0),
            shutdown: CancellationToken::new(),
        });
        let accept = tokio::spawn(accept_loop(listener, inner.clone()));
        Ok(RelayServer { inner, port, accept })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Program connections currently relayed.
    pub fn active_clients(&self) -> usize {
        self.inner.clients.lock().unwrap().len()
    }

    /// Resets every relayed connection (RST, no FIN). Called while redirection is still active so the resets
    /// reach the programs as if sent by their destinations, and they drop the connections at once instead of
    /// retrying them later outside the proxy.
    pub fn abort_all(&self) -> usize {
        self.abort(|_| true)
    }

    /// Resets relayed connections whose route uses any of `proxy_ids`. Returns how many.
    pub fn abort_routes(&self, proxy_ids: &[String]) -> usize {
        if proxy_ids.is_empty() {
            return 0;
        }
        self.abort(|route| route.iter().any(|id| proxy_ids.contains(id)))
    }

    fn abort(&self, matches: impl Fn(&[String]) -> bool) -> usize {
        let clients = self.inner.clients.lock().unwrap();
        let mut count = 0;
        for client in clients.values().filter(|c| matches(&c.route)) {
            client.reset.cancel();
            count += 1;
        }
        count
    }

    pub fn stop(&self) {
        self.inner.shutdown.cancel();
        self.accept.abort();
    }
}

impl Drop for RelayServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn listen(port: u16, bind: Option<IpAddr>) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = match bind {
        Some(address) => {
            let s = Socket::new(Domain::for_address(SocketAddr::new(address, port)), Type::STREAM, Some(Protocol::TCP))?;
            s.bind(&SocketAddr::new(address, port).into())?;
            s
        }
        None => {
            let dual = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)).and_then(|s| {
                s.set_only_v6(false)?;
                Ok(s)
            });
            match dual {
                Ok(s) => {
                    s.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
                    s
                }
                Err(_) => {
                    let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                    s.bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())?;
                    s
                }
            }
        }
    };
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

async fn accept_loop(listener: TcpListener, inner: Arc<Inner>) {
    loop {
        tokio::select! {
            _ = inner.shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    tokio::spawn(handle_client(stream, inner.clone()));
                }
                Err(e) => {
                    inner.deps.log.debug(format!("Relay accept error: {e}"));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

fn reset_on_close(stream: &TcpStream) {
    let _ = socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO));
}

async fn handle_client(mut client: TcpStream, inner: Arc<Inner>) {
    let deps = &inner.deps;
    let (Ok(remote), Ok(local)) = (client.peer_addr(), client.local_addr()) else { return };
    let key = NatKey { local: Ip::from_std(local.ip()), remote: Ip::from_std(remote.ip()), client_port: remote.port() };
    let Some(entry) = deps.nat.get(&key) else {
        deps.log.debug(format!("Relay: rejected unexpected connection from {remote} (no NAT entry)."));
        return;
    };
    entry.mark_accepted();
    let _ = client.set_nodelay(true);

    let decision = entry.decision.clone();
    let id = inner.next_client.fetch_add(1, Ordering::Relaxed);
    let reset = inner.shutdown.child_token();
    inner
        .clients
        .lock()
        .unwrap()
        .insert(id, Client { route: decision.route.iter().map(|p| p.id.clone()).collect(), reset: reset.clone() });

    let destination = entry.destination();
    let record = deps.tracker.open(
        "TCP",
        entry.process_id,
        &entry.process_name,
        &destination,
        decision.action,
        &decision.route_name,
        &decision.rule_name,
    );

    let outcome: Result<(), String> = async {
        if let Some(reason) = deps.guard.check(&decision.route) {
            deps.log.warning(format!("TCP {} -> {destination}: refused, {reason}", entry.process_name));
            reset_on_close(&client); // reset, so the program fails at once
            record.set_error(reason);
            return Ok(());
        }
        let target = build_target(&entry, deps.resolver.as_ref()).await.map_err(|e| e.0)?;
        let mut upstream = tokio::select! {
            _ = reset.cancelled() => { reset_on_close(&client); return Err("Reset".into()); }
            connected = deps.connector.connect(&decision.route, &target) => connected.map_err(|e| e.0)?,
        };
        record.set_state("Established");
        deps.log.debug(format!("TCP {}({}) -> {destination} via {}", entry.process_name, entry.process_id, decision.route_name));
        let piped = {
            let (cr, cw) = client.split();
            let (ur, uw) = tokio::io::split(&mut upstream);
            let up = copy_counted(cr, uw, |n| record.add_up(n));
            let down = copy_counted(ur, cw, |n| record.add_down(n));
            tokio::select! {
                _ = reset.cancelled() => None,
                result = async { tokio::try_join!(up, down) } => Some(result),
            }
        };
        // A reset or error on one side tears down both (the streams are dropped below).
        if piped.is_none() {
            reset_on_close(&client);
        }
        Ok(())
    }
    .await;

    if let Err(message) = outcome {
        if message != "Reset" {
            deps.log.warning(format!("TCP {} -> {destination}: {message}", entry.process_name));
            record.set_error(message);
        }
    }
    inner.clients.lock().unwrap().remove(&id);
    drop(client);
    entry.mark_closed();
    deps.tracker.close(&record, None);
}

async fn copy_counted<R, W>(mut from: R, mut to: W, count: impl Fn(u64)) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let n = from.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        to.write_all(&buffer[..n]).await?;
        count(n as u64);
    }
    to.shutdown().await // propagate the half-close
}

async fn build_target(entry: &NatEntry, resolver: &dyn HostResolver) -> Result<Target, ProxyError> {
    if !entry.is_fake_ip {
        return Ok(Target::Addr(entry.original_address(), entry.original_port));
    }
    let Some(host) = &entry.hostname else {
        return Err(ProxyError("Fake IP without a known host name.".into()));
    };
    if !entry.decision.route.is_empty() && entry.decision.resolves_remotely(host) {
        return Ok(Target::host(host, entry.original_port));
    }
    match resolver.resolve(host).await {
        Some(ip) => Ok(Target::Addr(ip, entry.original_port)),
        None => Err(ProxyError(format!("Could not resolve {host}."))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyType;
    use crate::proxy::tests::{proxy, socks5_server};
    use crate::resolve::StaticResolver;
    use tokio::net::TcpSocket;

    struct Rig {
        relay: RelayServer,
        nat: Arc<NatTable>,
        tracker: Arc<ConnectionTracker>,
        guard: Arc<RouteGuard>,
    }

    fn rig() -> Rig {
        let nat = Arc::new(NatTable::default());
        let tracker = Arc::new(ConnectionTracker::default());
        let guard = Arc::new(RouteGuard::default());
        let resolver: Arc<dyn HostResolver> = Arc::new(StaticResolver::default().with("echo.example", "127.0.0.1"));
        let deps = RelayDeps {
            nat: nat.clone(),
            connector: Connector::new(resolver.clone(), Duration::from_secs(5)),
            resolver,
            tracker: tracker.clone(),
            log: Arc::new(LogHub::default()),
            guard: guard.clone(),
        };
        let relay = RelayServer::start(0, Some("127.0.0.1".parse().unwrap()), deps).unwrap();
        Rig { relay, nat, tracker, guard }
    }

    async fn echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => s.write_all(&buf[..n]).await.unwrap(),
                        }
                    }
                });
            }
        });
        port
    }

    fn decision(route: Vec<ProxyServer>, remote: bool) -> Arc<Decision> {
        let mut d = Decision::default_direct();
        if !route.is_empty() {
            d.action = RuleAction::Proxy;
            d.route_name = route[0].name.clone();
        }
        d.route = Arc::from(route);
        d.resolve_remotely = remote;
        Arc::new(d)
    }

    /// Opens a client socket the way a reflected program connection looks: registers the NAT entry for its
    /// source port first, then connects to the relay.
    async fn connect(
        rig: &Rig,
        original_port: u16,
        decision: Arc<Decision>,
        host: Option<&str>,
        fake: bool,
    ) -> (TcpStream, Arc<NatEntry>) {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = socket.local_addr().unwrap().port();
        let lo = Ip::v4([127, 0, 0, 1]);
        let entry = Arc::new(NatEntry::new(
            NatKey { local: lo, remote: lo, client_port: port },
            original_port,
            decision,
            4242,
            "Wow.exe".into(),
            None,
            host.map(String::from),
            fake,
        ));
        rig.nat.add(entry.clone());
        let stream = socket.connect(format!("127.0.0.1:{}", rig.relay.port()).parse().unwrap()).await.unwrap();
        (stream, entry)
    }

    #[tokio::test]
    async fn direct_flow_is_piped_and_counted() {
        let rig = rig();
        let echo = echo_server().await;
        let (mut s, entry) = connect(&rig, echo, decision(vec![], false), None, false).await;
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert!(entry.is_accepted());
        drop(s);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(entry.is_closed());
        let records = rig.tracker.snapshot(true);
        assert_eq!(records.len(), 1);
        assert_eq!((records[0].bytes_up(), records[0].bytes_down()), (4, 4));
        assert_eq!(records[0].state(), "Closed");
        assert_eq!(records[0].destination, format!("127.0.0.1:{echo}"));
    }

    #[tokio::test]
    async fn fake_ip_goes_by_name_through_socks5() {
        let rig = rig();
        let (socks_port, server) = socks5_server(false).await;
        let p = proxy(ProxyType::Socks5, socks_port, None);
        let (mut s, _) = connect(&rig, 8085, decision(vec![p], true), Some("world.realm.example"), true).await;
        s.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        let seen = server.await.unwrap();
        assert_eq!(seen[3], 3, "name sent to the proxy, not resolved locally");
        assert_eq!(rig.tracker.snapshot(true)[0].destination, "world.realm.example:8085");
    }

    #[tokio::test]
    async fn remote_dns_exception_sends_the_ip() {
        let rig = rig();
        let (socks_port, server) = socks5_server(false).await;
        let p = proxy(ProxyType::Socks5, socks_port, None);
        let mut d = (*decision(vec![p], true)).clone();
        d.remote_dns_exceptions = vec![".example".to_string()].into();
        let (mut s, _) = connect(&rig, 8085, Arc::new(d), Some("echo.example"), true).await;
        s.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        let seen = server.await.unwrap();
        assert_eq!(seen[3], 1, "resolved locally and sent as an IPv4 address");
        assert_eq!(&seen[4..8], &[127, 0, 0, 1]);
    }

    #[tokio::test]
    async fn blocked_route_is_reset_and_abort_routes_works() {
        let rig = rig();
        let echo = echo_server().await;
        let mut p = proxy(ProxyType::Socks5, 1, None);
        p.id = "bad".into();
        rig.guard.set(HashMap::from([("bad".to_string(), "exit IP is your own IP".to_string())]));
        let (mut s, _) = connect(&rig, echo, decision(vec![p], false), None, false).await;
        let mut buf = [0u8; 1];
        let result = s.read(&mut buf).await;
        assert!(matches!(result, Ok(0) | Err(_)));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let rec = &rig.tracker.snapshot(true)[0];
        assert_eq!(rec.state(), "Failed");
        assert!(rec.error().unwrap().contains("is blocked"));

        // a live direct flow gets reset by abort_all
        let (mut live, _) = connect(&rig, echo, decision(vec![], false), None, false).await;
        live.write_all(b"x").await.unwrap();
        live.read_exact(&mut buf).await.unwrap();
        assert_eq!(rig.relay.active_clients(), 1);
        assert_eq!(rig.relay.abort_routes(&["other".into()]), 0);
        assert_eq!(rig.relay.abort_all(), 1);
        let after = live.read(&mut buf).await;
        assert!(matches!(after, Ok(0) | Err(_)));
    }

    #[tokio::test]
    async fn unknown_connections_are_dropped() {
        let rig = rig();
        let mut s = TcpStream::connect(format!("127.0.0.1:{}", rig.relay.port())).await.unwrap();
        let mut buf = [0u8; 1];
        assert!(matches!(s.read(&mut buf).await, Ok(0) | Err(_)));
        assert_eq!(rig.tracker.snapshot(true).len(), 0);
    }

    #[test]
    fn nat_sweep_and_guard() {
        let nat = NatTable::default();
        let lo = Ip::v4([127, 0, 0, 1]);
        let e = Arc::new(NatEntry::new(
            NatKey { local: lo, remote: lo, client_port: 1 },
            80,
            decision(vec![], false),
            1,
            "a".into(),
            None,
            None,
            false,
        ));
        nat.add(e.clone());
        nat.sweep(60_000, 30_000);
        assert_eq!(nat.len(), 1);
        e.mark_closed();
        nat.sweep(0, 30_000);
        nat.sweep(0, 30_000);
        assert!(nat.len() <= 1);

        let guard = RouteGuard::default();
        assert_eq!(guard.set(HashMap::from([("a".into(), "x".into())])), vec!["a"]);
        assert!(guard.set(HashMap::from([("a".into(), "y".into())])).is_empty());
        assert!(guard.is_blocked("a"));
        guard.set(HashMap::new());
        assert!(guard.is_empty());
    }
}
