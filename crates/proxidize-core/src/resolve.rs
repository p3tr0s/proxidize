//! Host name resolution: the OS resolver, a fixed table for tests, and a small UDP client that talks to upstream
//! DNS servers from one fixed source port so the engine can let its own queries past fake-IP interception.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::clock::now_ms;
use crate::dns::{Message, TYPE_A, TYPE_AAAA};
use crate::matching::split_list;
use crate::net::{normalize_host, Cidr, Ip};

pub type ResolveFuture<'a> = Pin<Box<dyn Future<Output = Option<Ip>> + Send + 'a>>;

pub trait HostResolver: Send + Sync {
    /// Resolves a host name, preferring IPv4. `None` when it doesn't resolve.
    fn resolve<'a>(&'a self, host: &'a str) -> ResolveFuture<'a>;
}

/// The operating system resolver. Not for use while fake-IP DNS is active: it would get fake answers.
pub struct SystemResolver;

impl HostResolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> ResolveFuture<'a> {
        Box::pin(async move {
            if let Ok(ip) = host.parse::<Ip>() {
                return Some(ip);
            }
            let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, 0)).await.ok()?.collect();
            addresses.iter().find(|a| a.is_ipv4()).or(addresses.first()).map(|a| Ip::from_std(a.ip()))
        })
    }
}

/// A fixed table, for tests.
#[derive(Default)]
pub struct StaticResolver {
    table: HashMap<String, Ip>,
}

impl StaticResolver {
    pub fn with(mut self, host: &str, address: &str) -> Self {
        self.table.insert(normalize_host(host), address.parse().expect("valid address"));
        self
    }
}

impl HostResolver for StaticResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> ResolveFuture<'a> {
        let found = host.parse::<Ip>().ok().or_else(|| self.table.get(&normalize_host(host)).copied());
        Box::pin(async move { found })
    }
}

type Pending = Arc<Mutex<HashMap<u16, oneshot::Sender<Message>>>>;

/// Minimal UDP DNS client bound to one local port.
pub struct UpstreamResolver {
    servers: Vec<Ip>,
    timeout: Duration,
    socket: Arc<UdpSocket>,
    local_port: u16,
    pending: Pending,
    cache: Mutex<HashMap<String, (Ip, u64)>>,
    receiver: JoinHandle<()>,
}

impl UpstreamResolver {
    /// Binds `[::]:preferred_port` (dual stack), falling back to any port, then to IPv4 only.
    pub fn new(servers: Vec<Ip>, preferred_port: u16, timeout: Duration) -> std::io::Result<UpstreamResolver> {
        let mut servers = servers;
        if servers.is_empty() {
            servers = fallback_servers();
        }
        let (std_socket, dual) = match bind_dual(preferred_port).or_else(|_| bind_dual(0)) {
            Ok(s) => (s, true),
            Err(_) => {
                let s = std::net::UdpSocket::bind(("0.0.0.0", preferred_port))
                    .or_else(|_| std::net::UdpSocket::bind(("0.0.0.0", 0)))?;
                (s, false)
            }
        };
        if !dual {
            servers.retain(|s| s.is_v4());
            if servers.is_empty() {
                servers = fallback_servers();
            }
        }
        std_socket.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(std_socket)?);
        let local_port = socket.local_addr()?.port();
        let pending: Pending = Arc::default();
        let receiver = tokio::spawn(receive_loop(socket.clone(), pending.clone()));
        Ok(UpstreamResolver { servers, timeout, socket, local_port, pending, cache: Mutex::default(), receiver })
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn servers(&self) -> &[Ip] {
        &self.servers
    }

    async fn query(&self, host: &str, kind: u16) -> Option<(Ip, u32)> {
        for server in &self.servers {
            let (tx, rx) = oneshot::channel();
            let id = {
                let mut map = self.pending.lock().unwrap();
                let mut id;
                loop {
                    id = random_id();
                    if !map.contains_key(&id) {
                        break;
                    }
                }
                map.insert(id, tx);
                id
            };
            let result = async {
                let query = Message::build_query(id, host, kind)?;
                let target = SocketAddr::new(to_socket_ip(*server, self.socket.local_addr().ok()?.is_ipv6()), 53);
                self.socket.send_to(&query, target).await.ok()?;
                tokio::time::timeout(self.timeout, rx).await.ok()?.ok()
            }
            .await;
            self.pending.lock().unwrap().remove(&id);
            let Some(response) = result else { continue };
            match response.response_code() {
                3 => return None, // NXDOMAIN is authoritative
                0 => {}
                _ => continue, // SERVFAIL / REFUSED: next server
            }
            return response.answers.iter().find(|a| a.kind == kind).and_then(|a| a.address.map(|ip| (ip, a.ttl)));
        }
        None
    }
}

impl HostResolver for UpstreamResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> ResolveFuture<'a> {
        Box::pin(async move {
            if let Ok(ip) = host.parse::<Ip>() {
                return Some(ip);
            }
            let host = normalize_host(host);
            if let Some((ip, expires)) = self.cache.lock().unwrap().get(&host) {
                if *expires > now_ms() {
                    return Some(*ip);
                }
            }
            let (ip, ttl) = match self.query(&host, TYPE_A).await {
                Some(found) => found,
                None => self.query(&host, TYPE_AAAA).await?,
            };
            let expires = now_ms() + (ttl.clamp(30, 3600) as u64) * 1000;
            self.cache.lock().unwrap().insert(host, (ip, expires));
            Some(ip)
        })
    }
}

impl Drop for UpstreamResolver {
    fn drop(&mut self) {
        self.receiver.abort();
    }
}

fn bind_dual(port: u16) -> std::io::Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    socket.set_only_v6(false)?;
    socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
    Ok(socket.into())
}

fn to_socket_ip(ip: Ip, dual: bool) -> IpAddr {
    match (ip.to_std(), dual) {
        (IpAddr::V4(v4), true) => IpAddr::V6(v4.to_ipv6_mapped()),
        (other, _) => other,
    }
}

async fn receive_loop(socket: Arc<UdpSocket>, pending: Pending) {
    let mut buffer = vec![0u8; 4096];
    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((n, _)) => {
                if let Some(message) = Message::parse(&buffer[..n]) {
                    if message.is_response() {
                        if let Some(tx) = pending.lock().unwrap().remove(&message.id) {
                            let _ = tx.send(message);
                        }
                    }
                }
            }
            // ICMP port unreachable surfaces as ConnectionReset on Windows: keep listening.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

fn random_id() -> u16 {
    let bytes = uuid::Uuid::new_v4().into_bytes();
    u16::from_le_bytes([bytes[0], bytes[1]]).max(1)
}

pub fn fallback_servers() -> Vec<Ip> {
    vec![Ip::v4([1, 1, 1, 1]), Ip::v4([8, 8, 8, 8])]
}

/// DNS servers from the configured list, else `discovered` (the adapters' servers), else public fallbacks.
/// Fake-range and site-local IPv6 servers are skipped; IPv4 first.
pub fn choose_servers(configured: &str, discovered: &[Ip], fake_range: Option<Cidr>) -> Vec<Ip> {
    let mut result: Vec<Ip> = split_list(configured).iter().filter_map(|s| s.parse().ok()).collect();
    if result.is_empty() {
        for ip in discovered {
            let site_local = !ip.is_v4() && (ip.raw() >> 118) == 0x3FB; // fec0::/10
            if site_local || fake_range.is_some_and(|r| r.contains(*ip)) || ip.is_loopback() || result.contains(ip) {
                continue;
            }
            result.push(*ip);
        }
    }
    if result.is_empty() {
        result = fallback_servers();
    }
    result.sort_by_key(|ip| !ip.is_v4());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_choice() {
        let fake = Cidr::parse("198.18.0.0/15");
        let found: Vec<Ip> = ["fec0:0:0:ffff::1", "2001:db8::53", "198.18.0.1", "192.168.1.1", "192.168.1.1"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let chosen = choose_servers("", &found, fake);
        assert_eq!(chosen.iter().map(|i| i.to_string()).collect::<Vec<_>>(), vec!["192.168.1.1", "2001:db8::53"]);
        assert_eq!(choose_servers("9.9.9.9; x", &found, fake), vec!["9.9.9.9".parse::<Ip>().unwrap()]);
        assert_eq!(choose_servers("", &[], None), fallback_servers());
    }

    #[tokio::test]
    async fn upstream_against_local_server() {
        // A fake DNS server on localhost answering A queries with 192.0.2.7.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, from) = server.recv_from(&mut buf).await.unwrap();
                let q = Message::parse(&buf[..n]).unwrap();
                let answer = if q.questions[0].name == "nx.example" {
                    let mut r = Message::build_response(&q, &[], 0).unwrap();
                    r[3] |= 3;
                    r
                } else {
                    Message::build_response(&q, &["192.0.2.7".parse().unwrap()], 300).unwrap()
                };
                server.send_to(&answer, from).await.unwrap();
            }
        });

        let resolver = UpstreamResolver::new(vec![Ip::v4([127, 0, 0, 1])], 0, Duration::from_secs(2)).unwrap();
        // the test server listens on a random port, so point the query there
        let host = "realm.example";
        let target = SocketAddr::new(to_socket_ip(Ip::v4([127, 0, 0, 1]), resolver.socket.local_addr().unwrap().is_ipv6()), port);
        let (tx, rx) = oneshot::channel();
        resolver.pending.lock().unwrap().insert(42, tx);
        resolver.socket.send_to(&Message::build_query(42, host, TYPE_A).unwrap(), target).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), rx).await.unwrap().unwrap();
        assert_eq!(response.answers[0].address.unwrap().to_string(), "192.0.2.7");
        assert!(resolver.resolve("10.1.2.3").await.is_some(), "literals skip the network");
    }
}
