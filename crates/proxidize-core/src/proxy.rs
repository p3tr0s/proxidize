//! Proxy clients (SOCKS5 with RFC 1929 auth, SOCKS4/4a, HTTP CONNECT, HTTPS = HTTP CONNECT over TLS), the SOCKS5 UDP
//! header codec and the connector that opens TCP connections directly or through a proxy chain.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{ProxyServer, ProxyType};
use crate::net::{Ip, Target};
use crate::resolve::{HostResolver, SystemResolver};

/// A connection the relay can use: plain TCP, or TLS layers (HTTPS proxies, also inside a chain).
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type Stream = Box<dyn Io>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyError(pub String);

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProxyError {}

pub type Result<T> = std::result::Result<T, ProxyError>;

fn err<T>(message: impl Into<String>) -> Result<T> {
    Err(ProxyError(message.into()))
}

/// Maps I/O errors during a handshake to a readable message for `proxy`.
fn io(proxy: &ProxyServer) -> impl Fn(std::io::Error) -> ProxyError + '_ {
    move |e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ProxyError(format!("{} closed the connection during the handshake.", proxy.name))
        } else {
            ProxyError(format!("{}: {e}", proxy.name))
        }
    }
}

pub const SOCKS5_CONNECT: u8 = 0x01;
pub const SOCKS5_UDP_ASSOCIATE: u8 = 0x03;

/// SOCKS5 greeting, optional username/password, then `command`. Returns BND.ADDR:BND.PORT from the reply (the
/// UDP relay endpoint for UDP ASSOCIATE).
pub async fn socks5_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    proxy: &ProxyServer,
    target: &Target,
    command: u8,
) -> Result<Target> {
    let e = io(proxy);
    let auth = proxy.has_credentials();
    let greeting: &[u8] = if auth { &[5, 2, 0, 2] } else { &[5, 1, 0] };
    stream.write_all(greeting).await.map_err(&e)?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.map_err(&e)?;
    if reply[0] != 5 {
        return err(format!("{}: not a SOCKS5 server.", proxy.name));
    }
    match reply[1] {
        0 => {}
        2 => {
            if !auth {
                return err(format!("{}: SOCKS5 server requires a username and password.", proxy.name));
            }
            let user = proxy.username.as_deref().unwrap_or_default().as_bytes();
            let pass = proxy.password.as_deref().unwrap_or_default().as_bytes();
            if user.len() > 255 || pass.len() > 255 {
                return err(format!("{}: username or password too long for SOCKS5.", proxy.name));
            }
            let mut request = Vec::with_capacity(3 + user.len() + pass.len());
            request.push(1);
            request.push(user.len() as u8);
            request.extend_from_slice(user);
            request.push(pass.len() as u8);
            request.extend_from_slice(pass);
            stream.write_all(&request).await.map_err(&e)?;
            let mut auth_reply = [0u8; 2];
            stream.read_exact(&mut auth_reply).await.map_err(&e)?;
            if auth_reply[1] != 0 {
                return err(format!("{}: SOCKS5 authentication failed.", proxy.name));
            }
        }
        0xFF => return err(format!("{}: SOCKS5 server accepted none of the offered authentication methods.", proxy.name)),
        other => return err(format!("{}: SOCKS5 server selected unsupported method {other}.", proxy.name)),
    }

    let mut request = vec![5, command, 0];
    write_address(&mut request, target)?;
    stream.write_all(&request).await.map_err(&e)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(&e)?;
    if head[0] != 5 {
        return err(format!("{}: invalid SOCKS5 reply.", proxy.name));
    }
    if head[1] != 0 {
        return err(format!("{}: SOCKS5 {} ({target}).", proxy.name, describe_reply(head[1])));
    }
    let mut buffer = vec![head[3]];
    match head[3] {
        1 => buffer.resize(1 + 4 + 2, 0),
        4 => buffer.resize(1 + 16 + 2, 0),
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(&e)?;
            buffer.push(len[0]);
            buffer.resize(2 + len[0] as usize + 2, 0);
        }
        other => return err(format!("{}: SOCKS5 reply has unknown address type {other}.", proxy.name)),
    }
    let start = if head[3] == 3 { 2 } else { 1 };
    stream.read_exact(&mut buffer[start..]).await.map_err(&e)?;
    parse_address(&buffer).map(|(t, _)| t).ok_or_else(|| ProxyError(format!("{}: malformed SOCKS5 bound address.", proxy.name)))
}

/// ATYP + address + port.
pub fn write_address(out: &mut Vec<u8>, target: &Target) -> Result<()> {
    match target {
        Target::Host(host, port) => {
            if host.len() > 255 || !host.is_ascii() {
                return err(format!("Host name not usable with SOCKS5: {host}"));
            }
            out.push(3);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Target::Addr(ip, port) if ip.is_v4() => {
            out.push(1);
            out.extend_from_slice(&ip.v4_value().to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Target::Addr(ip, port) => {
            out.push(4);
            out.extend_from_slice(&ip.raw().to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

/// Parses ATYP + address + port. Returns the endpoint and the bytes consumed.
pub fn parse_address(data: &[u8]) -> Option<(Target, usize)> {
    let port_at = |at: usize| -> Option<u16> { Some(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?])) };
    match *data.first()? {
        1 => Some((Target::Addr(Ip::from_slice_v4(data.get(1..5)?), port_at(5)?), 7)),
        4 => Some((Target::Addr(Ip::from_slice_v6(data.get(1..17)?), port_at(17)?), 19)),
        3 => {
            let len = *data.get(1)? as usize;
            let host = std::str::from_utf8(data.get(2..2 + len)?).ok()?;
            Some((Target::host(host, port_at(2 + len)?), 2 + len + 2))
        }
        _ => None,
    }
}

pub fn describe_reply(code: u8) -> String {
    match code {
        1 => "general failure".into(),
        2 => "connection not allowed by ruleset".into(),
        3 => "network unreachable".into(),
        4 => "host unreachable".into(),
        5 => "connection refused".into(),
        6 => "TTL expired".into(),
        7 => "command not supported".into(),
        8 => "address type not supported".into(),
        other => format!("error {other}"),
    }
}

/// SOCKS4, or SOCKS4a for host names (`0.0.0.1` plus the name after the user id).
pub async fn socks4_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    proxy: &ProxyServer,
    target: &Target,
) -> Result<()> {
    let e = io(proxy);
    let user = proxy.username.as_deref().unwrap_or_default().as_bytes();
    let mut request = vec![4, 1];
    request.extend_from_slice(&target.port().to_be_bytes());
    match target {
        Target::Host(host, _) => {
            request.extend_from_slice(&[0, 0, 0, 1]);
            request.extend_from_slice(user);
            request.push(0);
            request.extend_from_slice(host.as_bytes());
            request.push(0);
        }
        Target::Addr(ip, _) => {
            if !ip.is_v4() {
                return err(format!("{}: SOCKS4 cannot connect to IPv6 address {ip}.", proxy.name));
            }
            request.extend_from_slice(&ip.v4_value().to_be_bytes());
            request.extend_from_slice(user);
            request.push(0);
        }
    }
    stream.write_all(&request).await.map_err(&e)?;
    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply).await.map_err(&e)?;
    if reply[1] != 0x5A {
        return err(format!("{}: SOCKS4 request rejected (code 0x{:02X}) for {target}.", proxy.name, reply[1]));
    }
    Ok(())
}

const MAX_HTTP_HEADER: usize = 16 * 1024;

pub async fn http_connect_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    proxy: &ProxyServer,
    target: &Target,
) -> Result<()> {
    let e = io(proxy);
    let authority = target.authority();
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if proxy.has_credentials() {
        let pair = format!("{}:{}", proxy.username.as_deref().unwrap_or_default(), proxy.password.as_deref().unwrap_or_default());
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", base64::engine::general_purpose::STANDARD.encode(pair)));
    }
    request.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");
    stream.write_all(request.as_bytes()).await.map_err(&e)?;

    // Byte by byte, so no tunnelled payload is consumed past the header terminator.
    let mut header = Vec::with_capacity(256);
    let mut one = [0u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut one).await.map_err(&e)?;
        header.push(one[0]);
        if header.len() > MAX_HTTP_HEADER {
            return err(format!("{}: HTTP proxy response header too large.", proxy.name));
        }
    }
    let text = String::from_utf8_lossy(&header);
    let status_line = text.split("\r\n").next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let status = parts.next().and_then(|s| s.parse::<u16>().ok());
    match status {
        Some(code) if version.to_ascii_uppercase().starts_with("HTTP/") => {
            if (200..300).contains(&code) {
                Ok(())
            } else {
                err(format!("{}: HTTP CONNECT to {authority} failed: {status_line}", proxy.name))
            }
        }
        _ => err(format!("{}: invalid HTTP proxy response '{status_line}'.", proxy.name)),
    }
}

/// SOCKS5 UDP request header (RFC 1928 section 7).
pub mod udp {
    use super::*;

    pub const MAX_HEADER: usize = 3 + 1 + 1 + 255 + 2;

    pub fn write_header(out: &mut Vec<u8>, target: &Target) -> Result<()> {
        out.extend_from_slice(&[0, 0, 0]); // RSV, FRAG = 0 (no fragmentation)
        write_address(out, target)
    }

    /// Returns the source endpoint and the payload offset. Fragmented datagrams are not supported.
    pub fn parse(datagram: &[u8]) -> Option<(Target, usize)> {
        if datagram.len() < 4 || datagram[2] != 0 {
            return None;
        }
        let (source, consumed) = parse_address(&datagram[3..])?;
        Some((source, 3 + consumed))
    }
}

pub fn endpoint_of(proxy: &ProxyServer) -> Target {
    Target::host(&proxy.host, proxy.port)
}

pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, proxy: &ProxyServer, target: &Target) -> Result<()> {
    match proxy.kind {
        ProxyType::Socks5 => socks5_handshake(stream, proxy, target, SOCKS5_CONNECT).await.map(|_| ()),
        ProxyType::Socks4 => socks4_handshake(stream, proxy, target).await,
        ProxyType::Http | ProxyType::Https => http_connect_handshake(stream, proxy, target).await,
    }
}

/// Opens TCP connections directly or through a proxy chain.
#[derive(Clone)]
pub struct Connector {
    resolver: Arc<dyn HostResolver>,
    timeout: Duration,
}

impl Connector {
    pub fn new(resolver: Arc<dyn HostResolver>, timeout: Duration) -> Connector {
        Connector { resolver, timeout }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Resolves the first hop (the target itself when `route` is empty) to an address.
    pub async fn resolve_first(&self, route: &[ProxyServer], target: &Target) -> Result<(Ip, u16)> {
        let first = route.first().map(endpoint_of).unwrap_or_else(|| target.clone());
        match first {
            Target::Addr(ip, port) => Ok((ip, port)),
            Target::Host(host, port) => match tokio::time::timeout(self.timeout, self.resolver.resolve(&host)).await {
                Err(_) => err(format!("Timed out resolving {host}.")),
                Ok(None) => err(format!("Could not resolve {host}.")),
                Ok(Some(ip)) => Ok((ip, port)),
            },
        }
    }

    /// Connects to `target` through `route` (empty = direct). Every hop after the first is reached through the
    /// previous one, so only the first proxy's name is resolved locally. The stream is ready for payload.
    pub async fn connect(&self, route: &[ProxyServer], target: &Target) -> Result<Stream> {
        match tokio::time::timeout(self.timeout, self.connect_inner(route, target)).await {
            Ok(result) => result,
            Err(_) => match route.first() {
                None => err(format!("Timed out connecting to {target}.")),
                Some(p) => err(format!("Timed out connecting through {}.", p.name)),
            },
        }
    }

    /// A plain TCP connection to `target`, no proxy (the SOCKS5 UDP control connection).
    pub async fn connect_direct(&self, target: &Target) -> Result<TcpStream> {
        match tokio::time::timeout(self.timeout, self.open(&[], target)).await {
            Ok(result) => result,
            Err(_) => err(format!("Timed out connecting to {target}.")),
        }
    }

    async fn connect_inner(&self, route: &[ProxyServer], target: &Target) -> Result<Stream> {
        let mut stream: Stream = Box::new(self.open(route, target).await?);
        for (i, hop) in route.iter().enumerate() {
            let next = route.get(i + 1).map(endpoint_of).unwrap_or_else(|| target.clone());
            if hop.kind == ProxyType::Https {
                stream = tls_to(stream, hop).await?;
            }
            handshake(&mut stream, hop, &next).await?;
        }
        Ok(stream)
    }

    /// TCP to the first hop (or the target).
    async fn open(&self, route: &[ProxyServer], target: &Target) -> Result<TcpStream> {
        let (ip, port) = self.resolve_first(route, target).await?;
        let stream = TcpStream::connect((ip.to_std(), port)).await.map_err(|e| {
            let what = match route.first() {
                None => target.to_string(),
                Some(p) => format!("proxy {} ({}:{})", p.name, p.host, p.port),
            };
            ProxyError(format!("Cannot connect to {what}: {e}."))
        })?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }
}

/// TLS to an HTTPS proxy, over whatever reaches it.
async fn tls_to(stream: Stream, proxy: &ProxyServer) -> Result<Stream> {
    let name = crate::tls::server_name(&proxy.host)
        .ok_or_else(|| ProxyError(format!("{}: '{}' is not a valid TLS host name.", proxy.name, proxy.host)))?;
    let config = crate::tls::client_config(!proxy.skip_certificate_check);
    match tokio_rustls::TlsConnector::from(config).connect(name, stream).await {
        Ok(tls) => Ok(Box::new(tls)),
        Err(e) => {
            let hint = if e.to_string().to_ascii_lowercase().contains("certificate") && !proxy.skip_certificate_check {
                " If it uses a self-signed certificate, turn on \"Skip certificate check\" for it."
            } else {
                ""
            };
            err(format!("{}: TLS to the proxy failed: {e}.{hint}", proxy.name))
        }
    }
}

/// Connects through `route` to host:port, sends `HEAD /` and reports the status line with timings.
pub async fn test_route(route: &[ProxyServer], host: &str, port: u16, timeout: Duration) -> Result<String> {
    let connector = Connector::new(Arc::new(SystemResolver), timeout);
    let started = Instant::now();
    let mut stream = connector.connect(route, &Target::host(host, port)).await?;
    let connect_ms = started.elapsed().as_millis();
    let request = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Proxidize\r\nConnection: close\r\n\r\n");
    let read = async {
        stream.write_all(request.as_bytes()).await?;
        let mut buffer = vec![0u8; 1024];
        let mut total = 0;
        while total < buffer.len() {
            let n = stream.read(&mut buffer[total..]).await?;
            if n == 0 {
                break;
            }
            total += n;
            if buffer[..total].contains(&b'\n') {
                break;
            }
        }
        buffer.truncate(total);
        Ok::<_, std::io::Error>(buffer)
    };
    let response = tokio::time::timeout(timeout, read)
        .await
        .map_err(|_| ProxyError(format!("{host}:{port} did not answer in time.")))?
        .map_err(|e| ProxyError(format!("{host}:{port}: {e}")))?;
    let text = String::from_utf8_lossy(&response);
    let first = text.split('\n').next().unwrap_or_default().trim();
    Ok(format!(
        "Connected to {host}:{port} in {connect_ms} ms, total {} ms. Response: {}",
        started.elapsed().as_millis(),
        if first.is_empty() { "(none)" } else { first }
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::resolve::StaticResolver;
    use tokio::net::TcpListener;

    pub fn proxy(kind: ProxyType, port: u16, user: Option<&str>) -> ProxyServer {
        ProxyServer {
            name: format!("{kind:?}"),
            kind,
            host: "127.0.0.1".into(),
            port,
            username: user.map(String::from),
            password: user.map(|_| "secret".to_string()),
            ..Default::default()
        }
    }

    /// Minimal SOCKS5 server: auth optional, CONNECT only, then echoes `prefix` + whatever it receives.
    pub async fn socks5_server(require_auth: bool) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 2];
            s.read_exact(&mut head).await.unwrap();
            let mut methods = vec![0u8; head[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            if require_auth {
                s.write_all(&[5, 2]).await.unwrap();
                let mut v = [0u8; 2];
                s.read_exact(&mut v).await.unwrap();
                let mut user = vec![0u8; v[1] as usize];
                s.read_exact(&mut user).await.unwrap();
                let mut pl = [0u8; 1];
                s.read_exact(&mut pl).await.unwrap();
                let mut pass = vec![0u8; pl[0] as usize];
                s.read_exact(&mut pass).await.unwrap();
                let ok = user == b"relay" && pass == b"secret";
                s.write_all(&[1, if ok { 0 } else { 1 }]).await.unwrap();
                if !ok {
                    return Vec::new();
                }
            } else {
                s.write_all(&[5, 0]).await.unwrap();
            }
            let mut req = [0u8; 4];
            s.read_exact(&mut req).await.unwrap();
            let mut rest = vec![0u8; 512];
            let n = s.read(&mut rest).await.unwrap();
            let mut seen = req.to_vec();
            seen.extend_from_slice(&rest[..n]);
            s.write_all(&[5, 0, 0, 1, 10, 0, 0, 9, 0x1F, 0x90]).await.unwrap();
            let mut payload = [0u8; 5];
            s.read_exact(&mut payload).await.unwrap();
            s.write_all(&payload).await.unwrap();
            seen
        });
        (port, task)
    }

    #[tokio::test]
    async fn socks5_with_auth_sends_host_name() {
        let (port, server) = socks5_server(true).await;
        let p = proxy(ProxyType::Socks5, port, Some("relay"));
        let connector = Connector::new(Arc::new(StaticResolver::default()), Duration::from_secs(5));
        let mut stream = connector.connect(&[p], &Target::host("World.Realm.Example", 8085)).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut echo = [0u8; 5];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"hello");
        let seen = server.await.unwrap();
        assert_eq!(&seen[..4], &[5, 1, 0, 3]);
        assert_eq!(seen[4] as usize, "world.realm.example".len());
        assert_eq!(&seen[5..5 + 19], b"world.realm.example");
        assert_eq!(&seen[24..26], &8085u16.to_be_bytes());
    }

    #[tokio::test]
    async fn socks5_wrong_password_fails_cleanly() {
        let (port, _server) = socks5_server(true).await;
        let mut p = proxy(ProxyType::Socks5, port, Some("relay"));
        p.password = Some("nope".into());
        let connector = Connector::new(Arc::new(StaticResolver::default()), Duration::from_secs(5));
        let error = connector.connect(&[p], &Target::host("a.example", 1)).await.err().unwrap();
        assert!(error.0.contains("authentication failed"), "{error}");
    }

    #[tokio::test]
    async fn socks5_requires_credentials_we_lack() {
        let (port, _server) = socks5_server(true).await;
        let p = proxy(ProxyType::Socks5, port, None);
        let connector = Connector::new(Arc::new(StaticResolver::default()), Duration::from_secs(5));
        let error = connector.connect(&[p], &Target::host("a.example", 1)).await.err().unwrap();
        assert!(error.0.contains("requires a username"), "{error}");
    }

    #[tokio::test]
    async fn http_connect_and_socks4a() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nTUNNEL").await.unwrap();
            request
        });
        let p = proxy(ProxyType::Http, port, Some("relay"));
        let connector = Connector::new(Arc::new(StaticResolver::default()), Duration::from_secs(5));
        let mut stream = connector.connect(&[p], &Target::host("a.example", 443)).await.unwrap();
        let mut first = [0u8; 6];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"TUNNEL", "payload after the header is not swallowed");
        let request = server.await.unwrap();
        assert!(request.starts_with("CONNECT a.example:443 HTTP/1.1\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic cmVsYXk6c2VjcmV0\r\n"));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(&[0, 0x5A, 0, 0, 0, 0, 0, 0]).await.unwrap();
            buf.truncate(n);
            buf
        });
        let p = proxy(ProxyType::Socks4, port, None);
        connector.connect(&[p], &Target::host("b.example", 80)).await.unwrap();
        let seen = server.await.unwrap();
        assert_eq!(seen, [&[4u8, 1, 0, 80, 0, 0, 0, 1, 0][..], b"b.example\0"].concat());
    }

    /// An HTTPS proxy with a self-signed certificate for 127.0.0.1: CONNECT over TLS, then echo.
    async fn https_proxy() -> u16 {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (s, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut s) = acceptor.accept(s).await else { return };
                    let mut buf = vec![0u8; 1024];
                    let n = s.read(&mut buf).await.unwrap();
                    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("CONNECT a.example:443 HTTP/1.1"));
                    s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
                    let mut payload = [0u8; 4];
                    s.read_exact(&mut payload).await.unwrap();
                    s.write_all(&payload).await.unwrap();
                    s.flush().await.unwrap();
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn https_proxy_over_tls() {
        let port = https_proxy().await;
        let connector = Connector::new(Arc::new(StaticResolver::default()), Duration::from_secs(5));

        let mut p = proxy(ProxyType::Https, port, None);
        let error = connector.connect(&[p.clone()], &Target::host("a.example", 443)).await.err().unwrap();
        assert!(error.0.contains("TLS to the proxy failed") && error.0.contains("Skip certificate check"), "{error}");

        p.skip_certificate_check = true;
        let mut stream = connector.connect(&[p.clone()], &Target::host("a.example", 443)).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
    }

    #[tokio::test]
    async fn unreachable_proxy_names_it() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let p = proxy(ProxyType::Socks5, port, None);
        let connector = Connector::new(Arc::new(StaticResolver::default()), Duration::from_secs(5));
        let error = connector.connect(&[p], &Target::host("a.example", 1)).await.err().unwrap();
        assert!(error.0.starts_with("Cannot connect to proxy Socks5"), "{error}");
    }

    #[test]
    fn udp_header() {
        let mut out = Vec::new();
        udp::write_header(&mut out, &Target::Addr("203.0.113.5".parse().unwrap(), 3074)).unwrap();
        out.extend_from_slice(b"game");
        let (source, offset) = udp::parse(&out).unwrap();
        assert_eq!(source.to_string(), "203.0.113.5:3074");
        assert_eq!(&out[offset..], b"game");
        out[2] = 1;
        assert!(udp::parse(&out).is_none(), "fragments refused");
        let mut v6 = Vec::new();
        udp::write_header(&mut v6, &Target::Addr("2001:db8::1".parse().unwrap(), 53)).unwrap();
        assert_eq!(udp::parse(&v6).unwrap().1, 3 + 19);
    }
}
