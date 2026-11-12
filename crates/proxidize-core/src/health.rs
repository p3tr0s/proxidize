//! Exit IP / country lookup through one route, which doubles as the proxy's health check. Includes a small
//! HTTP/1.1 client (with TLS through rustls) that runs over the proxy connector, so the URL's host name is sent to
//! the proxy instead of being resolved locally.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::ProxyServer;
use crate::net::Target;
use crate::proxy::Connector;
use crate::resolve::HostResolver;

pub const DIRECT_ID: &str = "(direct)";

/// Free, no key, HTTP only, 45 requests a minute per IP: one round for about 40 proxies.
pub const DEFAULT_URL: &str = crate::config::DEFAULT_HEALTH_URL;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum HealthState {
    #[default]
    Ok,
    /// The lookup through the proxy failed (unreachable, auth, refused, timeout, service error).
    Down,
    /// Works, but the exit IP is your own: the proxy does not hide you.
    ExposesYourIp,
    /// Works, but another proxy has the same exit IP.
    SharedIp,
}

#[derive(Clone, Debug)]
pub struct ProxyHealth {
    /// Proxy id, or [`DIRECT_ID`] for the check without a proxy.
    pub id: String,
    pub name: String,
    pub ok: bool,
    pub exit_ip: Option<String>,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub latency_ms: u64,
    pub error: Option<String>,
    /// Set by [`annotate`]: the exit IP is your own, or shared with other proxies.
    pub warning: Option<String>,
    pub state: HealthState,
    /// Traffic through this proxy is currently refused (set by the engine).
    pub blocked: bool,
    pub checked_at: DateTime<Local>,
}

impl ProxyHealth {
    pub fn failed(id: &str, name: &str, error: impl Into<String>, latency_ms: u64) -> ProxyHealth {
        ProxyHealth {
            id: id.into(),
            name: name.into(),
            ok: false,
            exit_ip: None,
            country: None,
            country_code: None,
            city: None,
            latency_ms,
            error: Some(error.into()),
            warning: None,
            state: HealthState::Down,
            blocked: false,
            checked_at: Local::now(),
        }
    }

    pub fn country_text(&self) -> String {
        match (&self.country, &self.country_code) {
            (None, None) => String::new(),
            (Some(c), None) => c.clone(),
            (None, Some(code)) => code.clone(),
            (Some(c), Some(code)) => format!("{c} ({code})"),
        }
    }

    pub fn status_text(&self) -> String {
        let base = match self.state {
            HealthState::Down => "Down",
            HealthState::ExposesYourIp => "Leak: your IP",
            HealthState::SharedIp => "Shared IP",
            HealthState::Ok => "OK",
        };
        if self.blocked {
            format!("{base} (blocked)")
        } else {
            base.into()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpInfo {
    pub ip: String,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
}

/// Requests `url` through `route` (empty = direct) and reads the exit IP and country. Network and proxy errors
/// come back as a failed result, never as a panic or error.
pub async fn check(
    id: &str,
    name: &str,
    route: &[ProxyServer],
    url: &str,
    resolver: Arc<dyn HostResolver>,
    timeout: Duration,
) -> ProxyHealth {
    let started = Instant::now();
    let connector = Connector::new(resolver, timeout);
    let result = tokio::time::timeout(timeout, http_get(&connector, route, url)).await;
    let latency = started.elapsed().as_millis() as u64;
    let (status, body) = match result {
        Err(_) => return ProxyHealth::failed(id, name, format!("Timed out after {} s.", timeout.as_secs()), latency),
        Ok(Err(e)) => return ProxyHealth::failed(id, name, e, latency),
        Ok(Ok(response)) => response,
    };
    if !(200..300).contains(&status) {
        let reason = if status == 429 { " (rate limited - lower the check frequency)" } else { "" };
        return ProxyHealth::failed(id, name, format!("IP check service answered HTTP {status}{reason}."), latency);
    }
    match parse_ip_info(&String::from_utf8_lossy(&body)) {
        Err(service_error) => ProxyHealth::failed(
            id,
            name,
            service_error.unwrap_or_else(|| "The IP check service returned no IP address.".into()),
            latency,
        ),
        Ok(info) => ProxyHealth {
            id: id.into(),
            name: name.into(),
            ok: true,
            exit_ip: Some(info.ip),
            country: info.country,
            country_code: info.country_code,
            city: info.city,
            latency_ms: latency,
            error: None,
            warning: None,
            state: HealthState::Ok,
            blocked: false,
            checked_at: Local::now(),
        },
    }
}

/// Understands the common JSON shapes (ip-api.com, ipwho.is, ipinfo.io, ifconfig.co, ipapi.co, ...) and plain-text
/// "just the IP" answers. `Err(Some(message))` carries a service error message.
pub fn parse_ip_info(body: &str) -> Result<IpInfo, Option<String>> {
    let text = body.trim();
    if text.is_empty() {
        return Err(None);
    }
    if !text.starts_with('{') {
        let first = text.lines().next().unwrap_or_default().trim();
        return match first.parse::<std::net::IpAddr>() {
            Ok(_) => Ok(IpInfo { ip: first.into(), country: None, country_code: None, city: None }),
            Err(_) => Err(None),
        };
    }
    let root: serde_json::Value = serde_json::from_str(text).map_err(|_| None)?;
    let s = |key: &str| root.get(key).and_then(|v| v.as_str()).map(str::trim).filter(|v| !v.is_empty()).map(String::from);
    let message = || Some(format!("IP check service: {}", s("message").unwrap_or_else(|| "lookup failed".into())));
    if s("status").is_some_and(|v| v.eq_ignore_ascii_case("fail")) || root.get("success") == Some(&serde_json::Value::Bool(false))
    {
        return Err(message());
    }
    let ip = s("query").or_else(|| s("ip")).or_else(|| s("ip_addr")).or_else(|| s("address")).ok_or(None)?;
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(None);
    }
    let mut country = s("country_name").or_else(|| s("country"));
    let mut code = s("countryCode").or_else(|| s("country_code")).or_else(|| s("country_iso")).or_else(|| s("countryCodeIso"));
    if code.is_none() && country.as_ref().is_some_and(|c| c.len() == 2) {
        code = country.take(); // ipinfo.io: "country": "GR"
    }
    if let (Some(c), Some(k)) = (&country, &code) {
        if c.len() == 2 && c.eq_ignore_ascii_case(k) {
            country = None;
        }
    }
    Ok(IpInfo { ip, country, country_code: code.map(|c| c.to_ascii_uppercase()), city: s("city") })
}

/// Flags proxies whose exit IP equals your own (direct) IP, and proxies sharing an exit IP. `known_own_ip` is used
/// when this round has no successful direct result, so a leaking proxy stays flagged.
pub fn annotate(results: &[ProxyHealth], known_own_ip: Option<&str>) -> Vec<ProxyHealth> {
    let own_ip = results
        .iter()
        .find(|r| r.id == DIRECT_ID && r.ok)
        .and_then(|r| r.exit_ip.clone())
        .or_else(|| known_own_ip.map(String::from));
    results
        .iter()
        .map(|result| {
            let mut r = result.clone();
            if !r.ok || r.id == DIRECT_ID || r.exit_ip.is_none() {
                r.warning = None;
                r.state = if r.ok { HealthState::Ok } else { HealthState::Down };
                return r;
            }
            if own_ip.is_some() && own_ip == r.exit_ip {
                r.state = HealthState::ExposesYourIp;
                r.warning = Some("Exit IP is your own IP: this proxy does not hide you.".into());
                return r;
            }
            let shared: Vec<&str> = results
                .iter()
                .filter(|o| o.ok && o.id != DIRECT_ID && o.id != r.id && o.exit_ip == r.exit_ip)
                .map(|o| o.name.as_str())
                .collect();
            if shared.is_empty() {
                r.state = HealthState::Ok;
                r.warning = None;
            } else {
                r.state = HealthState::SharedIp;
                r.warning = Some(format!("Same exit IP as {}.", shared.join(", ")));
            }
            r
        })
        .collect()
}

/// What changed between two checks of the same route, or `None` when nothing notable did.
pub fn describe_change(previous: Option<&ProxyHealth>, current: &ProxyHealth) -> Option<String> {
    let err = current.error.as_deref().unwrap_or_default();
    let exit = format!("{} {}", current.exit_ip.as_deref().unwrap_or_default(), current.country_text()).trim_end().to_string();
    let Some(previous) = previous else {
        return match (&current.warning, current.ok) {
            (_, false) => Some(format!("{} is down: {err}", current.name)),
            (Some(w), true) => Some(format!("{}: {w}", current.name)),
            (None, true) => None,
        };
    };
    if previous.ok && !current.ok {
        return Some(format!("{} is down: {err}", current.name));
    }
    if !previous.ok && current.ok {
        return Some(format!("{} is back: {exit}", current.name));
    }
    if previous.ok && current.ok && previous.state != HealthState::Ok && current.state == HealthState::Ok {
        return Some(format!("{} is OK again: {exit}", current.name));
    }
    if let Some(w) = &current.warning {
        if previous.warning.as_ref() != Some(w) {
            return Some(format!("{}: {w}", current.name));
        }
    }
    if let (true, true, Some(a), Some(b)) = (previous.ok, current.ok, &previous.country_code, &current.country_code) {
        if !a.eq_ignore_ascii_case(b) {
            return Some(format!("{} changed country: {} -> {}", current.name, previous.country_text(), current.country_text()));
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------------------------
// A full round

/// What a round of checks needs.
#[derive(Clone)]
pub struct Round {
    /// The proxies to check now (all of them, or a selection).
    pub proxies: Vec<ProxyServer>,
    /// Every configured proxy id: results for removed proxies are dropped.
    pub configured: Vec<String>,
    pub check_direct: bool,
    pub url: String,
    pub timeout: Duration,
    /// Results of earlier rounds, by id.
    pub previous: HashMap<String, ProxyHealth>,
    /// Your own IP from an earlier round, used when this round's direct lookup fails.
    pub known_own_ip: Option<String>,
    pub block_leaking: bool,
}

#[derive(Clone, Debug, Default)]
pub struct RoundResult {
    /// Every known result (this round's plus earlier ones for proxies not checked now), annotated.
    pub health: HashMap<String, ProxyHealth>,
    /// Proxies that must carry no traffic (id -> reason).
    pub blocked: HashMap<String, String>,
    /// What changed, as (message, is_ok).
    pub changes: Vec<(String, bool)>,
    pub own_ip: Option<String>,
    /// A proxy started exposing your IP in this round.
    pub new_leak: bool,
    pub summary: String,
}

/// Checks every proxy in `round` (four at a time, plus your own IP), retries proxies that just failed once, then
/// annotates leaks and shared exit IPs and works out what to block.
pub async fn check_round(round: Round, resolver: Arc<dyn HostResolver>) -> RoundResult {
    let url = if round.url.trim().is_empty() { DEFAULT_URL.to_string() } else { round.url.trim().to_string() };
    let gate = Arc::new(tokio::sync::Semaphore::new(4));
    let run = |id: String, name: String, route: Vec<ProxyServer>| {
        let gate = gate.clone();
        let resolver = resolver.clone();
        let url = url.clone();
        let timeout = round.timeout;
        async move {
            let _permit = gate.acquire_owned().await;
            check(&id, &name, &route, &url, resolver, timeout).await
        }
    };
    let mut tasks: Vec<_> =
        round.proxies.iter().map(|p| tokio::spawn(run(p.id.clone(), p.name.clone(), vec![p.clone()]))).collect();
    if round.check_direct {
        tasks.push(tokio::spawn(run(DIRECT_ID.into(), "Your IP".into(), Vec::new())));
    }
    let mut fresh = Vec::new();
    for t in tasks {
        if let Ok(h) = t.await {
            fresh.push(h);
        }
    }

    // A proxy that just failed gets one more try before it is reported down (no alerts on a blip).
    let retry: Vec<ProxyServer> = round
        .proxies
        .iter()
        .filter(|p| fresh.iter().any(|f| f.id == p.id && !f.ok) && round.previous.get(&p.id).is_none_or(|b| b.ok))
        .cloned()
        .collect();
    if !retry.is_empty() {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let again: Vec<_> = retry.iter().map(|p| tokio::spawn(run(p.id.clone(), p.name.clone(), vec![p.clone()]))).collect();
        for t in again {
            if let Ok(h) = t.await {
                if let Some(slot) = fresh.iter_mut().find(|f| f.id == h.id) {
                    *slot = h;
                }
            }
        }
    }

    let own_ip = fresh.iter().find(|f| f.id == DIRECT_ID && f.ok).and_then(|f| f.exit_ip.clone()).or(round.known_own_ip.clone());
    // Compare against every known result: a partial check still sees the other proxies.
    let mut combined: Vec<ProxyHealth> = round
        .previous
        .values()
        .filter(|h| (round.configured.contains(&h.id) || h.id == DIRECT_ID) && !fresh.iter().any(|f| f.id == h.id))
        .cloned()
        .map(|mut h| {
            h.warning = None;
            h
        })
        .collect();
    combined.extend(fresh);
    let mut annotated = annotate(&combined, if round.check_direct { own_ip.as_deref() } else { None });

    // Fail closed: a proxy that exposes your IP carries nothing until a check shows it is fixed.
    let blocked: HashMap<String, String> = if round.block_leaking {
        annotated
            .iter()
            .filter(|h| h.state == HealthState::ExposesYourIp)
            .map(|h| (h.id.clone(), "its exit IP is your own IP".to_string()))
            .collect()
    } else {
        HashMap::new()
    };
    for h in &mut annotated {
        h.blocked = blocked.contains_key(&h.id);
    }
    let mut changes = Vec::new();
    for h in annotated.iter().filter(|h| h.id != DIRECT_ID) {
        if let Some(change) = describe_change(round.previous.get(&h.id), h) {
            changes.push((change, h.state == HealthState::Ok));
        }
    }
    let new_leak = annotated.iter().any(|h| {
        h.state == HealthState::ExposesYourIp && round.previous.get(&h.id).is_none_or(|p| p.state != HealthState::ExposesYourIp)
    });
    let proxies: Vec<&ProxyHealth> = annotated.iter().filter(|h| h.id != DIRECT_ID).collect();
    let ok = proxies.iter().filter(|h| h.ok).count();
    let mut summary = format!("Health check: {ok}/{} proxies OK", proxies.len());
    if let Some(me) = annotated.iter().find(|h| h.id == DIRECT_ID && h.ok) {
        summary.push_str(&format!(", your IP {} {}", me.exit_ip.as_deref().unwrap_or_default(), me.country_text()));
    }
    summary = summary.trim_end().to_string() + ".";
    let health = annotated.into_iter().map(|h| (h.id.clone(), h)).collect();
    RoundResult { health, blocked, changes, own_ip, new_leak, summary }
}

// ---------------------------------------------------------------------------------------------------------------
// HTTP

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn parse(text: &str) -> Option<Url> {
        let text = text.trim();
        let (https, rest) = match strip_prefix_ci(text, "http://") {
            Some(r) => (false, r),
            None => (true, strip_prefix_ci(text, "https://")?),
        };
        let split = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(split);
        let authority = authority.rsplit('@').next()?; // drop userinfo
        let default_port = if https { 443 } else { 80 };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']')?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse().ok()?,
                None if after.is_empty() => default_port,
                None => return None,
            };
            (h.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().ok()?),
                None => (authority.to_string(), default_port),
            }
        };
        if host.is_empty() {
            return None;
        }
        let path = path.split('#').next().unwrap_or_default();
        let path = if path.is_empty() || path.starts_with('?') { format!("/{path}") } else { path.to_string() };
        Some(Url { https, host, port, path })
    }

    fn host_header(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == if self.https { 443 } else { 80 } {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    fn join(&self, location: &str) -> Option<Url> {
        if location.contains("://") {
            return Url::parse(location);
        }
        let mut next = self.clone();
        if location.starts_with('/') {
            next.path = location.to_string();
        } else {
            let base = self.path.rsplit_once('/').map(|(b, _)| b).unwrap_or_default();
            next.path = format!("{base}/{location}");
        }
        Some(next)
    }
}

fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    (text.len() >= prefix.len() && text[..prefix.len()].eq_ignore_ascii_case(prefix)).then(|| &text[prefix.len()..])
}

const MAX_BODY: usize = 256 * 1024;

/// GET with up to five redirects. Returns the status and the body.
pub async fn http_get(connector: &Connector, route: &[ProxyServer], url: &str) -> Result<(u16, Vec<u8>), String> {
    let mut url = Url::parse(url).ok_or_else(|| format!("Invalid IP check URL '{url}'."))?;
    for _ in 0..5 {
        let target = Target::host(&url.host, url.port);
        let stream = connector.connect(route, &target).await.map_err(|e| e.0)?;
        let (status, headers, body) = if url.https {
            let config = tls_config();
            let name = rustls::pki_types::ServerName::try_from(url.host.clone())
                .map_err(|_| format!("Invalid TLS host '{}'.", url.host))?;
            let tls = tokio_rustls::TlsConnector::from(config).connect(name, stream).await.map_err(|e| format!("TLS: {e}"))?;
            exchange(tls, &url).await?
        } else {
            exchange(stream, &url).await?
        };
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            if let Some(location) = header(&headers, "location") {
                url = url.join(&location).ok_or_else(|| format!("Bad redirect to '{location}'."))?;
                continue;
            }
        }
        return Ok((status, body));
    }
    Err("Too many redirects.".into())
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("ring supports the default protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone())
}

type Response = (u16, Vec<(String, String)>, Vec<u8>);

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, url: &Url) -> Result<Response, String> {
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Proxidize-HealthCheck/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        url.path,
        url.host_header()
    );
    stream.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        // TLS servers often skip close_notify; treat an unexpected EOF after data as the end.
        let n = match stream.read(&mut buffer).await {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => 0,
            Err(e) => return Err(e.to_string()),
        };
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buffer[..n]);
        if raw.len() > MAX_BODY {
            return Err("IP check response too large.".into());
        }
        if let Some(done) = complete_response(&raw) {
            return done;
        }
    }
    complete_response(&raw).unwrap_or_else(|| parse_response(&raw, true))
}

/// `Some` once `raw` holds a full response (by Content-Length or chunked framing).
fn complete_response(raw: &[u8]) -> Option<Result<Response, String>> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&raw[..end]);
    let lower = head.to_ascii_lowercase();
    if lower.contains("transfer-encoding: chunked") {
        decode_chunked(&raw[end..])?;
        return Some(parse_response(raw, false));
    }
    let length = lower.lines().find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok()))?;
    (raw.len() >= end + length).then(|| parse_response(raw, false))
}

fn parse_response(raw: &[u8], at_eof: bool) -> Result<Response, String> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("Incomplete HTTP response.")? + 4;
    let head = String::from_utf8_lossy(&raw[..end - 4]).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|_| status_line.starts_with("HTTP/"))
        .ok_or_else(|| format!("Invalid HTTP response '{status_line}'."))?;
    let headers: Vec<(String, String)> =
        lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
    let body = &raw[end..];
    let body = if header(&headers, "transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        decode_chunked(body).ok_or("Truncated chunked response.")?
    } else if let Some(length) = header(&headers, "content-length").and_then(|v| v.parse::<usize>().ok()) {
        if body.len() < length {
            return Err("Truncated HTTP response.".into());
        }
        body[..length].to_vec()
    } else if at_eof {
        body.to_vec()
    } else {
        return Err("Incomplete HTTP response.".into());
    };
    Ok((status, headers, body))
}

fn decode_chunked(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = data.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&data[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        if data.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::StaticResolver;
    use tokio::net::TcpListener;

    fn ok(id: &str, ip: &str, code: &str) -> ProxyHealth {
        let mut h = ProxyHealth::failed(id, id, "", 1);
        h.ok = true;
        h.error = None;
        h.state = HealthState::Ok;
        h.exit_ip = Some(ip.into());
        h.country_code = Some(code.into());
        h
    }

    #[test]
    fn parses_services() {
        let ip_api = r#"{"status":"success","country":"Greece","countryCode":"GR","city":"Athens","query":"192.0.2.10"}"#;
        assert_eq!(
            parse_ip_info(ip_api).unwrap(),
            IpInfo {
                ip: "192.0.2.10".into(),
                country: Some("Greece".into()),
                country_code: Some("GR".into()),
                city: Some("Athens".into())
            }
        );
        let ipinfo = r#"{"ip":"198.51.100.4","country":"gr","city":"Athens"}"#;
        let i = parse_ip_info(ipinfo).unwrap();
        assert_eq!((i.country, i.country_code.as_deref()), (None, Some("GR")));
        assert_eq!(parse_ip_info("203.0.113.9\n").unwrap().ip, "203.0.113.9");
        assert_eq!(
            parse_ip_info(r#"{"status":"fail","message":"reserved range"}"#),
            Err(Some("IP check service: reserved range".into()))
        );
        assert_eq!(parse_ip_info(r#"{"success":false}"#), Err(Some("IP check service: lookup failed".into())));
        assert_eq!(parse_ip_info("<html>"), Err(None));
        assert_eq!(parse_ip_info(r#"{"ip":"not-an-ip"}"#), Err(None));
    }

    #[test]
    fn annotates_leaks_and_shared() {
        let mut direct = ok(DIRECT_ID, "192.0.2.112", "GR");
        direct.name = "Your IP".into();
        let rows = vec![direct, ok("a", "192.0.2.112", "GR"), ok("b", "203.0.113.1", "CH"), ok("c", "203.0.113.1", "CH")];
        let out = annotate(&rows, None);
        assert_eq!(out[1].state, HealthState::ExposesYourIp);
        assert_eq!(out[2].state, HealthState::SharedIp);
        assert_eq!(out[2].warning.as_deref(), Some("Same exit IP as c."));
        assert_eq!(out[0].state, HealthState::Ok);

        // direct failed this round: the remembered own IP still flags the leak
        let rows = vec![ProxyHealth::failed(DIRECT_ID, "Your IP", "timeout", 1), ok("a", "192.0.2.112", "GR")];
        assert_eq!(annotate(&rows, Some("192.0.2.112"))[1].state, HealthState::ExposesYourIp);
    }

    #[test]
    fn changes() {
        let a = ok("a", "203.0.113.1", "CH");
        let down = ProxyHealth::failed("a", "a", "refused", 1);
        assert_eq!(describe_change(None, &a), None);
        assert_eq!(describe_change(Some(&a), &down).as_deref(), Some("a is down: refused"));
        assert_eq!(describe_change(Some(&down), &a).as_deref(), Some("a is back: 203.0.113.1 CH"));
        let mut moved = a.clone();
        moved.country_code = Some("SE".into());
        assert_eq!(describe_change(Some(&a), &moved).as_deref(), Some("a changed country: CH -> SE"));
        assert_eq!(describe_change(Some(&a), &a), None);
    }

    #[test]
    fn urls() {
        let u = Url::parse("http://ip-api.com/json/?fields=status").unwrap();
        assert_eq!((u.https, u.host.as_str(), u.port, u.path.as_str()), (false, "ip-api.com", 80, "/json/?fields=status"));
        let u = Url::parse("HTTPS://[2001:db8::1]:8443?x#frag").unwrap();
        assert_eq!((u.https, u.host.as_str(), u.port, u.path.as_str()), (true, "2001:db8::1", 8443, "/?x"));
        assert_eq!(u.host_header(), "[2001:db8::1]:8443");
        assert!(Url::parse("ftp://x").is_none());
        assert!(Url::parse("http://:80/").is_none());
        assert_eq!(u.join("/next").unwrap().path, "/next");
        assert_eq!(Url::parse("http://a/b/c").unwrap().join("d").unwrap().path, "/b/d");
    }

    #[test]
    fn chunked() {
        assert_eq!(decode_chunked(b"4\r\nWiki\r\n5;x=1\r\npedia\r\n0\r\n\r\n").unwrap(), b"Wikipedia");
        assert!(decode_chunked(b"4\r\nWi").is_none());
    }

    #[tokio::test]
    async fn round_flags_leaks_and_blocks() {
        use tokio::net::TcpListener;
        // An IP service that always answers 192.0.2.112: direct and through the "proxy" alike (a leaking proxy).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let _ = s.read(&mut buf).await;
                    let body = "192.0.2.112";
                    let _ =
                        s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await;
                });
            }
        });
        // An HTTP proxy that tunnels everything to the IP service.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = proxy.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut header = Vec::new();
                    let mut one = [0u8; 1];
                    while !header.ends_with(b"\r\n\r\n") {
                        if s.read_exact(&mut one).await.is_err() {
                            return;
                        }
                        header.push(one[0]);
                    }
                    let mut up = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                    s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                });
            }
        });
        let p = ProxyServer {
            id: "p1".into(),
            name: "NVPN_UK".into(),
            kind: crate::config::ProxyType::Http,
            host: "127.0.0.1".into(),
            port: proxy_port,
            ..Default::default()
        };
        let round = Round {
            proxies: vec![p],
            configured: vec!["p1".into()],
            check_direct: true,
            url: format!("http://127.0.0.1:{port}/"),
            timeout: Duration::from_secs(5),
            previous: HashMap::new(),
            known_own_ip: None,
            block_leaking: true,
        };
        let result = check_round(round, Arc::new(StaticResolver::default())).await;
        assert_eq!(result.own_ip.as_deref(), Some("192.0.2.112"));
        assert_eq!(result.health["p1"].state, HealthState::ExposesYourIp);
        assert!(result.health["p1"].blocked);
        assert_eq!(result.blocked.keys().collect::<Vec<_>>(), vec!["p1"]);
        assert!(result.new_leak);
        assert_eq!(result.summary, "Health check: 1/1 proxies OK, your IP 192.0.2.112.");
        assert!(result.changes.iter().any(|(m, ok)| m.contains("does not hide you") && !ok));
    }

    #[tokio::test]
    async fn check_through_local_http_server_with_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            for i in 0..2 {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 2048];
                let n = s.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                if i == 0 {
                    assert!(req.starts_with("GET /start HTTP/1.1\r\n"));
                    s.write_all(b"HTTP/1.1 302 Found\r\nLocation: /json\r\nContent-Length: 0\r\n\r\n").await.unwrap();
                } else {
                    assert!(req.starts_with("GET /json HTTP/1.1\r\n"));
                    let body = r#"{"status":"success","country":"Switzerland","countryCode":"CH","city":"Zurich","query":"203.0.113.31"}"#;
                    let chunked = format!("{:x}\r\n{body}\r\n0\r\n\r\n", body.len());
                    s.write_all(format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{chunked}").as_bytes())
                        .await
                        .unwrap();
                }
            }
        });
        let resolver: Arc<dyn HostResolver> = Arc::new(StaticResolver::default().with("lookup.test", "127.0.0.1"));
        let h = check("p", "NVPN_CH", &[], &format!("http://lookup.test:{port}/start"), resolver.clone(), Duration::from_secs(5))
            .await;
        assert!(h.ok, "{:?}", h.error);
        assert_eq!(h.exit_ip.as_deref(), Some("203.0.113.31"));
        assert_eq!(h.country_text(), "Switzerland (CH)");

        let bad = check("p", "x", &[], "gopher://x", resolver, Duration::from_secs(1)).await;
        assert_eq!(bad.state, HealthState::Down);
        assert!(bad.error.unwrap().contains("Invalid IP check URL"));
    }
}
