//! ProxyCap ruleset import: the documented XML format (the input of ProxyCap's xml2prs tool) and the binary
//! machine.prs ("$PRSX") ProxyCap actually keeps, as far as its layout has been worked out.

use std::collections::{BTreeMap, HashMap};

use quick_xml::events::{BytesStart, Event};

use crate::config::{Config, DnsMode, ProxyChain, ProxyServer, ProxyType, Rule, RuleAction, TransportFilter};

/// ProxyCap's live ruleset.
pub const INSTALLED_RULESET: &str = r"C:\ProgramData\ProxyCap\machine.prs";

#[derive(Debug, Default)]
pub struct ImportResult {
    pub proxies: Vec<ProxyServer>,
    pub chains: Vec<ProxyChain>,
    pub rules: Vec<Rule>,
    /// At least one imported Proxy rule had "Resolve names remotely" on.
    pub uses_remote_dns: bool,
    /// Host patterns ProxyCap excluded from remote DNS (per rule there; applied globally here).
    pub remote_dns_exceptions: Vec<String>,
    pub warnings: Vec<String>,
}

impl ImportResult {
    pub fn summary(&self) -> String {
        let mut s =
            format!("{} proxy server(s), {} chain(s), {} rule(s)", self.proxies.len(), self.chains.len(), self.rules.len());
        if !self.warnings.is_empty() {
            s.push_str(&format!(", {} warning(s)", self.warnings.len()));
        }
        s
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ImportError(pub String);

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ImportError {}

fn fail<T>(message: impl Into<String>) -> Result<T, ImportError> {
    Err(ImportError(message.into()))
}

/// XML starts with `<` (optionally after a BOM and whitespace); anything else is treated as binary.
pub fn looks_binary(head: &[u8]) -> bool {
    let mut i = 0;
    if head.starts_with(&[0xEF, 0xBB, 0xBF]) {
        i = 3;
    } else if head.starts_with(&[0xFF, 0xFE]) || head.starts_with(&[0xFE, 0xFF]) {
        return false; // UTF-16 text: let the XML parser decide
    }
    while i < head.len() && matches!(head[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i >= head.len() || head[i] != b'<'
}

/// Imports either format from raw file bytes.
pub fn import_bytes(bytes: &[u8]) -> Result<ImportResult, ImportError> {
    if prs::is_prsx(bytes) {
        return import_binary(bytes);
    }
    if looks_binary(&bytes[..bytes.len().min(64)]) {
        return fail(
            "This file is binary but not a recognised ProxyCap ruleset (no $PRSX header).\n\n\
             Import ProxyCap's machine.prs or an XML ruleset export (<proxycap_ruleset>).",
        );
    }
    import_xml(&decode_text(bytes))
}

/// Reads a file even while ProxyCap holds it open (std opens with full sharing on Windows).
pub fn import_file(path: &std::path::Path) -> Result<ImportResult, ImportError> {
    let bytes = std::fs::read(path).map_err(|e| ImportError(format!("Could not read {}: {e}", path.display())))?;
    import_bytes(&bytes)
}

fn decode_text(bytes: &[u8]) -> String {
    let utf16 = |b: &[u8], le: bool| -> String {
        let units: Vec<u16> =
            b.as_chunks::<2>().0.iter().map(|c| if le { u16::from_le_bytes(*c) } else { u16::from_be_bytes(*c) }).collect();
        String::from_utf16_lossy(&units)
    };
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        utf16(rest, true)
    } else if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        utf16(rest, false)
    } else {
        String::from_utf8_lossy(bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes)).into_owned()
    }
}

fn unique_name<'a>(name: &str, taken: impl IntoIterator<Item = &'a String>) -> String {
    let taken: Vec<String> = taken.into_iter().map(|t| t.to_lowercase()).collect();
    if !taken.contains(&name.to_lowercase()) {
        return name.to_string();
    }
    (2..).map(|i| format!("{name} ({i})")).find(|c| !taken.contains(&c.to_lowercase())).unwrap()
}

/// Adds the imported items to `config`. `replace` clears existing proxies, chains and rules first.
pub fn apply(config: &mut Config, import: ImportResult, replace: bool, enable_remote_dns: bool) {
    let ImportResult { mut proxies, mut chains, rules, remote_dns_exceptions, .. } = import;
    if replace {
        config.proxies.clear();
        config.chains.clear();
        config.rules.clear();
    } else {
        let mut names: Vec<String> = config.proxies.iter().map(|p| p.name.clone()).collect();
        for p in &mut proxies {
            p.name = unique_name(&p.name, &names);
            names.push(p.name.clone());
        }
        let mut names: Vec<String> = config.chains.iter().map(|c| c.name.clone()).collect();
        for c in &mut chains {
            c.name = unique_name(&c.name, &names);
            names.push(c.name.clone());
        }
    }
    config.proxies.extend(proxies);
    config.chains.extend(chains);
    config.rules.extend(rules);
    if enable_remote_dns {
        config.settings.dns_mode = DnsMode::FakeIp;
    }
    if !remote_dns_exceptions.is_empty() {
        let mut existing: Vec<String> = config
            .settings
            .fake_ip_exclude_domains
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        for e in remote_dns_exceptions {
            if !existing.iter().any(|x| x.eq_ignore_ascii_case(&e)) {
                existing.push(e);
            }
        }
        config.settings.fake_ip_exclude_domains = existing.join(";");
    }
}

// ---------------------------------------------------------------------------------------------------------------
// XML

#[derive(Debug, Default)]
struct Element {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<Element>,
}

impl Element {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attributes.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name.eq_ignore_ascii_case(name))
    }

    /// `<collection><item/>...</collection>` items.
    fn items<'a>(&'a self, collection: &'a str, item: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children_named(collection).flat_map(move |c| c.children_named(item))
    }
}

fn local_name(raw: &[u8]) -> String {
    let name = String::from_utf8_lossy(raw);
    name.rsplit(':').next().unwrap_or_default().to_string()
}

fn element(start: &BytesStart) -> Result<Element, ImportError> {
    let mut attributes = Vec::new();
    for a in start.attributes() {
        let a = a.map_err(|e| ImportError(format!("Invalid XML: {e}")))?;
        let value = a.unescape_value().map_err(|e| ImportError(format!("Invalid XML: {e}")))?.into_owned();
        attributes.push((local_name(a.key.as_ref()), value));
    }
    Ok(Element { name: local_name(start.name().as_ref()), attributes, children: Vec::new() })
}

fn parse_xml(xml: &str) -> Result<Element, ImportError> {
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    loop {
        match reader.read_event().map_err(|e| ImportError(format!("Invalid XML: {e}")))? {
            Event::Start(start) => stack.push(element(&start)?),
            Event::Empty(start) => {
                let e = element(&start)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(e),
                    None => root = root.or(Some(e)),
                }
            }
            Event::End(_) => {
                let done = stack.pop().ok_or_else(|| ImportError("Invalid XML: unbalanced tags.".into()))?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(done),
                    None => root = root.or(Some(done)),
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    root.ok_or_else(|| ImportError("Invalid XML: no root element.".into()))
}

fn parse_bool(text: Option<&str>) -> bool {
    matches!(text.map(|t| t.trim().to_ascii_lowercase()).as_deref(), Some("true" | "yes" | "1"))
}

fn parse_int(text: Option<&str>) -> Option<i64> {
    text?.trim().parse().ok()
}

pub fn import_xml(xml: &str) -> Result<ImportResult, ImportError> {
    let root = parse_xml(xml)?;
    if !root.name.eq_ignore_ascii_case("proxycap_ruleset") {
        return fail("Not a ProxyCap XML ruleset: the root element must be <proxycap_ruleset>.");
    }
    let mut result = ImportResult::default();
    let mut proxies_by_name: HashMap<String, usize> = HashMap::new();
    let mut chains_by_name: HashMap<String, usize> = HashMap::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut default_proxy: Option<usize> = None;

    for e in root.items("proxy_servers", "proxy_server") {
        let name = e.attr("name").map(String::from).unwrap_or_else(|| format!("Proxy {}", result.proxies.len() + 1));
        let type_text = e.attr("type").unwrap_or("socks5").trim().to_ascii_lowercase();
        let kind = match type_text.as_str() {
            "socks5" => ProxyType::Socks5,
            "socks4" => ProxyType::Socks4,
            "http" => ProxyType::Http,
            _ => {
                result.warnings.push(format!(
                    "Proxy '{name}': type '{type_text}' is not supported by Proxidize (supported: socks5, socks4, http); skipped."
                ));
                skipped.push(name.to_lowercase());
                continue;
            }
        };
        let taken: Vec<String> = result.proxies.iter().map(|p| p.name.clone()).collect();
        let mut proxy = ProxyServer {
            name: unique_name(&name, &taken),
            kind,
            host: e.attr("hostname").or(e.attr("host")).unwrap_or("127.0.0.1").to_string(),
            port: parse_int(e.attr("port"))
                .filter(|p| (1..=65535).contains(p))
                .map(|p| p as u16)
                .unwrap_or(if kind == ProxyType::Http { 8080 } else { 1080 }),
            ..Default::default()
        };
        let auth = e.attr("auth_method").unwrap_or("none").trim().to_ascii_lowercase();
        match auth.as_str() {
            "none" | "" => {}
            "password" => {
                proxy.username = e.attr("username").map(String::from);
                proxy.password = e.attr("password").map(String::from);
                if proxy.username.as_deref().unwrap_or_default().is_empty() {
                    result.warnings.push(format!(
                        "Proxy '{name}': password authentication without a username; imported without credentials."
                    ));
                }
            }
            other => result
                .warnings
                .push(format!("Proxy '{name}': authentication method '{other}' is not supported; imported without credentials.")),
        }
        if parse_bool(e.attr("is_default")) {
            default_proxy = Some(result.proxies.len());
        }
        proxies_by_name.insert(name.to_lowercase(), result.proxies.len());
        result.proxies.push(proxy);
    }

    for e in root.items("proxy_chains", "proxy_chain") {
        let name = e.attr("name").map(String::from).unwrap_or_else(|| format!("Chain {}", result.chains.len() + 1));
        let taken: Vec<String> = result.chains.iter().map(|c| c.name.clone()).collect();
        let mut chain = ProxyChain { name: unique_name(&name, &taken), ..Default::default() };
        let mut broken = false;
        for hop in e.children_named("proxy_server") {
            let hop_name = hop.attr("name").unwrap_or_default();
            match proxies_by_name.get(&hop_name.to_lowercase()) {
                Some(&i) => chain.proxy_ids.push(result.proxies[i].id.clone()),
                None => {
                    result
                        .warnings
                        .push(format!("Chain '{name}': hop '{hop_name}' was skipped or not found; chain not imported."));
                    broken = true;
                    break;
                }
            }
        }
        if broken || chain.proxy_ids.is_empty() {
            skipped.push(name.to_lowercase());
            continue;
        }
        chains_by_name.insert(name.to_lowercase(), result.chains.len());
        result.chains.push(chain);
    }

    for e in root.items("routing_rules", "routing_rule") {
        let name = e.attr("name").map(String::from).unwrap_or_else(|| format!("Rule {}", result.rules.len() + 1));
        let mut rule = Rule {
            name: name.clone(),
            enabled: !parse_bool(e.attr("disabled")),
            resolve_remotely: parse_bool(e.attr("remote_dns")),
            action: match e.attr("action").unwrap_or("proxy").trim().to_ascii_lowercase().as_str() {
                "direct" => RuleAction::Direct,
                "block" => RuleAction::Block,
                _ => RuleAction::Proxy,
            },
            transport: match e.attr("transports").unwrap_or("all").trim().to_ascii_lowercase().as_str() {
                "tcp" => TransportFilter::Tcp,
                "udp" => TransportFilter::Udp,
                _ => TransportFilter::Both,
            },
            ..Default::default()
        };

        if rule.action == RuleAction::Proxy {
            let refs: Vec<&Element> = e.children_named("proxy_or_chain").collect();
            let ref_name = refs.first().and_then(|r| r.attr("name"));
            if refs.len() > 1 {
                result.warnings.push(format!(
                    "Rule '{name}': several proxies listed; Proxidize uses the first ('{}').",
                    ref_name.unwrap_or_default()
                ));
            }
            let key = ref_name.map(str::to_lowercase);
            if let Some(&i) = key.as_ref().and_then(|k| proxies_by_name.get(k)) {
                rule.route_id = Some(result.proxies[i].id.clone());
            } else if let Some(&i) = key.as_ref().and_then(|k| chains_by_name.get(k)) {
                rule.route_id = Some(result.chains[i].id.clone());
            } else if let (None, Some(i)) = (ref_name, default_proxy) {
                rule.route_id = Some(result.proxies[i].id.clone());
            } else {
                rule.enabled = false;
                rule.name = format!("{name} (proxy unavailable)");
                let shown = ref_name.unwrap_or("(none)");
                result.warnings.push(if key.as_ref().is_some_and(|k| skipped.contains(k)) {
                    format!("Rule '{name}': its proxy/chain '{shown}' was not imported; rule imported disabled.")
                } else {
                    format!("Rule '{name}': proxy/chain '{shown}' not found; rule imported disabled.")
                });
            }
            if rule.resolve_remotely && rule.enabled {
                result.uses_remote_dns = true;
            }
        }

        for program in e.items("programs", "program") {
            let Some(path) = program.attr("path").map(|p| p.trim().trim_matches('"')).filter(|p| !p.is_empty()) else { continue };
            if parse_bool(program.attr("dir_included")) {
                let dir = if path.ends_with('\\') || path.ends_with('/') { path.to_string() } else { format!("{path}\\") };
                rule.programs.push(format!("{dir}*"));
            } else {
                rule.programs.push(path.to_string());
            }
        }
        for range in e.items("ports", "port_range") {
            let Some(first) = parse_int(range.attr("first")) else { continue };
            let last = parse_int(range.attr("last")).unwrap_or(first);
            rule.ports.push(if first == last { first.to_string() } else { format!("{first}-{last}") });
        }
        for range in e.items("ip_addresses", "ip_range") {
            let Some(ip) = range.attr("ip").map(str::trim).filter(|s| !s.is_empty()) else { continue };
            let max = if ip.contains(':') { 128 } else { 32 };
            rule.destinations.push(match parse_int(range.attr("mask")) {
                Some(mask) if mask < max => format!("{ip}/{mask}"),
                _ => ip.to_string(),
            });
        }
        for host in e.items("hostnames", "hostname") {
            if let Some(w) = host.attr("wildcard").or(host.attr("name")).map(str::trim).filter(|s| !s.is_empty()) {
                rule.destinations.push(w.to_string());
            }
        }
        for exception in e.items("remote_dns_exceptions", "remote_dns_exception") {
            if let Some(w) = exception.attr("wildcard").map(str::trim).filter(|s| !s.is_empty()) {
                if !result.remote_dns_exceptions.iter().any(|x| x.eq_ignore_ascii_case(w)) {
                    result.remote_dns_exceptions.push(w.to_string());
                }
            }
        }
        result.rules.push(rule);
    }

    if !result.remote_dns_exceptions.is_empty() {
        result.warnings.push(
            "Remote DNS exceptions are per rule in ProxyCap; Proxidize applies them globally (Settings > Fake IP excluded domains).".into(),
        );
    }
    Ok(result)
}

// ---------------------------------------------------------------------------------------------------------------
// Binary machine.prs

/// Imports a binary machine.prs. Type code 1 is SOCKS5; unknown codes come in as SOCKS5 with a warning. Passwords
/// are obfuscated and never read: imported usernames need their password re-entered. Chains, ports and
/// destinations aren't recoverable, so rules match by program only.
pub fn import_binary(data: &[u8]) -> Result<ImportResult, ImportError> {
    let parsed = prs::parse(data)?;
    if parsed.proxies.is_empty() && parsed.rules.is_empty() {
        return fail("No proxies or rules could be read from this machine.prs.");
    }
    let mut result = ImportResult::default();
    let mut unknown_codes: BTreeMap<u32, usize> = BTreeMap::new();
    let mut with_user: Vec<String> = Vec::new();
    for record in &parsed.proxies {
        let taken: Vec<String> = result.proxies.iter().map(|p| p.name.clone()).collect();
        let mut proxy = ProxyServer {
            name: unique_name(&record.name, &taken),
            kind: ProxyType::Socks5,
            host: record.host.clone(),
            port: record.port,
            ..Default::default()
        };
        if record.type_code != 1 {
            *unknown_codes.entry(record.type_code).or_default() += 1;
        }
        if let Some(user) = &record.username {
            proxy.username = Some(user.clone());
            with_user.push(proxy.name.clone());
        }
        result.proxies.push(proxy);
    }
    if !with_user.is_empty() {
        result.warnings.push(format!(
            "{} proxy(s) use a username ({}). ProxyCap stores passwords obfuscated, so they were not imported - re-enter them in Proxy servers.",
            with_user.len(),
            with_user.join(", ")
        ));
    }
    if !unknown_codes.is_empty() {
        let found: Vec<String> = unknown_codes.iter().map(|(code, n)| format!("code {code} x{n}")).collect();
        result.warnings.push(format!(
            "Unrecognised ProxyCap proxy type codes ({}) were imported as SOCKS5. Check those proxies' type (only code 1 = SOCKS5 is confirmed).",
            found.join(", ")
        ));
    }

    let mut flagged: Vec<String> = Vec::new();
    for record in &parsed.rules {
        let mut rule = Rule {
            name: record.name.clone(),
            enabled: true,
            transport: match record.transports {
                Some(1) => TransportFilter::Tcp,
                Some(2) => TransportFilter::Udp,
                _ => TransportFilter::Both,
            },
            resolve_remotely: record.remote_dns,
            programs: record.programs.iter().map(|p| map_binary_program(p)).collect(),
            ..Default::default()
        };
        if record.action == 1 && record.remote_dns {
            result.uses_remote_dns = true;
        }
        if record.tail_flag == Some(1) {
            flagged.push(format!("'{}'", record.name));
        }
        match record.action {
            0 => rule.action = RuleAction::Direct,
            2 => rule.action = RuleAction::Block,
            1 => {
                rule.action = RuleAction::Proxy;
                if record.is_chain {
                    rule.enabled = false;
                    rule.name.push_str(" (chain)");
                    result.warnings.push(format!(
                        "Rule '{}': uses a proxy chain, which the binary format doesn't expose; imported disabled. Recreate the chain and pick it in the rule.",
                        record.name
                    ));
                } else if let Some(p) = result.proxies.get(record.proxy_index as usize) {
                    rule.route_id = Some(p.id.clone());
                } else {
                    rule.enabled = false;
                    rule.name.push_str(" (proxy unavailable)");
                    result
                        .warnings
                        .push(format!("Rule '{}': points at a proxy that could not be read; imported disabled.", record.name));
                }
            }
            other => {
                rule.action = RuleAction::Direct;
                rule.enabled = false;
                result.warnings.push(format!("Rule '{}': unknown action code {other}; imported disabled.", record.name));
            }
        }
        result.rules.push(rule);
    }

    if parsed.declared_rule_count == 0 && !parsed.rules.is_empty() {
        result.warnings.push(
            "The rule count in machine.prs could not be located (the first rule lists no programs); rules were recovered by pattern and some may be missing."
                .into(),
        );
    }
    if parsed.declared_rule_count > parsed.rules.len() {
        result.warnings.push(format!(
            "machine.prs declares {} rules but only {} could be read; rules without programs (IP / host name only) aren't recoverable from the binary format.",
            parsed.declared_rule_count,
            parsed.rules.len()
        ));
    }
    if !flagged.is_empty() {
        result.warnings.push(format!(
            "Rule(s) {} carry a ProxyCap flag Proxidize can't identify (possibly 'disabled' in ProxyCap). They were imported enabled - untick them if they shouldn't be active.",
            flagged.join(", ")
        ));
    }
    let mut by_user: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for p in &result.proxies {
        if let Some(u) = &p.username {
            by_user.entry(u).or_default().push(&p.name);
        }
    }
    for names in by_user.values().filter(|n| n.len() > 1) {
        result.warnings.push(format!(
            "{} share one username - select them in Proxy servers and use 'Credentials...' to set the password once.",
            names.join(", ")
        ));
    }
    result.warnings.push(
        "Binary .prs import covers proxies and program-to-proxy rules (transports and remote DNS are read where recognisable). Ports, destinations and chains need an XML export to carry over."
            .into(),
    );
    Ok(result)
}

/// Program entries without ".exe" are folders in ProxyCap (they match everything beneath them).
fn map_binary_program(path: &str) -> String {
    let path = path.trim().trim_matches('"');
    if path.to_ascii_lowercase().ends_with(".exe") || path.contains(['*', '?']) {
        path.to_string()
    } else {
        format!("{}\\*", path.trim_end_matches(['\\', '/']))
    }
}

/// The reverse-engineered "$PRSX" layout, little-endian:
///
/// ```text
/// "$PRSX" + 16-byte digest + ASCII version ("537") + u32 proxyCount
///   proxy: str name, u32 type, str host, u32 port, u32 authMethod, str username, str password(obfuscated), zero fields
/// u32 chainCount, u32 ?, u32 ruleCount
///   rule:  str name, u32[6] {action, isChain, proxyIndex, remoteDns, 0, programCount}, programCount x (str path, u32), tail
/// str = u32 charCount + charCount UTF-16LE chars
/// ```
///
/// Records are located by pattern and validated (printable name, type <= 32, host without spaces, port 1-65535),
/// so unknown fields don't matter. Only proxies with name/host/port and rules that list programs are recoverable.
pub mod prs {
    use super::{fail, ImportError};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ProxyRecord {
        pub name: String,
        /// Confirmed: 1 = SOCKS5. Other codes are not decoded yet.
        pub type_code: u32,
        pub host: String,
        pub port: u16,
        pub auth_method: u32,
        /// The password that follows is obfuscated and deliberately never read.
        pub username: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RuleRecord {
        pub name: String,
        /// 1 = proxy, 0 = direct, 2 = block.
        pub action: u32,
        pub is_chain: bool,
        pub proxy_index: u32,
        pub programs: Vec<String>,
        /// Header field after the proxy index: lines up with the XML `remote_dns` attribute.
        pub remote_dns: bool,
        /// From the rule tail when readable: 1 = TCP, 2 = UDP, 3 = both.
        pub transports: Option<u32>,
        /// Last tail field: 0 normally, seen as 1 once (meaning unconfirmed, possibly "disabled").
        pub tail_flag: Option<u32>,
    }

    #[derive(Debug, Default)]
    pub struct Ruleset {
        pub version: String,
        pub proxies: Vec<ProxyRecord>,
        pub rules: Vec<RuleRecord>,
        /// Rule count stored in the file; can exceed `rules.len()` when some rules aren't recoverable.
        pub declared_rule_count: usize,
    }

    const HEADER: usize = 5 + 16; // "$PRSX" + digest

    pub fn is_prsx(data: &[u8]) -> bool {
        data.len() > 5 && data.starts_with(b"$PRSX")
    }

    fn u(b: &[u8], o: usize) -> u32 {
        b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap())).unwrap_or(u32::MAX)
    }

    /// A length-prefixed UTF-16LE string of printable characters. Returns it and the offset after it.
    fn s(b: &[u8], o: usize, max: u32) -> Option<(String, usize)> {
        let n = u(b, o);
        if n == u32::MAX || n > max || o + 4 + 2 * n as usize > b.len() {
            return None;
        }
        let units: Vec<u16> =
            b[o + 4..o + 4 + 2 * n as usize].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        let text = String::from_utf16_lossy(&units);
        if text.chars().any(|c| (c as u32) < 32) {
            return None;
        }
        Some((text, o + 4 + 2 * n as usize))
    }

    pub fn parse(b: &[u8]) -> Result<Ruleset, ImportError> {
        if !is_prsx(b) {
            return fail("Not a ProxyCap binary ruleset: the file does not start with $PRSX.");
        }
        if b.len() < HEADER + 4 {
            return fail("ProxyCap ruleset is truncated.");
        }
        let mut result = Ruleset::default();
        let mut o = HEADER;
        let start = o;
        while o < b.len() && b[o].is_ascii_digit() {
            o += 1;
        }
        result.version = String::from_utf8_lossy(&b[start..o]).into_owned();
        let proxy_count = u(b, o);
        if proxy_count > 1000 {
            return fail("Unrecognised .prs layout (implausible proxy count).");
        }
        o += 4;

        for _ in 0..proxy_count {
            let mut found = None;
            let mut p = o;
            while found.is_none() && p + 16 < b.len() {
                found = read_proxy(b, p).map(|(record, next)| {
                    result.proxies.push(record);
                    next
                });
                p += 1;
            }
            match found {
                Some(next) => o = next,
                None => break,
            }
        }

        // Rules: the first spot where a u32 count is followed by a well-formed rule whose programs look like paths.
        let proxies = result.proxies.len();
        let mut p = o;
        while p + 8 < b.len() {
            let count = u(b, p);
            if count == 0 || count > 1000 {
                p += 1;
                continue;
            }
            let Some((first, mut cur)) = read_rule(b, p + 4, proxies) else {
                p += 1;
                continue;
            };
            result.declared_rule_count = count as usize;
            result.rules.push(first);
            for _ in 1..count {
                match scan_rule(b, cur, proxies) {
                    Some((rule, end)) => {
                        result.rules.push(rule);
                        cur = end;
                    }
                    None => break,
                }
            }
            break;
        }

        // The count is only found through a rule that lists programs. If the first rule has none (IP / host name
        // only), collect every recognisable rule after the proxies instead.
        if result.rules.is_empty() {
            let mut cur = o;
            while let Some((rule, end)) = scan_rule(b, cur, proxies) {
                result.rules.push(rule);
                cur = end;
            }
        }
        Ok(result)
    }

    fn read_proxy(b: &[u8], p: usize) -> Option<(ProxyRecord, usize)> {
        let (name, q) = s(b, p, 128).filter(|(n, _)| !n.is_empty())?;
        let type_code = u(b, q);
        if type_code > 32 {
            return None;
        }
        let (host, q2) = s(b, q + 4, 256).filter(|(h, _)| !h.is_empty() && !h.contains(' '))?;
        let port = u(b, q2);
        if port == 0 || port > 65535 {
            return None;
        }
        // The username follows the auth method. The obfuscated password after it is never read, but the next scan
        // resumes after the username so the password bytes can't be mistaken for a proxy name.
        let auth = u(b, q2 + 4);
        let mut next = q2 + 4;
        let mut username = None;
        if auth != u32::MAX && auth <= 16 {
            if let Some((user, after)) = s(b, q2 + 8, 256) {
                next = after;
                username = Some(user).filter(|u| !u.is_empty());
            }
        }
        let record = ProxyRecord {
            name,
            type_code,
            host,
            port: port as u16,
            auth_method: if auth == u32::MAX { 0 } else { auth },
            username,
        };
        Some((record, next))
    }

    fn scan_rule(b: &[u8], from: usize, proxies: usize) -> Option<(RuleRecord, usize)> {
        (from..b.len().saturating_sub(8)).find_map(|start| read_rule(b, start, proxies))
    }

    fn read_rule(b: &[u8], o: usize, proxies: usize) -> Option<(RuleRecord, usize)> {
        let (name, q) = s(b, o, 256).filter(|(n, _)| !n.is_empty())?;
        let mut f = [0u32; 6];
        for (i, field) in f.iter_mut().enumerate() {
            *field = u(b, q + 4 * i);
            if *field == u32::MAX {
                return None;
            }
        }
        if f[0] > 8 || f[1] > 1 || f[5] > 256 {
            return None;
        }
        if f[1] == 0 && f[2] as usize >= proxies && proxies > 0 {
            return None;
        }
        let mut programs = Vec::new();
        let mut p = q + 24;
        for _ in 0..f[5] {
            let (path, n) = s(b, p, 1024)?;
            programs.push(path);
            p = n + 4;
        }
        if programs.is_empty() || !programs.iter().all(|x| x.contains('\\') || x.contains('.')) {
            return None;
        }
        // Tail seen as {ipCount?, hostCount?, portCount?, transports, flag}; only read when the first three are
        // zero, i.e. when no (undecoded) address/host/port lists follow.
        let (mut transports, mut tail_flag) = (None, None);
        if u(b, p) == 0 && u(b, p + 4) == 0 && u(b, p + 8) == 0 {
            let t = u(b, p + 12);
            let flag = u(b, p + 16);
            if (1..=3).contains(&t) {
                transports = Some(t);
                tail_flag = (flag <= 1).then_some(flag);
            }
        }
        let rule = RuleRecord {
            name,
            action: f[0],
            is_chain: f[1] == 1,
            proxy_index: f[2],
            programs,
            remote_dns: f[3] == 1,
            transports,
            tail_flag,
        };
        Some((rule, p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Ip;
    use crate::rules::{Protocol, Query, RuleEngine};

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<proxycap_ruleset version="535">
  <proxy_servers>
    <proxy_server name="Home SOCKS" type="socks5" hostname="proxy.home.lan" port="1080" auth_method="password" username="petros" password="pw" is_default="true"/>
    <proxy_server name="Office HTTP" type="http" hostname="10.1.1.1" port="3128" auth_method="none" is_default="false"/>
    <proxy_server name="Jump SSH" type="ssh" hostname="ssh.example.com" port="22" auth_method="key" is_default="false"/>
  </proxy_servers>
  <proxy_chains>
    <proxy_chain name="Double"><proxy_server name="Office HTTP"/><proxy_server name="Home SOCKS"/></proxy_chain>
    <proxy_chain name="Broken"><proxy_server name="Jump SSH"/></proxy_chain>
  </proxy_chains>
  <routing_rules>
    <routing_rule name="LAN direct" action="direct" remote_dns="false" disabled="false" transports="all">
      <ip_addresses><ip_range ip="192.168.0.0" mask="16"/><ip_range ip="10.0.0.1" mask="32"/></ip_addresses>
    </routing_rule>
    <routing_rule name="Block ads" action="block" remote_dns="false" disabled="false" transports="tcp">
      <hostnames><hostname wildcard="*.doubleclick.net"/></hostnames>
    </routing_rule>
    <routing_rule name="Game" action="proxy" remote_dns="true" disabled="false" transports="all">
      <proxy_or_chain name="Double"/>
      <programs><program path="D:\Games\WoW\Wow.exe" dir_included="false"/><program path="D:\Games\Other" dir_included="true"/></programs>
      <ports><port_range first="3724" last="3724"/><port_range first="8000" last="8100"/></ports>
      <remote_dns_exceptions><remote_dns_exception wildcard="*.blizzard.com"/></remote_dns_exceptions>
    </routing_rule>
    <routing_rule name="Chrome default proxy" action="proxy" remote_dns="true" disabled="true" transports="all">
      <programs><program path="C:\Program Files\Google\Chrome\Application\chrome.exe" dir_included="false"/></programs>
    </routing_rule>
    <routing_rule name="Via SSH" action="proxy" remote_dns="false" disabled="false" transports="all">
      <proxy_or_chain name="Jump SSH"/>
    </routing_rule>
  </routing_rules>
</proxycap_ruleset>"#;

    fn query<'a>(name: &'a str, path: &'a str, port: u16) -> Query<'a> {
        Query {
            protocol: Protocol::Tcp,
            process_id: 1,
            process_name: Some(name),
            process_path: Some(path),
            address: Ip::v4([1, 2, 3, 4]),
            hostnames: &[],
            port,
        }
    }

    #[test]
    fn xml_import() {
        let import = import_xml(SAMPLE).unwrap();
        assert_eq!((import.proxies.len(), import.chains.len(), import.rules.len()), (2, 1, 5));
        assert!(import.warnings.iter().any(|w| w.contains("ssh")));
        let socks = &import.proxies[0];
        assert_eq!((socks.kind, socks.host.as_str()), (ProxyType::Socks5, "proxy.home.lan"));
        assert_eq!((socks.username.as_deref(), socks.password.as_deref()), (Some("petros"), Some("pw")));
        assert_eq!(import.proxies[1].kind, ProxyType::Http);
        assert!(!import.proxies[1].has_credentials());
        let chain = &import.chains[0];
        assert_eq!(chain.proxy_ids, vec![import.proxies[1].id.clone(), socks.id.clone()]);

        assert_eq!(import.rules[0].action, RuleAction::Direct);
        assert_eq!(import.rules[0].destinations, vec!["192.168.0.0/16", "10.0.0.1"]);
        assert_eq!((import.rules[1].action, import.rules[1].transport), (RuleAction::Block, TransportFilter::Tcp));
        assert_eq!(import.rules[1].destinations, vec!["*.doubleclick.net"]);
        let game = &import.rules[2];
        assert_eq!(game.route_id.as_ref(), Some(&chain.id));
        assert!(game.resolve_remotely);
        assert_eq!(game.programs, vec![r"D:\Games\WoW\Wow.exe", r"D:\Games\Other\*"]);
        assert_eq!(game.ports, vec!["3724", "8000-8100"]);
        assert_eq!(import.remote_dns_exceptions, vec!["*.blizzard.com"]);
        assert!(import.uses_remote_dns);
        assert!(!import.rules[3].enabled);
        assert_eq!(import.rules[3].route_id.as_ref(), Some(&socks.id), "default proxy");
        assert!(!import.rules[4].enabled && import.rules[4].route_id.is_none());

        let mut config = Config::example();
        config.proxies[0].name = "Home SOCKS".into();
        apply(&mut config, import, false, true);
        assert_eq!(config.proxies.len(), 3);
        assert_eq!(config.proxies[1].name, "Home SOCKS (2)");
        assert_eq!(config.settings.dns_mode, DnsMode::FakeIp);
        assert!(config.settings.fake_ip_exclude_domains.contains("*.blizzard.com"));
        assert!(RuleEngine::new(&config).errors.is_empty());

        let mut replaced = Config::example();
        apply(&mut replaced, import_xml(SAMPLE).unwrap(), true, false);
        assert_eq!((replaced.proxies.len(), replaced.rules.len()), (2, 5));
    }

    #[test]
    fn detection() {
        assert!(looks_binary(&[0x50, 0x52, 0x53, 0, 1, 2]));
        assert!(!looks_binary(b"<?xml version=\"1.0\"?><proxycap_ruleset/>"));
        assert!(!looks_binary(b"\xEF\xBB\xBF  <proxycap_ruleset/>"));
        assert!(import_xml("<not_proxycap/>").is_err());
        assert!(import_bytes(b"\x00\x01binary").unwrap_err().0.contains("no $PRSX header"));
        // UTF-16 XML with BOM
        let utf16: Vec<u8> =
            [0xFF, 0xFE].into_iter().chain("<proxycap_ruleset/>".encode_utf16().flat_map(|u| u.to_le_bytes())).collect();
        assert_eq!(import_bytes(&utf16).unwrap().rules.len(), 0);
    }

    fn build_prsx(declared: u32, leading_programless: bool) -> Vec<u8> {
        let mut w: Vec<u8> = Vec::new();
        fn u32le(w: &mut Vec<u8>, v: u32) {
            w.extend_from_slice(&v.to_le_bytes());
        }
        fn st(w: &mut Vec<u8>, t: &str) {
            let units: Vec<u16> = t.encode_utf16().collect();
            u32le(w, units.len() as u32);
            for u in units {
                w.extend_from_slice(&u.to_le_bytes());
            }
        }
        fn rule(w: &mut Vec<u8>, name: &str, fields: [u32; 6], programs: &[&str]) {
            st(w, name);
            for f in fields {
                u32le(w, f);
            }
            for p in programs {
                st(w, p);
                u32le(w, 0);
            }
            u32le(w, 0);
            u32le(w, 0);
        }
        w.extend_from_slice(b"$PRSX");
        w.extend(1..=16u8);
        w.extend_from_slice(b"537");
        u32le(&mut w, 2);
        st(&mut w, "Home SOCKS");
        u32le(&mut w, 4);
        st(&mut w, "proxy.home.lan");
        u32le(&mut w, 1080);
        u32le(&mut w, 1);
        st(&mut w, "petros");
        u32le(&mut w, 4);
        w.extend_from_slice(&[0x9C, 0xA1, 0x33, 0x7E, 0x51, 0xD2, 0x08, 0xC4]);
        for _ in 0..3 {
            u32le(&mut w, 0);
        }
        st(&mut w, "Office HTTP");
        u32le(&mut w, 1);
        st(&mut w, "10.1.1.1");
        u32le(&mut w, 3128);
        u32le(&mut w, 0);
        st(&mut w, "");
        st(&mut w, "");
        for _ in 0..3 {
            u32le(&mut w, 0);
        }
        u32le(&mut w, 0);
        u32le(&mut w, 0);
        u32le(&mut w, declared);
        if leading_programless {
            rule(&mut w, "LAN direct", [0, 0, 0, 1, 0, 0], &[]);
        }
        rule(&mut w, "WoW", [1, 0, 0, 1, 0, 2], &[r"D:\Games\WoW\Wow.exe", r"D:\Games\Other"]);
        rule(&mut w, "Office apps", [1, 0, 1, 1, 0, 1], &[r"C:\Tools\app.exe"]);
        rule(&mut w, "Chain rule", [1, 1, 0, 1, 0, 1], &[r"C:\x\y.exe"]);
        rule(&mut w, "Block updater", [2, 0, 0, 1, 0, 1], &[r"C:\Updater\upd.exe"]);
        w
    }

    #[test]
    fn binary_import() {
        let bytes = build_prsx(4, false);
        let parsed = prs::parse(&bytes).unwrap();
        assert_eq!(parsed.version, "537");
        assert_eq!(parsed.proxies.len(), 2);
        assert_eq!(parsed.proxies[0].type_code, 4);
        assert_eq!(parsed.proxies[0].username.as_deref(), Some("petros"));
        assert_eq!(parsed.proxies[1].username, None);
        assert_eq!((parsed.rules.len(), parsed.declared_rule_count), (4, 4));

        let import = import_bytes(&bytes).unwrap();
        let home = &import.proxies[0];
        assert_eq!(
            (home.name.as_str(), home.host.as_str(), home.port, home.kind),
            ("Home SOCKS", "proxy.home.lan", 1080, ProxyType::Socks5)
        );
        assert_eq!((home.username.as_deref(), home.password.as_deref()), (Some("petros"), None));
        assert!(import.warnings.iter().any(|w| w.contains("code 4 x1") && !w.contains("code 1 x")));
        assert!(import.warnings.iter().any(|w| w.contains("re-enter")));
        let wow = &import.rules[0];
        assert_eq!((wow.action, wow.route_id.as_ref()), (RuleAction::Proxy, Some(&home.id)));
        assert_eq!(wow.programs, vec![r"D:\Games\WoW\Wow.exe", r"D:\Games\Other\*"]);
        assert!(wow.enabled && wow.resolve_remotely);
        assert_eq!(wow.transport, TransportFilter::Both);
        assert_eq!(import.rules[1].route_id.as_ref(), Some(&import.proxies[1].id));
        assert!(!import.rules[2].enabled && import.rules[2].route_id.is_none() && import.rules[2].name.ends_with("(chain)"));
        assert_eq!(import.rules[3].action, RuleAction::Block);
        assert!(import.uses_remote_dns);

        let mut config = Config::example();
        apply(&mut config, import, true, false);
        let engine = RuleEngine::new(&config);
        assert!(engine.errors.is_empty());
        let d = engine.evaluate(&query("Wow.exe", r"D:\Games\WoW\Wow.exe", 3724));
        assert_eq!((d.rule_name.as_str(), d.route[0].name.as_str()), ("WoW", "Home SOCKS"));
        assert_eq!(engine.evaluate(&query("x.exe", r"D:\Games\Other\sub\x.exe", 80)).rule_name, "WoW");

        let partial = import_binary(&build_prsx(5, false)).unwrap();
        assert!(partial.warnings.iter().any(|w| w.contains("declares 5 rules but only 4")));
        let programless = prs::parse(&build_prsx(5, true)).unwrap();
        assert_eq!((programless.declared_rule_count, programless.rules.len()), (0, 4));
        assert_eq!(programless.rules[0].name, "WoW");

        assert!(prs::parse(b"$PRSX0123456789").is_err());
        let mut empty = b"$PRSX".to_vec();
        empty.extend([0u8; 16]);
        empty.extend_from_slice(b"537");
        empty.extend(0u32.to_le_bytes());
        assert!(import_binary(&empty).is_err());
    }

    /// A real ProxyCap 537 machine.prs with usernames, hosts, password bytes and digest replaced (same layout).
    #[test]
    fn real_fixture() {
        let bytes = include_bytes!("../tests/fixtures/machine-sanitized.prs");
        let parsed = prs::parse(bytes).unwrap();
        assert_eq!(parsed.version, "537");
        assert_eq!((parsed.proxies.len(), parsed.declared_rule_count, parsed.rules.len()), (7, 8, 8));
        let names = ["NVPN_NL", "NVPN_AL", "NVPN_DE", "NVPN_TR", "NVPN_US", "NVPN_UA", "My proxy"];
        for (i, p) in parsed.proxies.iter().enumerate() {
            assert_eq!(p.name, names[i]);
            assert_eq!((p.type_code, p.host.as_str(), p.port, p.auth_method), (1, "198.51.100.50", 1080 + i as u16, 1));
            assert_eq!(p.username.as_deref(), Some("example_user"));
        }
        let expected = [
            ("Wow1", 0, r"F:\Wow1\Wow.exe"),
            ("Wow2", 1, r"F:\Wow2\Wow.exe"),
            ("Wow3", 2, r"F:\Wow3\Wow.exe"),
            ("Wow4", 3, r"F:\Wow4\Wow.exe"),
            ("Wow5", 5, r"F:\Wow5\Wow.exe"),
            ("Wow6", 4, r"F:\Wow6\Wow.exe"),
            ("My rule(2)", 6, r"F:\Wow\Wow.exe"),
            ("My rule", 1, r"F:\Downloads\FirefoxPortable\App\Firefox64\firefox.exe"),
        ];
        for (r, (name, index, program)) in parsed.rules.iter().zip(expected) {
            assert_eq!((r.name.as_str(), r.action, r.is_chain, r.proxy_index), (name, 1, false, index));
            assert_eq!(r.programs, vec![program]);
            assert!(r.remote_dns);
            assert_eq!((r.transports, r.tail_flag), (Some(3), Some(0)));
        }

        let import = import_bytes(bytes).unwrap();
        assert!(import.proxies.iter().all(|p| p.kind == ProxyType::Socks5));
        assert!(!import.warnings.iter().any(|w| w.contains("Unrecognised")));
        assert!(import.warnings.iter().any(|w| w.contains("7 proxy(s) use a username")));
        assert!(!import.warnings.iter().any(|w| w.contains("declares")));
        let mut config = Config::example();
        apply(&mut config, import, true, false);
        let engine = RuleEngine::new(&config);
        assert!(engine.errors.is_empty());
        assert_eq!(engine.evaluate(&query("Wow.exe", r"f:\wow5\wow.exe", 3724)).route[0].name, "NVPN_UA");
        assert_eq!(
            engine.evaluate(&query("firefox.exe", r"F:\Downloads\FirefoxPortable\App\Firefox64\firefox.exe", 443)).route[0].name,
            "NVPN_AL"
        );
        assert_eq!(engine.evaluate(&query("Wow.exe", r"F:\Wow7\Wow.exe", 3724)).action, RuleAction::Direct);
    }
}
