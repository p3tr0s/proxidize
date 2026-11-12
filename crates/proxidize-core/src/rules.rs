//! The rule engine: first enabled match wins, no match = direct.

use crate::config::{Config, ProxyServer, ProxyType, Rule, RuleAction, TransportFilter};
use crate::matching::{host_matches, wildcard, PortRange};
use crate::net::{Cidr, Ip, IpRange};
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// What is known about a new connection when the rules are evaluated.
#[derive(Clone, Debug)]
pub struct Query<'a> {
    pub protocol: Protocol,
    pub process_id: i64,
    pub process_name: Option<&'a str>,
    pub process_path: Option<&'a str>,
    pub address: Ip,
    pub hostnames: &'a [String],
    pub port: u16,
}

/// The outcome for a connection. Cheap to clone (shared).
#[derive(Clone, Debug)]
pub struct Decision {
    pub action: RuleAction,
    pub rule_id: Option<String>,
    pub rule_name: String,
    /// The rule restricts programs (used to teach the kill switch full paths).
    pub rule_has_programs: bool,
    /// Proxy hops in order; empty for Direct/Block.
    pub route: Arc<[ProxyServer]>,
    pub route_name: String,
    pub resolve_remotely: bool,
}

impl Decision {
    pub fn default_direct() -> Decision {
        Decision {
            action: RuleAction::Direct,
            rule_id: None,
            rule_name: "(default)".into(),
            rule_has_programs: false,
            route: Arc::from(Vec::new()),
            route_name: "Direct".into(),
            resolve_remotely: false,
        }
    }

    pub fn block(rule_name: impl Into<String>, route_name: impl Into<String>) -> Decision {
        Decision {
            action: RuleAction::Block,
            rule_id: None,
            rule_name: rule_name.into(),
            rule_has_programs: false,
            route: Arc::from(Vec::new()),
            route_name: route_name.into(),
            resolve_remotely: false,
        }
    }

    /// UDP can only be relayed through exactly one SOCKS5 proxy.
    pub fn supports_udp(&self) -> bool {
        self.route.len() == 1 && self.route[0].kind == ProxyType::Socks5
    }

    /// Stable key of the route (proxy ids), for grouping UDP associations.
    pub fn route_key(&self) -> String {
        let ids: Vec<&str> = self.route.iter().map(|p| p.id.as_str()).collect();
        format!("{}|{}|{:?}", ids.join(","), self.resolve_remotely, self.action)
    }
}

#[derive(Clone, Debug)]
enum ProgramMatcher {
    Name(String),
    Path(String),
}

impl ProgramMatcher {
    fn pattern(&self) -> &str {
        match self {
            ProgramMatcher::Name(p) | ProgramMatcher::Path(p) => p,
        }
    }

    /// A full path without wildcards (`F:\Wow1\Wow.exe`).
    fn is_exact_path(&self) -> bool {
        match self {
            ProgramMatcher::Path(p) => !p.contains(['*', '?']) && p.len() > 2 && p.as_bytes()[1] == b':',
            ProgramMatcher::Name(_) => false,
        }
    }

    fn matches(&self, name: Option<&str>, path: Option<&str>) -> bool {
        match self {
            ProgramMatcher::Path(p) => path.is_some_and(|path| wildcard(path, p)),
            ProgramMatcher::Name(p) => name.is_some_and(|name| wildcard(name, p)),
        }
    }
}

#[derive(Clone, Debug)]
enum DestinationMatcher {
    Cidr(Cidr),
    Range(IpRange),
    Host(String),
}

impl DestinationMatcher {
    fn matches(&self, q: &Query) -> bool {
        match self {
            DestinationMatcher::Cidr(c) => c.contains(q.address),
            DestinationMatcher::Range(r) => r.contains(q.address),
            DestinationMatcher::Host(h) => q.hostnames.iter().any(|n| host_matches(n, h)),
        }
    }
}

#[derive(Clone, Debug)]
struct CompiledRule {
    programs: Vec<ProgramMatcher>,
    destinations: Vec<DestinationMatcher>,
    ports: Vec<PortRange>,
    transport: TransportFilter,
    decision: Decision,
}

impl CompiledRule {
    fn is_whole_program(&self) -> bool {
        !self.programs.is_empty() && self.destinations.is_empty() && self.ports.is_empty()
    }

    fn matches_program(&self, name: Option<&str>, path: Option<&str>) -> bool {
        self.programs.iter().any(|p| p.matches(name, path))
    }

    fn matches(&self, q: &Query) -> bool {
        match (self.transport, q.protocol) {
            (TransportFilter::Tcp, Protocol::Udp) | (TransportFilter::Udp, Protocol::Tcp) => return false,
            _ => {}
        }
        (self.ports.is_empty() || self.ports.iter().any(|p| p.contains(q.port)))
            && (self.programs.is_empty() || self.matches_program(q.process_name, q.process_path))
            && (self.destinations.is_empty() || self.destinations.iter().any(|d| d.matches(q)))
    }
}

/// Immutable compiled rule set; build a new one whenever the configuration changes.
#[derive(Clone, Debug)]
pub struct RuleEngine {
    rules: Vec<CompiledRule>,
    /// Problems found while compiling (invalid patterns, missing routes).
    pub errors: Vec<String>,
    pub has_tcp_rules: bool,
    pub has_udp_rules: bool,
    /// Some enabled non-Direct rule is limited to specific programs.
    pub has_program_rules: bool,
    kill_switch_paths: Vec<String>,
    default_direct: Decision,
}

impl RuleEngine {
    pub fn new(config: &Config) -> RuleEngine {
        let mut errors = Vec::new();
        let rules: Vec<CompiledRule> =
            config.rules.iter().filter(|r| r.enabled).map(|r| compile(config, r, &mut errors)).collect();
        let non_direct = |r: &&CompiledRule| r.decision.action != RuleAction::Direct;
        let has_tcp_rules = rules.iter().filter(non_direct).any(|r| r.transport != TransportFilter::Udp);
        let has_udp_rules = rules.iter().filter(non_direct).any(|r| r.transport != TransportFilter::Tcp);
        let has_program_rules = rules.iter().filter(non_direct).any(|r| !r.programs.is_empty());
        let mut kill_switch_paths: Vec<String> = Vec::new();
        for rule in rules.iter().filter(non_direct).filter(|r| r.is_whole_program()) {
            for p in rule.programs.iter().filter(|p| p.is_exact_path()) {
                if !kill_switch_paths.iter().any(|k| k.eq_ignore_ascii_case(p.pattern())) {
                    kill_switch_paths.push(p.pattern().to_string());
                }
            }
        }
        RuleEngine {
            rules,
            errors,
            has_tcp_rules,
            has_udp_rules,
            has_program_rules,
            kill_switch_paths,
            default_direct: Decision::default_direct(),
        }
    }

    pub fn evaluate(&self, q: &Query) -> &Decision {
        self.rules.iter().find(|r| r.matches(q)).map(|r| &r.decision).unwrap_or(&self.default_direct)
    }

    /// Full program paths (no wildcards) of enabled whole-program Proxy/Block rules: those programs may never connect
    /// directly, so the kill switch blocks them whenever the engine isn't redirecting.
    pub fn kill_switch_paths(&self) -> &[String] {
        &self.kill_switch_paths
    }

    /// True when a program at `path` is covered by an enabled whole-program Proxy/Block rule (by path or file name).
    pub fn is_kill_switch_program(&self, path: Option<&str>) -> bool {
        let Some(path) = path.filter(|p| !p.is_empty()) else {
            return false;
        };
        let name = &path[path.rfind(['\\', '/']).map(|i| i + 1).unwrap_or(0)..];
        self.rules
            .iter()
            .filter(|r| r.decision.action != RuleAction::Direct && r.is_whole_program())
            .any(|r| r.matches_program(Some(name), Some(path)))
    }
}

/// Resolves a proxy or chain id to its hops. `None` when missing or empty.
pub fn resolve_route(config: &Config, route_id: Option<&str>) -> Option<(Vec<ProxyServer>, String)> {
    if let Some(p) = config.find_proxy(route_id) {
        return Some((vec![p.clone()], p.name.clone()));
    }
    let chain = config.find_chain(route_id)?;
    let hops: Option<Vec<ProxyServer>> = chain.proxy_ids.iter().map(|id| config.find_proxy(Some(id)).cloned()).collect();
    hops.filter(|h| !h.is_empty()).map(|h| (h, chain.name.clone()))
}

fn compile(config: &Config, rule: &Rule, errors: &mut Vec<String>) -> CompiledRule {
    let programs = rule
        .programs
        .iter()
        .map(|p| p.trim().trim_matches('"'))
        .filter(|p| !p.is_empty())
        .map(|p| {
            if p.contains(['\\', '/']) {
                ProgramMatcher::Path(p.replace('/', "\\"))
            } else {
                ProgramMatcher::Name(p.to_string())
            }
        })
        .collect();

    let mut destinations = Vec::new();
    for d in rule.destinations.iter().map(|d| d.trim()).filter(|d| !d.is_empty()) {
        if d.contains('/') {
            match Cidr::parse(d) {
                Some(c) => destinations.push(DestinationMatcher::Cidr(c)),
                None => errors.push(format!("Rule '{}': invalid network '{d}'.", rule.name)),
            }
        } else if let Some(r) = IpRange::parse(d) {
            destinations.push(DestinationMatcher::Range(r));
        } else if let Ok(ip) = d.parse::<Ip>() {
            destinations.push(DestinationMatcher::Cidr(Cidr::single(ip)));
        } else {
            destinations.push(DestinationMatcher::Host(d.to_string()));
        }
    }

    let mut ports = Vec::new();
    for p in rule.ports.iter().filter(|p| !p.trim().is_empty()) {
        match PortRange::parse(p) {
            Some(r) => ports.push(r),
            None => errors.push(format!("Rule '{}': invalid port '{p}'.", rule.name)),
        }
    }

    let has_programs = !rule.programs.is_empty();
    let decision = match rule.action {
        RuleAction::Proxy => match resolve_route(config, rule.route_id.as_deref()) {
            Some((route, name)) => Decision {
                action: RuleAction::Proxy,
                rule_id: Some(rule.id.clone()),
                rule_name: rule.name.clone(),
                rule_has_programs: has_programs,
                route: Arc::from(route),
                route_name: name,
                resolve_remotely: rule.resolve_remotely,
            },
            None => {
                errors.push(format!("Rule '{}': proxy/chain not found or empty; matching traffic is blocked.", rule.name));
                Decision {
                    rule_id: Some(rule.id.clone()),
                    rule_has_programs: has_programs,
                    ..Decision::block(rule.name.clone(), "Block (invalid route)")
                }
            }
        },
        RuleAction::Block => Decision {
            rule_id: Some(rule.id.clone()),
            rule_has_programs: has_programs,
            ..Decision::block(rule.name.clone(), "Block")
        },
        RuleAction::Direct => Decision {
            rule_id: Some(rule.id.clone()),
            rule_name: rule.name.clone(),
            rule_has_programs: has_programs,
            ..Decision::default_direct()
        },
    };

    CompiledRule { programs, destinations, ports, transport: rule.transport, decision }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyChain, ProxyServer};

    fn q<'a>(name: &'a str, path: &'a str, ip: &str, hosts: &'a [String], port: u16, protocol: Protocol) -> Query<'a> {
        Query {
            protocol,
            process_id: 1,
            process_name: Some(name),
            process_path: Some(path),
            address: ip.parse().unwrap(),
            hostnames: hosts,
            port,
        }
    }

    #[test]
    fn first_match_wins_and_conditions() {
        let proxy = ProxyServer { name: "P".into(), ..Default::default() };
        let mut config = Config { proxies: vec![proxy.clone()], ..Default::default() };
        config.rules.push(Rule {
            name: "lan direct".into(),
            action: RuleAction::Direct,
            destinations: vec!["192.168.0.0/16".into()],
            ..Default::default()
        });
        config.rules.push(Rule {
            name: "wow".into(),
            route_id: Some(proxy.id.clone()),
            programs: vec![r"F:\Wow1\Wow.exe".into()],
            ..Default::default()
        });
        config.rules.push(Rule {
            name: "browser 443".into(),
            route_id: Some(proxy.id.clone()),
            programs: vec!["firefox.exe".into()],
            ports: vec!["443".into()],
            transport: TransportFilter::Tcp,
            ..Default::default()
        });
        config.rules.push(Rule {
            name: "example".into(),
            action: RuleAction::Block,
            destinations: vec![".example.com".into(), "10.0.0.1-10.0.0.9".into()],
            ..Default::default()
        });
        config.rules.push(Rule { name: "off".into(), enabled: false, action: RuleAction::Block, ..Default::default() });
        let engine = RuleEngine::new(&config);
        assert!(engine.errors.is_empty());

        let none: Vec<String> = vec![];
        let wow = q("Wow.exe", r"f:\wow1\wow.exe", "203.0.113.5", &none, 8085, Protocol::Tcp);
        assert_eq!(engine.evaluate(&wow).rule_name, "wow");
        assert_eq!(engine.evaluate(&wow).route_name, "P");

        let lan = q("Wow.exe", r"F:\Wow1\Wow.exe", "192.168.1.5", &none, 80, Protocol::Tcp);
        assert_eq!(engine.evaluate(&lan).action, RuleAction::Direct, "first match");

        let ff = q("FIREFOX.EXE", r"C:\x\firefox.exe", "1.1.1.1", &none, 443, Protocol::Tcp);
        assert_eq!(engine.evaluate(&ff).rule_name, "browser 443");
        let ff_udp = q("firefox.exe", r"C:\x\firefox.exe", "1.1.1.1", &none, 443, Protocol::Udp);
        assert_eq!(engine.evaluate(&ff_udp).rule_name, "(default)", "TCP-only rule");

        let hosts = vec!["cdn.example.com".to_string()];
        let ex = q("any.exe", r"C:\any.exe", "8.8.8.8", &hosts, 80, Protocol::Tcp);
        assert_eq!(engine.evaluate(&ex).action, RuleAction::Block);
        let range = q("any.exe", r"C:\any.exe", "10.0.0.5", &none, 80, Protocol::Tcp);
        assert_eq!(engine.evaluate(&range).action, RuleAction::Block);
        assert!(engine.has_tcp_rules && engine.has_udp_rules && engine.has_program_rules);
    }

    #[test]
    fn invalid_routes_and_patterns() {
        let mut config = Config::default();
        config.rules.push(Rule { name: "missing".into(), route_id: Some("nope".into()), ..Default::default() });
        config.rules.push(Rule {
            name: "bad".into(),
            destinations: vec!["1.2.3.4/99".into()],
            ports: vec!["x".into()],
            action: RuleAction::Direct,
            ..Default::default()
        });
        let engine = RuleEngine::new(&config);
        assert_eq!(engine.errors.len(), 3);
        let none: Vec<String> = vec![];
        let d = engine.evaluate(&q("a.exe", r"C:\a.exe", "1.1.1.1", &none, 1, Protocol::Tcp));
        assert_eq!(d.action, RuleAction::Block, "missing route fails closed");
    }

    #[test]
    fn chains_and_udp_support() {
        let a = ProxyServer { name: "A".into(), ..Default::default() };
        let b = ProxyServer { name: "B".into(), kind: ProxyType::Http, ..Default::default() };
        let chain = ProxyChain { name: "AB".into(), proxy_ids: vec![a.id.clone(), b.id.clone()], ..Default::default() };
        let mut config = Config { proxies: vec![a.clone(), b], chains: vec![chain.clone()], ..Default::default() };
        config.rules.push(Rule { name: "via chain".into(), route_id: Some(chain.id.clone()), ..Default::default() });
        let engine = RuleEngine::new(&config);
        let none: Vec<String> = vec![];
        let d = engine.evaluate(&q("x.exe", r"C:\x.exe", "1.1.1.1", &none, 1, Protocol::Tcp));
        assert_eq!(d.route.len(), 2);
        assert_eq!(d.route_name, "AB");
        assert!(!d.supports_udp());
        let single = resolve_route(&config, Some(&a.id)).unwrap();
        assert_eq!(single.0.len(), 1);
    }

    #[test]
    fn kill_switch_program_set() {
        let proxy = ProxyServer { name: "P".into(), ..Default::default() };
        let id = Some(proxy.id.clone());
        let mut config = Config { proxies: vec![proxy], ..Default::default() };
        let mut add = |name: &str, action: RuleAction, programs: &[&str], ports: &[&str], enabled: bool, dests: &[&str]| {
            config.rules.push(Rule {
                name: name.into(),
                action,
                route_id: id.clone(),
                programs: programs.iter().map(|s| s.to_string()).collect(),
                ports: ports.iter().map(|s| s.to_string()).collect(),
                destinations: dests.iter().map(|s| s.to_string()).collect(),
                enabled,
                ..Default::default()
            })
        };
        add("Wow1", RuleAction::Proxy, &[r"F:\Wow1\Wow.exe"], &[], true, &[]);
        add("Wow2 twice", RuleAction::Proxy, &[r"F:\Wow2\Wow.exe", r"f:\wow1\wow.exe"], &[], true, &[]);
        add("by name", RuleAction::Proxy, &["firefox.exe"], &[], true, &[]);
        add("folder", RuleAction::Block, &[r"D:\Games\*"], &[], true, &[]);
        add("ports only", RuleAction::Proxy, &[r"C:\Tools\a.exe"], &["443"], true, &[]);
        add("direct", RuleAction::Direct, &[r"C:\Tools\b.exe"], &[], true, &[]);
        add("disabled", RuleAction::Proxy, &[r"C:\Tools\c.exe"], &[], false, &[]);
        add("any program", RuleAction::Proxy, &[], &[], true, &["*.example.com"]);
        let engine = RuleEngine::new(&config);
        assert_eq!(engine.kill_switch_paths(), &[r"F:\Wow1\Wow.exe".to_string(), r"F:\Wow2\Wow.exe".to_string()]);
        assert!(engine.is_kill_switch_program(Some(r"C:\Program Files\Mozilla Firefox\firefox.exe")));
        assert!(engine.is_kill_switch_program(Some(r"D:\Games\X\x.exe")));
        assert!(!engine.is_kill_switch_program(Some(r"C:\Tools\a.exe")));
        assert!(!engine.is_kill_switch_program(Some(r"C:\Tools\b.exe")));
        assert!(!engine.is_kill_switch_program(Some(r"C:\Tools\c.exe")));
        assert!(!engine.is_kill_switch_program(None));
    }
}
