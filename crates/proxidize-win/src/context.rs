//! State shared by the redirectors of one engine run.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

use proxidize_core::config::{RuleAction, Settings};
use proxidize_core::fakeip::{DnsCache, FakeIpPool};
use proxidize_core::log::LogHub;
use proxidize_core::matching::DomainScope;
use proxidize_core::net::{Ip, Target};
use proxidize_core::proxy::Connector;
use proxidize_core::relay::{ConnectionTracker, NatTable, RouteGuard};
use proxidize_core::resolve::HostResolver;
use proxidize_core::rules::{Decision, Protocol, Query, RuleEngine};

use crate::process::{ProcessDetails, Processes};

pub type RoutedCallback = Box<dyn Fn(&str) + Send + Sync>;

pub struct EngineContext {
    rules: RwLock<Arc<RuleEngine>>,
    strict: AtomicBool,
    log_direct: AtomicBool,
    udp_idle_seconds: AtomicU32,
    relay_port: AtomicU16,
    proxy_endpoints: RwLock<HashSet<(Ip, u16)>>,
    pub log: Arc<LogHub>,
    pub tracker: Arc<ConnectionTracker>,
    pub nat: Arc<NatTable>,
    pub processes: Arc<dyn Processes>,
    pub dns_cache: Arc<DnsCache>,
    pub fake_ips: Option<Arc<FakeIpPool>>,
    pub fake_scope: Option<DomainScope>,
    pub resolver: Arc<dyn HostResolver>,
    pub connector: Connector,
    pub resolver_port: u16,
    pub self_pid: u32,
    pub guard: Arc<RouteGuard>,
    pub runtime: tokio::runtime::Handle,
    /// A program matched by name/wildcard was routed (so the kill switch can learn its full path).
    pub program_routed: Option<RoutedCallback>,
}

pub struct ContextParts {
    pub settings: Settings,
    pub rules: Arc<RuleEngine>,
    pub log: Arc<LogHub>,
    pub tracker: Arc<ConnectionTracker>,
    pub nat: Arc<NatTable>,
    pub processes: Arc<dyn Processes>,
    pub dns_cache: Arc<DnsCache>,
    pub fake_ips: Option<Arc<FakeIpPool>>,
    pub fake_scope: Option<DomainScope>,
    pub resolver: Arc<dyn HostResolver>,
    pub connector: Connector,
    pub resolver_port: u16,
    pub self_pid: u32,
    pub guard: Arc<RouteGuard>,
    pub runtime: tokio::runtime::Handle,
    pub program_routed: Option<RoutedCallback>,
}

impl EngineContext {
    pub fn new(p: ContextParts) -> EngineContext {
        EngineContext {
            rules: RwLock::new(p.rules),
            strict: AtomicBool::new(p.settings.strict_mode),
            log_direct: AtomicBool::new(p.settings.log_direct_connections),
            udp_idle_seconds: AtomicU32::new(p.settings.udp_idle_timeout_seconds),
            relay_port: AtomicU16::new(0),
            proxy_endpoints: RwLock::default(),
            log: p.log,
            tracker: p.tracker,
            nat: p.nat,
            processes: p.processes,
            dns_cache: p.dns_cache,
            fake_ips: p.fake_ips,
            fake_scope: p.fake_scope,
            resolver: p.resolver,
            connector: p.connector,
            resolver_port: p.resolver_port,
            self_pid: p.self_pid,
            guard: p.guard,
            runtime: p.runtime,
            program_routed: p.program_routed,
        }
    }

    pub fn rules(&self) -> Arc<RuleEngine> {
        self.rules.read().unwrap().clone()
    }

    pub fn set_rules(&self, rules: Arc<RuleEngine>) {
        *self.rules.write().unwrap() = rules;
    }

    /// Settings that apply live, without restarting the engine.
    pub fn update_live_settings(&self, s: &Settings) {
        self.strict.store(s.strict_mode, Ordering::Relaxed);
        self.log_direct.store(s.log_direct_connections, Ordering::Relaxed);
        self.udp_idle_seconds.store(s.udp_idle_timeout_seconds, Ordering::Relaxed);
    }

    /// Fail closed (see `Settings::strict_mode`).
    pub fn strict(&self) -> bool {
        self.strict.load(Ordering::Relaxed)
    }

    pub fn log_direct(&self) -> bool {
        self.log_direct.load(Ordering::Relaxed)
    }

    pub fn udp_idle_ms(&self) -> u64 {
        self.udp_idle_seconds.load(Ordering::Relaxed).max(10) as u64 * 1000
    }

    pub fn relay_port(&self) -> u16 {
        self.relay_port.load(Ordering::Relaxed)
    }

    pub fn set_relay_port(&self, port: u16) {
        self.relay_port.store(port, Ordering::Relaxed);
    }

    pub fn set_proxy_endpoints(&self, endpoints: HashSet<(Ip, u16)>) {
        *self.proxy_endpoints.write().unwrap() = endpoints;
    }

    /// Traffic to a configured proxy server is never redirected (no loops).
    pub fn is_proxy_endpoint(&self, address: Ip, port: u16) -> bool {
        self.proxy_endpoints.read().unwrap().contains(&(address, port))
    }

    /// Strict mode: the connection must not be decided without knowing its program (owner unknown or exited, and
    /// there are program rules).
    pub fn must_drop_unidentified(&self, p: &ProcessDetails) -> bool {
        self.strict() && !matches!(p.pid, Some(0) | Some(4)) && !p.alive && self.rules().has_program_rules
    }

    pub fn evaluate(&self, protocol: Protocol, p: &ProcessDetails, address: Ip, hostnames: &[String], port: u16) -> Decision {
        let rules = self.rules();
        let query = Query {
            protocol,
            process_id: p.pid_i64(),
            process_name: Some(&p.name),
            process_path: p.path.as_deref(),
            address,
            hostnames,
            port,
        };
        rules.evaluate(&query).clone()
    }

    /// Reports a routed program so the kill switch can learn its full path.
    pub fn notify_routed(&self, p: &ProcessDetails, d: &Decision) {
        if d.action != RuleAction::Direct && d.rule_has_programs {
            if let (Some(path), Some(callback)) = (&p.path, &self.program_routed) {
                callback(path);
            }
        }
    }

    /// The host name to show and match for `address`: the fake IP's name, else the last sniffed DNS name.
    pub fn names_for(&self, address: Ip) -> (Option<String>, Vec<String>, bool) {
        if let Some(pool) = &self.fake_ips {
            if pool.contains(address) {
                let host = pool.host_for(address);
                let names = host.iter().cloned().collect();
                return (host, names, true);
            }
        }
        let names = self.dns_cache.names(address).unwrap_or_default();
        (names.last().cloned(), names, false)
    }
}

pub fn format_destination(host: Option<&str>, address: Ip, port: u16) -> String {
    match host {
        Some(h) => format!("{h}:{port}"),
        None => Target::Addr(address, port).to_string(),
    }
}
