//! One redirection session: diversion handles, relay, resolver, kill switch. Start, stop and live config changes.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use proxidize_core::config::{Config, DnsMode, RuleAction, Settings};
use proxidize_core::fakeip::{DnsCache, FakeIpPool};
use proxidize_core::health::Url;
use proxidize_core::log::LogHub;
use proxidize_core::matching::DomainScope;
use proxidize_core::net::{Cidr, Ip};
use proxidize_core::proxy::Connector;
use proxidize_core::relay::{ConnectionTracker, NatTable, RelayDeps, RelayServer, RouteGuard};
use proxidize_core::resolve::{choose_servers, HostResolver, UpstreamResolver};
use proxidize_core::rules::RuleEngine;

use crate::context::{ContextParts, EngineContext};
use crate::divert::{DivertError, DivertOpener, Layer};
use crate::dnsdivert::{self, Worker};
use crate::killswitch::{Filters, KillSwitch};
use crate::process::{ProcessResolver, SocketMonitor, SystemInfo};
use crate::tcp::{self, TcpRedirector};
use crate::udp::{self, UdpRedirector};

/// What the engine needs from the operating system.
pub trait Platform: Send + Sync + 'static {
    fn opener(&self) -> Arc<dyn DivertOpener>;
    fn system(&self) -> Arc<dyn SystemInfo>;
    fn filters(&self) -> Arc<dyn Filters>;
    fn adapter_dns_servers(&self) -> Vec<Ip>;
    fn flush_dns(&self) {}
    fn firewall_rule(&self, _port: u16, _log: &LogHub) {}
    fn self_pid(&self) -> u32 {
        std::process::id()
    }
    /// Where the relay listens; `None` = every address.
    fn relay_bind(&self) -> Option<IpAddr> {
        None
    }
    fn data_dir(&self) -> Option<PathBuf> {
        None
    }
}

struct Running {
    config: Config,
    ctx: Arc<EngineContext>,
    relay: Option<RelayServer>,
    tcp: Option<TcpRedirector>,
    udp: Option<UdpRedirector>,
    interceptor: Option<Worker>,
    sniffer: Option<Worker>,
    _monitor: SocketMonitor,
    _resolver: Arc<UpstreamResolver>,
}

struct Shared {
    platform: Arc<dyn Platform>,
    log: Arc<LogHub>,
    tracker: Arc<ConnectionTracker>,
    /// Survives restarts: a leaking proxy stays blocked.
    guard: Arc<RouteGuard>,
    kill_switch: KillSwitch,
    runtime: tokio::runtime::Runtime,
    running: Mutex<Option<Running>>,
    config: Mutex<Option<Config>>,
    /// Kept across restarts so programs' cached fake IPs stay valid.
    fake_ips: Mutex<Option<Arc<FakeIpPool>>>,
    routed: Arc<Mutex<Vec<String>>>,
    generation: AtomicU64,
    stop_maintenance: AtomicBool,
}

/// The redirection engine. Dropping it stops redirection; the kill switch's persistent blocks stay.
pub struct Engine {
    shared: Arc<Shared>,
    maintenance: Option<JoinHandle<()>>,
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

impl Engine {
    pub fn new(platform: Arc<dyn Platform>, log: Arc<LogHub>, tracker: Arc<ConnectionTracker>) -> Engine {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("proxidize-net")
            .enable_all()
            .build()
            .expect("tokio runtime");
        let learned = platform.data_dir().map(|d| d.join("killswitch-learned.txt"));
        let kill_switch = KillSwitch::new(platform.filters(), log.clone(), learned);
        let shared = Arc::new(Shared {
            platform,
            log,
            tracker,
            guard: Arc::new(RouteGuard::default()),
            kill_switch,
            runtime,
            running: Mutex::new(None),
            config: Mutex::new(None),
            fake_ips: Mutex::new(None),
            routed: Arc::default(),
            generation: AtomicU64::new(0),
            stop_maintenance: AtomicBool::new(false),
        });
        let worker = shared.clone();
        let maintenance =
            std::thread::Builder::new().name("proxidize maintenance".into()).spawn(move || worker.maintenance_loop()).unwrap();
        Engine { shared, maintenance: Some(maintenance) }
    }

    pub fn is_running(&self) -> bool {
        self.shared.running.lock().unwrap().is_some()
    }

    /// Changes whenever the engine starts or stops (for the UI).
    pub fn generation(&self) -> u64 {
        self.shared.generation.load(Ordering::Relaxed)
    }

    pub fn runtime(&self) -> tokio::runtime::Handle {
        self.shared.runtime.handle().clone()
    }

    pub fn log(&self) -> &Arc<LogHub> {
        &self.shared.log
    }

    pub fn tracker(&self) -> &Arc<ConnectionTracker> {
        &self.shared.tracker
    }

    pub fn guard(&self) -> &Arc<RouteGuard> {
        &self.shared.guard
    }

    pub fn nat_entries(&self) -> usize {
        self.shared.running.lock().unwrap().as_ref().map(|r| r.ctx.nat.len()).unwrap_or(0)
    }

    pub fn fake_ip_count(&self) -> usize {
        self.shared.fake_ips.lock().unwrap().as_ref().map(|f| f.len()).unwrap_or(0)
    }

    pub fn dropped_packets(&self) -> u64 {
        self.shared.running.lock().unwrap().as_ref().and_then(|r| r.tcp.as_ref()).map(|t| t.dropped()).unwrap_or(0)
    }

    /// Programs blocked by the kill switch whenever redirection isn't active.
    pub fn kill_switch_program_count(&self) -> usize {
        self.shared.kill_switch.protected_paths().len()
    }

    pub fn kill_switch_paths(&self) -> Vec<String> {
        self.shared.kill_switch.protected_paths()
    }

    /// Starts redirection with a copy of `config`. On error the engine stays stopped.
    pub fn start(&self, config: &Config) -> Result<(), String> {
        let mut running = self.shared.running.lock().unwrap();
        if running.is_some() {
            return Ok(());
        }
        *self.shared.config.lock().unwrap() = Some(config.clone());
        let started = self.shared.start_core(config.clone())?;
        *running = Some(started);
        self.shared.generation.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn stop(&self) {
        let mut running = self.shared.running.lock().unwrap();
        if let Some(r) = running.take() {
            self.shared.stop_core(r);
            self.shared.log.info("Engine stopped.");
            self.shared.generation.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Applies a new configuration. Rule and proxy changes are swapped in atomically (open connections keep their
    /// route); settings or capture changes restart the engine.
    pub fn apply_config(&self, config: &Config) -> Result<(), String> {
        let s = &self.shared;
        let mut running = s.running.lock().unwrap();
        *s.config.lock().unwrap() = Some(config.clone());
        let rules = Arc::new(RuleEngine::new(config));
        let Some(current) = running.as_mut() else {
            s.apply_kill_switch(config, &rules, false);
            return Ok(());
        };
        s.log.set_verbose(config.settings.verbose_logging);
        current.ctx.update_live_settings(&config.settings);
        let old_rules = current.ctx.rules();
        let restart = settings_key(&current.config.settings) != settings_key(&config.settings)
            || needs_tcp(&old_rules, &current.config.settings) != needs_tcp(&rules, &config.settings)
            || needs_udp(&old_rules, &current.config.settings) != needs_udp(&rules, &config.settings)
            || proxy_hosts(&current.config) != proxy_hosts(config);
        if restart {
            s.log.info("Configuration change requires an engine restart.");
            let old = running.take().unwrap();
            s.stop_core(old);
            match s.start_core(config.clone()) {
                Ok(r) => *running = Some(r),
                Err(e) => {
                    s.generation.fetch_add(1, Ordering::Relaxed);
                    return Err(e);
                }
            }
            s.generation.fetch_add(1, Ordering::Relaxed);
        } else {
            current.config = config.clone();
            for e in &rules.errors {
                s.log.warning(e.clone());
            }
            s.apply_kill_switch(config, &rules, true); // new protected programs are blocked before the swap
            current.ctx.set_rules(rules.clone());
            current.ctx.set_proxy_endpoints(s.proxy_endpoints(config, current.ctx.resolver.as_ref()));
            warn_about_local_dns(&s.log, config);
            s.log.info("Rules updated.");
        }
        Ok(())
    }

    /// Blocks traffic through these proxies (id -> reason). Newly blocked proxies lose their relayed connections.
    /// An empty map lifts every block.
    pub fn set_blocked_proxies(&self, blocked: HashMap<String, String>) {
        let added = self.shared.guard.set(blocked);
        if added.is_empty() {
            return;
        }
        let aborted = self
            .shared
            .running
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|r| r.relay.as_ref())
            .map(|r| r.abort_routes(&added))
            .unwrap_or(0);
        let mut message = format!("Blocked {} after the proxy check", plural(added.len(), "proxy", "proxies"));
        if aborted > 0 {
            message.push_str(&format!(" and reset {} through them", plural(aborted, "connection", "connections")));
        }
        self.shared.log.warning(message);
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop();
        self.shared.stop_maintenance.store(true, Ordering::Release);
        if let Some(t) = self.maintenance.take() {
            let _ = t.join();
        }
        self.shared.kill_switch.revoke_running_allowance();
    }
}

impl Shared {
    fn start_core(&self, config: Config) -> Result<Running, String> {
        let settings = config.settings.clone();
        self.log.set_verbose(settings.verbose_logging);
        self.log.info("Starting engine...");
        let rules = Arc::new(RuleEngine::new(&config));
        for e in &rules.errors {
            self.log.warning(e.clone());
        }
        warn_about_local_dns(&self.log, &config);

        // Kill switch first: protected programs stay blocked until redirection is fully up.
        if settings.kill_switch {
            self.apply_kill_switch(&config, &rules, false);
        }

        let mut fake_ips = None;
        let mut fake_scope = None;
        let mut fake_range = None;
        if settings.dns_mode == DnsMode::FakeIp {
            let mut pool = self.fake_ips.lock().unwrap();
            let wanted = Cidr::parse(&settings.fake_ip_range);
            if pool.as_ref().map(|p| Some(p.range())) != Some(wanted) {
                *pool = Some(Arc::new(
                    FakeIpPool::new(&settings.fake_ip_range)
                        .ok_or_else(|| format!("Invalid fake IP range '{}'.", settings.fake_ip_range))?,
                ));
            }
            let p = pool.clone().unwrap();
            fake_range = Some(p.range());
            fake_ips = Some(p);
            let mut excluded: Vec<String> =
                config.proxies.iter().map(|p| p.host.clone()).filter(|h| h.parse::<Ip>().is_err()).collect();
            if let Some(url) = Url::parse(&settings.health_check_url) {
                if url.host.parse::<Ip>().is_err() {
                    excluded.push(url.host); // the direct IP check must get the real address
                }
            }
            fake_scope = Some(DomainScope::new(&settings.fake_ip_domains, &settings.fake_ip_exclude_domains, excluded));
        }

        let _enter = self.runtime.enter();
        let servers = choose_servers(&settings.upstream_dns_servers, &self.platform.adapter_dns_servers(), fake_range);
        let resolver = Arc::new(
            UpstreamResolver::new(servers.clone(), settings.resolver_port, Duration::from_secs(3))
                .map_err(|e| format!("DNS resolver: {e}"))?,
        );
        let list: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
        self.log.info(format!("Upstream DNS: {} (source port {})", list.join(", "), resolver.local_port()));
        let as_resolver: Arc<dyn HostResolver> = resolver.clone();
        let connector = Connector::new(as_resolver.clone(), Duration::from_secs(settings.connect_timeout_seconds.max(3) as u64));
        let opener = self.platform.opener();
        let processes = ProcessResolver::new(self.platform.system(), self.log.clone());
        let monitor = processes.start_monitor(opener.as_ref());

        let routed = self.routed.clone();
        let nat = Arc::new(NatTable::default());
        let ctx = Arc::new(EngineContext::new(ContextParts {
            settings: settings.clone(),
            rules: rules.clone(),
            log: self.log.clone(),
            tracker: self.tracker.clone(),
            nat: nat.clone(),
            processes,
            dns_cache: Arc::new(DnsCache::default()),
            fake_ips: fake_ips.clone(),
            fake_scope,
            resolver: as_resolver.clone(),
            connector: connector.clone(),
            resolver_port: resolver.local_port(),
            self_pid: self.platform.self_pid(),
            guard: self.guard.clone(),
            runtime: self.runtime.handle().clone(),
            program_routed: Some(Box::new(move |path: &str| {
                let mut pending = routed.lock().unwrap();
                if pending.len() < 256 && !pending.iter().any(|p| p.eq_ignore_ascii_case(path)) {
                    pending.push(path.to_string());
                }
            })),
        }));
        ctx.set_proxy_endpoints(self.proxy_endpoints(&config, as_resolver.as_ref()));

        let mut running = Running {
            config: config.clone(),
            ctx: ctx.clone(),
            relay: None,
            tcp: None,
            udp: None,
            interceptor: None,
            sniffer: None,
            _monitor: monitor,
            _resolver: resolver.clone(),
        };
        let result = (|| -> Result<(), String> {
            let need_tcp = needs_tcp(&rules, &settings);
            if need_tcp {
                let relay = RelayServer::start(
                    settings.relay_port,
                    self.platform.relay_bind(),
                    RelayDeps {
                        nat: nat.clone(),
                        connector: connector.clone(),
                        resolver: as_resolver.clone(),
                        tracker: self.tracker.clone(),
                        log: self.log.clone(),
                        guard: self.guard.clone(),
                    },
                )
                .map_err(|e| e.to_string())?;
                ctx.set_relay_port(relay.port());
                self.log.info(format!("Relay listening on port {}.", relay.port()));
                if settings.manage_firewall_rule {
                    self.platform.firewall_rule(relay.port(), &self.log);
                }
                running.relay = Some(relay);
            }
            running.sniffer = Some(dnsdivert::start_sniffer(
                ctx.clone(),
                open(
                    &*opener,
                    dnsdivert::SNIFF_FILTER,
                    Layer::Network,
                    dnsdivert::SNIFF_PRIORITY,
                    crate::divert::flags::SNIFF | crate::divert::flags::RECV_ONLY,
                )?,
            ));
            if need_tcp {
                running.tcp =
                    Some(TcpRedirector::start(ctx.clone(), open(&*opener, tcp::FILTER, Layer::Network, tcp::PRIORITY, 0)?));
                self.log.info("TCP redirection active.");
            } else {
                self.log.info("No enabled TCP rules: TCP traffic is not intercepted.");
            }
            if needs_udp(&rules, &settings) {
                let handle =
                    match opener.open(&udp::filter_with_fragments(resolver.local_port()), Layer::Network, udp::PRIORITY, 0) {
                        Ok(h) => h,
                        Err(e) => {
                            self.log.warning(format!(
                                "UDP fragment capture unavailable ({e}); fragmented datagrams are not inspected."
                            ));
                            open(&*opener, &udp::filter_plain(resolver.local_port()), Layer::Network, udp::PRIORITY, 0)?
                        }
                    };
                running.udp = Some(UdpRedirector::start(ctx.clone(), handle));
                self.log.info("UDP redirection active.");
            }
            // Fake IPs are handed out only once the redirectors that handle them are running.
            if fake_ips.is_some() {
                let filter = dnsdivert::intercept_filter(resolver.local_port());
                running.interceptor = Some(dnsdivert::start_interceptor(
                    ctx.clone(),
                    open(&*opener, &filter, Layer::Network, dnsdivert::INTERCEPT_PRIORITY, 0)?,
                ));
                self.platform.flush_dns();
                self.log.info(format!("Fake-IP DNS active ({}).", settings.fake_ip_range));
            }
            Ok(())
        })();
        if let Err(e) = result {
            self.stop_core(running);
            return Err(e);
        }

        // Redirection is active: lift the kill switch for as long as this process keeps the WFP session open.
        if settings.kill_switch {
            self.apply_kill_switch(&config, &rules, true);
        }
        let enabled = config.rules.iter().filter(|r| r.enabled).count();
        let mut summary =
            format!("Started: {} on, {}", plural(enabled, "rule", "rules"), plural(config.proxies.len(), "proxy", "proxies"));
        if settings.strict_mode {
            summary.push_str(", strict mode");
        }
        if settings.kill_switch {
            summary.push_str(&format!(
                ", kill switch on {}",
                plural(self.kill_switch.protected_paths().len(), "program", "programs")
            ));
        }
        self.log.info(summary);
        Ok(running)
    }

    fn stop_core(&self, mut r: Running) {
        let had_fake = r.interceptor.is_some();
        // Re-arm the kill switch before redirection stops: no window for direct connections.
        self.kill_switch.revoke_running_allowance();
        // Reset relayed connections while their packets are still reflected: the programs see a RST from their
        // destination and forget the connection, instead of the relay's FIN (or their retransmissions) leaving
        // unrewritten from the real address once the redirectors are gone.
        if let (Some(relay), Some(_)) = (&r.relay, &r.tcp) {
            if relay.active_clients() > 0 {
                relay.abort_all();
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        // Stop handing out fake IPs, then stop diverting so traffic flows normally, then the relay.
        r.interceptor.take();
        r.udp.take();
        r.tcp.take();
        r.sniffer.take();
        r.relay.take();
        drop(r);
        if had_fake {
            self.platform.flush_dns(); // drop cached fake answers
        }
    }

    /// Persistent blocks for whole-program Proxy/Block rules, plus the running override when redirecting.
    fn apply_kill_switch(&self, config: &Config, rules: &RuleEngine, running: bool) {
        if config.settings.kill_switch {
            self.kill_switch.sync(true, rules.kill_switch_paths(), |p| rules.is_kill_switch_program(Some(p)));
            if running {
                if let Err(e) = self.kill_switch.allow_while_running() {
                    self.log.error(format!("Kill switch: {e}"));
                }
            }
        } else {
            self.kill_switch.revoke_running_allowance();
            self.kill_switch.sync(false, &[], |_| false);
        }
    }

    fn proxy_endpoints(&self, config: &Config, resolver: &dyn HostResolver) -> HashSet<(Ip, u16)> {
        let mut set = HashSet::new();
        for proxy in &config.proxies {
            let address = match proxy.host.parse::<Ip>() {
                Ok(ip) => Some(ip),
                Err(_) => self.runtime.block_on(async {
                    tokio::time::timeout(Duration::from_secs(3), resolver.resolve(&proxy.host)).await.ok().flatten()
                }),
            };
            match address {
                Some(ip) => {
                    set.insert((ip, proxy.port));
                }
                None => self.log.debug(format!("Could not resolve proxy {}.", proxy.name)),
            }
        }
        set
    }

    fn maintenance_loop(&self) {
        let mut tick: u64 = 0;
        while !self.stop_maintenance.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_secs(1));
            tick += 1;
            let paths: Vec<String> = std::mem::take(&mut *self.routed.lock().unwrap());
            let running = self.running.lock().unwrap();
            let Some(r) = running.as_ref() else { continue };
            if !paths.is_empty() && r.config.settings.kill_switch {
                let rules = r.ctx.rules();
                let mut changed = false;
                for path in paths {
                    if rules.is_kill_switch_program(Some(&path)) && self.kill_switch.learn(&path) {
                        self.log.info(format!("Kill switch: now also protecting {path}."));
                        changed = true;
                    }
                }
                if changed {
                    self.apply_kill_switch(&r.config, &rules, true);
                }
            }
            if tick.is_multiple_of(5) {
                if let Some(udp) = &r.udp {
                    udp.sweep();
                }
            }
            if tick.is_multiple_of(15) {
                r.ctx.nat.sweep(60_000, 30_000);
                r.ctx.dns_cache.sweep();
                if let Some(tcp) = &r.tcp {
                    tcp.sweep();
                }
            }
        }
    }
}

fn open(
    opener: &dyn DivertOpener,
    filter: &str,
    layer: Layer,
    priority: i16,
    flags: u64,
) -> Result<Arc<dyn crate::divert::Divert>, String> {
    opener.open(filter, layer, priority, flags).map_err(|e: DivertError| e.to_string())
}

fn warn_about_local_dns(log: &LogHub, config: &Config) {
    if config.settings.dns_mode == DnsMode::Local
        && config.rules.iter().any(|r| r.enabled && r.action == RuleAction::Proxy && r.resolve_remotely)
    {
        log.warning(
            "DNS mode is Local: host names that proxied programs look up are resolved by your own DNS server, not the proxy. \
             Set Settings > DNS mode to FakeIp for remote DNS (no DNS leaks).",
        );
    }
}

/// Settings that need the diversion handles and sockets recreated.
fn settings_key(s: &Settings) -> String {
    format!(
        "{}|{}|{:?}|{}|{}|{}|{}|{}|{}|{}|{}",
        s.relay_port,
        s.resolver_port,
        s.dns_mode,
        s.fake_ip_range,
        s.fake_ip_domains,
        s.fake_ip_exclude_domains,
        s.upstream_dns_servers,
        s.enable_udp,
        s.connect_timeout_seconds,
        s.manage_firewall_rule,
        if s.dns_mode == DnsMode::FakeIp { s.health_check_url.as_str() } else { "" }
    )
}

fn needs_tcp(rules: &RuleEngine, s: &Settings) -> bool {
    rules.has_tcp_rules || s.dns_mode == DnsMode::FakeIp
}

fn needs_udp(rules: &RuleEngine, s: &Settings) -> bool {
    s.enable_udp && (rules.has_udp_rules || s.dns_mode == DnsMode::FakeIp)
}

fn proxy_hosts(c: &Config) -> Vec<String> {
    let mut hosts: Vec<String> = c.proxies.iter().map(|p| p.host.clone()).collect();
    hosts.sort();
    hosts
}
