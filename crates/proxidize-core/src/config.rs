//! Configuration: proxies, chains, rules and settings.
//!
//! The JSON format: PascalCase names, enums as strings, `passwordProtected` for encrypted passwords.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ProxyType {
    #[default]
    Socks5,
    Socks4,
    Http,
    /// HTTP CONNECT over TLS to the proxy.
    Https,
}

impl ProxyType {
    pub fn label(self) -> &'static str {
        match self {
            ProxyType::Socks5 => "SOCKS5",
            ProxyType::Socks4 => "SOCKS4",
            ProxyType::Http => "HTTP",
            ProxyType::Https => "HTTPS",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum RuleAction {
    Direct,
    #[default]
    Proxy,
    Block,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum TransportFilter {
    #[default]
    Both,
    Tcp,
    Udp,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DnsMode {
    /// Programs resolve names themselves; host-name rules match via sniffed DNS answers.
    #[default]
    Local,
    /// DNS answers are replaced with fake IPs so the real name can be sent to the proxy (remote DNS).
    FakeIp,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct ProxyServer {
    pub id: String,
    pub name: String,
    #[serde(rename = "Type")]
    pub kind: ProxyType,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    /// On-disk form of `password` (DPAPI on Windows). Managed by [`ConfigStore`].
    #[serde(rename = "passwordProtected", skip_serializing_if = "Option::is_none")]
    pub password_protected: Option<String>,
    /// Patch cable colour `#RRGGBB`; `None` = from the palette by position.
    pub color: Option<String>,
    /// HTTPS proxies: accept any certificate (a self-signed one on your own proxy).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub skip_certificate_check: bool,
}

impl Default for ProxyServer {
    fn default() -> Self {
        ProxyServer {
            id: new_id(),
            name: "New proxy".into(),
            kind: ProxyType::Socks5,
            host: "127.0.0.1".into(),
            port: 1080,
            username: None,
            password: None,
            password_protected: None,
            color: None,
            skip_certificate_check: false,
        }
    }
}

impl ProxyServer {
    pub fn has_credentials(&self) -> bool {
        self.username.as_deref().is_some_and(|u| !u.is_empty())
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct ProxyChain {
    pub id: String,
    pub name: String,
    /// Proxy ids in hop order: the first is connected directly, the last reaches the target.
    pub proxy_ids: Vec<String>,
}

impl Default for ProxyChain {
    fn default() -> Self {
        ProxyChain { id: new_id(), name: "New chain".into(), proxy_ids: Vec::new() }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub action: RuleAction,
    /// A proxy or chain id (when the action is Proxy).
    pub route_id: Option<String>,
    /// Executable names (`chrome.exe`, `firefox*.exe`) or full path globs (`C:\Games\*`). Empty = any program.
    pub programs: Vec<String>,
    /// Host globs, `.example.com`, IPs, CIDRs, IP ranges. Empty = any.
    pub destinations: Vec<String>,
    /// Ports or ranges (`443`, `8000-9000`). Empty = any.
    pub ports: Vec<String>,
    pub transport: TransportFilter,
    /// Send host names to the proxy instead of locally resolved IPs (needs DNS mode FakeIp).
    pub resolve_remotely: bool,
    /// With `resolve_remotely`: host names (globs, `.example.com`) still resolved locally, and sent as IPs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub remote_dns_exceptions: Vec<String>,
}

impl Default for Rule {
    fn default() -> Self {
        Rule {
            id: new_id(),
            name: "New rule".into(),
            enabled: true,
            action: RuleAction::Proxy,
            route_id: None,
            programs: Vec::new(),
            destinations: Vec::new(),
            ports: Vec::new(),
            transport: TransportFilter::Both,
            resolve_remotely: true,
            remote_dns_exceptions: Vec::new(),
        }
    }
}

pub const DEFAULT_HEALTH_URL: &str = "http://ip-api.com/json/?fields=status,message,country,countryCode,city,query";

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct Settings {
    // Leak protection
    pub strict_mode: bool,
    pub kill_switch: bool,
    // Startup and engine
    pub start_enabled: bool,
    pub start_with_windows: bool,
    pub start_minimized: bool,
    pub relay_port: u16,
    pub connect_timeout_seconds: u32,
    pub manage_firewall_rule: bool,
    // UDP
    pub enable_udp: bool,
    pub udp_idle_timeout_seconds: u32,
    // DNS
    pub dns_mode: DnsMode,
    pub fake_ip_range: String,
    pub fake_ip_domains: String,
    pub fake_ip_exclude_domains: String,
    pub upstream_dns_servers: String,
    pub resolver_port: u16,
    // Proxy check
    pub health_check_interval_minutes: u32,
    pub health_check_url: String,
    pub health_check_direct: bool,
    pub health_check_block_leaking: bool,
    pub health_check_notify: bool,
    // Logging
    pub log_direct_connections: bool,
    pub verbose_logging: bool,
    // Updates
    pub check_for_updates: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            strict_mode: true,
            kill_switch: true,
            start_enabled: true,
            start_with_windows: false,
            start_minimized: false,
            relay_port: 34010,
            connect_timeout_seconds: 15,
            manage_firewall_rule: true,
            enable_udp: true,
            udp_idle_timeout_seconds: 120,
            dns_mode: DnsMode::Local,
            fake_ip_range: "198.18.0.0/15".into(),
            fake_ip_domains: "*".into(),
            fake_ip_exclude_domains: "localhost;.local;.lan;.internal;.home.arpa;.arpa;.msftncsi.com;.msftconnecttest.com".into(),
            upstream_dns_servers: String::new(),
            resolver_port: 34053,
            health_check_interval_minutes: 3,
            health_check_url: DEFAULT_HEALTH_URL.into(),
            health_check_direct: true,
            health_check_block_leaking: true,
            health_check_notify: true,
            log_direct_connections: false,
            verbose_logging: false,
            check_for_updates: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct Config {
    pub version: u32,
    pub settings: Settings,
    pub proxies: Vec<ProxyServer>,
    pub chains: Vec<ProxyChain>,
    /// Evaluated top to bottom; the first matching enabled rule wins. No match = direct.
    pub rules: Vec<Rule>,
}

impl Default for Config {
    fn default() -> Self {
        Config { version: 1, settings: Settings::default(), proxies: Vec::new(), chains: Vec::new(), rules: Vec::new() }
    }
}

impl Config {
    pub fn find_proxy(&self, id: Option<&str>) -> Option<&ProxyServer> {
        let id = id?;
        self.proxies.iter().find(|p| p.id == id)
    }

    pub fn find_chain(&self, id: Option<&str>) -> Option<&ProxyChain> {
        let id = id?;
        self.chains.iter().find(|c| c.id == id)
    }

    pub fn describe_route(&self, route_id: Option<&str>) -> String {
        if let Some(p) = self.find_proxy(route_id) {
            return p.name.clone();
        }
        if let Some(c) = self.find_chain(route_id) {
            return format!("{} (chain)", c.name);
        }
        "(none)".into()
    }

    /// The starting point for a new install: one example proxy, no rules.
    pub fn example() -> Config {
        let example = ProxyServer { name: "Example SOCKS5".into(), host: "127.0.0.1".into(), port: 1080, ..Default::default() };
        Config { proxies: vec![example], ..Default::default() }
    }
}

// ---------------------------------------------------------------------------------------------------- storage

/// Encrypts secrets written to disk (DPAPI on Windows). `unprotect` returns `None` when it can't decrypt.
pub trait SecretProtector: Send + Sync {
    fn protect(&self, plain: &str) -> String;
    fn unprotect(&self, protected: &str) -> Option<String>;
}

static PROTECTOR: OnceLock<RwLock<Option<Arc<dyn SecretProtector>>>> = OnceLock::new();

fn protector_slot() -> &'static RwLock<Option<Arc<dyn SecretProtector>>> {
    PROTECTOR.get_or_init(|| RwLock::new(None))
}

/// Set once at startup by the platform layer. `None` = passwords stay in plain text.
pub fn set_protector(protector: Option<Arc<dyn SecretProtector>>) {
    *protector_slot().write().unwrap() = protector;
}

fn protector() -> Option<Arc<dyn SecretProtector>> {
    protector_slot().read().unwrap().clone()
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "{e}"),
            ConfigError::Json(e) => write!(f, "invalid configuration: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io(e)
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        ConfigError::Json(e)
    }
}

/// Reads and writes `config.json`, encrypting passwords on disk.
pub struct ConfigStore {
    path: PathBuf,
    /// Problems found by the last [`load`](Self::load), such as passwords that could not be decrypted.
    pub load_warnings: Vec<String>,
}

impl ConfigStore {
    pub fn new(path: impl Into<PathBuf>) -> ConfigStore {
        ConfigStore { path: path.into(), load_warnings: Vec::new() }
    }

    /// `%ProgramData%\Proxidize` on Windows; `./proxidize-data` elsewhere (tests and development).
    pub fn data_directory() -> PathBuf {
        match std::env::var_os("ProgramData") {
            Some(base) => Path::new(&base).join("Proxidize"),
            None => PathBuf::from("proxidize-data"),
        }
    }

    pub fn default_path() -> PathBuf {
        Self::data_directory().join("config.json")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads the file (creating it with [`Config::example`] when missing). Plain-text passwords from older files are
    /// migrated to the protected form.
    pub fn load(&mut self) -> Result<Config, ConfigError> {
        self.load_warnings.clear();
        if !self.path.exists() {
            let config = Config::example();
            self.save(&config)?;
            return Ok(config);
        }
        let json = std::fs::read_to_string(&self.path)?;
        let mut config: Config = serde_json::from_str(json.trim_start_matches('\u{feff}'))?;
        let had_plain = reveal_secrets(&mut config, &mut self.load_warnings);
        if had_plain && protector().is_some() {
            let _ = self.save(&config);
        }
        Ok(config)
    }

    /// Writes atomically (temp file + rename) with passwords protected.
    pub fn save(&self, config: &Config) -> Result<(), ConfigError> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let temp = self.path.with_extension("json.tmp");
        std::fs::write(&temp, serialize_for_disk(config)?)?;
        std::fs::rename(&temp, &self.path)?;
        Ok(())
    }
}

pub fn serialize(config: &Config) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(config)
}

/// Serializes with passwords replaced by their protected form (when a protector is set).
pub fn serialize_for_disk(config: &Config) -> Result<String, serde_json::Error> {
    let Some(p) = protector() else {
        return serialize(config);
    };
    let mut copy = config.clone();
    for proxy in &mut copy.proxies {
        if let Some(pw) = proxy.password.take().filter(|pw| !pw.is_empty()) {
            proxy.password_protected = Some(p.protect(&pw));
        }
    }
    serialize(&copy)
}

/// Parses a file written by [`serialize_for_disk`] (or an older plain-text config), decrypting passwords.
pub fn deserialize_from_disk(json: &str, warnings: &mut Vec<String>) -> Result<Config, serde_json::Error> {
    let mut config: Config = serde_json::from_str(json.trim_start_matches('\u{feff}'))?;
    reveal_secrets(&mut config, warnings);
    Ok(config)
}

/// Decrypts protected passwords in place. Returns true when plain-text passwords were present.
fn reveal_secrets(config: &mut Config, warnings: &mut Vec<String>) -> bool {
    let p = protector();
    let mut plain = false;
    for proxy in &mut config.proxies {
        if let Some(protected) = proxy.password_protected.take().filter(|s| !s.is_empty()) {
            match p.as_ref().and_then(|p| p.unprotect(&protected)) {
                Some(value) => proxy.password = Some(value),
                None => warnings.push(format!(
                    "Proxy '{}': the saved password could not be decrypted (config copied from another user or PC?). Re-enter it.",
                    proxy.name
                )),
            }
        } else if proxy.password.as_deref().is_some_and(|p| !p.is_empty()) {
            plain = true;
        }
    }
    plain
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The protector is process-wide: serialize the tests that set it.
    pub(crate) static PROTECTOR_LOCK: Mutex<()> = Mutex::new(());

    struct Reverse;

    impl SecretProtector for Reverse {
        fn protect(&self, plain: &str) -> String {
            format!("x:{}", plain.chars().rev().collect::<String>())
        }

        fn unprotect(&self, value: &str) -> Option<String> {
            value.strip_prefix("x:").map(|s| s.chars().rev().collect())
        }
    }

    #[test]
    fn reads_config_json() {
        let json = r##"{
          "Version": 1,
          "Settings": { "DnsMode": "FakeIp", "KillSwitch": true, "RelayPort": 34010 },
          "Proxies": [ { "Id": "a1", "Name": "NVPN_CH", "Type": "Socks5", "Host": "198.51.100.50", "Port": 1080,
                         "Username": "relay", "Color": "#4C8DF6" } ],
          "Chains": [ { "Id": "c1", "Name": "Double", "ProxyIds": ["a1"] } ],
          "Rules": [ { "Id": "r1", "Name": "Wow1", "Enabled": true, "Action": "Proxy", "RouteId": "a1",
                       "Programs": ["F:\\Wow1\\Wow.exe"], "Destinations": [], "Ports": [], "Transport": "Both",
                       "ResolveRemotely": true } ]
        }"##;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.settings.dns_mode, DnsMode::FakeIp);
        assert_eq!(config.settings.health_check_interval_minutes, 3, "missing settings get defaults");
        assert_eq!(config.proxies[0].kind, ProxyType::Socks5);
        assert_eq!(config.proxies[0].color.as_deref(), Some("#4C8DF6"));
        assert_eq!(config.rules[0].programs[0], r"F:\Wow1\Wow.exe");
        assert_eq!(config.find_chain(Some("c1")).unwrap().proxy_ids, vec!["a1"]);
        assert_eq!(config.describe_route(Some("c1")), "Double (chain)");

        let written = serialize(&config).unwrap();
        assert!(written.contains("\"ProxyIds\""), "PascalCase");
        assert!(written.contains("\"Type\": \"Socks5\""));
        assert!(!written.contains("passwordProtected"), "omitted when empty");
    }

    #[test]
    fn passwords_protected_on_disk() {
        let _guard = PROTECTOR_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("proxidize-cfg-{}", new_id()));
        let path = dir.join("config.json");
        set_protector(None);
        let mut store = ConfigStore::new(&path);
        let mut plain = Config::default();
        plain.proxies.push(ProxyServer {
            name: "A".into(),
            username: Some("u".into()),
            password: Some("s3cret-A".into()),
            ..Default::default()
        });
        store.save(&plain).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains("s3cret-A"));

        set_protector(Some(Arc::new(Reverse)));
        let mut loaded = store.load().unwrap();
        assert_eq!(loaded.proxies[0].password.as_deref(), Some("s3cret-A"));
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains("s3cret-A"), "migrated");
        assert!(on_disk.contains("passwordProtected"));

        loaded.proxies.push(ProxyServer { name: "B".into(), password: Some("s3cret-B".into()), ..Default::default() });
        store.save(&loaded).unwrap();
        assert!(!std::fs::read_to_string(&path).unwrap().contains("s3cret-B"));
        let again = ConfigStore::new(&path).load().unwrap();
        assert_eq!(again.proxies[1].password.as_deref(), Some("s3cret-B"));
        assert!(again.proxies[1].password_protected.is_none());

        std::fs::write(&path, std::fs::read_to_string(&path).unwrap().replace("\"x:", "\"y:")).unwrap();
        let mut broken = ConfigStore::new(&path);
        let unreadable = broken.load().unwrap();
        assert!(unreadable.proxies[0].password.is_none());
        assert_eq!(broken.load_warnings.len(), 2);
        set_protector(None);
        let _ = std::fs::remove_dir_all(dir);
    }
}
