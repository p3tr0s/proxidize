//! A plausible sample setup for screenshots: everyday programs, each on its own exit. Nothing is saved, started or
//! sent anywhere. Documentation addresses and example domains only.

use std::collections::HashMap;

use proxidize_core::config::{Config, DnsMode, ProxyChain, ProxyServer, Rule, RuleAction};
use proxidize_core::health::{HealthState, ProxyHealth, DIRECT_ID};
use proxidize_core::log::LogHub;
use proxidize_core::relay::ConnectionTracker;

pub fn scenario() -> (Config, HashMap<String, ProxyHealth>) {
    let mut config = Config::default();
    config.settings.dns_mode = DnsMode::FakeIp;
    config.settings.kill_switch = true;
    let mut add = |name: &str, host: &str, port: u16, user: bool| {
        let p = ProxyServer {
            name: name.into(),
            host: host.into(),
            port,
            username: user.then(|| "relay".to_string()),
            password: user.then(|| "x".to_string()),
            ..Default::default()
        };
        config.proxies.push(p.clone());
        p
    };
    let ch = add("Zurich", "100.72.14.9", 1080, true);
    let at = add("Vienna", "100.72.14.9", 1081, true);
    let be = add("Brussels", "100.72.14.9", 1082, true);
    let es = add("Madrid", "100.72.14.9", 1083, true);
    let it = add("Milan", "100.72.14.9", 1084, true);
    let se = add("Stockholm", "se.socks.example.net", 1080, true);
    let uk = add("London", "100.72.14.9", 1088, true);
    let de = add("Frankfurt", "100.72.14.9", 1089, true);
    let home = add("Home lab", "100.91.3.40", 1088, false);
    let fi = add("Helsinki", "100.72.14.9", 1087, true);

    let route = |name: &str, program: &str, proxy: &ProxyServer, enabled: bool| Rule {
        name: name.into(),
        programs: vec![program.into()],
        route_id: Some(proxy.id.clone()),
        enabled,
        ..Default::default()
    };
    config.rules = vec![
        route("Firefox", r"C:\Program Files\Mozilla Firefox\firefox.exe", &fi, true),
        route("Chrome", "chrome.exe", &ch, true),
        route("Discord", "Discord.exe", &it, true),
        route("Telegram", "Telegram.exe", &be, true),
        route("qBittorrent", r"C:\Program Files\qBittorrent\qbittorrent.exe", &se, true),
        route("Spotify", "Spotify.exe", &es, true),
        route("Thunderbird", "thunderbird.exe", &uk, true),
        route("Steam", r"C:\Program Files (x86)\Steam\steam.exe", &de, false),
        route("Slack", "slack.exe", &at, true),
        route("Remote desktop", "mstsc.exe", &home, true),
        Rule {
            name: "Telemetry".into(),
            action: RuleAction::Block,
            programs: vec!["CompatTelRunner.exe".into()],
            ..Default::default()
        },
        Rule {
            name: "Local network".into(),
            action: RuleAction::Direct,
            destinations: vec!["192.168.0.0/16".into(), "100.64.0.0/10".into()],
            ..Default::default()
        },
    ];
    config.chains.push(ProxyChain {
        name: "Double hop".into(),
        proxy_ids: vec![fi.id.clone(), se.id.clone()],
        ..Default::default()
    });

    let mut health = HashMap::new();
    let mut ok = |p: &ProxyServer, ip: &str, country: &str, code: &str, city: &str, ms: u64| {
        let mut h = ProxyHealth::failed(&p.id, &p.name, "", ms);
        h.ok = true;
        h.error = None;
        h.state = HealthState::Ok;
        h.exit_ip = Some(ip.into());
        h.country = Some(country.into());
        h.country_code = Some(code.into());
        h.city = Some(city.into());
        health.insert(p.id.clone(), h);
    };
    ok(&ch, "203.0.113.31", "Switzerland", "CH", "Zurich", 142);
    ok(&at, "203.0.113.12", "Austria", "AT", "Vienna", 108);
    ok(&be, "203.0.113.70", "Belgium", "BE", "Brussels", 131);
    ok(&es, "203.0.113.211", "Spain", "ES", "Madrid", 154);
    ok(&it, "203.0.113.88", "Italy", "IT", "Milan", 119);
    ok(&se, "198.51.100.25", "Sweden", "SE", "Stockholm", 176);
    ok(&de, "198.51.100.44", "Germany", "DE", "Frankfurt", 128);
    ok(&home, "192.0.2.180", "Greece", "GR", "Athens", 38);
    ok(&fi, "198.51.100.7", "Finland", "FI", "Helsinki", 96);
    let mut leak = ProxyHealth::failed(&uk.id, &uk.name, "", 41);
    leak.ok = true;
    leak.error = None;
    leak.exit_ip = Some("192.0.2.112".into());
    leak.country = Some("Greece".into());
    leak.country_code = Some("GR".into());
    leak.city = Some("Athens".into());
    leak.state = HealthState::ExposesYourIp;
    leak.warning = Some("Exit IP is your own IP: this proxy does not hide you.".into());
    leak.blocked = true;
    health.insert(uk.id.clone(), leak);
    let mut me = ProxyHealth::failed(DIRECT_ID, "Your IP", "", 22);
    me.ok = true;
    me.error = None;
    me.state = HealthState::Ok;
    me.exit_ip = Some("192.0.2.112".into());
    me.country = Some("Greece".into());
    me.country_code = Some("GR".into());
    health.insert(DIRECT_ID.into(), me);
    (config, health)
}

/// Fills the live views with a few connections and log lines.
pub fn seed(tracker: &ConnectionTracker, log: &LogHub) {
    let conn = |program: &str,
                pid: u32,
                destination: &str,
                route: &str,
                rule: &str,
                up: u64,
                down: u64,
                open: bool,
                error: Option<&str>| {
        let r = tracker.open("TCP", pid, program, destination, RuleAction::Proxy, route, rule);
        r.set_state(if error.is_none() { "Established" } else { "Failed" });
        r.add_up(up);
        r.add_down(down);
        if let Some(e) = error {
            r.set_error(e);
        }
        if !open {
            tracker.close(&r, None);
        }
    };
    conn("firefox.exe", 7788, "www.mozilla.org:443", "Helsinki", "Firefox", 81_220, 2_440_871, true, None);
    conn("firefox.exe", 7788, "cdn.example.com:443", "Helsinki", "Firefox", 12_004, 880_120, false, None);
    conn("chrome.exe", 11420, "mail.example.com:443", "Zurich", "Chrome", 204_880, 3_817_002, true, None);
    conn("Discord.exe", 12088, "gateway.discord.gg:443", "Milan", "Discord", 98_130, 1_302_551, true, None);
    conn("Telegram.exe", 9312, "api.telegram.org:443", "Brussels", "Telegram", 22_004, 410_440, true, None);
    conn("qbittorrent.exe", 6644, "tracker.example.org:6969", "Stockholm", "qBittorrent", 1_712_880, 46_550_301, true, None);
    conn("Spotify.exe", 14212, "audio-ak.spotify.example:443", "Madrid", "Spotify", 30_045, 27_011_920, true, None);
    conn("slack.exe", 13740, "wss-primary.slack.com:443", "Vienna", "Slack", 40_300, 908_112, true, None);
    conn("mstsc.exe", 5120, "desktop.home.example:3389", "Home lab", "Remote desktop", 2_440_118, 15_330_276, true, None);
    conn(
        "thunderbird.exe",
        9930,
        "imap.example.com:993",
        "London",
        "Thunderbird",
        0,
        0,
        false,
        Some("London is blocked: its exit IP is your own IP"),
    );

    log.info("Proxidize started");
    log.info("Kill switch: 2 programs can't connect unless Proxidize is redirecting them");
    log.info("Started: 11 rules on, 10 proxies, strict mode, kill switch on 2 programs");
    log.info("Health check: 9/10 proxies OK, your IP 192.0.2.112 Greece (GR).");
    log.warning("Health: London: Exit IP is your own IP: this proxy does not hide you.");
    log.warning("Blocked 1 proxy after the proxy check and reset 1 connection through them");
    log.info("TCP Discord.exe 192.168.1.20:52114 -> 203.0.113.88:443: reset, opened before redirection (Discord). The program will reconnect through its rule.");
}
