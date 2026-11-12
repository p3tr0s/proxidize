//! A plausible sample setup for screenshots: several game clients, each on its own exit, and a browser. Nothing is
//! saved, started or sent anywhere. Documentation addresses only (RFC 5737).

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
    let ch = add("NVPN_CH", "100.72.14.9", 1080, true);
    let al = add("NVPN_AL", "100.72.14.9", 1081, true);
    let be = add("NVPN_BE", "100.72.14.9", 1082, true);
    let es = add("NVPN_ES", "100.72.14.9", 1083, true);
    let it = add("NVPN_IT", "100.72.14.9", 1084, true);
    let se = add("NVPN_SE", "se.socks.example.net", 1080, true);
    let uk = add("NVPN_UK", "100.72.14.9", 1088, true);
    let de = add("NVPN_DE", "100.72.14.9", 1089, true);
    let home = add("HOME_LAB", "100.91.3.40", 1088, false);
    let fi = add("HETZ_FI", "100.72.14.9", 1087, true);

    let route = |name: &str, program: &str, proxy: &ProxyServer, enabled: bool| Rule {
        name: name.into(),
        programs: vec![program.into()],
        route_id: Some(proxy.id.clone()),
        enabled,
        ..Default::default()
    };
    config.rules = vec![
        route("Wow1", r"F:\Wow1\Wow.exe", &ch, true),
        route("Wow2", r"F:\Wow2\Wow.exe", &it, true),
        route("Wow3", r"F:\Wow3\Wow.exe", &be, true),
        route("Wow4", r"F:\Wow4\Wow.exe", &al, true),
        route("Wow5", r"F:\Wow5\Wow.exe", &se, true),
        route("Wow6", r"F:\Wow6\Wow.exe", &es, true),
        route("Wow7", r"F:\Wow7\Wow.exe", &uk, true),
        route("Wow8", r"F:\Wow8\Wow.exe", &de, false),
        route("Captain", r"F:\Wow\Wow - Captain.exe", &home, true),
        route("Firefox", r"F:\Downloads\FirefoxPortable\App\Firefox64\firefox.exe", &fi, true),
        Rule { name: "Updater".into(), action: RuleAction::Block, programs: vec!["Launcher.exe".into()], ..Default::default() },
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
    ok(&al, "203.0.113.12", "Albania", "AL", "Tirana", 168);
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
    conn("Wow.exe", 11420, "logon.realm.example:3724", "NVPN_CH", "Wow1", 18_420, 96_310, true, None);
    conn("Wow.exe", 11420, "world.realm.example:8085", "NVPN_CH", "Wow1", 1_204_880, 9_817_002, true, None);
    conn("Wow.exe", 12088, "world.realm.example:8085", "NVPN_IT", "Wow2", 988_130, 7_302_551, true, None);
    conn("Wow.exe", 9312, "world.realm.example:8085", "NVPN_BE", "Wow3", 1_022_004, 8_100_440, true, None);
    conn("Wow.exe", 13740, "world.realm.example:8085", "NVPN_AL", "Wow4", 640_300, 5_908_112, true, None);
    conn("Wow.exe", 6644, "world.realm.example:8085", "NVPN_SE", "Wow5", 712_880, 6_550_301, true, None);
    conn("Wow.exe", 14212, "world.realm.example:8085", "NVPN_ES", "Wow6", 830_045, 7_011_920, true, None);
    conn("Wow - Captain.exe", 5120, "world.realm.example:8085", "HOME_LAB", "Captain", 2_440_118, 15_330_276, true, None);
    conn("firefox.exe", 7788, "forum.realm.example:443", "HETZ_FI", "Firefox", 81_220, 2_440_871, true, None);
    conn("firefox.exe", 7788, "cdn.realm.example:443", "HETZ_FI", "Firefox", 12_004, 880_120, false, None);
    conn(
        "Wow.exe",
        9930,
        "world.realm.example:8085",
        "NVPN_UK",
        "Wow7",
        0,
        0,
        false,
        Some("NVPN_UK is blocked: its exit IP is your own IP"),
    );

    log.info("Proxidize started");
    log.info("Kill switch: 9 programs can't connect unless Proxidize is redirecting them");
    log.info("Started: 11 rules on, 10 proxies, strict mode, kill switch on 9 programs");
    log.info("Health check: 9/10 proxies OK, your IP 192.0.2.112 Greece (GR).");
    log.warning("Health: NVPN_UK: Exit IP is your own IP: this proxy does not hide you.");
    log.warning("Blocked 1 proxy after the proxy check and reset 1 connection through them");
    log.info("TCP Wow.exe 192.168.1.20:52114 -> 203.0.113.88:8085: reset, opened before redirection (Wow2). The program will reconnect through its rule.");
}
