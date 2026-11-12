//! The engine end to end on a simulated platform: mock packet diversion, a fake process table, in-memory WFP and
//! real sockets on loopback for the relay, the proxy and the destination.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use proxidize_core::config::{Config, DnsMode, ProxyServer, ProxyType, Rule, RuleAction};
use proxidize_core::dns::{Message, TYPE_A, TYPE_AAAA};
use proxidize_core::log::LogHub;
use proxidize_core::net::Ip;
use proxidize_core::packet::{self, PROTO_TCP, TCP_ACK, TCP_SYN};
use proxidize_core::relay::ConnectionTracker;

use crate::divert::mock::{MockDivert, MockOpener};
use crate::divert::{Address, DivertOpener};
use crate::engine::{Engine, Platform};
use crate::killswitch::{Filters, MemoryFilters};
use crate::process::tests::FakeSystem;
use crate::process::{SystemInfo, TcpRow, UdpRow};

struct TestPlatform {
    opener: Arc<MockOpener>,
    system: Arc<FakeSystem>,
    filters: Arc<MemoryFilters>,
}

impl Platform for TestPlatform {
    fn opener(&self) -> Arc<dyn DivertOpener> {
        self.opener.clone()
    }
    fn system(&self) -> Arc<dyn SystemInfo> {
        self.system.clone()
    }
    fn filters(&self) -> Arc<dyn Filters> {
        self.filters.clone()
    }
    fn adapter_dns_servers(&self) -> Vec<Ip> {
        vec![Ip::v4([127, 0, 0, 1])]
    }
    fn self_pid(&self) -> u32 {
        1
    }
    fn relay_bind(&self) -> Option<std::net::IpAddr> {
        Some("127.0.0.1".parse().unwrap())
    }
}

struct Rig {
    engine: Engine,
    platform: Arc<TestPlatform>,
    tracker: Arc<ConnectionTracker>,
    log: Arc<LogHub>,
}

const WOW: &str = r"F:\Wow1\Wow.exe";
const FIREFOX: &str = r"C:\Apps\firefox.exe";
const UPDATER: &str = r"C:\Apps\Launcher.exe";

fn config(proxy_port: u16, proxy_kind: ProxyType) -> Config {
    let proxy = ProxyServer {
        name: "NVPN_CH".into(),
        host: "127.0.0.1".into(),
        port: proxy_port,
        kind: proxy_kind,
        ..Default::default()
    };
    let mut config = Config { proxies: vec![proxy.clone()], ..Default::default() };
    config.rules.push(Rule {
        name: "Wow1".into(),
        programs: vec![WOW.into()],
        route_id: Some(proxy.id.clone()),
        ..Default::default()
    });
    config.rules.push(Rule {
        name: "Updater".into(),
        action: RuleAction::Block,
        programs: vec!["Launcher.exe".into()],
        ..Default::default()
    });
    let s = &mut config.settings;
    s.relay_port = 0;
    s.resolver_port = 0;
    s.kill_switch = true;
    s.strict_mode = true;
    s.manage_firewall_rule = false;
    s.dns_mode = DnsMode::Local;
    config
}

fn rig() -> Rig {
    let system = Arc::new(FakeSystem::default());
    system.spawn(100, WOW);
    system.spawn(200, FIREFOX);
    system.spawn(300, UPDATER);
    let platform = Arc::new(TestPlatform { opener: Arc::default(), system, filters: Arc::default() });
    let log = Arc::new(LogHub::default());
    log.set_verbose(true);
    let tracker = Arc::new(ConnectionTracker::default());
    let engine = Engine::new(platform.clone(), log.clone(), tracker.clone());
    Rig { engine, platform, tracker, log }
}

impl Rig {
    fn tcp(&self) -> Arc<MockDivert> {
        self.platform.opener.handle("tcp")
    }

    fn owns_tcp(&self, pid: u32, local: &str, lport: u16, remote: &str, rport: u16) {
        self.platform.system.tcp.lock().unwrap().push(TcpRow {
            local: local.parse().unwrap(),
            local_port: lport,
            remote: remote.parse().unwrap(),
            remote_port: rport,
            pid,
            listening: false,
        });
    }

    fn logs(&self) -> String {
        self.log.entries_after(0).iter().map(|e| e.message.clone()).collect::<Vec<_>>().join("\n")
    }
}

fn tcp_packet(src: &str, sport: u16, dst: &str, dport: u16, flags: u8) -> Vec<u8> {
    let s: Ip = src.parse().unwrap();
    let d: Ip = dst.parse().unwrap();
    let mut p = vec![0u8; 40];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&40u16.to_be_bytes());
    p[8] = 64;
    p[9] = PROTO_TCP;
    s.write_v4(&mut p[12..]);
    d.write_v4(&mut p[16..]);
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    p[24..28].copy_from_slice(&1000u32.to_be_bytes());
    p[28..32].copy_from_slice(&5000u32.to_be_bytes());
    p[32] = 0x50;
    p[33] = flags;
    let info = packet::parse(&p).unwrap();
    packet::update_checksums(&mut p, &info);
    p
}

/// Waits until the mock handle has injected something (or the timeout passes).
fn wait_sent(d: &MockDivert, timeout_ms: u64) -> Vec<(Vec<u8>, Address)> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let sent = d.take_sent();
        if !sent.is_empty() || Instant::now() > deadline {
            return sent;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A small SOCKS5 server (no auth): CONNECT to the requested address (names go to 127.0.0.1), then pipe.
fn socks5_server(rt: &tokio::runtime::Handle) -> (u16, Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = seen.clone();
    rt.spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            let log = log.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                s.read_exact(&mut head).await.ok()?;
                let mut methods = vec![0u8; head[1] as usize];
                s.read_exact(&mut methods).await.ok()?;
                s.write_all(&[5, 0]).await.ok()?;
                let mut req = [0u8; 4];
                s.read_exact(&mut req).await.ok()?;
                let target: SocketAddr = match req[3] {
                    1 => {
                        let mut a = [0u8; 6];
                        s.read_exact(&mut a).await.ok()?;
                        log.lock().unwrap().push(format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]));
                        SocketAddr::from(([a[0], a[1], a[2], a[3]], u16::from_be_bytes([a[4], a[5]])))
                    }
                    3 => {
                        let mut len = [0u8; 1];
                        s.read_exact(&mut len).await.ok()?;
                        let mut name = vec![0u8; len[0] as usize + 2];
                        s.read_exact(&mut name).await.ok()?;
                        let n = name.len();
                        log.lock().unwrap().push(String::from_utf8_lossy(&name[..n - 2]).into_owned());
                        SocketAddr::from(([127, 0, 0, 1], u16::from_be_bytes([name[n - 2], name[n - 1]])))
                    }
                    _ => return None,
                };
                let mut up = tokio::net::TcpStream::connect(target).await.ok()?;
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.ok()?;
                let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                Some(())
            });
        }
    });
    (port, seen)
}

/// Listens on 127.0.0.2, the "remote" destination in these tests.
fn echo_server(rt: &tokio::runtime::Handle) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.2:0")).unwrap();
    let port = listener.local_addr().unwrap().port();
    rt.spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

#[test]
fn start_opens_handles_and_arms_the_kill_switch() {
    let r = rig();
    let rt = r.engine.runtime();
    let (proxy_port, _) = socks5_server(&rt);
    r.engine.start(&config(proxy_port, ProxyType::Socks5)).unwrap();
    assert!(r.engine.is_running());
    let filters: Vec<String> = r.platform.opener.opened.lock().unwrap().iter().map(|(f, _, _)| f.clone()).collect();
    assert!(filters.iter().any(|f| f == crate::tcp::FILTER), "{filters:?}");
    assert!(filters.iter().any(|f| f == crate::dnsdivert::SNIFF_FILTER));
    assert!(filters.iter().any(|f| f.contains("ipv6.NextHdr == 44")), "UDP with fragments");
    assert!(!filters.iter().any(|f| f.contains("udp.DstPort == 53")), "no interceptor in Local DNS mode");
    assert_eq!(*r.platform.filters.blocks.lock().unwrap(), vec![WOW.to_string()]);
    assert!(r.platform.filters.is_allowing(), "running override while redirecting");

    r.engine.stop();
    assert!(!r.engine.is_running());
    assert!(!r.platform.filters.is_allowing(), "override revoked when stopped");
    assert_eq!(r.platform.filters.blocks.lock().unwrap().len(), 1, "blocks stay while stopped");
}

#[test]
fn proxied_connection_end_to_end() {
    let r = rig();
    let rt = r.engine.runtime();
    let (proxy_port, seen) = socks5_server(&rt);
    let echo = echo_server(&rt);
    r.engine.start(&config(proxy_port, ProxyType::Socks5)).unwrap();
    let tcp = r.tcp();

    // Wow.exe opens 127.0.0.1:sp -> 127.0.0.2:echo. The SYN is diverted and must be reflected to the relay.
    let client = std::net::TcpListener::bind("127.0.0.2:0").unwrap(); // reserve a free port to use as sp
    let sp = client.local_addr().unwrap().port();
    drop(client);
    r.owns_tcp(100, "127.0.0.1", sp, "127.0.0.2", echo);
    tcp.push(tcp_packet("127.0.0.1", sp, "127.0.0.2", echo, TCP_SYN), Address::outbound_packet(false));
    let sent = wait_sent(&tcp, 2000);
    assert_eq!(sent.len(), 1, "{}", r.logs());
    let (reflected, addr) = &sent[0];
    let info = packet::parse(reflected).unwrap();
    assert!(!addr.outbound(), "reflected inbound");
    assert_eq!(info.source.to_string(), "127.0.0.2");
    assert_eq!(info.destination.to_string(), "127.0.0.1");
    assert_ne!(info.destination_port, echo, "sent to the relay port");
    let relay_port = info.destination_port;
    assert_eq!(r.engine.nat_entries(), 1);

    // What the stack does with the reflected SYN: a connection from 127.0.0.2:sp to the relay on 127.0.0.1.
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    socket.set_reuse_address(true).unwrap();
    socket.bind(&SocketAddr::from(([127, 0, 0, 2], sp)).into()).unwrap();
    socket.connect(&SocketAddr::from(([127, 0, 0, 1], relay_port)).into()).unwrap();
    let mut stream: std::net::TcpStream = socket.into();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    use std::io::{Read, Write};
    stream.write_all(b"hello through the proxy").unwrap();
    let mut buf = [0u8; 23];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello through the proxy");
    assert_eq!(seen.lock().unwrap().as_slice(), ["127.0.0.2"], "the proxy was asked for the original destination");

    // The relay's reply (127.0.0.1:relay -> 127.0.0.2:sp) is reflected back as the destination talking.
    tcp.push(tcp_packet("127.0.0.1", relay_port, "127.0.0.2", sp, TCP_ACK), Address::outbound_packet(false));
    let back = wait_sent(&tcp, 2000);
    let b = packet::parse(&back[0].0).unwrap();
    assert_eq!((b.source.to_string(), b.source_port), ("127.0.0.2".to_string(), echo));
    assert_eq!((b.destination.to_string(), b.destination_port), ("127.0.0.1".to_string(), sp));
    assert!(packet::verify_checksums(&back[0].0, &b));

    drop(stream);
    std::thread::sleep(Duration::from_millis(200));
    let records = r.tracker.snapshot(true);
    let rec = records.iter().find(|c| c.rule_name == "Wow1").expect("connection recorded");
    assert_eq!((rec.process_name.as_str(), rec.route_name.as_str()), ("Wow.exe", "NVPN_CH"));
    assert_eq!(rec.bytes_up(), 23);
}

#[test]
fn block_rule_resets_and_strict_mode_drops_unknown_owners() {
    let r = rig();
    let (proxy_port, _) = socks5_server(&r.engine.runtime());
    r.engine.start(&config(proxy_port, ProxyType::Socks5)).unwrap();
    let tcp = r.tcp();

    r.owns_tcp(300, "10.0.0.2", 40000, "203.0.113.9", 443);
    tcp.push(tcp_packet("10.0.0.2", 40000, "203.0.113.9", 443, TCP_SYN), Address::outbound_packet(false));
    let sent = wait_sent(&tcp, 2000);
    let rst = packet::parse(&sent[0].0).unwrap();
    assert!(rst.is_rst() && rst.is_ack() && !sent[0].1.outbound(), "blocked SYN answered with RST+ACK");
    assert_eq!(rst.source.to_string(), "203.0.113.9");

    // Nobody owns this SYN: strict mode lets nothing out.
    tcp.push(tcp_packet("10.0.0.2", 40001, "203.0.113.9", 443, TCP_SYN), Address::outbound_packet(false));
    assert!(wait_sent(&tcp, 300).is_empty(), "unknown owner: dropped");
    assert!(r.engine.dropped_packets() >= 1);

    // Firefox has no rule: its SYN goes out unchanged.
    r.owns_tcp(200, "10.0.0.2", 40002, "203.0.113.9", 443);
    let syn = tcp_packet("10.0.0.2", 40002, "203.0.113.9", 443, TCP_SYN);
    tcp.push(syn.clone(), Address::outbound_packet(false));
    let sent = wait_sent(&tcp, 2000);
    assert_eq!(sent[0].0, syn);
    assert!(sent[0].1.outbound());
}

#[test]
fn flows_opened_before_redirection_are_reset() {
    let r = rig();
    let (proxy_port, _) = socks5_server(&r.engine.runtime());
    r.engine.start(&config(proxy_port, ProxyType::Socks5)).unwrap();
    let tcp = r.tcp();

    // Wow.exe already had a connection when the engine started: its next segment is answered with a RST.
    r.owns_tcp(100, "10.0.0.2", 41000, "203.0.113.20", 8085);
    tcp.push(tcp_packet("10.0.0.2", 41000, "203.0.113.20", 8085, TCP_ACK), Address::outbound_packet(false));
    let sent = wait_sent(&tcp, 2000);
    assert_eq!(sent.len(), 1);
    let rst = packet::parse(&sent[0].0).unwrap();
    assert!(rst.is_rst() && !sent[0].1.outbound(), "reset towards the program, nothing sent out");
    assert!(r.logs().contains("opened before redirection (Wow1)"));
    // Later segments of the killed flow are dropped quietly.
    tcp.push(tcp_packet("10.0.0.2", 41000, "203.0.113.20", 8085, TCP_ACK), Address::outbound_packet(false));
    assert!(wait_sent(&tcp, 200).is_empty());

    // Firefox's existing connection is allowed to continue.
    r.owns_tcp(200, "10.0.0.2", 41001, "203.0.113.20", 443);
    let seg = tcp_packet("10.0.0.2", 41001, "203.0.113.20", 443, TCP_ACK);
    tcp.push(seg.clone(), Address::outbound_packet(false));
    assert_eq!(wait_sent(&tcp, 2000)[0].0, seg);
}

#[test]
fn fake_ip_dns_and_remote_names() {
    let r = rig();
    let rt = r.engine.runtime();
    let (proxy_port, seen) = socks5_server(&rt);
    let echo = echo_server(&rt);
    let mut c = config(proxy_port, ProxyType::Socks5);
    c.settings.dns_mode = DnsMode::FakeIp;
    r.engine.start(&c).unwrap();
    let dns = r.platform.opener.handle("udp.DstPort == 53");

    // Wow.exe asks for world.realm.example: the interceptor answers with a fake address.
    let query = Message::build_query(7, "world.realm.example", TYPE_A).unwrap();
    let q = packet::build_udp("127.0.0.1".parse().unwrap(), 50500, "192.0.2.53".parse().unwrap(), 53, &query).unwrap();
    dns.push(q, Address::outbound_packet(false));
    let sent = wait_sent(&dns, 2000);
    let info = packet::parse(&sent[0].0).unwrap();
    assert_eq!((info.source_port, info.destination_port), (53, 50500));
    let answer = Message::parse(&sent[0].0[info.payload_offset..]).unwrap();
    let fake = answer.answers[0].address.unwrap();
    assert!(fake.to_string().starts_with("198.18."));

    let aaaa = Message::build_query(8, "world.realm.example", TYPE_AAAA).unwrap();
    dns.push(
        packet::build_udp("127.0.0.1".parse().unwrap(), 50501, "192.0.2.53".parse().unwrap(), 53, &aaaa).unwrap(),
        Address::outbound_packet(false),
    );
    let sent = wait_sent(&dns, 2000);
    let info = packet::parse(&sent[0].0).unwrap();
    assert!(Message::parse(&sent[0].0[info.payload_offset..]).unwrap().answers.is_empty(), "no IPv6 answers");

    // Single-label names are not faked.
    let local = Message::build_query(9, "printer", TYPE_A).unwrap();
    let raw = packet::build_udp("127.0.0.1".parse().unwrap(), 50502, "192.0.2.53".parse().unwrap(), 53, &local).unwrap();
    dns.push(raw.clone(), Address::outbound_packet(false));
    let sent = wait_sent(&dns, 2000);
    assert_eq!(sent[0].0, raw, "passed through unchanged");

    // Wow.exe connects to the fake address: the proxy gets the name.
    let tcp = r.tcp();
    let fake_text = fake.to_string();
    r.owns_tcp(100, "127.0.0.1", 42000, &fake_text, echo);
    tcp.push(tcp_packet("127.0.0.1", 42000, &fake_text, echo, TCP_SYN), Address::outbound_packet(false));
    let sent = wait_sent(&tcp, 2000);
    let reflected = packet::parse(&sent[0].0).unwrap();
    assert_eq!(reflected.source, fake, "reflected from the fake address");
    assert_ne!(reflected.destination_port, echo, "to the relay");
    assert_eq!(r.engine.nat_entries(), 1);
    // (The relay side of fake-IP flows, where the name goes to the proxy, is covered by proxidize-core's relay
    // tests: a loopback test can't open a connection from 198.18.x.x.)
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn udp_through_a_non_socks5_route_is_blocked_and_direct_udp_passes() {
    let r = rig();
    let (proxy_port, _) = socks5_server(&r.engine.runtime());
    r.engine.start(&config(proxy_port, ProxyType::Http)).unwrap();
    let udp = r.platform.opener.handle("udp.SrcPort !=");

    r.platform.system.udp.lock().unwrap().push(UdpRow { local: Ip::UNSPECIFIED_V4, local_port: 50000, pid: 100 });
    let dgram = packet::build_udp("10.0.0.2".parse().unwrap(), 50000, "203.0.113.9".parse().unwrap(), 3074, b"game").unwrap();
    udp.push(dgram, Address::outbound_packet(false));
    assert!(wait_sent(&udp, 300).is_empty(), "HTTP proxies can't carry UDP: blocked, never direct");
    assert!(r.logs().contains("UDP needs a single SOCKS5 proxy"));

    r.platform.system.udp.lock().unwrap().push(UdpRow { local: Ip::UNSPECIFIED_V4, local_port: 50001, pid: 200 });
    let direct = packet::build_udp("10.0.0.2".parse().unwrap(), 50001, "203.0.113.9".parse().unwrap(), 443, b"quic").unwrap();
    udp.push(direct.clone(), Address::outbound_packet(false));
    assert_eq!(wait_sent(&udp, 2000)[0].0, direct);
}

#[test]
fn live_rule_changes_and_restarts() {
    let r = rig();
    let (proxy_port, _) = socks5_server(&r.engine.runtime());
    let mut c = config(proxy_port, ProxyType::Socks5);
    r.engine.start(&c).unwrap();
    let generation = r.engine.generation();

    // A new whole-program rule: swapped in live, and the kill switch covers it at once.
    c.rules.push(Rule {
        name: "Firefox".into(),
        programs: vec![FIREFOX.into()],
        route_id: Some(c.proxies[0].id.clone()),
        ..Default::default()
    });
    r.engine.apply_config(&c).unwrap();
    assert_eq!(r.engine.generation(), generation, "no restart for rule changes");
    assert_eq!(r.platform.filters.blocks.lock().unwrap().len(), 2);
    assert!(r.logs().contains("Rules updated."));

    // Switching DNS mode restarts.
    c.settings.dns_mode = DnsMode::FakeIp;
    r.engine.apply_config(&c).unwrap();
    assert!(r.engine.generation() > generation);
    assert!(r.engine.is_running());

    // Turning the kill switch off removes the blocks.
    c.settings.kill_switch = false;
    r.engine.apply_config(&c).unwrap();
    assert!(r.platform.filters.blocks.lock().unwrap().is_empty());
}
