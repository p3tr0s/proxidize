//! DNS on the packet path: the fake-IP interceptor (answers A queries for in-scope names with fake addresses, and
//! AAAA/HTTPS/SVCB with empty answers so programs fall back to IPv4) and the sniffer that learns which names map to
//! which addresses for host-name rules.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use proxidize_core::dns::{Message, TYPE_A, TYPE_AAAA, TYPE_HTTPS, TYPE_SVCB};
use proxidize_core::packet;

use crate::context::EngineContext;
use crate::divert::{is_shutdown_error, Address, Divert, MTU_MAX};

pub const INTERCEPT_PRIORITY: i16 = 100;
pub const SNIFF_PRIORITY: i16 = 200;
pub const SNIFF_FILTER: &str = "udp.SrcPort == 53";
const FAKE_TTL: u32 = 1;

pub fn intercept_filter(resolver_port: u16) -> String {
    format!("outbound and !loopback and udp.DstPort == 53 and udp.SrcPort != {resolver_port}")
}

/// A capture thread that stops (and is joined) on drop.
pub struct Worker {
    handle: Arc<dyn Divert>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.handle.shutdown();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn spawn(name: &str, handle: Arc<dyn Divert>, mut on_packet: impl FnMut(&mut [u8], &mut Address) + Send + 'static) -> Worker {
    let stopping = Arc::new(AtomicBool::new(false));
    let (h, stop) = (handle.clone(), stopping.clone());
    let thread = std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let mut buffer = vec![0u8; MTU_MAX];
            let mut addr = Address::default();
            while !stop.load(Ordering::Acquire) {
                match h.recv(&mut buffer, &mut addr) {
                    Ok(n) => on_packet(&mut buffer[..n], &mut addr),
                    Err(code) if stop.load(Ordering::Acquire) || is_shutdown_error(code) => break,
                    Err(_) => {}
                }
            }
        })
        .unwrap();
    Worker { handle, stopping, thread: Some(thread) }
}

pub fn start_interceptor(ctx: Arc<EngineContext>, handle: Arc<dyn Divert>) -> Worker {
    let divert = handle.clone();
    spawn("proxidize dns interceptor", handle, move |packet, addr| {
        let answered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| answer(&ctx, divert.as_ref(), packet, addr)));
        if !matches!(answered, Ok(true)) {
            divert.send(packet, addr);
        }
    })
}

/// Answers the query with a fake address. True when it did (the original query is dropped).
pub fn answer(ctx: &EngineContext, divert: &dyn Divert, packet: &[u8], addr: &Address) -> bool {
    let (Some(fake), Some(scope)) = (&ctx.fake_ips, &ctx.fake_scope) else { return false };
    let Some(info) = packet::parse(packet).filter(|i| i.is_udp()) else { return false };
    let Some(query) = Message::parse(&packet[info.payload_offset..info.payload_offset + info.payload_len]) else { return false };
    if query.is_response() || query.opcode() != 0 || query.questions.len() != 1 {
        return false;
    }
    let question = &query.questions[0];
    if question.class != 1 || !scope.matches(&question.name) {
        return false;
    }
    let response = match question.kind {
        TYPE_A => {
            let ip = fake.get_or_allocate(&question.name);
            ctx.log.debug(format!("DNS {} -> fake {ip}", question.name));
            Message::build_response(&query, &[ip], FAKE_TTL)
        }
        TYPE_AAAA | TYPE_HTTPS | TYPE_SVCB => Message::build_response(&query, &[], FAKE_TTL),
        _ => return false,
    };
    let Some(response) = response else { return false };
    let Some(mut reply) = packet::build_udp(info.destination, info.destination_port, info.source, info.source_port, &response)
    else {
        return false;
    };
    let mut a = *addr;
    a.set_outbound(false);
    divert.reinject(&mut reply, &mut a);
    true
}

pub fn start_sniffer(ctx: Arc<EngineContext>, handle: Arc<dyn Divert>) -> Worker {
    let mut counter = 0u32;
    spawn("proxidize dns sniffer", handle, move |packet, _| {
        learn(&ctx, packet);
        counter = counter.wrapping_add(1);
        if counter.is_multiple_of(5000) {
            ctx.dns_cache.sweep();
        }
    })
}

/// Records the addresses in a DNS answer under the queried name (fake addresses excluded).
pub fn learn(ctx: &EngineContext, packet: &[u8]) {
    let Some(info) = packet::parse(packet).filter(|i| i.is_udp()) else { return };
    let Some(message) = Message::parse(&packet[info.payload_offset..info.payload_offset + info.payload_len]) else { return };
    if !message.is_response() || message.questions.is_empty() {
        return;
    }
    let name = &message.questions[0].name;
    for answer in &message.answers {
        if let Some(address) = answer.address {
            if !ctx.fake_ips.as_ref().is_some_and(|f| f.contains(address)) {
                ctx.dns_cache.add(address, name, answer.ttl);
            }
        }
    }
}
