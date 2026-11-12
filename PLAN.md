# Plan: ProxyForge in Rust

Proxidize is the Rust rewrite of [ProxyForge](https://github.com/p3tr0s/proxyforge) (C#/.NET 10). The goal is the
same app as **one `proxidize.exe`**: no runtime to install, no DLLs or driver files next to it. WinDivert's DLL and
signed driver are embedded and extracted on first run.

ProxyForge stays the reference until every box below is ticked; its self-tests were ported alongside the code
(the reference vectors for checksums, the sanitized `machine.prs` fixture, the proxy and relay end-to-end tests).

## Layout

| Crate | What it holds | Builds on |
|---|---|---|
| `proxidize-core` | Config, rules, packet codec, fragments, DNS, fake IPs, proxy clients and chains, relay, health check, ProxyCap import, log | any OS (tested on Linux and Windows in CI) |
| `proxidize-win` | WinDivert (embedded), TCP/UDP redirectors, DNS interception, process lookup, WFP kill switch, DPAPI, autostart, engine | Windows |
| `proxidize` | The egui app and the tray | Windows |

## Parity checklist

### Core (`proxidize-core`) — done

- [x] Addresses, CIDRs, ranges, targets with IDN normalisation
- [x] Wildcards, `.domain` host patterns, port ranges, fake-IP domain scope
- [x] Config: ProxyForge's JSON format as is (PascalCase, enums as strings), example config, atomic save, password protection hook, plain-password migration
- [x] Rule engine: programs (name/path globs), destinations (hosts, IPs, CIDRs, ranges), ports, transport; first match wins; invalid routes block; kill-switch program set
- [x] Packets: IPv4/IPv6 + TCP/UDP parse and rewrite, checksums (C# reference vectors), IPv6 extension headers, UDP build, RST for SYN and for established segments
- [x] IP fragment reassembly (IPv4 and IPv6), overlap/oversize/expiry handling, bounded
- [x] DNS codec, compression pointers, fake-IP pool with recycling, reverse DNS cache (bounded)
- [x] Upstream DNS client from a fixed source port, server selection
- [x] SOCKS5 (no auth / user+password), SOCKS4/4a, HTTP CONNECT (Basic), chains of any length, SOCKS5 UDP header codec
- [x] Relay: NAT table, reflected-connection accept, remote DNS by name, route guard, AbortAll / AbortRoutes with RST, byte counters, connection list
- [x] Health check: IP/country lookup through each route, HTTP and HTTPS (rustls), redirects, chunked bodies, leak / shared-IP annotation, change descriptions
- [x] ProxyCap import: XML (proxies, chains, rules, ports, IPs, hosts, remote DNS exceptions) and binary `machine.prs`

### Windows (`proxidize-win`) — done, running on Windows

The redirection logic is written against small traits (packet diversion, process tables, WFP), so it is tested on
Linux too: the engine runs end to end against a simulated platform (a proxied connection through the real relay and
a SOCKS5 server, block/RST, strict-mode drops, pre-existing flows reset, fake-IP DNS, UDP rules, live config).

- [x] WinDivert loaded at runtime: embedded DLL + `.sys`, extracted to `%ProgramData%\Proxidize\bin\WinDivert-<hash>`, folder locked to SYSTEM/Administrators and files verified byte for byte before loading
- [x] Process lookup: socket-layer events + TCP/UDP owner tables, pid creation-time validation
- [x] TCP redirector: SYN reflection to the relay, NAT, strict fail-closed handling, reset of pre-existing flows, TIME_WAIT leftovers dropped, deferred owner lookup
- [x] UDP redirector: SOCKS5 UDP ASSOCIATE per route, fragments reassembled, UDP blocked when the route can't carry it, health-check guard
- [x] DNS: fake-IP interception, sniffing for host-name rules, own resolver port excluded
- [x] WFP kill switch: persistent per-app block filters + dynamic-session permit while running, learned paths, `--remove-killswitch` helper
- [x] DPAPI password protection (same entropy as ProxyForge, so its config imports with passwords)
- [x] Start with Windows (Task Scheduler, elevated), firewall rule for the relay, DNS cache flush, adapter DNS servers
- [x] Engine: start/stop, live config apply, kill-switch learning, maintenance sweeps, route guard
- [x] Health checks on a schedule, notifications (with the app)
- [x] First run on real Windows (0.1.0: redirection works once ProxyForge's leftover kill switch is removed)

### App (`proxidize`) — done

- [x] egui window in the ProxyForge patch-panel design: Overview switchboard, Rules, Proxies, Chains, Connections, Log, Settings
- [x] Editors for proxies (with cable colour and a test), chains, rules (with a running-program picker), credentials for many proxies
- [x] ProxyCap import preview (merge / replace, backup of the current config), ProxyForge import (passwords included)
- [x] Scheduled proxy checks with retry, leak blocking and notifications (tray balloons)
- [x] Tray icon as a link light, close to tray, start minimised, single instance
- [x] Admin manifest, icon, version info embedded in the exe
- [x] `--screenshots` and the UI screenshots workflow (Linux preview build under Xvfb)
- [x] System clipboard (0.1.1)
- [x] Updates: GitHub release check on start and every 12 hours, banner + tray notice, one-click install verified against `SHA256SUMS.txt`, exe swap and restart (0.2.0)

### Release

- [x] CI: core on Linux; workspace clippy + tests + release build on Windows
- [x] First release (`0.1.0`)
- [ ] Make the repository public so the update check can see releases

## After 0.1.0: closing the gap to ProxyCap

- [ ] HTTPS proxies (TLS to the proxy, then CONNECT) — rustls is already in
- [ ] Remote DNS exceptions per rule (config field + rule engine; import keeps them per rule)
- [ ] Shadowsocks (AEAD ciphers, TCP and UDP)
- [ ] SSH tunnels (direct-tcpip channels, password and key auth)
- [ ] Windows service mode: engine as a service (redirects before sign-in), the app talks to it over a local pipe
- [ ] ICMP through SOCKS isn't possible; at most: block or allow it per rule
