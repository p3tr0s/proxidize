# Proxidize

Per-program proxy redirection for Windows, in one exe. Pick a program, pick a SOCKS5 / SOCKS4 / HTTP proxy or a
chain, and its traffic goes through it, whether or not the program supports proxies.

This is the Rust rewrite of [ProxyForge](https://github.com/p3tr0s/proxyforge): same rules, same config file, same
leak protection, shipped as a single `proxidize.exe` (WinDivert's driver is embedded and unpacked on first start).

![Proxidize overview: each program plugged into its proxy, with the exit IP and country](docs/overview.png)

**Status: feature-complete, not yet run on real Windows.** Everything is ported and tested (the engine runs end to
end against a simulated platform in the test suite), but the first Windows run is still ahead; until it has happened
and [PLAN.md](PLAN.md) says so, keep ProxyForge as your daily driver. Releases start at `0.1.0`.

## What it does

- **Rules** by program (name or path glob), destination (host globs, `.domain`, IPs, CIDRs, IP ranges), ports and
  transport; first match wins; actions **Proxy / Direct / Block**
- **Proxies:** SOCKS5 (no auth / username+password), SOCKS4 / 4a, HTTP CONNECT (Basic auth); **chains** of any length
- **Remote DNS** through fake-IP DNS: host names go to the proxy, not to your resolver
- **UDP** through SOCKS5 UDP ASSOCIATE; UDP a route can't carry is blocked, never sent directly
- **Leak protection:** strict fail-closed packet handling and a WFP **kill switch** that keeps proxied programs
  offline whenever Proxidize isn't redirecting (stopped, crashed, not started yet after a reboot)
- **Proxy check:** exit IP and country through every proxy, on a schedule; a proxy whose exit IP is your own is
  blocked until it's fixed; tray notifications on changes
- **ProxyCap import** (binary `machine.prs` and XML) and **ProxyForge import** (config with passwords)
- Start with Windows (elevated, no prompt), passwords encrypted with DPAPI, tray icon as a link light

## Using it

Run `proxidize.exe` (it asks for Administrator rights: the packet driver and the kill switch need them). Add a proxy
under **Proxies**, a rule under **Rules**, press **Start**. Closing the window keeps it running in the tray.

| Flag | |
|---|---|
| `--minimized` | start in the tray (used by Start with Windows) |
| `--remove-killswitch` | delete every Proxidize filter from Windows Filtering Platform, e.g. after uninstalling |
| `--demo` | open with sample data, nothing is saved or redirected |
| `--screenshots <folder>` | render every page with the sample data to PNGs |

Config: `%ProgramData%\Proxidize\config.json` (ProxyForge's format). Logs: `%ProgramData%\Proxidize\logs`.

## Layout

| Crate | What it holds |
|---|---|
| `crates/proxidize-core` | Config, rule engine, packet codec, fragment reassembly, DNS and fake IPs, SOCKS/HTTP clients and chains, relay, proxy check, ProxyCap import |
| `crates/proxidize-win` | The engine: WinDivert (embedded), TCP/UDP redirectors, DNS interception, process lookup, WFP kill switch, DPAPI, autostart |
| `crates/proxidize` | The app: egui window in the patch-panel design, tray |

The redirection logic is written against small traits (packet diversion, process tables, WFP), so the engine's
tests run on any OS. On Linux the app builds as a preview (no redirection) for screenshots and design work.

## Build

Windows 10/11 x64 with the Rust toolchain (`rustup`, MSVC):

```
powershell -File scripts\get-windivert.ps1
cargo build --release
```

`get-windivert.ps1` downloads WinDivert 2.2.2 into `third_party\`; the build embeds it. `cargo test --workspace`
runs the tests. CI builds on every push and publishes a release when the version in `Cargo.toml` has no
release yet (and isn't a `-dev` version).

## Known limitations

- Localhost traffic is never redirected. Programs using DNS-over-HTTPS bypass fake-IP DNS.
- UDP needs a SOCKS5 proxy with UDP ASSOCIATE support.
- The kill switch covers whole-program rules only.
- ICMP (ping, traceroute) is not redirected.
- Some anti-cheat and anti-virus products block WinDivert.

## License

MIT (see `LICENSE`). WinDivert is LGPLv3 / GPLv2 dual-licensed; it is downloaded at build time, not part of the
source, embedded unmodified in the exe, and its license ships in the release zip.
