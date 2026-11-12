# Proxidize

Per-program proxy redirection for Windows, in one exe. Pick a program, pick a SOCKS5 / SOCKS4 / HTTP proxy or a
chain, and its traffic goes through it — whether or not the program supports proxies.

This is the Rust rewrite of [ProxyForge](https://github.com/p3tr0s/proxyforge): same rules, same config file, same
leak protection, but shipped as a single `proxidize.exe` with nothing to install next to it.

**Status: in progress.** The platform-independent core is done and tested; the Windows engine and the UI are next.
[PLAN.md](PLAN.md) tracks what is left before the first release. Until then, use ProxyForge.

## Layout

| Crate | What it holds |
|---|---|
| `crates/proxidize-core` | Config, rule engine, packet codec, fragment reassembly, DNS and fake IPs, SOCKS/HTTP clients and chains, relay, health check, ProxyCap import |
| `crates/proxidize-win` | Windows engine: WinDivert, redirectors, process lookup, WFP kill switch, DPAPI, autostart |
| `crates/proxidize` | The app (egui) |

## Build

Windows 10/11 x64 with the Rust toolchain (`rustup`, MSVC):

```
powershell -File scripts\get-windivert.ps1
cargo build --release
```

`get-windivert.ps1` downloads WinDivert 2.2.2 into `third_party\`; the build embeds it in the exe. The core crate
also builds and tests on Linux and macOS: `cargo test -p proxidize-core`.

## License

MIT (see `LICENSE`). WinDivert is LGPLv3 / GPLv2 dual-licensed; it is downloaded at build time, not part of the
source, and embedded unmodified in the exe, with its license shipped in the release zip.
