# Changelog

## 0.4.0 — 2026-11-13

- **HTTPS proxies:** a new proxy type that connects to the proxy over TLS, also as a hop inside a chain. The
  certificate is checked by default; "Skip certificate check" accepts a self-signed one on your own proxy.
- **Resolve locally, per rule:** with remote DNS on, a rule can list host names (`*.corp.example`, `.lan`, `printer`)
  that are resolved on your PC and sent to the proxy as IPs. The ProxyCap import keeps these exceptions on their rule.
- The ProxyCap XML import accepts HTTPS proxies.

## 0.3.0 — 2026-11-12

- Passwords are encrypted with Proxidize's own key. Configs from earlier versions still open, and are re-encrypted
  on the next save.
- The sample data (`--demo`, screenshots) shows everyday programs.

## 0.2.0 — 2026-11-12

- **Updates:** Proxidize checks for new releases on start and every 12 hours. **Update and restart** downloads the
  new version, checks its SHA-256 against the release, installs it and restarts, resuming redirection if it was on.
  **Settings → Updates** turns the check off or runs it now.

## 0.1.1 — 2026-11-12

- Copy and paste work with other programs (they only worked inside Proxidize).

## 0.1.0 — 2026-11-12

First release: per-program rules, SOCKS5 / SOCKS4 / HTTP proxies and chains, fake-IP remote DNS, UDP through SOCKS5,
strict fail-closed redirection, the kill switch, scheduled proxy checks with exit IP and country, ProxyCap import,
tray icon and Start with Windows.
