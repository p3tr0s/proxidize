//! Updates from the GitHub releases of the repository: the newest version, its exe, and a SHA-256 check against the
//! release's `SHA256SUMS.txt` before anything is installed.

use crate::health;
use crate::proxy::Connector;

pub const REPOSITORY: &str = "p3tr0s/proxidize";
pub const LATEST_URL: &str = "https://api.github.com/repos/p3tr0s/proxidize/releases/latest";
const MAX_EXE: usize = 96 * 1024 * 1024;
const MAX_JSON: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    /// Without the leading `v`.
    pub version: String,
    /// The release page (notes).
    pub page: String,
    pub exe_name: String,
    pub exe_url: String,
    pub sums_url: String,
}

/// `0.1.1`, `v0.2.0`, `0.1.0-dev` → (major, minor, patch, is a pre-release).
pub fn parse_version(text: &str) -> Option<(u64, u64, u64, bool)> {
    let text = text.trim().trim_start_matches(['v', 'V']);
    let (core, pre) = match text.split_once('-') {
        Some((c, _)) => (c, true),
        None => (text, false),
    };
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    let v = (parts.next()??, parts.next().unwrap_or(Some(0))?, parts.next().unwrap_or(Some(0))?);
    Some((v.0, v.1, v.2, pre))
}

/// Whether `candidate` is newer than `current`. A release beats a pre-release of the same number.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some((a, b, c, pre_a)), Some((x, y, z, pre_x))) => (a, b, c, !pre_a) > (x, y, z, !pre_x),
        _ => false,
    }
}

/// Reads GitHub's `releases/latest` answer.
pub fn parse_latest(body: &[u8]) -> Result<Release, String> {
    let json: serde_json::Value = serde_json::from_slice(body).map_err(|e| format!("Unreadable release information ({e})."))?;
    let tag = json["tag_name"].as_str().ok_or("The release has no version tag.")?;
    let version = tag.trim_start_matches(['v', 'V']).to_string();
    parse_version(&version).ok_or_else(|| format!("Unrecognised release version '{tag}'."))?;
    let assets = json["assets"].as_array().cloned().unwrap_or_default();
    let asset = |pick: &dyn Fn(&str) -> bool| {
        assets.iter().find_map(|a| {
            let name = a["name"].as_str()?;
            let url = a["browser_download_url"].as_str()?;
            pick(name).then(|| (name.to_string(), url.to_string()))
        })
    };
    let (exe_name, exe_url) = asset(&|n: &str| n.to_ascii_lowercase().ends_with("-win-x64.exe"))
        .ok_or_else(|| format!("Release {version} has no Windows exe."))?;
    let (_, sums_url) = asset(&|n: &str| n.eq_ignore_ascii_case("SHA256SUMS.txt"))
        .ok_or_else(|| format!("Release {version} has no SHA256SUMS.txt."))?;
    let page = json["html_url"].as_str().map(String::from).unwrap_or_else(|| format!("https://github.com/{REPOSITORY}/releases"));
    Ok(Release { version, page, exe_name, exe_url, sums_url })
}

/// The hash `sums` lists for `name` (`<hex>  <name>` or `<hex> *<name>` lines), lower-case.
pub fn expected_hash(sums: &str, name: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let (hash, file) = line.trim().split_once(char::is_whitespace)?;
        let file = file.trim().trim_start_matches('*');
        (file.eq_ignore_ascii_case(name) && hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    })
}

pub fn sha256_hex(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// The newest published release.
pub async fn latest(connector: &Connector) -> Result<Release, String> {
    latest_from(connector, LATEST_URL).await
}

pub async fn latest_from(connector: &Connector, url: &str) -> Result<Release, String> {
    let (status, body) = health::fetch(connector, &[], url, "application/vnd.github+json", MAX_JSON)
        .await
        .map_err(|e| format!("Update check failed: {e}"))?;
    match status {
        200 => parse_latest(&body),
        404 => Err("Update check: no published release found (is the repository public?).".into()),
        403 | 429 => Err("Update check: GitHub is rate-limiting requests; trying again later.".into()),
        other => Err(format!("Update check failed: GitHub answered HTTP {other}.")),
    }
}

/// Downloads the release's exe and checks it against `SHA256SUMS.txt`. Only a matching file is returned.
pub async fn download(connector: &Connector, release: &Release) -> Result<Vec<u8>, String> {
    let (status, sums) = health::fetch(connector, &[], &release.sums_url, "*/*", MAX_JSON)
        .await
        .map_err(|e| format!("Downloading the checksums failed: {e}"))?;
    if status != 200 {
        return Err(format!("Downloading the checksums failed: HTTP {status}."));
    }
    let sums = String::from_utf8_lossy(&sums);
    let expected =
        expected_hash(&sums, &release.exe_name).ok_or_else(|| format!("SHA256SUMS.txt doesn't list {}.", release.exe_name))?;
    let (status, exe) = health::fetch(connector, &[], &release.exe_url, "application/octet-stream", MAX_EXE)
        .await
        .map_err(|e| format!("Downloading {} failed: {e}", release.exe_name))?;
    if status != 200 {
        return Err(format!("Downloading {} failed: HTTP {status}.", release.exe_name));
    }
    let actual = sha256_hex(&exe);
    if actual != expected {
        return Err(format!(
            "The downloaded {} doesn't match its published SHA-256 (expected {expected}, got {actual}); not installing it.",
            release.exe_name
        ));
    }
    if !exe.starts_with(b"MZ") {
        return Err(format!("The downloaded {} is not a Windows program; not installing it.", release.exe_name));
    }
    Ok(exe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::{HostResolver, StaticResolver};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn versions() {
        assert_eq!(parse_version("v0.1.1"), Some((0, 1, 1, false)));
        assert_eq!(parse_version("0.1.0-dev"), Some((0, 1, 0, true)));
        assert_eq!(parse_version("1.2"), Some((1, 2, 0, false)));
        assert_eq!(parse_version("x"), None);
        assert!(is_newer("0.2.0", "0.1.1"));
        assert!(is_newer("v0.1.10", "0.1.9"));
        assert!(is_newer("0.1.0", "0.1.0-dev"));
        assert!(!is_newer("0.1.1", "0.1.1"));
        assert!(!is_newer("0.1.0", "0.1.1"));
        assert!(!is_newer("garbage", "0.1.1"));
    }

    #[test]
    fn hashes() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let sums =
            "ABCD  other.zip\nba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad *proxidize-0.2.0-win-x64.exe\r\n";
        assert_eq!(
            expected_hash(sums, "proxidize-0.2.0-win-x64.exe").as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(expected_hash(sums, "other.zip"), None); // not a SHA-256
    }

    fn release_json(port: u16) -> String {
        format!(
            r#"{{"tag_name":"v0.2.0","html_url":"https://github.com/p3tr0s/proxidize/releases/tag/v0.2.0",
                "assets":[{{"name":"proxidize-0.2.0-win-x64.zip","browser_download_url":"http://127.0.0.1:{port}/zip"}},
                          {{"name":"proxidize-0.2.0-win-x64.exe","browser_download_url":"http://127.0.0.1:{port}/exe"}},
                          {{"name":"SHA256SUMS.txt","browser_download_url":"http://127.0.0.1:{port}/sums"}}]}}"#
        )
    }

    #[test]
    fn parses_latest() {
        let r = parse_latest(release_json(1).as_bytes()).unwrap();
        assert_eq!(r.version, "0.2.0");
        assert_eq!(r.exe_name, "proxidize-0.2.0-win-x64.exe");
        assert_eq!(r.exe_url, "http://127.0.0.1:1/exe");
        assert_eq!(r.sums_url, "http://127.0.0.1:1/sums");
        assert!(parse_latest(br#"{"tag_name":"v0.2.0","assets":[]}"#).unwrap_err().contains("no Windows exe"));
    }

    /// A release server: JSON, a redirect to the exe (as GitHub does), the exe in 1 MB, and the checksums.
    async fn server(exe: Vec<u8>, sums: String) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let json = release_json(port);
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let (exe, sums, json) = (exe.clone(), sums.clone(), json.clone());
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap();
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split(' ').nth(1).unwrap_or_default().to_string();
                    let (head, body): (String, Vec<u8>) = match path.as_str() {
                        "/latest" => ("200 OK".into(), json.into_bytes()),
                        "/exe" => ("302 Found\r\nLocation: /blob?sig=x".into(), Vec::new()),
                        "/blob?sig=x" => ("200 OK".into(), exe),
                        "/sums" => ("200 OK".into(), sums.into_bytes()),
                        _ => ("404 Not Found".into(), Vec::new()),
                    };
                    let _ = s.write_all(format!("HTTP/1.1 {head}\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes()).await;
                    let _ = s.write_all(&body).await;
                });
            }
        });
        port
    }

    fn connector() -> Connector {
        let resolver: Arc<dyn HostResolver> = Arc::new(StaticResolver::default());
        Connector::new(resolver, Duration::from_secs(5))
    }

    #[tokio::test]
    async fn downloads_and_verifies() {
        let mut exe = b"MZ".to_vec();
        exe.extend((0..1_000_000u32).map(|i| (i % 251) as u8));
        let sums = format!("{}  proxidize-0.2.0-win-x64.exe\n", sha256_hex(&exe));
        let port = server(exe.clone(), sums).await;
        let release = latest_from(&connector(), &format!("http://127.0.0.1:{port}/latest")).await.unwrap();
        assert_eq!(release.version, "0.2.0");
        assert_eq!(download(&connector(), &release).await.unwrap(), exe);

        let missing = latest_from(&connector(), &format!("http://127.0.0.1:{port}/nothing")).await.unwrap_err();
        assert!(missing.contains("no published release"), "{missing}");
    }

    #[tokio::test]
    async fn refuses_a_mismatched_file() {
        let exe = b"MZ tampered".to_vec();
        let port = server(exe, format!("{}  proxidize-0.2.0-win-x64.exe\n", "0".repeat(64))).await;
        let release = latest_from(&connector(), &format!("http://127.0.0.1:{port}/latest")).await.unwrap();
        let error = download(&connector(), &release).await.unwrap_err();
        assert!(error.contains("doesn't match"), "{error}");
    }
}
