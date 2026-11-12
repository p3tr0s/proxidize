//! Pattern matching used by rules and DNS scoping.

/// `*` and `?` wildcards, case-insensitive (ASCII).
pub fn wildcard(text: &str, pattern: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    let (mut ti, mut pi) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || eq(p[pi], t[ti])) {
            ti += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            mark = ti;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn eq(a: char, b: char) -> bool {
    a == b || a.to_lowercase().eq(b.to_lowercase())
}

/// Host patterns: `.example.com` means the domain and all subdomains, anything else is a wildcard.
pub fn host_matches(host: &str, pattern: &str) -> bool {
    let host = host.trim_end_matches('.');
    if pattern.len() > 1 && pattern.starts_with('.') && !pattern.contains(['*', '?']) {
        let bare = &pattern[1..];
        return host.eq_ignore_ascii_case(bare)
            || (host.len() > pattern.len() && host[host.len() - pattern.len()..].eq_ignore_ascii_case(pattern));
    }
    wildcard(host, pattern)
}

/// Splits `a;b, c` style lists (also newlines, spaces, tabs).
pub fn split_list(list: &str) -> Vec<String> {
    list.split([';', ',', '\r', '\n', ' ', '\t']).map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
}

/// `443`, `8000-9000` or `*`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PortRange {
    pub first: u16,
    pub last: u16,
}

impl PortRange {
    pub fn parse(text: &str) -> Option<PortRange> {
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        if text == "*" {
            return Some(PortRange { first: 0, last: 65535 });
        }
        match text.split_once('-') {
            None => text.parse::<u16>().ok().map(|p| PortRange { first: p, last: p }),
            Some((a, b)) => {
                let a = a.trim().parse::<u16>().ok()?;
                let b = b.trim().parse::<u16>().ok()?;
                Some(PortRange { first: a.min(b), last: a.max(b) })
            }
        }
    }

    pub fn contains(&self, port: u16) -> bool {
        port >= self.first && port <= self.last
    }
}

/// Which names get fake IPs: included patterns minus excluded ones. Single-label names never match.
#[derive(Clone, Debug, Default)]
pub struct DomainScope {
    include: Vec<String>,
    exclude: Vec<String>,
}

impl DomainScope {
    pub fn new(include: &str, exclude: &str, extra_excludes: impl IntoIterator<Item = String>) -> DomainScope {
        let mut ex = split_list(exclude);
        ex.extend(extra_excludes.into_iter().filter(|e| !e.trim().is_empty()));
        DomainScope { include: split_list(include), exclude: ex }
    }

    pub fn matches(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.');
        if name.is_empty() || !name.contains('.') {
            return false;
        }
        if self.exclude.iter().any(|p| host_matches(name, p)) {
            return false;
        }
        self.include.iter().any(|p| host_matches(name, p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards() {
        assert!(wildcard("Wow.exe", "wow*.exe"));
        assert!(wildcard("chrome.exe", "CHROME.EXE"));
        assert!(wildcard(r"F:\Wow1\Wow.exe", r"f:\wow1\*"));
        assert!(wildcard("abc", "a?c"));
        assert!(!wildcard("abcd", "a?c"));
        assert!(wildcard("anything", "*"));
        assert!(!wildcard("firefox.exe", "chrome.exe"));
        assert!(wildcard("aXbXc", "a*b*c"));
    }

    #[test]
    fn hosts() {
        assert!(host_matches("example.com", ".example.com"));
        assert!(host_matches("a.b.example.com.", ".example.com"));
        assert!(!host_matches("badexample.com", ".example.com"));
        assert!(host_matches("cdn.x.net", "*.x.net"));
        assert!(!host_matches("x.net", "*.x.net"));
    }

    #[test]
    fn ports() {
        assert_eq!(PortRange::parse("443"), Some(PortRange { first: 443, last: 443 }));
        assert!(PortRange::parse("9000-8000").unwrap().contains(8500));
        assert!(PortRange::parse("*").unwrap().contains(1));
        assert!(PortRange::parse("70000").is_none());
        assert!(PortRange::parse("x").is_none());
    }

    #[test]
    fn domain_scope() {
        let scope = DomainScope::new("*", "localhost;.local;.lan", ["nl.socks.example.net".to_string()]);
        assert!(scope.matches("realm.example.com"));
        assert!(!scope.matches("printer.local"));
        assert!(!scope.matches("wpad"), "single label");
        assert!(!scope.matches("nl.socks.example.net"), "proxy hosts excluded");
        assert_eq!(split_list("a; b,c\n d"), vec!["a", "b", "c", "d"]);
    }
}
