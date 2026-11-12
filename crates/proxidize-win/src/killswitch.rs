//! Leak protection for programs that must never connect directly:
//!
//! * persistent WFP block filters (ALE connect, IPv4 and IPv6) per program path, which survive Proxidize exiting,
//!   crashing and reboots;
//! * while the engine redirects, a permit-all filter in the same sublayer at a higher weight, added through a
//!   *dynamic* WFP session. The base filtering engine deletes it when that session closes, including when the
//!   process dies, so the blocks take effect again without Proxidize doing anything.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use proxidize_core::log::LogHub;

/// The filtering platform operations the kill switch needs.
pub trait Filters: Send + Sync {
    /// Replaces our persistent block filters with one per path (one transaction). Returns the paths applied;
    /// paths that can't be blocked (missing file) are skipped with a warning.
    fn apply_blocks(&self, paths: &[String], log: &LogHub) -> Result<Vec<String>, String>;
    /// Deletes our block filters; `remove_objects` also deletes the provider and sublayer. Returns how many.
    fn remove_blocks(&self, remove_objects: bool) -> Result<usize, String>;
    /// Adds the permit-all override in a dynamic session (kept open until `revoke`).
    fn allow_while_running(&self) -> Result<(), String>;
    /// Closes the dynamic session: its filters disappear with it.
    fn revoke(&self);
    fn is_allowing(&self) -> bool;
}

pub struct KillSwitch {
    filters: Arc<dyn Filters>,
    log: Arc<LogHub>,
    learned_file: Option<PathBuf>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    learned: Vec<String>,
    protected: Vec<String>,
    /// `None`: the first sync always reconciles filters left by an earlier run.
    last_applied: Option<String>,
}

fn contains_ci(list: &[String], item: &str) -> bool {
    list.iter().any(|x| x.eq_ignore_ascii_case(item))
}

impl KillSwitch {
    pub fn new(filters: Arc<dyn Filters>, log: Arc<LogHub>, learned_file: Option<PathBuf>) -> KillSwitch {
        let mut state = State::default();
        if let Some(text) = learned_file.as_ref().and_then(|f| std::fs::read_to_string(f).ok()) {
            for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                if !contains_ci(&state.learned, line) {
                    state.learned.push(line.to_string());
                }
            }
        }
        KillSwitch { filters, log, learned_file, state: Mutex::new(state) }
    }

    /// Programs blocked whenever the engine isn't redirecting.
    pub fn protected_paths(&self) -> Vec<String> {
        self.state.lock().unwrap().protected.clone()
    }

    pub fn is_allowing_while_running(&self) -> bool {
        self.filters.is_allowing()
    }

    /// Remembers the full path of a program matched by name or wildcard. True when new (the caller re-syncs).
    pub fn learn(&self, path: &str) -> bool {
        let mut s = self.state.lock().unwrap();
        if contains_ci(&s.learned, path) {
            return false;
        }
        s.learned.push(path.to_string());
        s.learned.sort_by_key(|p| p.to_lowercase());
        if let Some(file) = &self.learned_file {
            if let Some(dir) = file.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Err(e) = std::fs::write(file, s.learned.join("\r\n")) {
                self.log.debug(format!("Kill switch: could not save learned paths: {e}"));
            }
        }
        true
    }

    /// Makes the persistent blocks match `exact_paths` plus learned paths that are still protected programs.
    /// Disabled or empty removes them.
    pub fn sync(&self, enabled: bool, exact_paths: &[String], is_protected: impl Fn(&str) -> bool) {
        let mut s = self.state.lock().unwrap();
        let mut desired: Vec<String> = Vec::new();
        if enabled {
            for path in exact_paths.iter().chain(s.learned.iter().filter(|p| is_protected(p))) {
                if !contains_ci(&desired, path) {
                    desired.push(path.clone());
                }
            }
        }
        let mut keys: Vec<String> = desired.iter().map(|p| p.to_lowercase()).collect();
        keys.sort();
        let signature = keys.join("|");
        if s.last_applied.as_deref() == Some(signature.as_str()) {
            return;
        }
        let result = if desired.is_empty() {
            self.filters.remove_blocks(!enabled && !self.filters.is_allowing()).map(|removed| {
                if removed > 0 {
                    self.log.info(format!("Kill switch: removed {removed} block filter(s)."));
                }
                Vec::new()
            })
        } else {
            self.filters.apply_blocks(&desired, &self.log).inspect(|applied| {
                let n = applied.len();
                self.log.info(format!(
                    "Kill switch: {n} {} can't connect unless Proxidize is redirecting {}",
                    if n == 1 { "program" } else { "programs" },
                    if n == 1 { "it" } else { "them" }
                ));
            })
        };
        match result {
            Ok(applied) => {
                s.protected = applied;
                s.last_applied = Some(signature);
            }
            Err(e) => self.log.error(format!("Kill switch update failed: {e}")),
        }
    }

    /// Adds the running override. Call once the redirectors are active.
    pub fn allow_while_running(&self) -> Result<(), String> {
        if self.filters.is_allowing() {
            return Ok(());
        }
        self.filters.allow_while_running()
    }

    /// Protected programs are blocked again. Call before the redirectors stop.
    pub fn revoke_running_allowance(&self) {
        self.filters.revoke();
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        self.filters.revoke();
    }
}

/// No filtering platform (tests, other OSes): remembers what it was asked to do.
#[derive(Default)]
pub struct MemoryFilters {
    pub blocks: Mutex<Vec<String>>,
    pub allowing: Mutex<bool>,
}

impl Filters for MemoryFilters {
    fn apply_blocks(&self, paths: &[String], _log: &LogHub) -> Result<Vec<String>, String> {
        *self.blocks.lock().unwrap() = paths.to_vec();
        Ok(paths.to_vec())
    }

    fn remove_blocks(&self, _remove_objects: bool) -> Result<usize, String> {
        let mut b = self.blocks.lock().unwrap();
        let n = b.len();
        b.clear();
        Ok(n)
    }

    fn allow_while_running(&self) -> Result<(), String> {
        *self.allowing.lock().unwrap() = true;
        Ok(())
    }

    fn revoke(&self) {
        *self.allowing.lock().unwrap() = false;
    }

    fn is_allowing(&self) -> bool {
        *self.allowing.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_learn_and_running_override() {
        let filters = Arc::new(MemoryFilters::default());
        let dir = std::env::temp_dir().join(format!("proxidize-ks-{}", std::process::id()));
        let file = dir.join("learned.txt");
        let ks = KillSwitch::new(filters.clone(), Arc::new(LogHub::default()), Some(file.clone()));
        let exact = vec![r"F:\Wow1\Wow.exe".to_string()];
        ks.sync(true, &exact, |_| true);
        assert_eq!(*filters.blocks.lock().unwrap(), exact);
        assert!(ks.learn(r"C:\Games\Wow.exe"));
        assert!(!ks.learn(r"c:\games\wow.exe"), "case-insensitive");
        ks.sync(true, &exact, |p| p.to_lowercase().ends_with("wow.exe"));
        assert_eq!(filters.blocks.lock().unwrap().len(), 2);
        assert_eq!(ks.protected_paths().len(), 2);

        // learned paths survive a restart
        let again = KillSwitch::new(Arc::new(MemoryFilters::default()), Arc::new(LogHub::default()), Some(file.clone()));
        assert!(!again.learn(r"C:\Games\Wow.exe"));

        ks.allow_while_running().unwrap();
        assert!(ks.is_allowing_while_running());
        ks.revoke_running_allowance();
        assert!(!ks.is_allowing_while_running());
        ks.sync(false, &[], |_| false);
        assert!(filters.blocks.lock().unwrap().is_empty());
        drop(ks);
        let _ = std::fs::remove_dir_all(dir);
    }
}
