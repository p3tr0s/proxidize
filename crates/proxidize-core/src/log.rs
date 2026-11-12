//! In-memory ring buffer of log lines with an optional rolling log file.

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use chrono::{DateTime, Local};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warning,
    Error,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::Debug => "Debug",
            Level::Info => "Info",
            Level::Warning => "Warning",
            Level::Error => "Error",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub sequence: u64,
    pub time: DateTime<Local>,
    pub level: Level,
    pub message: String,
}

const CAPACITY: usize = 5000;
const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Default)]
pub struct LogHub {
    entries: Mutex<(u64, VecDeque<Entry>)>,
    file: Mutex<Option<PathBuf>>,
    verbose: AtomicBool,
}

impl LogHub {
    pub fn new(file: Option<PathBuf>) -> LogHub {
        let file = file.filter(|f| f.parent().map(|d| fs::create_dir_all(d).is_ok()).unwrap_or(true));
        LogHub { file: Mutex::new(file), ..Default::default() }
    }

    pub fn set_verbose(&self, on: bool) {
        self.verbose.store(on, Ordering::Relaxed);
    }

    pub fn verbose(&self) -> bool {
        self.verbose.load(Ordering::Relaxed)
    }

    pub fn debug(&self, message: impl Into<String>) {
        if self.verbose() {
            self.write(Level::Debug, message.into());
        }
    }

    pub fn info(&self, message: impl Into<String>) {
        self.write(Level::Info, message.into());
    }

    pub fn warning(&self, message: impl Into<String>) {
        self.write(Level::Warning, message.into());
    }

    pub fn error(&self, message: impl Into<String>) {
        self.write(Level::Error, message.into());
    }

    pub fn write(&self, level: Level, message: String) {
        let entry = {
            let mut guard = self.entries.lock().unwrap();
            guard.0 += 1;
            let entry = Entry { sequence: guard.0, time: Local::now(), level, message };
            guard.1.push_back(entry.clone());
            while guard.1.len() > CAPACITY {
                guard.1.pop_front();
            }
            entry
        };
        self.write_file(&entry);
    }

    pub fn last_sequence(&self) -> u64 {
        self.entries.lock().unwrap().0
    }

    /// Entries with a sequence number greater than `after`.
    pub fn entries_after(&self, after: u64) -> Vec<Entry> {
        self.entries.lock().unwrap().1.iter().filter(|e| e.sequence > after).cloned().collect()
    }

    fn write_file(&self, entry: &Entry) {
        let guard = self.file.lock().unwrap();
        let Some(path) = guard.as_ref() else { return };
        // logging must never take the engine down: errors are ignored
        if fs::metadata(path).map(|m| m.len() > MAX_FILE_BYTES).unwrap_or(false) {
            let mut rolled = path.clone().into_os_string();
            rolled.push(".1");
            let _ = fs::rename(path, rolled);
        }
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{} [{}] {}", entry.time.format("%Y-%m-%d %H:%M:%S%.3f"), entry.level.label(), entry.message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_and_sequence() {
        let log = LogHub::default();
        log.debug("hidden");
        log.info("a");
        log.set_verbose(true);
        log.debug("b");
        assert_eq!(log.entries_after(0).len(), 2);
        assert_eq!(log.entries_after(1)[0].message, "b");
        for i in 0..CAPACITY + 10 {
            log.info(format!("{i}"));
        }
        assert_eq!(log.entries_after(0).len(), CAPACITY);
        assert_eq!(log.last_sequence(), (CAPACITY + 12) as u64);
    }
}
