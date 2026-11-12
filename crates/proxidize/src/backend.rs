//! What the window drives: the Windows engine, or a preview stand-in (other OSes, screenshots) that redirects
//! nothing but still runs proxy checks.

use std::collections::HashMap;
use std::sync::Arc;

use proxidize_core::config::Config;
use proxidize_core::log::LogHub;
use proxidize_core::relay::ConnectionTracker;
use proxidize_core::rules::RuleEngine;

pub trait Backend: Send + Sync {
    fn is_running(&self) -> bool;
    fn start(&self, config: &Config) -> Result<(), String>;
    fn stop(&self);
    fn apply(&self, config: &Config) -> Result<(), String>;
    fn set_blocked(&self, blocked: HashMap<String, String>);
    /// Programs the kill switch keeps offline while stopped.
    fn protected_programs(&self, config: &Config) -> usize;
    fn runtime(&self) -> tokio::runtime::Handle;
    fn sync_autostart(&self, _enabled: bool) {}
    /// False for the preview: Start is unavailable.
    fn can_redirect(&self) -> bool;
}

pub struct Preview {
    runtime: tokio::runtime::Runtime,
    running: std::sync::atomic::AtomicBool,
}

impl Preview {
    pub fn new() -> Preview {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("tokio runtime");
        Preview { runtime, running: Default::default() }
    }
}

impl Backend for Preview {
    fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn start(&self, _config: &Config) -> Result<(), String> {
        Err("Redirection needs Windows.".into())
    }

    fn stop(&self) {}

    fn apply(&self, _config: &Config) -> Result<(), String> {
        Ok(())
    }

    fn set_blocked(&self, _blocked: HashMap<String, String>) {}

    fn protected_programs(&self, config: &Config) -> usize {
        if config.settings.kill_switch {
            RuleEngine::new(config).kill_switch_paths().len()
        } else {
            0
        }
    }

    fn runtime(&self) -> tokio::runtime::Handle {
        self.runtime.handle().clone()
    }

    fn can_redirect(&self) -> bool {
        false
    }
}

/// A preview that reports itself as running (screenshots).
pub struct Demo(pub Preview);

impl Backend for Demo {
    fn is_running(&self) -> bool {
        true
    }
    fn start(&self, _: &Config) -> Result<(), String> {
        Ok(())
    }
    fn stop(&self) {}
    fn apply(&self, _: &Config) -> Result<(), String> {
        Ok(())
    }
    fn set_blocked(&self, _: HashMap<String, String>) {}
    fn protected_programs(&self, config: &Config) -> usize {
        self.0.protected_programs(config)
    }
    fn runtime(&self) -> tokio::runtime::Handle {
        self.0.runtime()
    }
    fn can_redirect(&self) -> bool {
        true
    }
}

#[cfg(windows)]
pub struct Windows {
    engine: proxidize_win::engine::Engine,
}

#[cfg(windows)]
impl Windows {
    pub fn new(log: Arc<LogHub>, tracker: Arc<ConnectionTracker>) -> Windows {
        let platform = Arc::new(proxidize_win::platform::WindowsPlatform::default());
        Windows { engine: proxidize_win::engine::Engine::new(platform, log, tracker) }
    }
}

#[cfg(windows)]
impl Backend for Windows {
    fn is_running(&self) -> bool {
        self.engine.is_running()
    }
    fn start(&self, config: &Config) -> Result<(), String> {
        self.engine.start(config)
    }
    fn stop(&self) {
        self.engine.stop()
    }
    fn apply(&self, config: &Config) -> Result<(), String> {
        self.engine.apply_config(config)
    }
    fn set_blocked(&self, blocked: HashMap<String, String>) {
        self.engine.set_blocked_proxies(blocked)
    }
    fn protected_programs(&self, _config: &Config) -> usize {
        self.engine.kill_switch_program_count()
    }
    fn runtime(&self) -> tokio::runtime::Handle {
        self.engine.runtime()
    }
    fn sync_autostart(&self, enabled: bool) {
        proxidize_win::win::sync_autostart(enabled, self.engine.log());
    }
    fn can_redirect(&self) -> bool {
        true
    }
}

/// The platform's backend: the engine on Windows, the preview elsewhere.
#[allow(unused_variables)]
pub fn platform(log: Arc<LogHub>, tracker: Arc<ConnectionTracker>) -> Arc<dyn Backend> {
    #[cfg(windows)]
    {
        Arc::new(Windows::new(log, tracker))
    }
    #[cfg(not(windows))]
    {
        Arc::new(Preview::new())
    }
}
