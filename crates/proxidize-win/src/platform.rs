//! The real Windows platform for the engine.

use std::sync::Arc;

use proxidize_core::config::ConfigStore;
use proxidize_core::log::LogHub;
use proxidize_core::net::Ip;

use crate::divert::DivertOpener;
use crate::engine::Platform;
use crate::killswitch::Filters;
use crate::process::SystemInfo;

pub struct WindowsPlatform {
    filters: Arc<crate::wfp::WfpFilters>,
}

impl Default for WindowsPlatform {
    fn default() -> Self {
        WindowsPlatform { filters: Arc::new(crate::wfp::WfpFilters::default()) }
    }
}

impl Platform for WindowsPlatform {
    fn opener(&self) -> Arc<dyn DivertOpener> {
        Arc::new(crate::windivert::WinDivertOpener)
    }

    fn system(&self) -> Arc<dyn SystemInfo> {
        Arc::new(crate::win::WindowsSystem)
    }

    fn filters(&self) -> Arc<dyn Filters> {
        self.filters.clone()
    }

    fn adapter_dns_servers(&self) -> Vec<Ip> {
        crate::win::adapter_dns_servers()
    }

    fn flush_dns(&self) {
        crate::win::flush_dns_cache();
    }

    fn firewall_rule(&self, port: u16, log: &LogHub) {
        crate::win::ensure_firewall_rule(port, log);
    }

    fn data_dir(&self) -> Option<std::path::PathBuf> {
        Some(ConfigStore::data_directory())
    }
}
