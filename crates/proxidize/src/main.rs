//! Proxidize: per-program proxy redirection for Windows, in one exe.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod backend;
mod demo;
mod dialogs;
mod pages;
mod procs;
mod shots;
mod theme;
#[cfg(windows)]
mod tray;
mod widgets;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui;
use proxidize_core::config::ConfigStore;
use proxidize_core::log::LogHub;
use proxidize_core::relay::ConnectionTracker;

struct Args {
    minimized: bool,
    remove_kill_switch: bool,
    screenshots: Option<PathBuf>,
    demo: bool,
}

fn args() -> Args {
    let mut a = Args { minimized: false, remove_kill_switch: false, screenshots: None, demo: false };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.to_ascii_lowercase().as_str() {
            "--minimized" => a.minimized = true,
            "--remove-killswitch" => a.remove_kill_switch = true,
            "--demo" => a.demo = true,
            "--screenshots" => a.screenshots = Some(it.next().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("shots"))),
            _ => {}
        }
    }
    a
}

/// The window icon: the link light on the rack.
fn app_icon() -> egui::IconData {
    let size = 64usize;
    let mut rgba = vec![0u8; size * size * 4];
    for y in 0..size {
        for x in 0..size {
            let i = (y * size + x) * 4;
            let rack = (4..60).contains(&x) && (4..60).contains(&y);
            let light = (22..42).contains(&x) && (22..42).contains(&y);
            let px = if light {
                [0x4C, 0xC3, 0x8A, 255]
            } else if rack {
                [0x19, 0x19, 0x1B, 255]
            } else {
                [0, 0, 0, 0]
            };
            rgba[i..i + 4].copy_from_slice(&px);
        }
    }
    egui::IconData { rgba, width: size as u32, height: size as u32 }
}

#[cfg(windows)]
fn single_instance() -> bool {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::CreateMutexW;
    let name: Vec<u16> = "Global\\Proxidize.SingleInstance".encode_utf16().chain(std::iter::once(0)).collect();
    // The handle is kept for the life of the process on purpose.
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    !(handle.is_null() || unsafe { GetLastError() } == ERROR_ALREADY_EXISTS)
}

#[cfg(windows)]
fn attach_console() {
    use windows_sys::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
    unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
}

fn main() -> eframe::Result {
    let args = args();
    #[cfg(windows)]
    proxidize_core::config::set_protector(Some(Arc::new(proxidize_win::win::Dpapi)));

    if args.remove_kill_switch {
        #[cfg(windows)]
        {
            attach_console();
            match proxidize_win::wfp::remove_everything() {
                Ok(n) => println!("Kill switch: removed {n} filter(s)."),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        return Ok(());
    }

    let demo = args.demo || args.screenshots.is_some();
    #[cfg(windows)]
    if !demo && !single_instance() {
        return Ok(()); // already running: it lives in the tray
    }

    let data = ConfigStore::data_directory();
    let log = Arc::new(if demo { LogHub::default() } else { LogHub::new(Some(data.join("logs").join("proxidize.log"))) });
    let tracker = Arc::new(ConnectionTracker::default());

    let mut warnings = Vec::new();
    let mut first_run = false;
    let (config, store, health, backend) = if demo {
        let (config, health) = demo::scenario();
        demo::seed(&tracker, &log);
        let backend: Arc<dyn backend::Backend> = Arc::new(backend::Demo(backend::Preview::new()));
        (config, None, health, backend)
    } else {
        log.info(format!("Proxidize {} started", env!("CARGO_PKG_VERSION")));
        #[cfg(windows)]
        if !proxidize_win::win::is_elevated() {
            warnings.push("Proxidize is not running as Administrator: redirection and the kill switch need it.".to_string());
        }
        first_run = !ConfigStore::default_path().exists();
        let mut store = ConfigStore::new(ConfigStore::default_path());
        let config = match store.load() {
            Ok(c) => c,
            Err(e) => {
                warnings.push(format!(
                    "The configuration could not be read ({e}); starting with an empty one. The file was left as it is."
                ));
                let mut c = proxidize_core::config::Config::example();
                c.settings.start_enabled = false;
                c
            }
        };
        warnings.append(&mut store.load_warnings);
        let backend = backend::platform(log.clone(), tracker.clone());
        (config, Some(store), HashMap::new(), backend)
    };

    let startup = app::Startup {
        config,
        store,
        backend,
        log,
        tracker,
        health,
        demo,
        minimized: args.minimized,
        screenshots: args.screenshots.map(shots::Shots::new),
        warnings,
        first_run,
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Proxidize")
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([980.0, 600.0])
            .with_icon(Arc::new(app_icon())),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native("Proxidize", options, Box::new(move |cc| Ok(Box::new(app::App::new(cc, startup)))))
}
