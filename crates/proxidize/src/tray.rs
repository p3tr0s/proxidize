//! The tray icon: a link light (green redirecting, red when a proxy needs attention, amber busy, hollow stopped)
//! with a menu, and balloon notifications for the proxy check.

use std::sync::mpsc::{channel, Receiver};
use std::sync::Mutex;

use eframe::egui;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

pub enum Action {
    Open,
    Toggle,
    Check,
    Exit,
}

pub struct Tray {
    icon: TrayIcon,
    status: MenuItem,
    toggle: MenuItem,
    open_id: tray_icon::menu::MenuId,
    check_id: tray_icon::menu::MenuId,
    exit_id: tray_icon::menu::MenuId,
    events: Receiver<Action>,
    last: Mutex<(u8, String)>,
}

/// A 32x32 link light: filled square, or a hollow one when stopped.
pub fn light_icon(rgb: [u8; 3], hollow: bool) -> tray_icon::Icon {
    let size = 32usize;
    let mut rgba = vec![0u8; size * size * 4];
    for y in 0..size {
        for x in 0..size {
            let inside = (6..26).contains(&x) && (6..26).contains(&y);
            let edge = inside && (!(9..23).contains(&x) || !(9..23).contains(&y));
            if inside && (!hollow || edge) {
                let i = (y * size + x) * 4;
                rgba[i..i + 4].copy_from_slice(&[rgb[0], rgb[1], rgb[2], 255]);
            }
        }
    }
    tray_icon::Icon::from_rgba(rgba, size as u32, size as u32).expect("icon")
}

const OK: [u8; 3] = [0x4C, 0xC3, 0x8A];
const FAULT: [u8; 3] = [0xE5, 0x48, 0x4D];
const CAUTION: [u8; 3] = [0xE0, 0xA4, 0x3A];
const OFF: [u8; 3] = [0x9A, 0x9A, 0xA0];

impl Tray {
    pub fn new(ctx: &egui::Context) -> Option<Tray> {
        let status = MenuItem::new("Stopped", false, None);
        let open = MenuItem::new("Open Proxidize", true, None);
        let toggle = MenuItem::new("Start redirecting", true, None);
        let check = MenuItem::new("Check proxies", true, None);
        let exit = MenuItem::new("Exit", true, None);
        let menu = Menu::new();
        menu.append_items(&[
            &status,
            &PredefinedMenuItem::separator(),
            &open,
            &toggle,
            &check,
            &PredefinedMenuItem::separator(),
            &exit,
        ])
        .ok()?;
        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .with_tooltip("Proxidize: stopped")
            .with_icon(light_icon(OFF, true))
            .build()
            .ok()?;
        let (tx, events) = channel();
        let (open_id, toggle_id, check_id, exit_id) =
            (open.id().clone(), toggle.id().clone(), check.id().clone(), exit.id().clone());
        {
            let tx = tx.clone();
            let ctx = ctx.clone();
            let (open_id, check_id, exit_id) = (open_id.clone(), check_id.clone(), exit_id.clone());
            MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
                let action = if e.id == open_id {
                    Action::Open
                } else if e.id == toggle_id {
                    Action::Toggle
                } else if e.id == check_id {
                    Action::Check
                } else if e.id == exit_id {
                    Action::Exit
                } else {
                    return;
                };
                let _ = tx.send(action);
                ctx.request_repaint();
            }));
        }
        {
            let ctx = ctx.clone();
            TrayIconEvent::set_event_handler(Some(move |e: TrayIconEvent| {
                if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e {
                    let _ = tx.send(Action::Open);
                    ctx.request_repaint();
                }
            }));
        }
        Some(Tray { icon, status, toggle, open_id, check_id, exit_id, events, last: Mutex::new((255, String::new())) })
    }

    pub fn actions(&self) -> Vec<Action> {
        let _ = (&self.open_id, &self.check_id, &self.exit_id);
        self.events.try_iter().collect()
    }

    pub fn update(&self, running: bool, fault: bool, busy: bool, status: &str, open: usize) {
        let state: u8 = match (busy, running, fault) {
            (true, _, _) => 1,
            (false, true, true) => 2,
            (false, true, false) => 3,
            _ => 0,
        };
        let tip = if running { format!("Proxidize: redirecting, {open} open") } else { "Proxidize: stopped".to_string() };
        let mut last = self.last.lock().unwrap();
        if last.0 != state {
            let icon = match state {
                1 => light_icon(CAUTION, false),
                2 => light_icon(FAULT, false),
                3 => light_icon(OK, false),
                _ => light_icon(OFF, true),
            };
            let _ = self.icon.set_icon(Some(icon));
            self.toggle.set_text(if running { "Stop redirecting" } else { "Start redirecting" });
            self.toggle.set_enabled(!busy);
        }
        if last.0 != state || last.1 != tip {
            let _ = self.icon.set_tooltip(Some(&tip));
            self.status.set_text(if fault && running { "Redirecting, a proxy needs attention" } else { status });
        }
        *last = (state, tip);
    }

    /// A balloon from the tray icon (a toast on Windows 10/11).
    pub fn notify(&self, title: &str, text: &str) {
        use windows_sys::Win32::UI::Shell::{Shell_NotifyIconW, NIF_INFO, NIIF_INFO, NIM_MODIFY, NOTIFYICONDATAW};
        let mut data: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        data.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        data.hWnd = self.icon.window_handle();
        data.uID = 1; // tray-icon numbers its icons from 1, and this is the only one
        data.uFlags = NIF_INFO;
        data.dwInfoFlags = NIIF_INFO;
        copy_wide(&mut data.szInfo, text);
        copy_wide(&mut data.szInfoTitle, title);
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
    }
}

fn copy_wide(target: &mut [u16], text: &str) {
    let units: Vec<u16> = text.encode_utf16().take(target.len() - 1).collect();
    target[..units.len()].copy_from_slice(&units);
    target[units.len()] = 0;
}
