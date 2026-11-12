//! `--screenshots <folder>`: renders every page (and the main editors) with the demo data and saves PNGs.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use eframe::egui;

use crate::app::{App, Page};
use crate::dialogs::Dialog;

#[derive(Clone, Copy)]
enum Shot {
    Page(Page, &'static str),
    RuleEditor,
    ProxyEditor,
}

const SHOTS: [Shot; 9] = [
    Shot::Page(Page::Overview, "overview"),
    Shot::Page(Page::Rules, "rules"),
    Shot::Page(Page::Proxies, "proxies"),
    Shot::Page(Page::Chains, "chains"),
    Shot::Page(Page::Connections, "connections"),
    Shot::Page(Page::Log, "log"),
    Shot::Page(Page::Settings, "settings"),
    Shot::RuleEditor,
    Shot::ProxyEditor,
];

pub struct Shots {
    dir: PathBuf,
    index: usize,
    frames: u32,
    requested: bool,
    image: Arc<Mutex<Option<Arc<egui::ColorImage>>>>,
}

impl Shots {
    pub fn new(dir: PathBuf) -> Shots {
        let _ = std::fs::create_dir_all(&dir);
        Shots { dir, index: 0, frames: 0, requested: false, image: Arc::default() }
    }
}

fn name(shot: Shot) -> &'static str {
    match shot {
        Shot::Page(_, n) => n,
        Shot::RuleEditor => "rule-editor",
        Shot::ProxyEditor => "proxy-editor",
    }
}

pub fn step(app: &mut App, ctx: &egui::Context) {
    let Some(shots) = app.screenshots.as_mut() else { return };
    if shots.index >= SHOTS.len() {
        app.quitting = true;
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        return;
    }
    let shot = SHOTS[shots.index];
    if shots.frames == 0 {
        match shot {
            Shot::Page(page, _) => {
                app.dialog = None;
                app.page = page;
                if page == Page::Rules {
                    app.views.selected_rule = app.config.rules.get(3).map(|r| r.id.clone());
                }
                if page == Page::Proxies {
                    app.views.selected_proxies = app.config.proxies.get(6).map(|p| vec![p.id.clone()]).unwrap_or_default();
                }
            }
            Shot::RuleEditor => {
                app.page = Page::Rules;
                app.dialog = Some(Dialog::edit_rule(&app.config.rules[0]));
            }
            Shot::ProxyEditor => {
                app.page = Page::Proxies;
                app.dialog = Some(Dialog::edit_proxy(&app.config.proxies[0]));
            }
        }
    }
    let shots = app.screenshots.as_mut().unwrap();
    shots.frames += 1;
    ctx.request_repaint();
    // a few frames for layout and fonts to settle
    if shots.frames == 6 && !shots.requested {
        let slot = shots.image.clone();
        let repaint = ctx.clone();
        ctx.request_screenshot(move |image| {
            *slot.lock().unwrap() = Some(image);
            repaint.request_repaint();
        });
        shots.requested = true;
    }
    let image = shots.image.lock().unwrap().take();
    if let Some(image) = image {
        let [w, h] = image.size;
        let bytes: Vec<u8> = image.pixels.iter().flat_map(|c| c.to_array()).collect();
        if let Some(buffer) = image::RgbaImage::from_raw(w as u32, h as u32, bytes) {
            let path = shots.dir.join(format!("{}.png", name(shot)));
            if let Err(e) = buffer.save(&path) {
                eprintln!("{}: {e}", path.display());
            }
        }
        shots.index += 1;
        shots.frames = 0;
        shots.requested = false;
    }
}
