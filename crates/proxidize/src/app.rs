//! The window: navigation rail, status header, pages, dialogs; engine jobs and proxy checks in the background.

use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, Align2, Color32, Pos2, Rect, Sense, Stroke, Vec2};
use proxidize_core::config::{Config, ConfigStore};
use proxidize_core::health::{self, HealthState, ProxyHealth, Round, RoundResult, DIRECT_ID};
use proxidize_core::log::{Level, LogHub};
use proxidize_core::relay::ConnectionTracker;
use proxidize_core::resolve::SystemResolver;

use crate::backend::Backend;
use crate::dialogs::Dialog;
use crate::theme::{self, *};
use crate::widgets::{self, Kind};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    Overview,
    Rules,
    Proxies,
    Chains,
    Connections,
    Log,
    Settings,
}

pub const PAGES: [Page; 7] =
    [Page::Overview, Page::Rules, Page::Proxies, Page::Chains, Page::Connections, Page::Log, Page::Settings];

impl Page {
    pub fn title(self) -> &'static str {
        match self {
            Page::Overview => "Overview",
            Page::Rules => "Rules",
            Page::Proxies => "Proxies",
            Page::Chains => "Chains",
            Page::Connections => "Connections",
            Page::Log => "Log",
            Page::Settings => "Settings",
        }
    }
}

type JobFn = Box<dyn FnOnce(&dyn Backend) -> Result<(), String> + Send>;

struct Job {
    label: Option<&'static str>,
    run: JobFn,
}

/// Per-page view state.
#[derive(Default)]
pub struct Views {
    pub rule_filter: String,
    pub proxy_filter: String,
    pub chain_filter: String,
    pub connection_filter: String,
    pub log_filter: String,
    pub selected_rule: Option<String>,
    pub selected_proxies: Vec<String>,
    pub selected_chain: Option<String>,
    pub selected_connection: Option<u64>,
    pub show_closed: bool,
    pub log_level: usize,
    pub settings_draft: Option<proxidize_core::config::Settings>,
}

pub struct App {
    pub config: Config,
    store: Option<ConfigStore>,
    pub backend: Arc<dyn Backend>,
    pub log: Arc<LogHub>,
    pub tracker: Arc<ConnectionTracker>,
    pub health: HashMap<String, ProxyHealth>,
    pub own_ip: Option<String>,
    pub checking: bool,
    health_tx: Sender<RoundResult>,
    health_rx: Receiver<RoundResult>,
    next_check: Option<Instant>,
    jobs: Sender<Job>,
    job_results: Receiver<(Option<&'static str>, Result<(), String>)>,
    pub busy: Option<&'static str>,
    pending_jobs: usize,
    pub page: Page,
    pub views: Views,
    pub dialog: Option<Dialog>,
    pub message: Option<(String, bool)>,
    pub unseen_warnings: usize,
    log_seen: u64,
    pub demo: bool,
    pub ctx: egui::Context,
    pub start_hidden: bool,
    pub quitting: bool,
    #[cfg(windows)]
    pub tray: Option<crate::tray::Tray>,
    pub screenshots: Option<crate::shots::Shots>,
}

pub struct Startup {
    pub config: Config,
    pub store: Option<ConfigStore>,
    pub backend: Arc<dyn Backend>,
    pub log: Arc<LogHub>,
    pub tracker: Arc<ConnectionTracker>,
    pub health: HashMap<String, ProxyHealth>,
    pub demo: bool,
    pub minimized: bool,
    pub screenshots: Option<crate::shots::Shots>,
    pub warnings: Vec<String>,
    /// No config.json yet: offer ProxyForge's configuration.
    pub first_run: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, s: Startup) -> App {
        theme::install(&cc.egui_ctx);
        let ctx = cc.egui_ctx.clone();
        let (health_tx, health_rx) = channel();
        let (jobs, job_rx) = channel::<Job>();
        let (result_tx, job_results) = channel();
        let backend = s.backend.clone();
        let repaint = ctx.clone();
        std::thread::Builder::new()
            .name("proxidize engine jobs".into())
            .spawn(move || {
                while let Ok(job) = job_rx.recv() {
                    let result = (job.run)(backend.as_ref());
                    if result_tx.send((job.label, result)).is_err() {
                        break;
                    }
                    repaint.request_repaint();
                }
            })
            .unwrap();
        let own_ip = s.health.get(DIRECT_ID).and_then(|h| h.exit_ip.clone());
        let mut app = App {
            config: s.config,
            store: s.store,
            backend: s.backend,
            log: s.log,
            tracker: s.tracker,
            health: s.health,
            own_ip,
            checking: false,
            health_tx,
            health_rx,
            next_check: None,
            jobs,
            job_results,
            busy: None,
            pending_jobs: 0,
            page: Page::Overview,
            views: Views { show_closed: true, ..Default::default() },
            dialog: None,
            message: None,
            unseen_warnings: 0,
            log_seen: 0,
            demo: s.demo,
            ctx,
            start_hidden: s.minimized,
            quitting: false,
            #[cfg(windows)]
            tray: None,
            screenshots: s.screenshots,
        };
        for w in s.warnings {
            app.log.warning(w);
        }
        if !app.demo {
            #[cfg(windows)]
            {
                app.tray = crate::tray::Tray::new(&app.ctx);
            }
            let interval = app.config.settings.health_check_interval_minutes;
            if interval > 0 {
                app.next_check = Some(Instant::now() + Duration::from_secs(5));
            }
            if app.config.settings.start_with_windows {
                // keep the scheduled task pointing at this exe (it may have moved)
                app.job(None, |b| {
                    b.sync_autostart(true);
                    Ok(())
                });
            }
            if s.first_run {
                if let Some(path) = ConfigStore::proxyforge_config_path().filter(|p| p.exists()) {
                    app.import_proxyforge(&path);
                }
            }
            if app.config.settings.start_enabled && app.backend.can_redirect() {
                app.start_engine();
            } else {
                let config = app.config.clone();
                app.job(None, move |b| b.apply(&config)); // not starting: still line the kill switch up with the config
            }
        }
        app
    }

    fn job(&mut self, label: Option<&'static str>, run: impl FnOnce(&dyn Backend) -> Result<(), String> + Send + 'static) {
        self.pending_jobs += 1;
        if label.is_some() {
            self.busy = label;
        }
        let _ = self.jobs.send(Job { label, run: Box::new(run) });
    }

    pub fn start_engine(&mut self) {
        let config = self.config.clone();
        self.job(Some("Starting"), move |b| b.start(&config));
    }

    pub fn toggle_engine(&mut self) {
        if self.busy.is_some() {
            return;
        }
        if self.backend.is_running() {
            self.job(Some("Stopping"), |b| {
                b.stop();
                Ok(())
            });
        } else if !self.backend.can_redirect() {
            self.message = Some(("Redirection needs Windows: this build only previews the interface.".into(), true));
        } else {
            self.start_engine();
        }
    }

    /// Saves `config`, makes it current and hands it to the engine.
    pub fn commit(&mut self, config: Config) {
        let autostart_changed = config.settings.start_with_windows != self.config.settings.start_with_windows;
        self.config = config;
        if let Some(store) = &self.store {
            if let Err(e) = store.save(&self.config) {
                self.log.error(format!("Saving the configuration failed: {e}"));
                self.message = Some((format!("Couldn't save the configuration: {e}"), true));
            }
        }
        let config = self.config.clone();
        if autostart_changed {
            let enabled = config.settings.start_with_windows;
            self.job(None, move |b| {
                b.sync_autostart(enabled);
                Ok(())
            });
        }
        if self.config.settings.health_check_interval_minutes == 0 {
            self.next_check = None;
        } else if self.next_check.is_none() {
            self.next_check =
                Some(Instant::now() + Duration::from_secs(60 * self.config.settings.health_check_interval_minutes as u64));
        }
        self.job(None, move |b| b.apply(&config));
    }

    /// Looks up the exit IP and country through every proxy (or `only` these) and directly.
    pub fn check_proxies(&mut self, only: Option<Vec<String>>) {
        if self.checking || self.demo {
            return;
        }
        let s = &self.config.settings;
        let proxies: Vec<_> =
            self.config.proxies.iter().filter(|p| only.as_ref().is_none_or(|ids| ids.contains(&p.id))).cloned().collect();
        if proxies.is_empty() && !s.health_check_direct {
            return;
        }
        self.checking = true;
        let round = Round {
            proxies,
            configured: self.config.proxies.iter().map(|p| p.id.clone()).collect(),
            check_direct: s.health_check_direct,
            url: s.health_check_url.clone(),
            timeout: Duration::from_secs(s.connect_timeout_seconds.clamp(5, 60) as u64),
            previous: self.health.clone(),
            known_own_ip: self.own_ip.clone(),
            block_leaking: s.health_check_block_leaking,
        };
        let tx = self.health_tx.clone();
        let ctx = self.ctx.clone();
        self.backend.runtime().spawn(async move {
            let result = health::check_round(round, Arc::new(SystemResolver)).await;
            let _ = tx.send(result);
            ctx.request_repaint();
        });
    }

    fn on_health(&mut self, result: RoundResult) {
        self.checking = false;
        self.backend.set_blocked(result.blocked.clone());
        for (change, ok) in &result.changes {
            if *ok {
                self.log.info(format!("Health: {change}"));
            } else {
                self.log.warning(format!("Health: {change}"));
            }
        }
        self.log.info(result.summary.clone());
        if result.own_ip.is_some() {
            self.own_ip = result.own_ip.clone();
        }
        #[cfg(windows)]
        if self.config.settings.health_check_notify && !result.changes.is_empty() {
            if let Some(tray) = &self.tray {
                let text = if result.changes.len() == 1 {
                    result.changes[0].0.clone()
                } else {
                    format!("{}\n(+{} more - see Proxies)", result.changes[0].0, result.changes.len() - 1)
                };
                tray.notify("Proxidize proxy check", &text);
            }
        }
        self.health = result.health;
    }

    pub fn route_health(&self, rule: &proxidize_core::config::Rule) -> Option<&ProxyHealth> {
        if rule.action != proxidize_core::config::RuleAction::Proxy {
            return None;
        }
        let route = rule.route_id.as_deref();
        let id = self
            .config
            .find_proxy(route)
            .map(|p| p.id.clone())
            .or_else(|| self.config.find_chain(route).and_then(|c| c.proxy_ids.last().cloned()))?;
        self.health.get(&id)
    }

    pub fn proxy_health(&self) -> Vec<&ProxyHealth> {
        self.health.values().filter(|h| h.id != DIRECT_ID && self.config.proxies.iter().any(|p| p.id == h.id)).collect()
    }

    /// Fault: a proxy leaks or is down.
    pub fn fault(&self) -> bool {
        self.proxy_health().iter().any(|h| matches!(h.state, HealthState::Down | HealthState::ExposesYourIp))
    }

    pub fn engine_light(&self) -> (Color32, bool) {
        if self.busy.is_some() {
            (LIGHT_CAUTION, false)
        } else if self.backend.is_running() {
            (if self.fault() { LIGHT_FAULT } else { LIGHT_OK }, false)
        } else {
            (LIGHT_OFF, true)
        }
    }

    fn status(&self) -> (String, String) {
        if let Some(busy) = self.busy {
            return (busy.to_string(), String::new());
        }
        let rules = self.config.rules.iter().filter(|r| r.enabled).count();
        if self.backend.is_running() {
            let open = self.tracker.active_count();
            let mut detail = format!(
                "{rules} {} on, {open} open {}",
                if rules == 1 { "rule" } else { "rules" },
                if open == 1 { "connection" } else { "connections" }
            );
            let proxies = self.proxy_health();
            let leaking: Vec<&str> =
                proxies.iter().filter(|h| h.state == HealthState::ExposesYourIp).map(|h| h.name.as_str()).collect();
            let down: Vec<&str> = proxies.iter().filter(|h| h.state == HealthState::Down).map(|h| h.name.as_str()).collect();
            if !leaking.is_empty() {
                detail.push_str(&format!(
                    ". {} {} your IP",
                    leaking.join(", "),
                    if leaking.len() == 1 { "exposes" } else { "expose" }
                ));
            } else if !down.is_empty() {
                let more = if down.len() > 3 { format!(" and {} more", down.len() - 3) } else { String::new() };
                detail.push_str(&format!(". {}{more} down", down.iter().take(3).copied().collect::<Vec<_>>().join(", ")));
            }
            ("Redirecting".into(), detail)
        } else {
            let protected = self.backend.protected_programs(&self.config);
            let detail = if !self.backend.can_redirect() {
                "Preview: redirection needs Windows".to_string()
            } else if self.config.settings.kill_switch && protected > 0 {
                format!(
                    "The kill switch keeps {protected} {} offline until you start",
                    if protected == 1 { "program" } else { "programs" }
                )
            } else {
                "Nothing is redirected".to_string()
            };
            ("Stopped".into(), detail)
        }
    }

    fn poll(&mut self) {
        while let Ok(r) = self.health_rx.try_recv() {
            self.on_health(r);
        }
        while let Ok((label, result)) = self.job_results.try_recv() {
            self.pending_jobs = self.pending_jobs.saturating_sub(1);
            if label.is_some() {
                self.busy = None;
            }
            if let Err(e) = result {
                self.log.error(e.clone());
                self.message = Some((e, true));
            }
        }
        if let Some(at) = self.next_check {
            if Instant::now() >= at {
                self.check_proxies(None);
                let minutes = self.config.settings.health_check_interval_minutes as u64;
                self.next_check = (minutes > 0).then(|| Instant::now() + Duration::from_secs(minutes * 60));
            }
        }
        // Warnings the user hasn't looked at yet (badge on Log).
        let entries = self.log.entries_after(self.log_seen);
        if let Some(last) = entries.last() {
            self.unseen_warnings += entries.iter().filter(|e| e.level >= Level::Warning).count();
            self.log_seen = last.sequence;
        }
        if self.page == Page::Log {
            self.unseen_warnings = 0;
        }
        #[cfg(windows)]
        self.poll_tray();
    }

    #[cfg(windows)]
    fn poll_tray(&mut self) {
        let Some(tray) = &self.tray else { return };
        let running = self.backend.is_running();
        let fault = self.fault();
        let (status, _) = self.status();
        tray.update(running, fault, self.busy.is_some(), &status, self.tracker.active_count());
        for action in tray.actions() {
            match action {
                crate::tray::Action::Open => self.show_window(),
                crate::tray::Action::Toggle => self.toggle_engine(),
                crate::tray::Action::Check => self.check_proxies(None),
                crate::tray::Action::Exit => {
                    self.quitting = true;
                    self.ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
    }

    #[cfg(windows)]
    fn show_window(&self) {
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    // -------------------------------------------------------------------------------------------------- layout

    fn rail(&mut self, ui: &mut egui::Ui) {
        let rect = ui.max_rect();
        let p = ui.painter().clone();
        p.rect_filled(rect, 0, RACK);
        let x = rect.left() + S4 + 4.0;
        let (light, hollow) = self.engine_light();
        theme::light(&p, x, rect.top() + 46.0, light, hollow);
        p.text(Pos2::new(x + 20.0, rect.top() + 46.0), Align2::LEFT_CENTER, "Proxidize", wordmark(), TEXT);

        let mut y = rect.top() + 88.0;
        for page in PAGES {
            let item = Rect::from_min_size(Pos2::new(rect.left() + S4, y), Vec2::new(rect.width() - 2.0 * S4, 34.0));
            let response = ui.interact(item, egui::Id::unique(("nav", page.title())), Sense::click());
            if response.clicked() {
                self.page = page;
                if page == Page::Log {
                    self.unseen_warnings = 0;
                }
            }
            let selected = self.page == page;
            if selected || response.hovered() {
                p.rect_filled(item, 6, if selected { RAISED } else { Color32::from_rgb(0x17, 0x17, 0x18) });
            }
            p.text(
                Pos2::new(item.left() + S4, item.center().y),
                Align2::LEFT_CENTER,
                page.title(),
                body(),
                if selected { TEXT } else { TEXT_SECONDARY },
            );
            let (badge, light) = self.badge(page);
            let mut bx = item.right() - S3;
            if let Some(color) = light {
                theme::light(&p, bx - 8.0, item.center().y, color, false);
                bx -= 16.0;
            }
            if let Some(text) = badge {
                p.text(Pos2::new(bx, item.center().y), Align2::RIGHT_CENTER, text, data_small(), TEXT_MUTED);
            }
            response.on_hover_cursor(egui::CursorIcon::PointingHand);
            y += 38.0;
        }

        let me = self.health.get(DIRECT_ID).filter(|h| h.ok);
        let value = me
            .map(|h| format!("{}  {}", h.exit_ip.as_deref().unwrap_or_default(), h.country_code.as_deref().unwrap_or_default()))
            .unwrap_or_else(|| "Not checked".into());
        p.text(Pos2::new(x, rect.bottom() - 56.0), Align2::LEFT_CENTER, "Your IP", small(), TEXT_MUTED);
        p.text(Pos2::new(x, rect.bottom() - 34.0), Align2::LEFT_CENTER, value.trim_end(), data(), TEXT_SECONDARY);
    }

    fn badge(&self, page: Page) -> (Option<String>, Option<Color32>) {
        match page {
            Page::Rules => {
                let n = self.config.rules.iter().filter(|r| r.enabled).count();
                ((n > 0).then(|| n.to_string()), None)
            }
            Page::Proxies => {
                let n = self.config.proxies.len();
                let health = self.proxy_health();
                let light = if health.is_empty() {
                    None
                } else if self.fault() {
                    Some(LIGHT_FAULT)
                } else if health.iter().any(|h| h.state == HealthState::SharedIp) {
                    Some(LIGHT_CAUTION)
                } else {
                    Some(LIGHT_OK)
                };
                ((n > 0).then(|| n.to_string()), light)
            }
            Page::Connections => {
                let n = self.tracker.active_count();
                ((n > 0).then(|| n.to_string()), None)
            }
            Page::Log => (
                (self.unseen_warnings > 0).then(|| self.unseen_warnings.to_string()),
                (self.unseen_warnings > 0).then_some(LIGHT_CAUTION),
            ),
            _ => (None, None),
        }
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        let rect = ui.max_rect();
        let p = ui.painter().clone();
        p.hline(rect.x_range(), rect.bottom() - 0.5, Stroke::new(1.0, HAIRLINE));
        let (light, hollow) = self.engine_light();
        let x = rect.left() + 32.0;
        theme::light(&p, x, rect.center().y, light, hollow);
        let (headline, detail) = self.status();
        let r = p.text(Pos2::new(x + 22.0, rect.center().y), Align2::LEFT_CENTER, &headline, body_strong(), TEXT);
        let detail_rect =
            Rect::from_min_max(Pos2::new(r.right() + S3, rect.top()), Pos2::new(rect.right() - 260.0, rect.bottom()));
        theme::text(&p, detail_rect, &detail, body(), TEXT_SECONDARY, Align2::LEFT_CENTER);

        let buttons =
            Rect::from_min_max(Pos2::new(rect.right() - 260.0, rect.top()), Pos2::new(rect.right() - 24.0, rect.bottom()));
        ui.scope_builder(
            egui::UiBuilder::new().max_rect(buttons).layout(egui::Layout::right_to_left(egui::Align::Center)),
            |ui| {
                let running = self.backend.is_running();
                let label = if running { "Stop" } else { "Start" };
                if widgets::button_enabled(ui, label, if running { Kind::Secondary } else { Kind::Primary }, self.busy.is_none())
                    .clicked()
                {
                    self.toggle_engine();
                }
                let check = if self.checking { "Checking" } else { "Check proxies" };
                if widgets::button_enabled(ui, check, Kind::Secondary, !self.checking).clicked() {
                    self.check_proxies(None);
                }
            },
        );
    }

    /// Page title, subtitle and the page's main actions on the right.
    pub fn page_heading(
        &mut self,
        ui: &mut egui::Ui,
        title: &str,
        subtitle: &str,
        actions: impl FnOnce(&mut App, &mut egui::Ui),
    ) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(egui::RichText::new(title).font(theme::title()).color(TEXT));
                ui.label(egui::RichText::new(subtitle).font(body()).color(TEXT_SECONDARY));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| actions(self, ui));
        });
        ui.add_space(S4);
    }

    fn message_bar(&mut self, ui: &mut egui::Ui) {
        let Some((text, error)) = self.message.clone() else { return };
        egui::Frame::NONE
            .fill(if error { LIGHT_FAULT.linear_multiply(0.12) } else { RAISED })
            .stroke(Stroke::new(1.0, if error { LIGHT_FAULT.linear_multiply(0.5) } else { HAIRLINE_STRONG }))
            .corner_radius(RADIUS)
            .inner_margin(egui::Margin::symmetric(12, 8))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&text).color(TEXT));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if widgets::button(ui, "Dismiss", Kind::Quiet).clicked() {
                            self.message = None;
                        }
                    });
                });
            });
        ui.add_space(S3);
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        if self.start_hidden {
            self.start_hidden = false;
            #[cfg(windows)]
            if self.tray.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
        }
        // Closing the window keeps Proxidize running in the tray.
        if ctx.input(|i| i.viewport().close_requested()) && !self.quitting {
            #[cfg(windows)]
            if self.tray.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
        }
        ctx.request_repaint_after(Duration::from_secs(1));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.shortcuts(&ctx);
        egui::Panel::left("rail")
            .exact_size(232.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(egui::Frame::NONE.fill(RACK))
            .show(ui, |ui| {
                self.rail(ui);
            });
        egui::Panel::top("header")
            .exact_size(64.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(egui::Frame::NONE.fill(PAGE))
            .show(ui, |ui| {
                self.header(ui);
            });
        egui::CentralPanel::no_frame().show(ui, |ui| {
            egui::Frame::NONE.fill(PAGE).inner_margin(egui::Margin { left: 36, right: 36, top: 24, bottom: 16 }).show(ui, |ui| {
                ui.set_min_size(ui.available_size());
                self.message_bar(ui);
                match self.page {
                    Page::Overview => self.overview(ui),
                    Page::Rules => self.rules_page(ui),
                    Page::Proxies => self.proxies_page(ui),
                    Page::Chains => self.chains_page(ui),
                    Page::Connections => self.connections_page(ui),
                    Page::Log => self.log_page(ui),
                    Page::Settings => self.settings_page(ui),
                }
            });
        });
        self.show_dialog(&ctx);
        if self.screenshots.is_some() {
            crate::shots::step(self, &ctx);
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if !self.demo {
            self.backend.stop();
        }
    }
}

impl App {
    fn shortcuts(&mut self, ctx: &egui::Context) {
        if self.dialog.is_some() || ctx.egui_wants_keyboard_input() {
            return;
        }
        let keys = [
            egui::Key::Num1,
            egui::Key::Num2,
            egui::Key::Num3,
            egui::Key::Num4,
            egui::Key::Num5,
            egui::Key::Num6,
            egui::Key::Num7,
        ];
        ctx.input(|i| {
            for (k, page) in keys.iter().zip(PAGES) {
                if i.modifiers.command && i.key_pressed(*k) {
                    self.page = page;
                }
            }
        });
        if ctx.input(|i| i.key_pressed(egui::Key::F5)) {
            self.check_proxies(None);
        }
    }
}
