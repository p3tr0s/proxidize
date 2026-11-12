//! Editors and confirmations, shown one at a time as modal sheets.

use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

use eframe::egui::{self, Align2, Color32, Pos2, Sense, Stroke, StrokeKind, Vec2};
use proxidize_core::config::{
    Config, ConfigStore, ProxyChain, ProxyServer, ProxyType, Rule, RuleAction, Settings, TransportFilter,
};
use proxidize_core::matching::split_list;
use proxidize_core::proxycap::{self, ImportResult};

use crate::app::App;
use crate::pages::{file_name, rules_using, type_label};
use crate::theme::{self, *};
use crate::widgets::{self, Kind};

pub enum Confirm {
    DeleteRule(String),
    DeleteProxies(Vec<String>),
    DeleteChain(String),
    #[allow(dead_code)]
    RemoveKillSwitch,
}

pub enum Dialog {
    Proxy {
        draft: ProxyServer,
        is_new: bool,
        test_target: String,
        test: Option<Receiver<Result<String, String>>>,
        result: Option<(String, bool)>,
    },
    Chain {
        draft: ProxyChain,
        is_new: bool,
        add: Option<String>,
    },
    Rule {
        draft: Rule,
        is_new: bool,
        programs: String,
        destinations: String,
        ports: String,
        picker: Option<Vec<(String, String)>>,
        picker_filter: String,
    },
    Credentials {
        ids: Vec<String>,
        names: String,
        username: String,
        password: String,
    },
    Confirm {
        title: String,
        body: String,
        button: &'static str,
        action: Confirm,
    },
    ImportPath {
        path: String,
    },
    ImportPreview {
        source: String,
        result: Box<ImportResult>,
        replace: bool,
        remote_dns: bool,
        /// ProxyForge's settings, and whether to take them.
        settings: Option<(Box<Settings>, bool)>,
    },
}

impl Dialog {
    pub fn new_proxy(config: &Config) -> Dialog {
        let draft = ProxyServer {
            name: format!("Proxy {}", config.proxies.len() + 1),
            color: Some(theme::to_hex(theme::free_cable(config))),
            ..Default::default()
        };
        Dialog::Proxy { draft, is_new: true, test_target: "example.com:80".into(), test: None, result: None }
    }

    pub fn edit_proxy(p: &ProxyServer) -> Dialog {
        Dialog::Proxy { draft: p.clone(), is_new: false, test_target: "example.com:80".into(), test: None, result: None }
    }

    pub fn new_chain() -> Dialog {
        Dialog::Chain { draft: ProxyChain { name: "New chain".into(), ..Default::default() }, is_new: true, add: None }
    }

    pub fn edit_chain(c: &ProxyChain) -> Dialog {
        Dialog::Chain { draft: c.clone(), is_new: false, add: None }
    }

    pub fn new_rule(config: &Config) -> Dialog {
        let rule = Rule {
            name: format!("Rule {}", config.rules.len() + 1),
            route_id: config.proxies.first().map(|p| p.id.clone()),
            ..Default::default()
        };
        Dialog::rule(rule, true)
    }

    pub fn edit_rule(r: &Rule) -> Dialog {
        Dialog::rule(r.clone(), false)
    }

    fn rule(draft: Rule, is_new: bool) -> Dialog {
        Dialog::Rule {
            programs: draft.programs.join("\n"),
            destinations: draft.destinations.join("\n"),
            ports: draft.ports.join(", "),
            draft,
            is_new,
            picker: None,
            picker_filter: String::new(),
        }
    }

    pub fn credentials(config: &Config, ids: &[String]) -> Dialog {
        let proxies: Vec<&ProxyServer> = config.proxies.iter().filter(|p| ids.contains(&p.id)).collect();
        let username = proxies.first().and_then(|p| p.username.clone()).unwrap_or_default();
        let names = proxies.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", ");
        Dialog::Credentials { ids: ids.to_vec(), names, username, password: String::new() }
    }

    pub fn confirm_delete_rule(r: &Rule) -> Dialog {
        Dialog::Confirm {
            title: "Delete rule".into(),
            body: format!("Delete the rule '{}'? Its programs fall through to the next matching rule.", r.name),
            button: "Delete",
            action: Confirm::DeleteRule(r.id.clone()),
        }
    }

    pub fn confirm_delete_proxies(config: &Config, ids: &[String]) -> Dialog {
        let names: Vec<&str> = config.proxies.iter().filter(|p| ids.contains(&p.id)).map(|p| p.name.as_str()).collect();
        let used: Vec<String> = ids.iter().flat_map(|id| rules_using(config, id)).collect();
        let mut body = if names.len() == 1 {
            format!("Delete {}?", names[0])
        } else {
            format!("Delete {} proxies ({})?", names.len(), names.join(", "))
        };
        if !used.is_empty() {
            body.push_str(&format!(
                " Rules that use them ({}) will block their traffic until you pick another proxy.",
                used.join(", ")
            ));
        }
        Dialog::Confirm { title: "Delete proxies".into(), body, button: "Delete", action: Confirm::DeleteProxies(ids.to_vec()) }
    }

    pub fn confirm_delete_chain(config: &Config, c: &ProxyChain) -> Dialog {
        let used = rules_using(config, &c.id);
        let mut body = format!("Delete the chain '{}'?", c.name);
        if !used.is_empty() {
            body.push_str(&format!(
                " Rules that use it ({}) will block their traffic until you pick another route.",
                used.join(", ")
            ));
        }
        Dialog::Confirm { title: "Delete chain".into(), body, button: "Delete", action: Confirm::DeleteChain(c.id.clone()) }
    }

    #[allow(dead_code)]
    pub fn confirm_remove_kill_switch() -> Dialog {
        Dialog::Confirm {
            title: "Remove kill switch filters".into(),
            body: "This deletes every Proxidize filter from Windows Filtering Platform. Protected programs can connect directly until the kill switch syncs again (next start or settings change).".into(),
            button: "Remove filters",
            action: Confirm::RemoveKillSwitch,
        }
    }

    pub fn import_path() -> Dialog {
        Dialog::ImportPath { path: String::new() }
    }
}

enum Outcome {
    Keep,
    Close,
}

fn sheet(ctx: &egui::Context, id: &str, title: &str, width: f32, add: impl FnOnce(&mut egui::Ui) -> Outcome) -> Outcome {
    let response = egui::Modal::new(egui::Id::unique(id))
        .backdrop_color(Color32::from_black_alpha(150))
        .frame(
            egui::Frame::NONE
                .fill(CARD)
                .stroke(Stroke::new(1.0, HAIRLINE_STRONG))
                .corner_radius(6)
                .inner_margin(egui::Margin::same(24)),
        )
        .show(ctx, |ui| {
            ui.set_width(width);
            ui.label(egui::RichText::new(title).font(theme::title()).color(TEXT));
            ui.add_space(S3);
            add(ui)
        });
    let escape = ctx.input(|i| i.key_pressed(egui::Key::Escape));
    if escape {
        Outcome::Close
    } else {
        response.inner
    }
}

fn buttons(ui: &mut egui::Ui, primary: &str, enabled: bool) -> (bool, bool) {
    ui.add_space(S4);
    let mut ok = false;
    let mut cancel = false;
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        ok = widgets::button_enabled(ui, primary, Kind::Primary, enabled).clicked();
        cancel = widgets::button(ui, "Cancel", Kind::Secondary).clicked();
    });
    (ok, cancel)
}

fn cable_picker(ui: &mut egui::Ui, current: &mut Option<String>, effective: Color32) {
    ui.horizontal(|ui| {
        for (i, c) in CABLES.iter().enumerate() {
            let (rect, response) = ui.allocate_exact_size(Vec2::new(26.0, 22.0), Sense::click());
            let chosen = current.as_deref().and_then(theme::parse_hex).unwrap_or(effective) == *c;
            let p = ui.painter();
            p.rect_filled(rect.shrink(3.0), 2, *c);
            if chosen {
                p.rect_stroke(rect, 3, Stroke::new(1.5, TEXT), StrokeKind::Inside);
            } else if response.hovered() {
                p.rect_stroke(rect, 3, Stroke::new(1.0, TEXT_MUTED), StrokeKind::Inside);
            }
            if response.on_hover_text(CABLE_NAMES[i]).clicked() {
                *current = Some(theme::to_hex(*c));
            }
        }
    });
}

impl App {
    pub fn show_dialog(&mut self, ctx: &egui::Context) {
        let Some(mut dialog) = self.dialog.take() else { return };
        let outcome = match &mut dialog {
            Dialog::Proxy { draft, is_new, test_target, test, result } => {
                if let Some(rx) = test {
                    if let Ok(r) = rx.try_recv() {
                        *result = Some(match r {
                            Ok(s) => (s, false),
                            Err(e) => (e, true),
                        });
                        *test = None;
                    }
                }
                let title = if *is_new { "Add proxy" } else { "Edit proxy" };
                let runtime = self.backend.runtime();
                let config = self.config.clone();
                let mut save = false;
                let o = sheet(ctx, "proxy", title, 520.0, |ui| {
                    widgets::form_row(ui, "Name", |ui| widgets::field(ui, &mut draft.name, 320.0));
                    widgets::form_row(ui, "Type", |ui| {
                        egui::ComboBox::from_id_salt("ptype").width(160.0).selected_text(type_label(draft.kind)).show_ui(
                            ui,
                            |ui| {
                                for t in [ProxyType::Socks5, ProxyType::Socks4, ProxyType::Http] {
                                    ui.selectable_value(&mut draft.kind, t, type_label(t));
                                }
                            },
                        );
                    });
                    widgets::form_row(ui, "Host", |ui| widgets::field(ui, &mut draft.host, 320.0));
                    widgets::form_row(ui, "Port", |ui| widgets::number(ui, &mut draft.port, 1..=65535));
                    let mut user = draft.username.clone().unwrap_or_default();
                    let mut pass = draft.password.clone().unwrap_or_default();
                    widgets::form_row(ui, "Username", |ui| widgets::field(ui, &mut user, 320.0));
                    widgets::form_row(ui, "Password", |ui| widgets::password(ui, &mut pass, 320.0));
                    draft.username = Some(user).filter(|u| !u.is_empty());
                    draft.password = Some(pass).filter(|p| !p.is_empty());
                    if draft.kind == ProxyType::Socks4 && draft.password.is_some() {
                        widgets::hint(ui, "SOCKS4 has no passwords: only the username (user id) is sent.");
                    }
                    let effective = theme::cable_of(draft, &config);
                    widgets::form_row(ui, "Cable", |ui| cable_picker(ui, &mut draft.color, effective));
                    ui.add_space(S2);
                    widgets::form_row(ui, "Test via", |ui| {
                        widgets::field(ui, test_target, 200.0);
                        if widgets::button_enabled(
                            ui,
                            if test.is_some() { "Testing" } else { "Test" },
                            Kind::Secondary,
                            test.is_none(),
                        )
                        .clicked()
                        {
                            let target = test_target.trim().to_string();
                            match target.rsplit_once(':').and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h.to_string(), p))) {
                                Some((host, port)) => {
                                    let (tx, rx) = channel();
                                    let proxy = draft.clone();
                                    let ctx = ui.ctx().clone();
                                    runtime.spawn(async move {
                                        let r = proxidize_core::proxy::test_route(&[proxy], &host, port, Duration::from_secs(10))
                                            .await
                                            .map_err(|e| e.0);
                                        let _ = tx.send(r);
                                        ctx.request_repaint();
                                    });
                                    *test = Some(rx);
                                    *result = None;
                                }
                                None => {
                                    *result =
                                        Some(("Enter the test target as host:port, for example example.com:80".into(), true))
                                }
                            }
                        }
                    });
                    if let Some((text, error)) = result {
                        ui.label(egui::RichText::new(text.as_str()).font(small()).color(if *error {
                            LIGHT_FAULT
                        } else {
                            LIGHT_OK
                        }));
                    }
                    let valid = !draft.name.trim().is_empty() && !draft.host.trim().is_empty() && draft.port > 0;
                    let (ok, cancel) = buttons(ui, "Save", valid);
                    save = ok;
                    if ok || cancel {
                        Outcome::Close
                    } else {
                        Outcome::Keep
                    }
                });
                if save {
                    let mut c = self.config.clone();
                    draft.name = draft.name.trim().into();
                    draft.host = draft.host.trim().into();
                    match c.proxies.iter_mut().find(|p| p.id == draft.id) {
                        Some(p) => *p = draft.clone(),
                        None => c.proxies.push(draft.clone()),
                    }
                    self.views.selected_proxies = vec![draft.id.clone()];
                    self.commit(c);
                }
                o
            }
            Dialog::Chain { draft, is_new, add } => {
                let title = if *is_new { "Add chain" } else { "Edit chain" };
                let config = self.config.clone();
                let mut save = false;
                let o = sheet(ctx, "chain", title, 520.0, |ui| {
                    widgets::form_row(ui, "Name", |ui| widgets::field(ui, &mut draft.name, 320.0));
                    ui.add_space(S2);
                    widgets::hint(ui, "The first proxy is reached directly; each next one is reached through the one before it.");
                    let mut remove = None;
                    let mut swap = None;
                    for (i, id) in draft.proxy_ids.iter().enumerate() {
                        ui.horizontal(|ui| {
                            let name =
                                config.find_proxy(Some(id)).map(|p| p.name.clone()).unwrap_or_else(|| "(missing proxy)".into());
                            let color = config.find_proxy(Some(id)).map(|p| theme::cable_of(p, &config)).unwrap_or(LIGHT_OFF);
                            let (rect, _) = ui.allocate_exact_size(Vec2::new(260.0, 28.0), Sense::hover());
                            let p = ui.painter();
                            p.text(
                                Pos2::new(rect.left(), rect.center().y),
                                Align2::LEFT_CENTER,
                                format!("{}", i + 1),
                                data_small(),
                                TEXT_MUTED,
                            );
                            theme::cable(
                                p,
                                Pos2::new(rect.left() + 18.0, rect.center().y),
                                Pos2::new(rect.left() + 40.0, rect.center().y),
                                color,
                                false,
                            );
                            theme::text(p, rect.with_min_x(rect.left() + 50.0), &name, data(), TEXT, Align2::LEFT_CENTER);
                            if widgets::button_enabled(ui, "Up", Kind::Quiet, i > 0).clicked() {
                                swap = Some((i, i - 1));
                            }
                            if widgets::button_enabled(ui, "Down", Kind::Quiet, i + 1 < draft.proxy_ids.len()).clicked() {
                                swap = Some((i, i + 1));
                            }
                            if widgets::button(ui, "Remove", Kind::Quiet).clicked() {
                                remove = Some(i);
                            }
                        });
                    }
                    if let Some((a, b)) = swap {
                        draft.proxy_ids.swap(a, b);
                    }
                    if let Some(i) = remove {
                        draft.proxy_ids.remove(i);
                    }
                    ui.horizontal(|ui| {
                        let selected = add
                            .clone()
                            .and_then(|id| config.find_proxy(Some(&id)).map(|p| p.name.clone()))
                            .unwrap_or_else(|| "Pick a proxy".into());
                        egui::ComboBox::from_id_salt("hop").width(260.0).selected_text(selected).show_ui(ui, |ui| {
                            for p in &config.proxies {
                                ui.selectable_value(add, Some(p.id.clone()), &p.name);
                            }
                        });
                        if widgets::button_enabled(ui, "Add hop", Kind::Secondary, add.is_some()).clicked() {
                            draft.proxy_ids.push(add.take().unwrap());
                        }
                    });
                    if draft.proxy_ids.iter().filter_map(|id| config.find_proxy(Some(id))).any(|p| p.kind == ProxyType::Socks4)
                        && draft.proxy_ids.len() > 1
                    {
                        widgets::hint(ui, "SOCKS4 hops can't reach IPv6 addresses.");
                    }
                    let (ok, cancel) = buttons(ui, "Save", !draft.name.trim().is_empty() && !draft.proxy_ids.is_empty());
                    save = ok;
                    if ok || cancel {
                        Outcome::Close
                    } else {
                        Outcome::Keep
                    }
                });
                if save {
                    let mut c = self.config.clone();
                    match c.chains.iter_mut().find(|x| x.id == draft.id) {
                        Some(x) => *x = draft.clone(),
                        None => c.chains.push(draft.clone()),
                    }
                    self.views.selected_chain = Some(draft.id.clone());
                    self.commit(c);
                }
                o
            }
            Dialog::Rule { draft, is_new, programs, destinations, ports, picker, picker_filter } => {
                let title = if *is_new { "Add rule" } else { "Edit rule" };
                let config = self.config.clone();
                let mut save = false;
                let o = sheet(ctx, "rule", title, 600.0, |ui| {
                    if let Some(list) = picker {
                        // The running-program picker replaces the form while it is open.
                        widgets::hint(ui, "Pick a running program; its full path is added to the rule.");
                        widgets::search(ui, picker_filter, "Filter", 300.0);
                        let mut picked = None;
                        egui::ScrollArea::vertical().max_height(340.0).show(ui, |ui| {
                            let f = picker_filter.to_lowercase();
                            for (name, path) in list
                                .iter()
                                .filter(|(n, p)| f.is_empty() || n.to_lowercase().contains(&f) || p.to_lowercase().contains(&f))
                            {
                                let (rect, response) = widgets::row(ui, 40.0, false, egui::Id::unique(("pick", path)));
                                widgets::two_lines(
                                    ui.painter(),
                                    rect.shrink2(Vec2::new(S2, 0.0)),
                                    name,
                                    data(),
                                    TEXT,
                                    path,
                                    TEXT_MUTED,
                                );
                                if response.clicked() {
                                    picked = Some(path.clone());
                                }
                            }
                        });
                        if let Some(path) = picked {
                            if !programs.lines().any(|l| l.trim().eq_ignore_ascii_case(&path)) {
                                if !programs.trim().is_empty() {
                                    programs.push('\n');
                                }
                                programs.push_str(&path);
                            }
                            *picker = None;
                        }
                        ui.add_space(S3);
                        if widgets::button(ui, "Back", Kind::Secondary).clicked() {
                            *picker = None;
                        }
                        return Outcome::Keep;
                    }
                    widgets::form_row(ui, "Name", |ui| {
                        widgets::field(ui, &mut draft.name, 300.0);
                        widgets::square_check(ui, &mut draft.enabled, "On");
                    });
                    widgets::form_row(ui, "Action", |ui| {
                        for (a, label) in
                            [(RuleAction::Proxy, "Proxy"), (RuleAction::Direct, "Direct"), (RuleAction::Block, "Block")]
                        {
                            if ui.selectable_label(draft.action == a, label).clicked() {
                                draft.action = a;
                            }
                        }
                    });
                    if draft.action == RuleAction::Proxy {
                        widgets::form_row(ui, "Through", |ui| {
                            let current = config.describe_route(draft.route_id.as_deref());
                            egui::ComboBox::from_id_salt("route").width(300.0).selected_text(current).show_ui(ui, |ui| {
                                for p in &config.proxies {
                                    ui.selectable_value(&mut draft.route_id, Some(p.id.clone()), &p.name);
                                }
                                for c in &config.chains {
                                    ui.selectable_value(&mut draft.route_id, Some(c.id.clone()), format!("{} (chain)", c.name));
                                }
                            });
                        });
                        widgets::form_row(ui, "", |ui| {
                            widgets::square_check(
                                ui,
                                &mut draft.resolve_remotely,
                                "Resolve host names through the proxy (needs DNS mode Fake IP)",
                            );
                        });
                    }
                    widgets::form_row(ui, "Programs", |ui| {
                        ui.vertical(|ui| {
                            ui.add(
                                egui::TextEdit::multiline(programs)
                                    .desired_width(400.0)
                                    .desired_rows(3)
                                    .hint_text("chrome.exe or C:\\Games\\Wow\\Wow.exe, one per line. Empty: any program."),
                            );
                            if widgets::button(ui, "Running programs", Kind::Secondary).clicked() {
                                *picker = Some(crate::procs::running());
                            }
                        });
                    });
                    widgets::form_row(ui, "Destinations", |ui| {
                        ui.add(
                            egui::TextEdit::multiline(destinations)
                                .desired_width(400.0)
                                .desired_rows(2)
                                .hint_text("*.example.com, .example.com, 10.0.0.0/8, 1.2.3.4-1.2.3.9. Empty: anywhere."),
                        );
                    });
                    widgets::form_row(ui, "Ports", |ui| {
                        ui.add(
                            egui::TextEdit::singleline(ports).desired_width(400.0).hint_text("443, 8000-9000. Empty: any port."),
                        );
                    });
                    widgets::form_row(ui, "Transport", |ui| {
                        for (t, label) in
                            [(TransportFilter::Both, "TCP and UDP"), (TransportFilter::Tcp, "TCP"), (TransportFilter::Udp, "UDP")]
                        {
                            if ui.selectable_label(draft.transport == t, label).clicked() {
                                draft.transport = t;
                            }
                        }
                    });
                    let mut problems = Vec::new();
                    for p in split_ports(ports) {
                        if proxidize_core::matching::PortRange::parse(&p).is_none() {
                            problems.push(format!("'{p}' is not a port or range"));
                        }
                    }
                    if draft.action == RuleAction::Proxy && config.describe_route(draft.route_id.as_deref()).is_empty() {
                        problems.push("Pick a proxy or chain".into());
                    }
                    for p in &problems {
                        ui.label(egui::RichText::new(p).font(small()).color(LIGHT_FAULT));
                    }
                    let (ok, cancel) = buttons(ui, "Save", problems.is_empty() && !draft.name.trim().is_empty());
                    save = ok;
                    if ok || cancel {
                        Outcome::Close
                    } else {
                        Outcome::Keep
                    }
                });
                if save {
                    draft.programs =
                        programs.lines().map(|l| l.trim().trim_matches('"').to_string()).filter(|l| !l.is_empty()).collect();
                    draft.destinations = split_list(destinations);
                    draft.ports = split_ports(ports);
                    let mut c = self.config.clone();
                    match c.rules.iter_mut().find(|r| r.id == draft.id) {
                        Some(r) => *r = draft.clone(),
                        None => c.rules.push(draft.clone()),
                    }
                    self.views.selected_rule = Some(draft.id.clone());
                    self.commit(c);
                }
                o
            }
            Dialog::Credentials { ids, names, username, password } => {
                let mut save = false;
                let o = sheet(ctx, "creds", "Credentials", 480.0, |ui| {
                    widgets::hint(ui, &format!("Sets the same username and password on {names}."));
                    ui.add_space(S2);
                    widgets::form_row(ui, "Username", |ui| widgets::field(ui, username, 280.0));
                    widgets::form_row(ui, "Password", |ui| widgets::password(ui, password, 280.0));
                    let (ok, cancel) = buttons(ui, "Save", true);
                    save = ok;
                    if ok || cancel {
                        Outcome::Close
                    } else {
                        Outcome::Keep
                    }
                });
                if save {
                    let mut c = self.config.clone();
                    for p in c.proxies.iter_mut().filter(|p| ids.contains(&p.id)) {
                        p.username = Some(username.trim().to_string()).filter(|u| !u.is_empty());
                        p.password = Some(password.clone()).filter(|p| !p.is_empty());
                    }
                    self.commit(c);
                }
                o
            }
            Dialog::Confirm { title, body, button, action } => {
                let mut go = false;
                let o = sheet(ctx, "confirm", title, 460.0, |ui| {
                    ui.label(egui::RichText::new(body.as_str()).color(TEXT_SECONDARY));
                    ui.add_space(S4);
                    let mut cancel = false;
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        go = widgets::button(ui, button, Kind::Danger).clicked();
                        cancel = widgets::button(ui, "Cancel", Kind::Secondary).clicked();
                    });
                    if go || cancel {
                        Outcome::Close
                    } else {
                        Outcome::Keep
                    }
                });
                if go {
                    self.confirmed(action);
                }
                o
            }
            Dialog::ImportPath { path } => {
                let mut go = false;
                let o = sheet(ctx, "importpath", "Import from ProxyCap", 520.0, |ui| {
                    widgets::hint(ui, "A binary machine.prs or an XML ruleset export (<proxycap_ruleset>). You can drop the file on the window.");
                    widgets::form_row(ui, "File", |ui| widgets::field(ui, path, 340.0));
                    let (ok, cancel) = buttons(ui, "Read file", !path.trim().is_empty());
                    go = ok;
                    if ok || cancel {
                        Outcome::Close
                    } else {
                        Outcome::Keep
                    }
                });
                if go {
                    let p = path.trim().trim_matches('"').to_string();
                    self.import_proxycap(Some(p));
                    return;
                }
                o
            }
            Dialog::ImportPreview { source, result, replace, remote_dns, settings } => {
                let mut apply = false;
                let o = sheet(ctx, "import", "Import", 620.0, |ui| {
                    ui.label(egui::RichText::new(format!("{source}: {}", result.summary())).color(TEXT));
                    ui.add_space(S2);
                    egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                        for p in &result.proxies {
                            ui.label(
                                egui::RichText::new(format!("{}  {} {}:{}", p.name, type_label(p.kind), p.host, p.port))
                                    .font(data())
                                    .color(TEXT),
                            );
                        }
                        for r in &result.rules {
                            let programs: Vec<&str> = r.programs.iter().map(|p| file_name(p)).collect();
                            ui.label(
                                egui::RichText::new(format!("Rule {}: {}", r.name, programs.join(", ")))
                                    .font(body())
                                    .color(if r.enabled { TEXT_SECONDARY } else { TEXT_MUTED }),
                            );
                        }
                        for w in &result.warnings {
                            ui.horizontal(|ui| {
                                let (rect, _) = ui.allocate_exact_size(Vec2::new(10.0, 18.0), Sense::hover());
                                theme::light(ui.painter(), rect.left(), rect.center().y, LIGHT_CAUTION, false);
                                ui.label(egui::RichText::new(w).font(small()).color(TEXT_SECONDARY));
                            });
                        }
                    });
                    ui.add_space(S3);
                    ui.horizontal(|ui| {
                        if ui.selectable_label(!*replace, "Add to my configuration").clicked() {
                            *replace = false;
                        }
                        if ui.selectable_label(*replace, "Replace proxies, chains and rules").clicked() {
                            *replace = true;
                        }
                    });
                    if result.uses_remote_dns {
                        widgets::square_check(
                            ui,
                            remote_dns,
                            "Switch DNS mode to Fake IP (the imported rules resolve names through the proxy)",
                        );
                    }
                    widgets::hint(ui, "The current configuration is backed up first.");
                    let (ok, cancel) = buttons(ui, "Import", true);
                    apply = ok;
                    if ok || cancel {
                        Outcome::Close
                    } else {
                        Outcome::Keep
                    }
                });
                if apply {
                    let taken = std::mem::take(result.as_mut());
                    let new_settings = settings.as_ref().filter(|(_, take)| *take).map(|(s, _)| (**s).clone());
                    self.apply_import(taken, *replace, *remote_dns && new_settings.is_none(), new_settings);
                }
                o
            }
        };
        if matches!(outcome, Outcome::Keep) {
            self.dialog = Some(dialog);
        }
    }

    fn confirmed(&mut self, action: &Confirm) {
        let mut c = self.config.clone();
        match action {
            Confirm::DeleteRule(id) => {
                c.rules.retain(|r| &r.id != id);
                self.views.selected_rule = None;
            }
            Confirm::DeleteProxies(ids) => {
                c.proxies.retain(|p| !ids.contains(&p.id));
                for chain in &mut c.chains {
                    chain.proxy_ids.retain(|id| !ids.contains(id));
                }
                self.views.selected_proxies.clear();
            }
            Confirm::DeleteChain(id) => {
                c.chains.retain(|x| &x.id != id);
                self.views.selected_chain = None;
            }
            Confirm::RemoveKillSwitch => {
                #[cfg(windows)]
                match proxidize_win::wfp::remove_everything() {
                    Ok(n) => self.log.info(format!("Kill switch: removed {n} filter(s).")),
                    Err(e) => self.message = Some((e, true)),
                }
                return;
            }
        }
        self.commit(c);
    }

    /// Reads a ProxyCap ruleset and shows what it holds.
    pub fn import_proxycap(&mut self, path: Option<String>) {
        let Some(path) = path else { return };
        match proxycap::import_file(std::path::Path::new(&path)) {
            Ok(result) => {
                let remote_dns = result.uses_remote_dns;
                self.dialog = Some(Dialog::ImportPreview {
                    source: file_name(&path).to_string(),
                    result: Box::new(result),
                    replace: self.config.rules.is_empty(),
                    remote_dns,
                    settings: None,
                });
            }
            Err(e) => self.message = Some((e.0, true)),
        }
    }

    /// ProxyForge's config.json: same format, passwords included (same DPAPI entropy). Read only: ProxyForge's
    /// file is never written.
    pub fn import_proxyforge(&mut self, path: &std::path::Path) {
        let mut warnings = Vec::new();
        let parsed = std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|json| proxidize_core::config::deserialize_from_disk(&json, &mut warnings).map_err(|e| e.to_string()));
        match parsed {
            Ok(config) => {
                let settings = Some((Box::new(config.settings.clone()), true));
                let result = ImportResult {
                    proxies: config.proxies,
                    chains: config.chains,
                    rules: config.rules,
                    uses_remote_dns: config.settings.dns_mode == proxidize_core::config::DnsMode::FakeIp,
                    remote_dns_exceptions: Vec::new(),
                    warnings,
                };
                let remote_dns = result.uses_remote_dns;
                self.dialog = Some(Dialog::ImportPreview {
                    source: "ProxyForge".into(),
                    result: Box::new(result),
                    replace: true,
                    remote_dns,
                    settings,
                });
            }
            Err(e) => self.message = Some((format!("Couldn't read ProxyForge's configuration: {e}"), true)),
        }
    }

    fn apply_import(&mut self, result: ImportResult, replace: bool, remote_dns: bool, settings: Option<Settings>) {
        let backup = ConfigStore::data_directory()
            .join(format!("config-before-import-{}.json", chrono::Local::now().format("%Y%m%d-%H%M%S")));
        if let Ok(json) = proxidize_core::config::serialize_for_disk(&self.config) {
            let _ = std::fs::write(&backup, json);
        }
        let mut c = self.config.clone();
        let summary = result.summary();
        proxycap::apply(&mut c, result, replace, remote_dns);
        if let Some(s) = settings {
            c.settings = s;
        }
        self.commit(c);
        self.log.info(format!("Imported {summary}."));
        self.message = Some((format!("Imported {summary}. The previous configuration is in {}.", backup.display()), false));
    }
}

fn split_ports(text: &str) -> Vec<String> {
    text.split([',', ';', ' ', '\n']).map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
}
