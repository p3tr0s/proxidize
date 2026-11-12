//! The pages: Overview (the switchboard), Rules, Proxies, Chains, Connections, Log and Settings.

use eframe::egui::{self, Align2, Color32, Pos2, Rect, Sense, Stroke, Vec2};
use proxidize_core::config::{Config, DnsMode, ProxyType, Rule, RuleAction, Settings, TransportFilter};
use proxidize_core::health::{HealthState, DIRECT_ID};
use proxidize_core::log::Level;

use crate::app::App;
use crate::dialogs::Dialog;
use crate::theme::{self, *};
use crate::widgets::{self, cells, fixed, flex, right, Kind};

pub fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

pub fn fmt_bytes(n: u64) -> String {
    match n {
        0..=999 => format!("{n} B"),
        1_000..=999_999 => format!("{:.1} KB", n as f64 / 1e3),
        1_000_000..=999_999_999 => format!("{:.1} MB", n as f64 / 1e6),
        _ => format!("{:.2} GB", n as f64 / 1e9),
    }
}

pub fn type_label(t: ProxyType) -> &'static str {
    match t {
        ProxyType::Socks5 => "SOCKS5",
        ProxyType::Socks4 => "SOCKS4",
        ProxyType::Http => "HTTP",
    }
}

fn matches(filter: &str, fields: &[&str]) -> bool {
    let f = filter.trim().to_lowercase();
    f.is_empty() || fields.iter().any(|x| x.to_lowercase().contains(&f))
}

/// What a rule matches besides programs, in words.
pub fn describe_match(rule: &Rule) -> String {
    let mut parts = Vec::new();
    if !rule.destinations.is_empty() {
        parts.push(rule.destinations.join(", "));
    }
    if !rule.ports.is_empty() {
        parts.push(format!("port {}", rule.ports.join(", ")));
    }
    match rule.transport {
        TransportFilter::Tcp => parts.push("TCP only".into()),
        TransportFilter::Udp => parts.push("UDP only".into()),
        TransportFilter::Both => {}
    }
    if parts.is_empty() {
        "Everything".into()
    } else {
        parts.join(", ")
    }
}

fn programs_text(rule: &Rule) -> String {
    match rule.programs.len() {
        0 => "Any program".into(),
        _ => rule.programs.iter().map(|p| file_name(p).to_string()).collect::<Vec<_>>().join(", "),
    }
}

impl App {
    /// The route's name and cable: a proxy, or a chain (coloured by its exit hop).
    pub fn route_cable(&self, route_id: Option<&str>) -> Option<(String, Color32, String)> {
        if let Some(p) = self.config.find_proxy(route_id) {
            return Some((
                p.name.clone(),
                theme::cable_of(p, &self.config),
                format!("{} {}:{}", type_label(p.kind), p.host, p.port),
            ));
        }
        let chain = self.config.find_chain(route_id)?;
        let color = chain
            .proxy_ids
            .last()
            .and_then(|id| self.config.find_proxy(Some(id)))
            .map(|p| theme::cable_of(p, &self.config))
            .unwrap_or(LIGHT_OFF);
        Some((chain.name.clone(), color, format!("Chain of {}", chain.proxy_ids.len())))
    }

    // ---------------------------------------------------------------------------------------------- Overview

    pub fn overview(&mut self, ui: &mut egui::Ui) {
        self.page_heading(ui, "Overview", "Which program leaves through which proxy, and from which IP", |app, ui| {
            if widgets::button(ui, "Add rule", Kind::Secondary).clicked() {
                app.dialog = Some(Dialog::new_rule(&app.config));
            }
        });
        self.facts(ui);
        ui.add_space(S4);

        let cols =
            [flex("Program", 1.0, 160.0), flex("", 0.9, 80.0), fixed("Proxy", 220.0), fixed("Exit", 250.0), right("Open", 60.0)];
        widgets::header(ui, &cols);
        let open_by_rule = {
            let mut m: std::collections::HashMap<String, usize> = Default::default();
            for c in self.tracker.snapshot(false) {
                *m.entry(c.rule_name.clone()).or_default() += 1;
            }
            m
        };
        let rules = self.config.rules.clone();
        if rules.is_empty() {
            ui.add_space(S6);
            widgets::hint(ui, "No rules yet. Add one to send a program through a proxy.");
            return;
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("board").show_rows(
            ui,
            60.0,
            rules.len(),
            |ui, range| {
                for rule in &rules[range] {
                    let selected = self.views.selected_rule.as_deref() == Some(&rule.id);
                    let (rect, response) = widgets::row(ui, 60.0, selected, egui::Id::unique(("board", &rule.id)));
                    if response.clicked() {
                        self.views.selected_rule = Some(rule.id.clone());
                    }
                    if response.double_clicked() {
                        self.dialog = Some(Dialog::edit_rule(rule));
                    }
                    let r = cells(rect, &cols);
                    let p = ui.painter();
                    let enabled = rule.enabled;
                    let fg = |c: Color32| if enabled { c } else { theme::dim(c) };
                    let detail = match rule.programs.len() {
                        0 => describe_match(rule),
                        1 => rule.programs[0].clone(),
                        n => format!("{} and {} more", file_name(&rule.programs[0]), n - 1),
                    };
                    widgets::two_lines(p, r[0], &rule.name, data(), fg(TEXT), &detail, fg(TEXT_MUTED));

                    let health = self.route_health(rule);
                    let blocked = health.is_some_and(|h| h.blocked);
                    match rule.action {
                        RuleAction::Proxy => {
                            if let Some((name, color, detail)) = self.route_cable(rule.route_id.as_deref()) {
                                let y = r[1].center().y;
                                theme::cable(
                                    p,
                                    Pos2::new(r[1].left() + S2, y),
                                    Pos2::new(r[2].left() - S3, y),
                                    fg(color),
                                    blocked,
                                );
                                widgets::two_lines(p, r[2], &name, data_strong(), fg(TEXT), &detail, fg(TEXT_MUTED));
                            } else {
                                widgets::two_lines(
                                    p,
                                    r[2],
                                    "Missing proxy",
                                    data_strong(),
                                    LIGHT_FAULT,
                                    "Edit the rule to pick one",
                                    TEXT_MUTED,
                                );
                            }
                        }
                        RuleAction::Direct => {
                            let y = r[1].center().y;
                            p.line_segment(
                                [Pos2::new(r[1].left() + S2, y), Pos2::new(r[2].left() - S3, y)],
                                Stroke::new(1.0, fg(HAIRLINE_STRONG)),
                            );
                            widgets::two_lines(
                                p,
                                r[2],
                                "Direct",
                                data_strong(),
                                fg(TEXT_SECONDARY),
                                "Your own connection",
                                fg(TEXT_MUTED),
                            );
                        }
                        RuleAction::Block => {
                            widgets::two_lines(
                                p,
                                r[2],
                                "Blocked",
                                data_strong(),
                                fg(LIGHT_FAULT),
                                "Nothing gets through",
                                fg(TEXT_MUTED),
                            );
                        }
                    }

                    let mid = r[3].center().y;
                    if let Some(h) = health {
                        let (light, hollow) = theme::light_of(Some(h));
                        theme::light(p, r[3].left(), mid - 9.0, if enabled { light } else { LIGHT_OFF }, hollow);
                        let ip = h.exit_ip.clone().unwrap_or_else(|| "No answer".into());
                        let line1 = Rect::from_min_max(Pos2::new(r[3].left() + 18.0, mid - 18.0), Pos2::new(r[3].right(), mid));
                        theme::text(p, line1, &ip, data_strong(), fg(TEXT), Align2::LEFT_BOTTOM);
                        let second = if blocked {
                            "Blocked: exit IP is your own".to_string()
                        } else if !h.ok {
                            h.error.clone().unwrap_or_default()
                        } else {
                            let place = match (&h.city, h.country_text().as_str()) {
                                (Some(c), country) if !country.is_empty() => format!("{c}, {country}"),
                                (None, country) => country.to_string(),
                                (Some(c), _) => c.clone(),
                            };
                            format!("{place}, {} ms", h.latency_ms)
                        };
                        let color = if blocked || !h.ok {
                            LIGHT_FAULT
                        } else if h.state == HealthState::SharedIp {
                            LIGHT_CAUTION
                        } else {
                            TEXT_MUTED
                        };
                        let line2 = Rect::from_min_max(Pos2::new(r[3].left(), mid + 1.0), Pos2::new(r[3].right(), mid + 18.0));
                        theme::text(p, line2, &second, data_small(), fg(color), Align2::LEFT_TOP);
                    } else if rule.action == RuleAction::Proxy {
                        theme::light(p, r[3].left(), mid, LIGHT_OFF, true);
                        theme::text(
                            p,
                            r[3].translate(Vec2::new(18.0, 0.0)),
                            "Not checked",
                            data_small(),
                            TEXT_MUTED,
                            Align2::LEFT_CENTER,
                        );
                    }
                    let open = open_by_rule.get(&rule.name).copied().unwrap_or(0);
                    let open_text = if enabled { open.to_string() } else { "Off".into() };
                    theme::text(
                        p,
                        r[4],
                        &open_text,
                        data_strong(),
                        if open > 0 { TEXT } else { TEXT_MUTED },
                        Align2::RIGHT_CENTER,
                    );
                }
            },
        );
    }

    fn facts(&self, ui: &mut egui::Ui) {
        let protected = self.backend.protected_programs(&self.config);
        let s = &self.config.settings;
        let health = self.proxy_health();
        let mut facts: Vec<(&str, String, Option<Color32>)> = vec![
            if s.kill_switch {
                (
                    "Kill switch",
                    if protected == 1 { "On, 1 program".into() } else { format!("On, {protected} programs") },
                    Some(LIGHT_OK),
                )
            } else {
                ("Kill switch", "Off".into(), Some(LIGHT_CAUTION))
            },
            if s.dns_mode == DnsMode::FakeIp {
                ("DNS lookups", "Through the proxy".into(), Some(LIGHT_OK))
            } else {
                ("DNS lookups", "Your own resolver".into(), Some(LIGHT_CAUTION))
            },
        ];
        facts.push(if health.is_empty() {
            ("Proxies", "Not checked".into(), None)
        } else {
            let ok = health.iter().filter(|h| h.state == HealthState::Ok).count();
            let light = if self.fault() {
                LIGHT_FAULT
            } else if health.iter().any(|h| h.state == HealthState::SharedIp) {
                LIGHT_CAUTION
            } else {
                LIGHT_OK
            };
            ("Proxies", format!("{ok} of {} working", health.len()), Some(light))
        });
        facts.push(match self.health.get(DIRECT_ID).filter(|h| h.ok) {
            Some(me) => (
                "Your IP",
                format!("{}  {}", me.exit_ip.as_deref().unwrap_or_default(), me.country_code.as_deref().unwrap_or_default())
                    .trim_end()
                    .to_string(),
                None,
            ),
            None => ("Your IP", "Not checked".into(), None),
        });
        let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 62.0), Sense::hover());
        let p = ui.painter();
        let w = rect.width() / facts.len() as f32;
        for (i, (label, value, light)) in facts.iter().enumerate() {
            let x = rect.left() + w * i as f32;
            if i > 0 {
                p.vline(x - S4, (rect.top() + 4.0)..=(rect.bottom() - 4.0), Stroke::new(1.0, HAIRLINE));
            }
            p.text(Pos2::new(x, rect.top() + 14.0), Align2::LEFT_CENTER, *label, small(), TEXT_MUTED);
            let mut vx = x;
            if let Some(c) = light {
                theme::light(p, x, rect.top() + 42.0, *c, false);
                vx += 20.0;
            }
            theme::text(
                p,
                Rect::from_min_max(Pos2::new(vx, rect.top() + 28.0), Pos2::new(x + w - S6, rect.top() + 56.0)),
                value,
                figure(),
                TEXT,
                Align2::LEFT_CENTER,
            );
        }
    }

    // ---------------------------------------------------------------------------------------------- Rules

    pub fn rules_page(&mut self, ui: &mut egui::Ui) {
        self.page_heading(ui, "Rules", "First match wins. Programs no rule matches connect directly.", |app, ui| {
            if widgets::button(ui, "Add rule", Kind::Primary).clicked() {
                app.dialog = Some(Dialog::new_rule(&app.config));
            }
        });
        let selected = self.views.selected_rule.clone();
        let index = selected.as_ref().and_then(|id| self.config.rules.iter().position(|r| &r.id == id));
        ui.horizontal(|ui| {
            widgets::search(ui, &mut self.views.rule_filter, "Search rules", 240.0);
            ui.add_space(S2);
            if widgets::button_enabled(ui, "Edit", Kind::Secondary, index.is_some()).clicked() {
                self.dialog = Some(Dialog::edit_rule(&self.config.rules[index.unwrap()]));
            }
            if widgets::button_enabled(ui, "Duplicate", Kind::Secondary, index.is_some()).clicked() {
                let mut copy = self.config.rules[index.unwrap()].clone();
                copy.id = Rule::default().id;
                copy.name = format!("{} (copy)", copy.name);
                let mut c = self.config.clone();
                c.rules.insert(index.unwrap() + 1, copy.clone());
                self.views.selected_rule = Some(copy.id);
                self.commit(c);
            }
            if widgets::button_enabled(ui, "Move up", Kind::Quiet, index.is_some_and(|i| i > 0)).clicked() {
                self.move_rule(index.unwrap(), -1);
            }
            if widgets::button_enabled(ui, "Move down", Kind::Quiet, index.is_some_and(|i| i + 1 < self.config.rules.len()))
                .clicked()
            {
                self.move_rule(index.unwrap(), 1);
            }
            if widgets::button_enabled(ui, "Delete", Kind::Danger, index.is_some()).clicked() {
                let rule = &self.config.rules[index.unwrap()];
                self.dialog = Some(Dialog::confirm_delete_rule(rule));
            }
        });
        ui.add_space(S3);

        // keyboard: Space toggles, Enter edits, Delete removes, Alt+Up/Down moves
        if let Some(i) = index {
            if self.dialog.is_none() && !ui.ctx().egui_wants_keyboard_input() {
                let (space, enter, delete, up, down) = ui.input(|inp| {
                    (
                        inp.key_pressed(egui::Key::Space),
                        inp.key_pressed(egui::Key::Enter),
                        inp.key_pressed(egui::Key::Delete),
                        inp.modifiers.alt && inp.key_pressed(egui::Key::ArrowUp),
                        inp.modifiers.alt && inp.key_pressed(egui::Key::ArrowDown),
                    )
                });
                if space {
                    self.toggle_rule(i);
                } else if enter {
                    self.dialog = Some(Dialog::edit_rule(&self.config.rules[i]));
                } else if delete {
                    self.dialog = Some(Dialog::confirm_delete_rule(&self.config.rules[i]));
                } else if up && i > 0 {
                    self.move_rule(i, -1);
                } else if down && i + 1 < self.config.rules.len() {
                    self.move_rule(i, 1);
                }
            }
        }

        let cols = [
            fixed("", 36.0),
            flex("Name", 0.8, 120.0),
            flex("Programs", 1.2, 140.0),
            flex("Matches", 1.0, 120.0),
            fixed("Route", 210.0),
            fixed("Exit", 190.0),
        ];
        widgets::header(ui, &cols);
        let visible: Vec<(usize, Rule)> = self
            .config
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                let route = self.config.describe_route(r.route_id.as_deref());
                matches(&self.views.rule_filter, &[&r.name, &r.programs.join(" "), &r.destinations.join(" "), &route])
            })
            .map(|(i, r)| (i, r.clone()))
            .collect();
        if visible.is_empty() {
            ui.add_space(S6);
            widgets::hint(
                ui,
                if self.config.rules.is_empty() {
                    "No rules yet. Add rule sends a program through a proxy."
                } else {
                    "No rule matches the search."
                },
            );
            return;
        }
        let mut toggle = None;
        egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("rules").show_rows(
            ui,
            44.0,
            visible.len(),
            |ui, range| {
                for (i, rule) in &visible[range] {
                    let selected = self.views.selected_rule.as_deref() == Some(&rule.id);
                    let (rect, response) = widgets::row(ui, 44.0, selected, egui::Id::unique(("rule", &rule.id)));
                    let r = cells(rect, &cols);
                    if widgets::row_toggle(ui, r[0], egui::Id::unique(("rule-on", &rule.id)), rule.enabled) {
                        toggle = Some(*i);
                    } else if response.clicked() {
                        self.views.selected_rule = Some(rule.id.clone());
                    }
                    if response.double_clicked() {
                        self.dialog = Some(Dialog::edit_rule(rule));
                    }
                    response.context_menu(|ui| {
                        if ui.button("Edit").clicked() {
                            self.dialog = Some(Dialog::edit_rule(rule));
                        }
                        if ui.button(if rule.enabled { "Turn off" } else { "Turn on" }).clicked() {
                            toggle = Some(*i);
                        }
                        if ui.button("Delete").clicked() {
                            self.dialog = Some(Dialog::confirm_delete_rule(rule));
                        }
                    });
                    let p = ui.painter();
                    let fg = |c: Color32| if rule.enabled { c } else { theme::dim(c) };
                    theme::text(p, r[1], &rule.name, data(), fg(TEXT), Align2::LEFT_CENTER);
                    theme::text(p, r[2], &programs_text(rule), body(), fg(TEXT_SECONDARY), Align2::LEFT_CENTER);
                    theme::text(p, r[3], &describe_match(rule), body(), fg(TEXT_SECONDARY), Align2::LEFT_CENTER);
                    match rule.action {
                        RuleAction::Proxy => match self.route_cable(rule.route_id.as_deref()) {
                            Some((name, color, _)) => {
                                let y = r[4].center().y;
                                theme::cable(p, Pos2::new(r[4].left(), y), Pos2::new(r[4].left() + 28.0, y), fg(color), false);
                                theme::text(p, r[4].with_min_x(r[4].left() + 38.0), &name, data(), fg(TEXT), Align2::LEFT_CENTER);
                            }
                            None => {
                                theme::text(p, r[4], "Missing proxy", data(), LIGHT_FAULT, Align2::LEFT_CENTER);
                            }
                        },
                        RuleAction::Direct => {
                            theme::text(p, r[4], "Direct", data(), fg(TEXT_SECONDARY), Align2::LEFT_CENTER);
                        }
                        RuleAction::Block => {
                            theme::text(p, r[4], "Block", data(), fg(LIGHT_FAULT), Align2::LEFT_CENTER);
                        }
                    }
                    if let Some(h) = self.route_health(rule) {
                        let (light, hollow) = theme::light_of(Some(h));
                        theme::light(p, r[5].left(), r[5].center().y, light, hollow);
                        let text = h.exit_ip.clone().unwrap_or_else(|| h.status_text());
                        theme::text(
                            p,
                            r[5].with_min_x(r[5].left() + 18.0),
                            &text,
                            data(),
                            fg(TEXT_SECONDARY),
                            Align2::LEFT_CENTER,
                        );
                    }
                }
            },
        );
        if let Some(i) = toggle {
            self.toggle_rule(i);
        }
    }

    pub fn toggle_rule(&mut self, index: usize) {
        let mut c = self.config.clone();
        c.rules[index].enabled = !c.rules[index].enabled;
        self.views.selected_rule = Some(c.rules[index].id.clone());
        self.commit(c);
    }

    fn move_rule(&mut self, index: usize, delta: i32) {
        let target = index as i32 + delta;
        if target < 0 || target as usize >= self.config.rules.len() {
            return;
        }
        let mut c = self.config.clone();
        c.rules.swap(index, target as usize);
        self.commit(c);
    }

    // ---------------------------------------------------------------------------------------------- Proxies

    pub fn proxies_page(&mut self, ui: &mut egui::Ui) {
        self.page_heading(
            ui,
            "Proxies",
            "Where traffic goes out. Each proxy has a cable colour used everywhere it appears.",
            |app, ui| {
                if widgets::button(ui, "Add proxy", Kind::Primary).clicked() {
                    app.dialog = Some(Dialog::new_proxy(&app.config));
                }
                let import = widgets::button(ui, "Import", Kind::Secondary);
                egui::Popup::menu(&import).show(|ui| {
                    ui.set_min_width(280.0);
                    if ui.button("From installed ProxyCap (machine.prs)").clicked() {
                        app.import_proxycap(Some(proxidize_core::proxycap::INSTALLED_RULESET.into()));
                    }
                    if ui.button("From a ProxyCap file (.prs or .xml)").clicked() {
                        app.dialog = Some(Dialog::import_path());
                    }
                    if let Some(path) = proxidize_core::config::ConfigStore::proxyforge_config_path().filter(|p| p.exists()) {
                        if ui.button("From ProxyForge").clicked() {
                            app.import_proxyforge(&path);
                        }
                    }
                });
            },
        );
        let selected: Vec<String> = self.views.selected_proxies.clone();
        let one = (selected.len() == 1).then(|| self.config.proxies.iter().position(|p| p.id == selected[0])).flatten();
        ui.horizontal(|ui| {
            widgets::search(ui, &mut self.views.proxy_filter, "Search proxies", 240.0);
            ui.add_space(S2);
            if widgets::button_enabled(ui, "Edit", Kind::Secondary, one.is_some()).clicked() {
                self.dialog = Some(Dialog::edit_proxy(&self.config.proxies[one.unwrap()]));
            }
            if widgets::button_enabled(ui, "Credentials", Kind::Secondary, !selected.is_empty()).clicked() {
                self.dialog = Some(Dialog::credentials(&self.config, &selected));
            }
            if widgets::button_enabled(ui, "Check selected", Kind::Secondary, !selected.is_empty() && !self.checking).clicked() {
                self.check_proxies(Some(selected.clone()));
            }
            if widgets::button_enabled(ui, "Delete", Kind::Danger, !selected.is_empty()).clicked() {
                self.dialog = Some(Dialog::confirm_delete_proxies(&self.config, &selected));
            }
        });
        ui.add_space(S3);
        if self.dialog.is_none() && !ui.ctx().egui_wants_keyboard_input() {
            if let Some(i) = one {
                if ui.input(|inp| inp.key_pressed(egui::Key::Enter)) {
                    self.dialog = Some(Dialog::edit_proxy(&self.config.proxies[i]));
                }
            }
            if !selected.is_empty() && ui.input(|inp| inp.key_pressed(egui::Key::Delete)) {
                self.dialog = Some(Dialog::confirm_delete_proxies(&self.config, &selected));
            }
            if ui.input(|inp| inp.modifiers.command && inp.key_pressed(egui::Key::A)) {
                self.views.selected_proxies = self.config.proxies.iter().map(|p| p.id.clone()).collect();
            }
        }

        let cols = [
            flex("Name", 1.0, 120.0),
            fixed("Type", 72.0),
            flex("Address", 1.2, 140.0),
            fixed("Status", 186.0),
            fixed("Exit IP", 130.0),
            flex("Location", 0.9, 110.0),
            right("Latency", 76.0),
        ];
        widgets::header(ui, &cols);
        let visible: Vec<_> = self
            .config
            .proxies
            .iter()
            .filter(|p| matches(&self.views.proxy_filter, &[&p.name, &p.host, p.username.as_deref().unwrap_or_default()]))
            .cloned()
            .collect();
        if visible.is_empty() {
            ui.add_space(S6);
            widgets::hint(
                ui,
                if self.config.proxies.is_empty() {
                    "No proxies yet. Add proxy, or import them from ProxyCap."
                } else {
                    "No proxy matches the search."
                },
            );
            return;
        }
        let modifiers = ui.input(|i| i.modifiers);
        egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("proxies").show_rows(
            ui,
            44.0,
            visible.len(),
            |ui, range| {
                for proxy in &visible[range] {
                    let is_selected = self.views.selected_proxies.contains(&proxy.id);
                    let (rect, response) = widgets::row(ui, 44.0, is_selected, egui::Id::unique(("proxy", &proxy.id)));
                    if response.clicked() {
                        if modifiers.command {
                            if is_selected {
                                self.views.selected_proxies.retain(|id| id != &proxy.id);
                            } else {
                                self.views.selected_proxies.push(proxy.id.clone());
                            }
                        } else if modifiers.shift && !self.views.selected_proxies.is_empty() {
                            let ids: Vec<&String> = visible.iter().map(|p| &p.id).collect();
                            let anchor = ids.iter().position(|id| *id == &self.views.selected_proxies[0]).unwrap_or(0);
                            let here = ids.iter().position(|id| *id == &proxy.id).unwrap_or(0);
                            let (a, b) = (anchor.min(here), anchor.max(here));
                            let first = self.views.selected_proxies[0].clone();
                            self.views.selected_proxies = std::iter::once(first.clone())
                                .chain(ids[a..=b].iter().map(|s| (*s).clone()).filter(|s| *s != first))
                                .collect();
                        } else {
                            self.views.selected_proxies = vec![proxy.id.clone()];
                        }
                    }
                    if response.double_clicked() {
                        self.dialog = Some(Dialog::edit_proxy(proxy));
                    }
                    response.context_menu(|ui| {
                        if ui.button("Edit").clicked() {
                            self.dialog = Some(Dialog::edit_proxy(proxy));
                        }
                        if ui.button("Check").clicked() {
                            self.check_proxies(Some(vec![proxy.id.clone()]));
                        }
                        if ui.button("Delete").clicked() {
                            self.dialog = Some(Dialog::confirm_delete_proxies(&self.config, std::slice::from_ref(&proxy.id)));
                        }
                    });
                    let r = cells(rect, &cols);
                    let p = ui.painter();
                    let color = theme::cable_of(proxy, &self.config);
                    let y = r[0].center().y;
                    theme::cable(p, Pos2::new(r[0].left(), y), Pos2::new(r[0].left() + 22.0, y), color, false);
                    theme::text(p, r[0].with_min_x(r[0].left() + 32.0), &proxy.name, data(), TEXT, Align2::LEFT_CENTER);
                    theme::text(p, r[1], type_label(proxy.kind), data_small(), TEXT_SECONDARY, Align2::LEFT_CENTER);
                    let auth =
                        proxy.username.as_deref().filter(|u| !u.is_empty()).map(|u| format!("  ({u})")).unwrap_or_default();
                    theme::text(
                        p,
                        r[2],
                        &format!("{}:{}{auth}", proxy.host, proxy.port),
                        data(),
                        TEXT_SECONDARY,
                        Align2::LEFT_CENTER,
                    );
                    let health = self.health.get(&proxy.id);
                    let (light, hollow) = theme::light_of(health);
                    theme::light(p, r[3].left(), y, light, hollow);
                    let status = health.map(|h| h.status_text()).unwrap_or_else(|| "Not checked".into());
                    let status_rect = r[3].with_min_x(r[3].left() + 18.0);
                    let shown = theme::text(
                        p,
                        status_rect,
                        &status,
                        body(),
                        if health.is_some() { TEXT } else { TEXT_MUTED },
                        Align2::LEFT_CENTER,
                    );
                    if let Some(h) = health {
                        let tip = h.error.clone().or_else(|| h.warning.clone());
                        if let Some(tip) = tip {
                            ui.interact(shown.union(r[3]), egui::Id::unique(("ptip", &proxy.id)), Sense::hover())
                                .on_hover_text(tip);
                        }
                        theme::text(ui.painter(), r[4], h.exit_ip.as_deref().unwrap_or("-"), data(), TEXT, Align2::LEFT_CENTER);
                        let place = match (&h.city, h.country_text()) {
                            (Some(c), t) if !t.is_empty() => format!("{c}, {t}"),
                            (_, t) => t,
                        };
                        theme::text(ui.painter(), r[5], &place, body(), TEXT_SECONDARY, Align2::LEFT_CENTER);
                        if h.ok {
                            theme::text(
                                ui.painter(),
                                r[6],
                                &format!("{} ms", h.latency_ms),
                                data(),
                                TEXT_SECONDARY,
                                Align2::RIGHT_CENTER,
                            );
                        }
                    }
                }
            },
        );
    }

    // ---------------------------------------------------------------------------------------------- Chains

    pub fn chains_page(&mut self, ui: &mut egui::Ui) {
        self.page_heading(
            ui,
            "Chains",
            "Proxies in a row: the first is reached directly, the last one connects to the destination.",
            |app, ui| {
                if widgets::button_enabled(ui, "Add chain", Kind::Primary, !app.config.proxies.is_empty()).clicked() {
                    app.dialog = Some(Dialog::new_chain());
                }
            },
        );
        let index = self.views.selected_chain.as_ref().and_then(|id| self.config.chains.iter().position(|c| &c.id == id));
        ui.horizontal(|ui| {
            widgets::search(ui, &mut self.views.chain_filter, "Search chains", 240.0);
            ui.add_space(S2);
            if widgets::button_enabled(ui, "Edit", Kind::Secondary, index.is_some()).clicked() {
                self.dialog = Some(Dialog::edit_chain(&self.config.chains[index.unwrap()]));
            }
            if widgets::button_enabled(ui, "Delete", Kind::Danger, index.is_some()).clicked() {
                self.dialog = Some(Dialog::confirm_delete_chain(&self.config, &self.config.chains[index.unwrap()]));
            }
        });
        ui.add_space(S3);
        let cols = [flex("Name", 0.7, 140.0), flex("Hops, in order", 2.0, 200.0), fixed("Used by", 140.0)];
        widgets::header(ui, &cols);
        let chains: Vec<_> =
            self.config.chains.iter().filter(|c| matches(&self.views.chain_filter, &[&c.name])).cloned().collect();
        if chains.is_empty() {
            ui.add_space(S6);
            widgets::hint(
                ui,
                if self.config.chains.is_empty() {
                    "No chains. A chain sends traffic through several proxies, one after another."
                } else {
                    "No chain matches the search."
                },
            );
            return;
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("chains").show(ui, |ui| {
            for chain in &chains {
                let selected = self.views.selected_chain.as_deref() == Some(&chain.id);
                let (rect, response) = widgets::row(ui, 44.0, selected, egui::Id::unique(("chain", &chain.id)));
                if response.clicked() {
                    self.views.selected_chain = Some(chain.id.clone());
                }
                if response.double_clicked() {
                    self.dialog = Some(Dialog::edit_chain(chain));
                }
                let r = cells(rect, &cols);
                let p = ui.painter();
                theme::text(p, r[0], &chain.name, data(), TEXT, Align2::LEFT_CENTER);
                let mut x = r[1].left();
                let y = r[1].center().y;
                for (i, id) in chain.proxy_ids.iter().enumerate() {
                    let Some(proxy) = self.config.find_proxy(Some(id)) else {
                        theme::text(
                            p,
                            Rect::from_min_max(Pos2::new(x, r[1].top()), r[1].max),
                            "(missing proxy)",
                            data(),
                            LIGHT_FAULT,
                            Align2::LEFT_CENTER,
                        );
                        break;
                    };
                    let color = theme::cable_of(proxy, &self.config);
                    theme::cable(p, Pos2::new(x, y), Pos2::new(x + 22.0, y), color, false);
                    let w = theme::text(
                        p,
                        Rect::from_min_max(Pos2::new(x + 30.0, r[1].top()), r[1].max),
                        &proxy.name,
                        data(),
                        TEXT,
                        Align2::LEFT_CENTER,
                    )
                    .width();
                    x += 30.0 + w + S4;
                    if i + 1 < chain.proxy_ids.len() && x < r[1].right() {
                        p.text(Pos2::new(x - S2, y), Align2::CENTER_CENTER, "›", data(), TEXT_MUTED);
                        x += S2;
                    }
                }
                let used = self.config.rules.iter().filter(|r| r.route_id.as_deref() == Some(&chain.id)).count();
                theme::text(
                    p,
                    r[2],
                    &if used == 1 { "1 rule".into() } else { format!("{used} rules") },
                    body(),
                    TEXT_SECONDARY,
                    Align2::LEFT_CENTER,
                );
            }
        });
    }

    // ---------------------------------------------------------------------------------------------- Connections

    pub fn connections_page(&mut self, ui: &mut egui::Ui) {
        self.page_heading(ui, "Connections", "What is connected right now, and through which route", |_, _| {});
        ui.horizontal(|ui| {
            widgets::search(ui, &mut self.views.connection_filter, "Search connections", 240.0);
            ui.add_space(S3);
            widgets::square_check(ui, &mut self.views.show_closed, "Show closed");
            ui.add_space(S3);
            if widgets::button(ui, "Clear closed", Kind::Quiet).clicked() {
                self.tracker.clear_closed();
            }
        });
        ui.add_space(S3);
        let cols = [
            fixed("Started", 78.0),
            fixed("", 44.0),
            flex("Program", 0.9, 120.0),
            flex("Destination", 1.3, 150.0),
            flex("Route", 0.8, 110.0),
            right("Up", 84.0),
            right("Down", 84.0),
            fixed("State", 124.0),
        ];
        widgets::header(ui, &cols);
        let records: Vec<_> = self
            .tracker
            .snapshot(self.views.show_closed)
            .into_iter()
            .filter(|c| matches(&self.views.connection_filter, &[&c.process_name, &c.destination, &c.route_name, &c.rule_name]))
            .collect();
        if records.is_empty() {
            ui.add_space(S6);
            widgets::hint(
                ui,
                if self.backend.is_running() { "No connections yet." } else { "Start redirecting to see connections here." },
            );
            return;
        }
        let cables: std::collections::HashMap<String, Color32> = self
            .config
            .proxies
            .iter()
            .map(|p| (p.name.clone(), theme::cable_of(p, &self.config)))
            .chain(self.config.chains.iter().filter_map(|c| self.route_cable(Some(&c.id)).map(|(n, col, _)| (n, col))))
            .collect();
        egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("connections").show_rows(
            ui,
            34.0,
            records.len(),
            |ui, range| {
                for c in &records[range] {
                    let selected = self.views.selected_connection == Some(c.id);
                    let (rect, response) = widgets::row(ui, 34.0, selected, egui::Id::unique(("conn", c.id)));
                    if response.clicked() {
                        self.views.selected_connection = Some(c.id);
                    }
                    response.context_menu(|ui| {
                        if ui.button("Copy destination").clicked() {
                            ui.ctx().copy_text(c.destination.clone());
                        }
                        if ui.button("Copy row").clicked() {
                            ui.ctx().copy_text(format!(
                                "{} {} {}({}) {} via {} [{}] up {} down {} {}",
                                c.started.format("%H:%M:%S"),
                                c.protocol,
                                c.process_name,
                                c.process_id,
                                c.destination,
                                c.route_name,
                                c.rule_name,
                                c.bytes_up(),
                                c.bytes_down(),
                                c.state()
                            ));
                        }
                    });
                    let r = cells(rect, &cols);
                    let p = ui.painter();
                    let open = c.ended().is_none();
                    let fg = if open { TEXT } else { TEXT_SECONDARY };
                    theme::text(
                        p,
                        r[0],
                        &c.started.format("%H:%M:%S").to_string(),
                        data_small(),
                        TEXT_MUTED,
                        Align2::LEFT_CENTER,
                    );
                    theme::text(p, r[1], c.protocol, data_small(), TEXT_MUTED, Align2::LEFT_CENTER);
                    theme::text(p, r[2], &format!("{}  {}", c.process_name, c.process_id), data(), fg, Align2::LEFT_CENTER);
                    theme::text(p, r[3], &c.destination, data(), fg, Align2::LEFT_CENTER);
                    let y = r[4].center().y;
                    let route_x = match (c.action, cables.get(&c.route_name)) {
                        (RuleAction::Proxy, Some(color)) => {
                            theme::cable(
                                p,
                                Pos2::new(r[4].left(), y),
                                Pos2::new(r[4].left() + 18.0, y),
                                if open { *color } else { theme::dim(*color) },
                                false,
                            );
                            r[4].left() + 26.0
                        }
                        _ => r[4].left(),
                    };
                    theme::text(p, r[4].with_min_x(route_x), &c.route_name, data(), fg, Align2::LEFT_CENTER);
                    theme::text(p, r[5], &fmt_bytes(c.bytes_up()), data_small(), TEXT_SECONDARY, Align2::RIGHT_CENTER);
                    theme::text(p, r[6], &fmt_bytes(c.bytes_down()), data_small(), TEXT_SECONDARY, Align2::RIGHT_CENTER);
                    let state = c.state();
                    let (light, hollow) = match state.as_str() {
                        "Established" => (LIGHT_OK, false),
                        "Failed" | "Blocked" => (LIGHT_FAULT, false),
                        "Connecting" => (LIGHT_CAUTION, false),
                        _ => (LIGHT_OFF, !open),
                    };
                    theme::light(p, r[7].left(), y, light, hollow);
                    let shown = theme::text(p, r[7].with_min_x(r[7].left() + 16.0), &state, body(), fg, Align2::LEFT_CENTER);
                    if let Some(error) = c.error() {
                        ui.interact(shown.union(r[7]), egui::Id::unique(("cerr", c.id)), Sense::hover()).on_hover_text(error);
                    }
                }
            },
        );
    }

    // ---------------------------------------------------------------------------------------------- Log

    pub fn log_page(&mut self, ui: &mut egui::Ui) {
        self.page_heading(ui, "Log", "Newest first", |app, ui| {
            let dir = proxidize_core::config::ConfigStore::data_directory().join("logs");
            if widgets::button(ui, "Open log folder", Kind::Secondary).clicked() {
                open_folder(&dir);
            }
            if widgets::button(ui, "Copy", Kind::Secondary).clicked() {
                let text: Vec<String> = app
                    .log
                    .entries_after(0)
                    .iter()
                    .map(|e| format!("{} [{}] {}", e.time.format("%H:%M:%S"), e.level.label(), e.message))
                    .collect();
                ui.ctx().copy_text(text.join("\n"));
            }
        });
        const LEVELS: [&str; 3] = ["Everything", "Warnings and errors", "Errors only"];
        ui.horizontal(|ui| {
            widgets::search(ui, &mut self.views.log_filter, "Search the log", 240.0);
            ui.add_space(S2);
            egui::ComboBox::from_id_salt("level").width(190.0).selected_text(LEVELS[self.views.log_level]).show_ui(ui, |ui| {
                for (i, l) in LEVELS.iter().enumerate() {
                    ui.selectable_value(&mut self.views.log_level, i, *l);
                }
            });
        });
        ui.add_space(S3);
        let min = match self.views.log_level {
            1 => Level::Warning,
            2 => Level::Error,
            _ => Level::Debug,
        };
        let mut entries: Vec<_> = self
            .log
            .entries_after(0)
            .into_iter()
            .filter(|e| e.level >= min && matches(&self.views.log_filter, &[&e.message]))
            .collect();
        entries.reverse();
        let cols = [fixed("Time", 84.0), fixed("", 22.0), flex("Message", 1.0, 200.0)];
        widgets::header(ui, &cols);
        egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("log").show_rows(
            ui,
            30.0,
            entries.len(),
            |ui, range| {
                for e in &entries[range] {
                    let (rect, response) = widgets::row(ui, 30.0, false, egui::Id::unique(("log", e.sequence)));
                    let r = cells(rect, &cols);
                    let p = ui.painter();
                    theme::text(p, r[0], &e.time.format("%H:%M:%S").to_string(), data_small(), TEXT_MUTED, Align2::LEFT_CENTER);
                    let color = match e.level {
                        Level::Error => Some(LIGHT_FAULT),
                        Level::Warning => Some(LIGHT_CAUTION),
                        _ => None,
                    };
                    if let Some(c) = color {
                        theme::light(p, r[1].left(), r[1].center().y, c, false);
                    }
                    let fg = if e.level == Level::Debug { TEXT_MUTED } else { TEXT };
                    let shown = theme::text(p, r[2], &e.message, body(), fg, Align2::LEFT_CENTER);
                    if shown.width() + 4.0 >= r[2].width() {
                        response.clone().on_hover_text(&e.message);
                    }
                    response.context_menu(|ui| {
                        if ui.button("Copy").clicked() {
                            ui.ctx().copy_text(e.message.clone());
                        }
                    });
                }
            },
        );
    }

    // ---------------------------------------------------------------------------------------------- Settings

    pub fn settings_page(&mut self, ui: &mut egui::Ui) {
        let mut draft = self.views.settings_draft.take().unwrap_or_else(|| self.config.settings.clone());
        let dirty = draft != self.config.settings;
        let mut apply = false;
        let mut revert = false;
        self.page_heading(ui, "Settings", "Changes apply when you press Apply; some restart redirection.", |_, ui| {
            if widgets::button_enabled(ui, "Apply", Kind::Primary, dirty).clicked() {
                apply = true;
            }
            if widgets::button_enabled(ui, "Revert", Kind::Secondary, dirty).clicked() {
                revert = true;
            }
        });
        egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("settings").show(ui, |ui| {
            ui.set_max_width(760.0);
            settings_form(ui, &mut draft);
            widgets::section(ui, "Updates");
            widgets::square_check(
                ui,
                &mut draft.check_for_updates,
                "Check GitHub for new versions (on start, then every 12 hours)",
            );
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("Proxidize {}", env!("CARGO_PKG_VERSION"))).font(body()).color(TEXT));
                let label = if self.updates.busy == Some("Checking") { "Checking" } else { "Check now" };
                let enabled = self.updates.busy.is_none() && !self.demo;
                if widgets::button_enabled(ui, label, Kind::Secondary, enabled).clicked() {
                    self.check_updates(true);
                }
                if self.updates.available.is_some() && crate::app::can_update() {
                    let downloading = self.updates.busy == Some("Downloading");
                    let label = if downloading { "Downloading" } else { "Update and restart" };
                    if widgets::button_enabled(ui, label, Kind::Primary, !downloading).clicked() {
                        self.download_update();
                    }
                }
            });
            if let Some(status) = &self.updates.status {
                widgets::hint(ui, status);
            }
            widgets::hint(ui, "Updates are checked against the release's SHA-256 before they're installed.");
            widgets::section(ui, "Maintenance");
            ui.horizontal(|ui| {
                if widgets::button(ui, "Open data folder", Kind::Secondary).clicked() {
                    open_folder(&proxidize_core::config::ConfigStore::data_directory());
                }
                #[cfg(windows)]
                if widgets::button(ui, "Remove kill switch filters", Kind::Danger).clicked() {
                    self.dialog = Some(Dialog::confirm_remove_kill_switch());
                }
            });
            widgets::hint(ui, "Remove kill switch filters unblocks every protected program, also while Proxidize isn't running.");
            ui.add_space(S8);
        });
        if revert {
            draft = self.config.settings.clone();
        }
        if apply {
            let mut c = self.config.clone();
            c.settings = draft.clone();
            self.commit(c);
            self.log.info("Settings applied.");
        }
        self.views.settings_draft = (draft != self.config.settings).then_some(draft);
    }
}

fn settings_form(ui: &mut egui::Ui, s: &mut Settings) {
    widgets::section(ui, "Leak protection");
    widgets::square_check(ui, &mut s.strict_mode, "Strict mode: nothing leaves directly unless the rules allow it");
    widgets::hint(
        ui,
        "Connections from unidentified programs wait, flows opened before redirection are reset, internal errors drop packets.",
    );
    widgets::square_check(
        ui,
        &mut s.kill_switch,
        "Kill switch: proxied programs stay offline whenever Proxidize isn't redirecting",
    );
    widgets::hint(
        ui,
        "Covers whole-program Proxy and Block rules. Uses Windows Filtering Platform filters that survive restarts.",
    );

    widgets::section(ui, "Startup");
    widgets::square_check(ui, &mut s.start_enabled, "Start redirecting when Proxidize opens");
    widgets::square_check(ui, &mut s.start_with_windows, "Start with Windows (elevated, no prompt)");
    widgets::square_check(ui, &mut s.start_minimized, "Start in the tray");

    widgets::section(ui, "DNS");
    widgets::form_row(ui, "DNS mode", |ui| {
        egui::ComboBox::from_id_salt("dns")
            .width(260.0)
            .selected_text(if s.dns_mode == DnsMode::FakeIp {
                "Fake IP: names resolved by the proxy"
            } else {
                "Local: your own DNS server"
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut s.dns_mode, DnsMode::FakeIp, "Fake IP: names resolved by the proxy");
                ui.selectable_value(&mut s.dns_mode, DnsMode::Local, "Local: your own DNS server");
            });
    });
    widgets::form_row(ui, "Fake IP range", |ui| widgets::field(ui, &mut s.fake_ip_range, 260.0));
    widgets::form_row(ui, "Fake IP for", |ui| widgets::field(ui, &mut s.fake_ip_domains, 420.0));
    widgets::form_row(ui, "Never fake", |ui| widgets::field(ui, &mut s.fake_ip_exclude_domains, 420.0));
    widgets::form_row(ui, "Upstream DNS", |ui| widgets::field(ui, &mut s.upstream_dns_servers, 260.0));
    widgets::hint(ui, "Upstream DNS empty: the network adapters' servers. Separate entries with ;");

    widgets::section(ui, "Proxy check");
    widgets::form_row(ui, "Every (minutes)", |ui| widgets::number(ui, &mut s.health_check_interval_minutes, 0..=1440));
    widgets::form_row(ui, "Lookup service", |ui| widgets::field(ui, &mut s.health_check_url, 420.0));
    widgets::square_check(ui, &mut s.health_check_direct, "Also look up your own IP (needed to spot leaking proxies)");
    widgets::square_check(ui, &mut s.health_check_block_leaking, "Block proxies whose exit IP is your own until they are fixed");
    widgets::square_check(ui, &mut s.health_check_notify, "Notify when a proxy goes down, comes back or starts leaking");

    widgets::section(ui, "Connections");
    widgets::form_row(ui, "Connect timeout (s)", |ui| widgets::number(ui, &mut s.connect_timeout_seconds, 3..=120));
    widgets::square_check(ui, &mut s.enable_udp, "Redirect UDP (SOCKS5 UDP ASSOCIATE)");
    widgets::form_row(ui, "UDP idle timeout (s)", |ui| widgets::number(ui, &mut s.udp_idle_timeout_seconds, 10..=3600));
    widgets::form_row(ui, "Relay port", |ui| widgets::number(ui, &mut s.relay_port, 1024..=65535));
    widgets::form_row(ui, "Resolver port", |ui| widgets::number(ui, &mut s.resolver_port, 1024..=65535));
    widgets::square_check(ui, &mut s.manage_firewall_rule, "Add a Windows Firewall rule for the relay");

    widgets::section(ui, "Logging");
    widgets::square_check(ui, &mut s.log_direct_connections, "List direct connections under Connections");
    widgets::square_check(ui, &mut s.verbose_logging, "Verbose log (every connection)");
}

pub fn open_folder(path: &std::path::Path) {
    let _ = std::fs::create_dir_all(path);
    #[cfg(windows)]
    let _ = std::process::Command::new("explorer.exe").arg(path).spawn();
    #[cfg(not(windows))]
    let _ = std::process::Command::new("xdg-open").arg(path).spawn();
}

/// Config helpers used by dialogs.
pub fn rules_using(config: &Config, route_id: &str) -> Vec<String> {
    config.rules.iter().filter(|r| r.route_id.as_deref() == Some(route_id)).map(|r| r.name.clone()).collect()
}
