//! Project the operator panel's confirmed facts into its desktop status card.
use serde_json::{json, Value};

struct GatewayCard<'a> {
    gateway: &'a Value,
    tunnel: &'a Value,
    native: bool,
    attached: bool,
    live: bool,
    native_stopped: bool,
    connected: bool,
    can_start: bool,
    can_stop: bool,
    can_restart: bool,
    phase: Option<&'a str>,
    reason: &'a str,
}

impl<'a> GatewayCard<'a> {
    fn from_panel(panel: &'a Value) -> Self {
        let gateway = &panel["gateway"];
        let native = gateway["native"] == true;
        let attached = native || gateway["external"] == true;
        let live = gateway["live"] == true;
        let owned = gateway["ownedRunning"] == true;
        let controls = &gateway["controls"];
        let (can_start, can_stop, can_restart, reason) = if controls.is_object() {
            (controls["canStart"] == true, controls["canStop"] == true, controls["canRestart"] == true,
             controls["reason"].as_str().unwrap_or(""))
        } else if attached {
            (false, false, false, "The external owner controls this service.")
        } else {
            (!live, owned, live, "")
        };
        Self {
            gateway, tunnel: &panel["tunnel"], native, attached, live,
            native_stopped: native && gateway["stopped"] == true && !live && !owned,
            connected: panel["liveProfile"]["connected"] == true,
            can_start, can_stop, can_restart, phase: controls["phase"].as_str().filter(|p| !p.is_empty()), reason,
        }
    }

    fn detail(&self, phase: Option<&str>, read_error: bool) -> String {
        if !self.attached { return String::new(); }
        let mut parts = Vec::new();
        if let Some(phase) = phase {
            parts.push(format!("Bridge is {phase}…"));
        } else if self.native_stopped && !read_error {
            parts.push("Start it to connect your AI.".into());
        } else if read_error || !self.connected {
            parts.push("The configured Bridge session is unavailable.".into());
        } else if !self.native {
            parts.push("Run by an independent Bridge.".into());
        }
        if self.native && self.tunnel["configured"] == true {
            parts.push(match self.tunnel["error"].as_str().filter(|e| !e.is_empty()) {
                Some(error) => format!("Web tunnel unavailable: {error}"),
                None if self.tunnel["childRunning"] == true => "Web tunnel running (remote access not verified).".into(),
                None => "Web tunnel stopped. Web chats cannot connect.".into(),
            });
        }
        if !self.reason.is_empty() { parts.push(self.reason.into()); }
        if self.can_restart && self.live {
            parts.push("Restart resets access to the startup profile.".into());
        } else if self.can_start {
            parts.push("Bridge starts with its startup profile.".into());
        }
        parts.join(" ")
    }

    fn view(&self, pending: Option<&str>, read_error: bool) -> Value {
        let phase = pending.or(self.phase);
        let unavailable = read_error || (self.attached && !self.native_stopped && !self.connected);
        let live = self.live && !unavailable;
        let (title, tone, power_label) = match phase {
            Some("starting") => ("Starting…", "busy", "Starting Bridge…"),
            Some("stopping") => ("Stopping…", "busy", "Stopping Bridge…"),
            Some("restarting") => ("Restarting…", "busy", "Restarting Bridge…"),
            Some(_) => ("Busy…", "busy", "Bridge is busy…"),
            None => {
                let (title, tone) = if live { ("Running", "on") } else if unavailable {
                    ("Unavailable", "error")
                } else { ("Stopped", "off") };
                (title, tone, if self.live { "Restart Bridge" } else { "Start Bridge" })
            }
        };
        let ready = phase.is_none() && !read_error;
        let tooltip = self.gateway["port"].as_u64().filter(|_| live).map(|port| format!("Local port {port}"));
        json!({
            "title": title, "tone": tone, "tooltip": tooltip.unwrap_or_default(),
            "detail": self.detail(phase, read_error), "showNotice": self.attached,
            "showActions": !self.attached || self.can_start || self.can_stop || self.can_restart || phase.is_some(),
            "showStop": self.can_stop || matches!(phase, Some("stopping" | "restarting")),
            "canPower": ready && if self.live { self.can_restart } else { self.can_start },
            "canStop": ready && self.can_stop, "powerLabel": power_label,
            "powerSecondary": self.live || phase.is_some(),
            "quitLabel": if self.native { "Quit and stop Bridge" } else { "Quit" },
        })
    }
}

pub(super) fn with_status_card(mut panel: Value) -> Value {
    let card = GatewayCard::from_panel(&panel);
    panel["statusCard"] = json!({
        "current": card.view(None, false), "readError": card.view(None, true),
        "pending": {
            "starting": card.view(Some("starting"), false),
            "stopping": card.view(Some("stopping"), false),
            "restarting": card.view(Some("restarting"), false),
        },
    });
    panel
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attached_state_preserves_authority_across_phases_and_failed_reads() {
        let mut panel = json!({
            "gateway": {"native": true, "live": true, "ownedRunning": true, "port": 17770,
                "controls": {"canStart": false, "canRestart": true, "canStop": true}},
            "liveProfile": {"connected": true},
            "tunnel": {"configured": true, "childRunning": true},
        });
        let model = with_status_card(panel.clone());
        let current = &model["statusCard"]["current"];
        assert_eq!(current["title"], "Running");
        assert_eq!(current["tooltip"], "Local port 17770");
        assert_eq!(current["canPower"], true);
        assert_eq!(current["canStop"], true);
        assert!(current["detail"].as_str().unwrap().contains("remote access not verified"));
        let failure = &model["statusCard"]["readError"];
        assert_eq!(failure["tone"], "error");
        assert_eq!(failure["tooltip"], "");
        assert_eq!(failure["canStop"], false);
        for (phase, label, power) in [("starting", "Starting…", "Starting Bridge…"),
            ("stopping", "Stopping…", "Stopping Bridge…"), ("restarting", "Restarting…", "Restarting Bridge…")] {
            panel["gateway"]["controls"]["phase"] = json!(phase);
            let confirmed = with_status_card(panel.clone());
            let card = &confirmed["statusCard"]["current"];
            assert_eq!(card, &model["statusCard"]["pending"][phase]);
            assert_eq!((&card["title"], &card["powerLabel"]), (&json!(label), &json!(power)));
            assert_eq!(card["tone"], "busy");
            assert_eq!(card["canPower"], false);
            assert_eq!(card["canStop"], false);
        }
        panel["gateway"]["controls"]["phase"] = Value::Null;
        panel["tunnel"]["error"] = json!("unreachable");
        assert!(with_status_card(panel)["statusCard"]["current"]["detail"].as_str().unwrap()
            .contains("Web tunnel unavailable: unreachable"));
    }

    #[test]
    fn stopped_unavailable_external_and_standalone_have_distinct_controls() {
        let standalone = with_status_card(json!({"gateway": {"live": true, "ownedRunning": false}}));
        let card = &standalone["statusCard"]["current"];
        assert_eq!(card["showNotice"], false);
        assert_eq!(card["canPower"], true);
        assert_eq!(card["canStop"], false);
        assert_eq!(card["quitLabel"], "Quit");

        let mut panel = json!({"gateway": {"native": true, "live": false, "stopped": true,
            "controls": {"canStart": true, "canStop": false}}, "liveProfile": {"connected": false}});
        let stopped = with_status_card(panel.clone());
        let card = &stopped["statusCard"]["current"];
        assert_eq!(card["title"], "Stopped");
        assert_eq!(card["tone"], "off");
        assert_eq!(card["canPower"], true);
        assert!(card["detail"].as_str().unwrap().contains("Start it to connect your AI."));
        panel["gateway"]["stopped"] = json!(false);
        panel["gateway"]["controls"] = json!({"canStop": true, "reason": "Cleanup still pending."});
        let failed = with_status_card(panel);
        let card = &failed["statusCard"]["current"];
        assert_eq!(card["title"], "Unavailable");
        assert_eq!(card["canPower"], false);
        assert_eq!(card["canStop"], true);
        assert!(card["detail"].as_str().unwrap().contains("Cleanup still pending."));
        let external = with_status_card(json!({"gateway": {"external": true}, "liveProfile": {"connected": false}}));
        assert_eq!(external["statusCard"]["current"]["showActions"], false);
        assert_eq!(external["statusCard"]["current"]["tone"], "error");
    }
}
