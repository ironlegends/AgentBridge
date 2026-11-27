//! Per-boot observations of admitted MCP clients. No request payload is retained.

use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

const MAX_SESSIONS: usize = 64;
const MAX_LINKS: usize = 16;
const MAX_CALLS: usize = 10;
const MAX_SEEN_CONTEXTS: usize = 4096;
const LIVE_WINDOW: Duration = Duration::from_secs(120);
// Leave space below the desktop operator HTTP client's 2 MiB response limit.
const MAX_SNAPSHOT_BYTES: usize = 1_900_000;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Client {
    OAuth { provider: &'static str, client_hash: String },
    Local(&'static str),
}

impl Client {
    fn display(&self) -> (&'static str, &'static str, &str) {
        match self {
            Self::OAuth { provider, client_hash } => (provider, "http", &client_hash[..8]),
            Self::Local(transport) => ("local", transport, "local"),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct ToolCall {
    tool_name: String,
    outcome: &'static str,
    time: String,
}

#[derive(Debug)]
struct Session {
    id: String,
    first_seen: String,
    last_seen: String,
    last_activity: Instant,
    request_count: u64,
    in_flight: usize,
    tool_calls: VecDeque<ToolCall>,
    links: Links,
}

impl Session {
    fn new(activity: Instant, wall_time: String) -> Self {
        Self {
            id: agent_bridge_missions::operator::random_token_hex(16),
            first_seen: wall_time.clone(),
            last_seen: wall_time,
            last_activity: activity,
            request_count: 0,
            in_flight: 0,
            tool_calls: VecDeque::new(),
            links: Links::default(),
        }
    }

    fn live(&self, now: Instant) -> bool {
        self.in_flight > 0 || now.saturating_duration_since(self.last_activity) <= LIVE_WINDOW
    }
}

#[derive(Debug, Default)]
struct Links {
    contexts: VecDeque<String>,
    commands: VecDeque<Arc<CommandRecord>>,
}

fn remember<T>(list: &mut VecDeque<T>, value: T, same: impl Fn(&T, &T) -> bool) {
    list.retain(|previous| !same(previous, &value));
    if list.len() == MAX_LINKS {
        list.pop_front();
    }
    list.push_back(value);
}

thread_local! {
    // The gateway dispatch and its tool handlers execute synchronously on one
    // worker. Keep nested scopes and unwind from a failed dispatch safely.
    static REQUEST_LINKS: RefCell<Option<Links>> = const { RefCell::new(None) };
}

pub(crate) fn link_context(id: &str) {
    if id.len() > 64 {
        return;
    }
    REQUEST_LINKS.with_borrow_mut(|current| {
        if let Some(links) = current {
            remember(&mut links.contexts, id.to_owned(), PartialEq::eq);
        }
    });
}

pub(crate) fn link_command(command: Option<&Arc<CommandRecord>>) {
    let Some(command) = command else { return; };
    REQUEST_LINKS.with_borrow_mut(|current| {
        if let Some(links) = current {
            remember(&mut links.commands, Arc::clone(command), same_command);
        }
    });
}

fn same_command(left: &Arc<CommandRecord>, right: &Arc<CommandRecord>) -> bool {
    left.display_id == right.display_id
}

fn collect_links(dispatch: impl FnOnce() -> Option<String>) -> (Option<String>, Links) {
    struct Restore(Option<Links>);
    impl Drop for Restore {
        fn drop(&mut self) {
            REQUEST_LINKS.replace(self.0.take());
        }
    }
    let _restore = Restore(REQUEST_LINKS.replace(Some(Links::default())));
    let response = dispatch();
    (response, REQUEST_LINKS.take().unwrap_or_default())
}

#[derive(Debug)]
struct Registry {
    sessions: HashMap<Client, Session>,
    pending: HashMap<Client, usize>,
    // Exclude even contexts whose session or link was evicted this boot.
    // On overflow, omit earlier contexts rather than mislabel them.
    seen_contexts: Option<BTreeSet<String>>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            sessions: HashMap::new(),
            pending: HashMap::new(),
            seen_contexts: Some(BTreeSet::new()),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ClientSessions {
    registry: Mutex<Registry>,
}

struct Request<'a> {
    owner: &'a ClientSessions,
    client: Client,
    started: Instant,
    wall_time: String,
    registered: bool,
}

impl ClientSessions {
    fn lock(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.registry.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn begin(&self, client: Client, started: Instant) -> Request<'_> {
        let wall_time = timestamp(SystemTime::now());
        let mut registry = self.lock();
        // A first request stays pending until the router accepts it. A
        // refusal cannot show a new client or displace an existing one.
        let pending_has_room = registry.pending.len() < MAX_SESSIONS
            || registry.pending.contains_key(&client);
        let registered = if let Some(session) = registry.sessions.get_mut(&client) {
            session.in_flight += 1;
            true
        } else if pending_has_room {
            *registry.pending.entry(client.clone()).or_default() += 1;
            true
        } else {
            false
        };
        Request { owner: self, client, started, wall_time, registered }
    }

    pub(crate) fn dispatch(
        &self,
        client: Client,
        router: &crate::runtime::Router,
        frame: &str,
        response_limit: usize,
        dispatch: impl FnOnce() -> Option<String>,
    ) -> Option<String> {
        #[derive(Deserialize)]
        struct Frame<'a> {
            #[serde(borrow)]
            method: Option<Cow<'a, str>>,
        }
        #[derive(Deserialize)]
        struct Reply<'a> {
            jsonrpc: &'a str,
            result: ToolOutcome,
            error: Option<IgnoredAny>,
        }
        #[derive(Deserialize)]
        struct ToolOutcome {
            #[serde(default, rename = "isError")]
            is_error: bool,
        }

        let request = self.begin(client, Instant::now());
        let (response, links) = collect_links(dispatch);
        // Only a successful router reply within the transport limit admits
        // activity. A silent notification supplies no admission outcome.
        let admitted = response.as_deref().filter(|body| body.len() <= response_limit)
            .and_then(|body| serde_json::from_str::<Reply<'_>>(body).ok())
            .is_some_and(|reply| reply.jsonrpc == "2.0" && reply.error.is_none() && !reply.result.is_error);
        if !admitted {
            return response;
        }
        let tool = serde_json::from_str::<Frame<'_>>(frame).ok()
            .filter(|frame| frame.method.as_deref() == Some("tools/call"))
            .and_then(|_| crate::request_audit::requested_tool(frame))
            .and_then(|name| {
                router.published_tools().into_iter()
                    .find(|tool| tool.name == name)
                    .map(|tool| tool.name.chars().take(128).collect())
            });
        request.finish(links, tool, Instant::now());
        response
    }

    fn views(&self, now: Instant) -> (Vec<SessionView>, Option<BTreeSet<String>>) {
        let registry = self.lock();
        let mut views: Vec<_> = registry.sessions.iter().map(|(client, session)| {
            let (provider, transport, label) = client.display();
            (session.last_activity, SessionView {
                session_id: session.id.clone(),
                provider, transport, client_label: label.to_owned(),
                first_seen: session.first_seen.clone(), last_seen: session.last_seen.clone(),
                live: session.live(now), request_count: session.request_count,
                in_flight: session.in_flight,
                tool_calls: session.tool_calls.iter().rev().cloned().collect(),
                context_ids: session.links.contexts.iter().rev().cloned().collect(),
                terminal_session_ids: session.links.commands.iter().rev().map(|command| command.display_id.clone()).collect(),
                contexts: Vec::new(),
                commands: session.links.commands.iter().rev().map(|command| command.view()).collect(),
            })
        }).collect();
        views.sort_unstable_by(|(a_time, a), (b_time, b)| {
            b.live.cmp(&a.live).then_with(|| b_time.cmp(a_time))
                .then_with(|| a.session_id.cmp(&b.session_id))
        });
        (views.into_iter().map(|(_, view)| view).collect(), registry.seen_contexts.clone())
    }

    pub(crate) fn snapshot(
        &self, boot_id: &str, database: Option<&crate::runtime::SharedCoreDatabase>,
        database_path: Option<&std::path::Path>,
    ) -> Result<Value, crate::runtime::RuntimeError> {
        let (mut sessions, seen) = self.views(Instant::now());
        let linked: Vec<_> = sessions.iter().flat_map(|session| &session.context_ids).cloned().collect();
        let budget = MAX_SNAPSHOT_BYTES.saturating_sub(serde_json::to_vec(&sessions)?.len());
        let joined = if let Some(database) = database {
            database.lock().ok().and_then(|db| {
                agent_bridge_missions::operator::inspect_session_contexts(
                    db.connection(), &linked, seen.as_ref(), budget,
                ).ok()
            })
        } else if let (Some(path), Some(seen)) = (database_path.filter(|path| path.is_file()), seen.as_ref()) {
            earlier_from_database(path, seen, budget).ok().map(|earlier| (Vec::new(), earlier))
        } else {
            None
        };
        let mission_data_available = joined.is_some();
        let earlier = if let Some((contexts, earlier)) = joined {
            let mut contexts = contexts.into_iter();
            for session in &mut sessions {
                session.contexts = contexts.by_ref().take(session.context_ids.len()).flatten().collect();
            }
            earlier
        } else {
            Vec::new()
        };
        Ok(json!({
            "boot_id": boot_id,
            "generated_at": timestamp(SystemTime::now()),
            "live_window_seconds": LIVE_WINDOW.as_secs(),
            "mission_data_available": mission_data_available,
            "totals": {
                "live": sessions.iter().filter(|session| session.live).count(),
                "connected": sessions.len(),
            },
            "sessions": sessions,
            "earlier": earlier,
        }))
    }
}

pub(crate) fn earlier_from_database(
    path: &std::path::Path, seen: &BTreeSet<String>, budget: usize,
) -> Result<Vec<Value>, crate::runtime::RuntimeError> {
    let db = agent_bridge_core::CoreDatabase::open_existing_read_only(path)?;
    let (_, earlier) = agent_bridge_missions::operator::inspect_session_contexts(
        db.connection(), &[], Some(seen), budget,
    ).map_err(|error| error.message)?;
    Ok(earlier)
}

impl Request<'_> {
    fn finish(mut self, links: Links, tool: Option<String>, now: Instant) {
        let mut registry = self.owner.lock();
        if let Some(seen) = &mut registry.seen_contexts {
            seen.extend(links.contexts.iter().cloned());
            if seen.len() > MAX_SEEN_CONTEXTS {
                registry.seen_contexts = None;
            }
        }
        if !registry.sessions.contains_key(&self.client) && registry.sessions.len() == MAX_SESSIONS {
            let Some(evict) = registry.sessions.iter()
                .filter(|(_, session)| session.in_flight == 0)
                .min_by_key(|(_, session)| (session.last_activity, &session.id))
                .map(|(client, _)| client.clone())
            else {
                return;
            };
            registry.sessions.remove(&evict);
        }
        if !registry.sessions.contains_key(&self.client) {
            let mut session = Session::new(self.started, self.wall_time.clone());
            session.in_flight = registry.pending.remove(&self.client).unwrap_or(0);
            registry.sessions.insert(self.client.clone(), session);
        }
        let session = registry.sessions.get_mut(&self.client).expect("admitted session");
        let completed = timestamp(SystemTime::now());
        if now >= session.last_activity {
            session.last_seen.clone_from(&completed);
            session.last_activity = now;
        }
        session.request_count = session.request_count.saturating_add(1);
        if self.registered {
            session.in_flight -= 1;
            self.registered = false;
        }
        if let Some(tool_name) = tool {
            if session.tool_calls.len() == MAX_CALLS {
                session.tool_calls.pop_front();
            }
            session.tool_calls.push_back(ToolCall { tool_name, outcome: "success", time: completed });
        }
        for id in links.contexts {
            remember(&mut session.links.contexts, id, PartialEq::eq);
        }
        for command in links.commands {
            remember(&mut session.links.commands, command, same_command);
        }
    }
}

impl Drop for Request<'_> {
    fn drop(&mut self) {
        if self.registered {
            let mut registry = self.owner.lock();
            if let Some(session) = registry.sessions.get_mut(&self.client) {
                session.in_flight -= 1;
            } else if let Some(pending) = registry.pending.get_mut(&self.client) {
                *pending -= 1;
                if *pending == 0 {
                    registry.pending.remove(&self.client);
                }
            }
        }
    }
}

#[derive(Serialize)]
struct SessionView {
    session_id: String,
    provider: &'static str,
    transport: &'static str,
    client_label: String,
    first_seen: String,
    last_seen: String,
    request_count: u64,
    in_flight: usize,
    live: bool,
    tool_calls: Vec<ToolCall>,
    context_ids: Vec<String>,
    terminal_session_ids: Vec<String>,
    contexts: Vec<Value>,
    commands: Vec<CommandView>,
}

#[derive(Serialize)]
struct CommandView {
    id: String,
    program: &'static str,
    started_at: String,
    ended_at: Option<String>,
    exit_code: Option<i32>,
    state: &'static str,
}

/// A projection shared with the terminal registry. A retained receipt owns
/// no process, registry, OS handle or output buffer.
#[derive(Debug)]
pub(crate) struct CommandRecord {
    display_id: String,
    label: &'static str,
    started_at: String,
    end: Mutex<Option<(String, Option<i32>)>>,
}

impl CommandRecord {
    pub(crate) fn for_request(label: &'static str) -> Option<Arc<Self>> {
        REQUEST_LINKS.with_borrow(|links| links.is_some()).then(|| Arc::new(Self {
            // This identifier is independent of the UUID used by process tools.
            display_id: format!("display-{}", agent_bridge_missions::operator::random_token_hex(16)),
            label,
            started_at: timestamp(SystemTime::now()),
            end: Mutex::new(None),
        }))
    }

    pub(crate) fn finish(&self, exit_code: Option<i32>) {
        let mut end = self.end.lock().unwrap_or_else(|error| error.into_inner());
        end.get_or_insert_with(|| (timestamp(SystemTime::now()), exit_code));
    }

    fn view(&self) -> CommandView {
        let end = self.end.lock().unwrap_or_else(|error| error.into_inner());
        CommandView {
            id: self.display_id.clone(),
            program: self.label,
            started_at: self.started_at.clone(),
            ended_at: end.as_ref().map(|(time, _)| time.clone()),
            exit_code: end.as_ref().and_then(|(_, code)| *code),
            state: if end.is_some() { "ended" } else { "running" },
        }
    }
}

fn timestamp(time: SystemTime) -> String {
    agent_bridge_missions::operator::utc_timestamp(time)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(index: usize) -> Client {
        Client::OAuth { provider: "chatgpt", client_hash: format!("{index:064x}") }
    }

    fn accept(registry: &ClientSessions, client: Client, time: Instant) {
        registry.begin(client, time).finish(Links::default(), None, time);
    }

    #[test]
    fn connected_sessions_evicts_the_oldest_idle_session_only() {
        let registry = ClientSessions::default();
        let start = Instant::now();
        for index in 0..MAX_SESSIONS {
            accept(&registry, client(index), start + Duration::from_secs(index as u64));
        }
        let held = registry.begin(client(0), start);
        let refused = registry.begin(client(MAX_SESSIONS), start);
        assert_eq!(registry.views(start).0.len(), 64);
        drop(refused);
        assert!(registry.lock().sessions.contains_key(&client(1)));
        accept(&registry, client(MAX_SESSIONS), start + Duration::from_secs(64));
        let entries = registry.lock();
        assert_eq!(entries.sessions.len(), 64);
        assert_eq!(entries.sessions[&client(0)].in_flight, 1);
        assert!(!entries.sessions.contains_key(&client(1)));
        assert!(entries.sessions.contains_key(&client(MAX_SESSIONS)));
        drop(entries);
        drop(held);
    }

    #[test]
    fn connected_sessions_drops_overflow_when_all_slots_have_in_flight_requests() {
        let registry = ClientSessions::default();
        let start = Instant::now();
        for index in 0..64 {
            accept(&registry, client(index), start);
        }
        let _held: Vec<_> = (0..64).map(|index| registry.begin(client(index), start)).collect();
        accept(&registry, client(64), start);
        let entries = registry.lock();
        assert_eq!(entries.sessions.len(), 64);
        assert!(entries.sessions.values().all(|session| session.in_flight == 1));
        assert!(!entries.sessions.contains_key(&client(64)));
    }

    #[test]
    fn connected_sessions_live_window_counts_running_requests_after_expiry() {
        let registry = ClientSessions::default();
        let start = Instant::now();
        accept(&registry, Client::Local("http"), start);
        accept(&registry, Client::Local("stdio"), start + Duration::from_secs(1));
        assert!(registry.views(start + Duration::from_secs(120)).0.iter().all(|s| s.live));
        let after = start + Duration::from_secs(122);
        assert!(registry.views(after).0.iter().all(|s| !s.live));
        let held = registry.begin(Client::Local("http"), after);
        let views = registry.views(after).0;
        assert_eq!(views[0].transport, "http");
        assert!(views[0].live);
        assert!(!views[1].live);
        drop(held);
        assert!(registry.views(after).0.iter().all(|s| !s.live));
    }

    #[test]
    fn connected_sessions_ignores_handler_refusals_and_silent_notifications() {
        use agent_bridge_gateway::{GatewayConfig, McpGateway, ToolCallResult, ToolDefinition, ToolMapHandler};

        let name = "example_refusal";
        let mut handlers = ToolMapHandler::new();
        handlers.register(name, |_| {
            link_context("example-discarded-context");
            let command = CommandRecord::for_request("git-version");
            link_command(command.as_ref());
            Ok(ToolCallResult::tool_error("WRITE_ACCESS_REQUIRED"))
        });
        let router = McpGateway::new(
            GatewayConfig::new("fixture", "1"),
            vec![ToolDefinition::new(name, None, json!({"type":"object"}))],
            handlers,
        );
        let registry = ClientSessions::default();
        let existing = Client::Local("stdio");
        let start = Instant::now() - LIVE_WINDOW - Duration::from_secs(1);
        accept(&registry, existing.clone(), start);
        let before = registry.lock().sessions[&existing].last_seen.clone();
        let call = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call",
            "params":{"name":name,"arguments":{}}}).to_string();
        for caller in [existing.clone(), Client::Local("http")] {
            let response = registry.dispatch(caller, &router, &call, 1024, || router.handle_str(&call)).unwrap();
            assert_eq!(serde_json::from_str::<Value>(&response).unwrap()["result"]["isError"], true);
        }
        let mut era = agent_bridge_gateway::modern::StdioEra::default();
        let initialized = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert!(registry.dispatch(client(1), &router, initialized, 1024,
            || era.dispatch(&router, initialized)).is_none());
        assert!(registry.dispatch(existing, &router, initialized, 1024,
            || router.handle_str(initialized)).is_none());

        let (sessions, seen) = registry.views(Instant::now());
        assert_eq!(sessions.len(), 1);
        let session = &sessions[0];
        assert_eq!(session.last_seen, before);
        assert_eq!(session.request_count, 1);
        assert_eq!(session.in_flight, 0);
        assert!(!session.live);
        assert!(session.tool_calls.is_empty());
        assert!(session.context_ids.is_empty());
        assert!(session.commands.is_empty());
        assert!(session.terminal_session_ids.is_empty());
        assert!(seen.unwrap().is_empty());
    }

    #[test]
    fn connected_sessions_exports_only_stable_display_command_ids() {
        let registry = ClientSessions::default();
        let now = Instant::now();
        let (_, links) = collect_links(|| {
            for _ in 0..2 {
                let record = CommandRecord::for_request("git-version");
                link_command(record.as_ref());
                link_command(record.as_ref());
            }
            None
        });
        registry.begin(Client::Local("stdio"), now).finish(links, None, now);
        let snapshot = registry.snapshot("example-boot", None, None).unwrap();
        let session = &snapshot["sessions"][0];
        let commands = session["commands"].as_array().unwrap();
        assert_eq!(commands.len(), 2);
        let ids: Vec<_> = commands.iter().map(|command| command["id"].as_str().unwrap()).collect();
        assert_ne!(ids[0], ids[1]);
        assert_eq!(session["terminal_session_ids"], json!(ids));
        assert!(ids.iter().all(|id| id.starts_with("display-")));
        let refreshed = registry.snapshot("example-boot", None, None).unwrap();
        assert_eq!(refreshed["sessions"][0]["terminal_session_ids"], session["terminal_session_ids"]);
    }

    #[test]
    fn connected_sessions_caps_recent_links_and_tool_calls() {
        let registry = ClientSessions::default();
        let now = Instant::now();
        let client = Client::Local("stdio");
        let mut expected_oldest_command = None;
        for index in 0..18 {
            let (_, links) = collect_links(|| {
                link_context(&format!("example-context-{index}"));
                let command = CommandRecord::for_request("git-version").unwrap();
                if index == 2 {
                    expected_oldest_command = Some(command.display_id.clone());
                }
                link_command(Some(&command));
                None
            });
            registry.begin(client.clone(), now).finish(links, Some(format!("example-tool-{index}")), now);
        }
        let (views, seen) = registry.views(now);
        let session = &views[0];
        assert_eq!(session.context_ids.len(), 16);
        assert_eq!(session.terminal_session_ids.len(), 16);
        assert_eq!(session.tool_calls.len(), 10);
        assert_eq!(session.context_ids[15], "example-context-2");
        assert_eq!(session.terminal_session_ids[15], expected_oldest_command.unwrap());
        assert_eq!(session.tool_calls[9].tool_name, "example-tool-8");
        assert!(seen.unwrap().contains("example-context-0"));
    }
}
