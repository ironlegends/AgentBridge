//! Outbound stdio extensions over an in-memory fake child: no process is
//! started, no network is used and no real secret is read.

use agent_bridge_extensions::stdio::{
    observe_executable, valid_child_env_name, verify_executable, StdioChild, StdioLaunch, StdioLauncher, StdioSpec,
};
use agent_bridge_extensions::{Registry, ServerControl, SessionPool, ToolScope};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// The live-session limit is process-wide; session tests run one at a time.
static SESSIONS: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> { SESSIONS.lock().unwrap_or_else(|p| p.into_inner()) }

fn hash(value: &Value) -> String {
    let mut canonical = value.clone();
    canonical.sort_all_objects();
    hex::encode(Sha256::digest(canonical.to_string().as_bytes()))
}

fn descriptor() -> Value {
    json!({"name": "search_items", "description": "Search example items",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}})
}

#[cfg(windows)]
const EXE: &str = "C:\\Tools\\example\\example-mcp.exe";
#[cfg(not(windows))]
const EXE: &str = "/opt/example/example-mcp";

fn scratch(tag: &str) -> PathBuf {
    let base = std::env::temp_dir();
    let base = if cfg!(unix) { std::fs::canonicalize(&base).unwrap_or(base) } else { base };
    let dir = base.join(format!("ab-stdio-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A minimal native image header: a console (or GUI) PE on Windows, ELF
/// elsewhere. It is only hashed and inspected, never executed.
fn native_file(dir: &Path, name: &str, console: bool) -> PathBuf {
    let mut bytes = vec![0u8; 512];
    if cfg!(windows) {
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x80 + 22..0x80 + 24].copy_from_slice(&0x0022u16.to_le_bytes());
        bytes[0x80 + 24..0x80 + 26].copy_from_slice(&0x020bu16.to_le_bytes());
        let subsystem: u16 = if console { 3 } else { 2 };
        bytes[0x80 + 92..0x80 + 94].copy_from_slice(&subsystem.to_le_bytes());
    } else {
        bytes[..4].copy_from_slice(b"\x7fELF");
    }
    write_executable(dir, name, &bytes)
}

fn write_executable(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(if cfg!(windows) { format!("{name}.exe") } else { name.to_owned() });
    std::fs::write(&path, bytes).unwrap();
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    path
}

fn file_sha256(path: &Path) -> String { hex::encode(Sha256::digest(std::fs::read(path).unwrap())) }

fn server(executable: &Path, sha: &str) -> Value {
    json!({"stdio": {"executable": executable.to_str().unwrap(), "executable_sha256": sha, "args": ["stdio"]},
        "tools": {"search_items": {"descriptor_sha256": hash(&descriptor()), "descriptor": descriptor(),
            "parameters": {"query": {"type": "search_terms"}}}}})
}

fn bytes_of(servers: Value) -> Vec<u8> { serde_json::to_vec(&json!({"version": 1, "servers": servers})).unwrap() }

/// The registry as the CLI sees it after an exact enabled local decision.
fn enabled(raw: &[u8]) -> Registry {
    let parsed = Registry::parse(raw).unwrap();
    let controls: BTreeMap<_, _> = ["example", "other"].iter().filter_map(|name| {
        let sha = parsed.server_sha256(name).unwrap()?;
        Some((name.to_string(), ServerControl { enabled: true, config_sha256: sha }))
    }).collect();
    Registry::parse(raw).unwrap().with_controls(&controls).unwrap()
}

fn query(text: &str) -> Map<String, Value> { json!({"query": text}).as_object().unwrap().clone() }

#[derive(Clone, Copy, PartialEq)]
enum Mode { Modern, Legacy, LoseCall, Stall }

#[derive(Default)]
struct Shared {
    result_override: Option<Value>,
    launches: usize,
    methods: Vec<String>,
    events: Vec<&'static str>,
    environments: Vec<BTreeMap<OsString, OsString>>,
    arguments: Vec<Vec<String>>,
    stalled: usize,
    release: bool,
    /// The launch number whose child exits at its next input.
    crash_launch: Option<usize>,
    cache_fixture: bool,
    descriptor_drift: bool,
    tool_error: bool,
    stall_list: bool,
}

struct Fake { mode: Mode, shared: Arc<Mutex<Shared>> }

impl Fake {
    fn new(mode: Mode) -> Arc<Self> { Arc::new(Self { mode, shared: Arc::default() }) }
    fn state(&self) -> MutexGuard<'_, Shared> { self.shared.lock().unwrap_or_else(|p| p.into_inner()) }
}

impl StdioLauncher for Fake {
    fn launch(&self, launch: &StdioLaunch) -> io::Result<Box<dyn StdioChild>> {
        let mut state = self.state();
        state.launches += 1;
        state.environments.push(launch.environment.clone());
        state.arguments.push(launch.arguments.to_vec());
        let launch_number = state.launches;
        Ok(Box::new(Child { mode: self.mode, launch: launch_number, shared: self.shared.clone(), inbox: Vec::new(),
            outbox: VecDeque::new(), stderr: b"fixture diagnostics\n".to_vec().into(),
            stdin_open: true, exited: false, pending: None }))
    }
}

/// Speaks newline-delimited JSON-RPC like an MCP stdio server.
struct Child {
    mode: Mode,
    launch: usize,
    shared: Arc<Mutex<Shared>>,
    inbox: Vec<u8>,
    outbox: VecDeque<u8>,
    stderr: VecDeque<u8>,
    stdin_open: bool,
    exited: bool,
    pending: Option<Value>,
}

impl Child {
    fn state(&self) -> MutexGuard<'_, Shared> { self.shared.lock().unwrap_or_else(|p| p.into_inner()) }

    fn send(&mut self, id: &Value, result: Value) {
        let line = json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string();
        self.outbox.extend(line.bytes().chain([b'\n']));
    }

    fn fail(&mut self, id: &Value) {
        let line = json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "Method not found"}}).to_string();
        self.outbox.extend(line.bytes().chain([b'\n']));
    }

    fn observed_descriptor(&self)->Value{
        let state=self.state();
        let mut tool=descriptor();
        if state.cache_fixture {
            tool["annotations"]=json!({"readOnlyHint":true,"destructiveHint":false});
        }
        if state.descriptor_drift { tool["description"]=json!("Changed live descriptor"); }
        tool
    }

    fn call_result(&self) -> Value {
        if let Some(result) = self.state().result_override.clone() { return result; }
        let state=self.state();
        if state.cache_fixture {
            return json!({"resultType":"complete","isError":state.tool_error,
                "content":[{"type":"text","text":"RAW_FIXTURE_PRIVATE"}],
                "structuredContent":{"visible":"filtered result","private":"RAW_FIXTURE_PRIVATE"}});
        }
        let content = json!([{"type": "text", "text": "fixture"}]);
        if self.mode == Mode::Legacy { json!({"content": content}) }
        else { json!({"resultType": "complete", "content": content}) }
    }

    fn handle(&mut self, message: Value) {
        let Some(method) = message["method"].as_str().map(str::to_owned) else { return };
        self.state().methods.push(method.clone());
        let id = message["id"].clone();
        let legacy = self.mode == Mode::Legacy;
        match method.as_str() {
            "server/discover" if legacy => self.fail(&id),
            "server/discover" => self.send(&id, json!({"resultType": "complete", "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {}}, "ttlMs": 0, "cacheScope": "private",
                "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "fixture", "version": "0"}}})),
            "initialize" => self.send(&id, json!({"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                "serverInfo": {"name": "legacy-fixture", "version": "0"}})),
            "tools/list" if self.state().stall_list => {
                self.pending = Some(id);
                self.state().stalled += 1;
            }
            "tools/list" if legacy => {
                let tool=self.observed_descriptor();
                self.send(&id,json!({"tools":[tool]}));
            },
            "tools/list" => {
                let tool=self.observed_descriptor();
                self.send(&id,json!({"resultType":"complete","ttlMs":0,"cacheScope":"private","tools":[tool]}));
            },
            "tools/call" => match self.mode {
                // The tool may have run, but its reply is lost with the child.
                Mode::LoseCall => { self.exited = true; self.outbox.clear(); }
                Mode::Stall => { self.pending = Some(id); self.state().stalled += 1; }
                _ => { let result = self.call_result(); self.send(&id, result); }
            },
            _ if id.is_null() => {}
            _ => self.fail(&id),
        }
    }
}

impl StdioChild for Child {
    fn read_stdout(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pending.is_some() && self.state().release {
            let id = self.pending.take().unwrap();
            let result = self.call_result();
            self.send(&id, result);
        }
        if self.outbox.is_empty() {
            return if self.exited { Ok(0) } else { Err(io::ErrorKind::WouldBlock.into()) };
        }
        let count = buf.len().min(self.outbox.len());
        for (slot, byte) in buf.iter_mut().zip(self.outbox.drain(..count)) { *slot = byte; }
        Ok(count)
    }

    fn read_stderr(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.stderr.is_empty() { return Err(io::ErrorKind::WouldBlock.into()); }
        let count = buf.len().min(self.stderr.len());
        for (slot, byte) in buf.iter_mut().zip(self.stderr.drain(..count)) { *slot = byte; }
        Ok(count)
    }

    fn write_stdin(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.state().crash_launch == Some(self.launch) { self.exited = true; }
        if !self.stdin_open || self.exited { return Err(io::ErrorKind::BrokenPipe.into()); }
        self.inbox.extend_from_slice(buf);
        while let Some(end) = self.inbox.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.inbox.drain(..=end).collect();
            self.handle(serde_json::from_slice(&line).expect("one JSON-RPC message per line"));
        }
        Ok(buf.len())
    }

    fn close_stdin(&mut self) {
        if self.stdin_open {
            self.stdin_open = false;
            // A well-behaved server exits at end of input.
            self.exited = true;
            self.state().events.push("close_stdin");
        }
    }

    fn terminate(&mut self) -> io::Result<()> {
        self.exited = true;
        self.state().events.push("terminate");
        Ok(())
    }

    fn finish(&mut self) -> io::Result<bool> { Ok(self.exited) }
}

fn spec_with(executable: &str, change: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut entry = json!({"stdio": {"executable": executable, "executable_sha256": "a".repeat(64),
        "args": ["stdio", "--read-only"], "env": {"EXAMPLE_TOKEN": "AGENT_BRIDGE_EXTENSION_EXAMPLE_TOKEN"}},
        "tools": {}});
    change(&mut entry);
    bytes_of(json!({"example": entry}))
}

#[test]
fn stdio_spec_parse_accepts_exact_pin_and_refuses_shapes() {
    let accepted = Registry::parse(&spec_with(EXE, |_| {})).expect("exact stdio pin");
    let spec = accepted.server_stdio("example").unwrap();
    assert_eq!(spec.executable, EXE);
    assert_eq!(spec.args, ["stdio", "--read-only"]);
    assert_eq!(accepted.server_endpoint("example"), None);
    let cwd = Path::new(EXE).parent().unwrap().to_str().unwrap().to_owned();
    assert!(Registry::parse(&spec_with(EXE, |e| e["stdio"]["cwd"] = json!(cwd))).is_ok());

    let mut bad_paths = vec!["example-mcp", "", "relative/example-mcp"];
    if cfg!(windows) {
        bad_paths.extend(["C:\\Tools\\..\\example-mcp.exe", "C:\\Tools\\.\\example-mcp.exe", "C:/Tools/example-mcp.exe",
            "\\\\server\\share\\example-mcp.exe", "\\\\?\\C:\\Tools\\example-mcp.exe", "C:\\Tools\\example-mcp.cmd",
            "C:\\Tools\\example-mcp.bat", "C:\\Tools\\example-mcp.ps1", "C:\\Tools\\example-mcp.exe:stream",
            "C:\\Tools\\\\example-mcp.exe", "C:\\Tools\\example-mcp.exe\\", "C:\\Tools\\example;mcp.exe",
            "C:\\Tools\\nul\\example-mcp.exe", "C:example-mcp.exe"]);
    } else {
        bad_paths.extend(["/opt/../example-mcp", "/opt/./example-mcp", "//opt/example-mcp", "/opt/example-mcp/",
            "/opt/example:mcp", "/"]);
    }
    let long = Path::new(EXE).parent().unwrap()
        .join(format!("{}{}", "x".repeat(1100), if cfg!(windows) { ".exe" } else { "" }));
    let long = long.to_str().unwrap().to_owned();
    bad_paths.push(&long);
    for path in &bad_paths {
        assert!(Registry::parse(&spec_with(path, |_| {})).is_err(), "accepted executable {path:?}");
    }
    assert!(Registry::parse(&spec_with(EXE, |e| e["stdio"]["cwd"] = json!("relative"))).is_err());

    let refusals: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
        ("uppercase pin", Box::new(|e| e["stdio"]["executable_sha256"] = json!("A".repeat(64)))),
        ("short pin", Box::new(|e| e["stdio"]["executable_sha256"] = json!("a".repeat(63)))),
        ("65 args", Box::new(|e| e["stdio"]["args"] = json!(vec!["x"; 65]))),
        ("NUL arg", Box::new(|e| e["stdio"]["args"] = json!(["a\u{0}b"]))),
        ("long arg", Box::new(|e| e["stdio"]["args"] = json!(["x".repeat(4097)]))),
        ("arg budget", Box::new(|e| e["stdio"]["args"] = json!(vec!["x".repeat(4000); 5]))),
        ("raw source", Box::new(|e| e["stdio"]["env"] = json!({"EXAMPLE_TOKEN": "EXAMPLE_TOKEN"}))),
        ("PATH", Box::new(|e| e["stdio"]["env"] = json!({"Path": "AGENT_BRIDGE_EXTENSION_EXAMPLE_PATH"}))),
        ("loader", Box::new(|e| e["stdio"]["env"] = json!({"LD_PRELOAD": "AGENT_BRIDGE_EXTENSION_EXAMPLE_A"}))),
        ("dyld", Box::new(|e| e["stdio"]["env"] = json!({"dyld_insert_libraries": "AGENT_BRIDGE_EXTENSION_EXAMPLE_A"}))),
        ("node", Box::new(|e| e["stdio"]["env"] = json!({"NODE_OPTIONS": "AGENT_BRIDGE_EXTENSION_EXAMPLE_A"}))),
        ("safe set", Box::new(|e| e["stdio"]["env"] = json!({"SYSTEMROOT": "AGENT_BRIDGE_EXTENSION_EXAMPLE_A"}))),
        ("case duplicate", Box::new(|e| e["stdio"]["env"] = json!({"Token": "AGENT_BRIDGE_EXTENSION_EXAMPLE_A",
            "TOKEN": "AGENT_BRIDGE_EXTENSION_EXAMPLE_B"}))),
        ("bad child name", Box::new(|e| e["stdio"]["env"] = json!({"1TOKEN": "AGENT_BRIDGE_EXTENSION_EXAMPLE_A"}))),
        ("33 refs", Box::new(|e| e["stdio"]["env"] = Value::Object((0..33).map(|i|
            (format!("VAR_{i}"), json!(format!("AGENT_BRIDGE_EXTENSION_EXAMPLE_{i}")))).collect()))),
        ("unknown field", Box::new(|e| e["stdio"]["shell"] = json!(true))),
        ("both transports", Box::new(|e| e["endpoint"] = json!("https://example.com/mcp"))),
        ("neither transport", Box::new(|e| { e.as_object_mut().unwrap().remove("stdio"); })),
        ("bearer", Box::new(|e| e["bearer_env"] = json!("AGENT_BRIDGE_EXTENSION_EXAMPLE_TOKEN"))),
        ("headers", Box::new(|e| e["header_env"] = json!({"X-Api-Key": "AGENT_BRIDGE_EXTENSION_EXAMPLE_KEY"}))),
    ];
    for (case, change) in refusals {
        assert!(Registry::parse(&spec_with(EXE, change)).is_err(), "{case}");
    }
    // A public documentation name keeps its HTTP meaning.
    for reserved in ["mcp_docs", "microsoft_learn"] {
        let raw = bytes_of(json!({reserved: {"stdio": {"executable": EXE, "executable_sha256": "a".repeat(64)}, "tools": {}}}));
        assert!(Registry::parse(&raw).is_err(), "{reserved}");
    }
    assert!(valid_child_env_name("EXAMPLE_TOKEN") && valid_child_env_name("_x1"));
    for name in ["PATH", "pathext", "ComSpec", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "PYTHONPATH", "BASH_ENV",
        "ENV", "ELECTRON_RUN_AS_NODE", "HOME", "TEMP", "A-B", "", &"A".repeat(129), "GLIBC_TUNABLES",
        "DOTNET_STARTUP_HOOKS", "dotnet_root", "COR_PROFILER_PATH", "CORECLR_ENABLE_PROFILING"] {
        assert!(!valid_child_env_name(name), "{name}");
    }
    let mut direct = StdioSpec { executable: EXE.into(), executable_sha256: "b".repeat(64), args: vec![],
        env: BTreeMap::new(), cwd: None, inherit_path: false };
    direct.validate().unwrap();
    direct.cwd = Some("relative".into());
    assert!(direct.validate().is_err());
}

#[test]
fn stdio_server_without_enabled_matching_control_is_disabled() {
    let docs = json!({"name": "search_model_context_protocol",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}});
    let raw = bytes_of(json!({
        "example": server(Path::new(EXE), &"a".repeat(64)),
        "mcp_docs": {"endpoint": "https://modelcontextprotocol.io/mcp", "tools": {"search_model_context_protocol": {
            "descriptor_sha256": hash(&docs), "descriptor": docs, "parameters": {"query": {"type": "search_terms"}}}}}
    }));
    // No local decision: the HTTP server keeps its default, stdio is denied.
    let parsed = Registry::parse(&raw).unwrap();
    assert_eq!(parsed.list(), ["mcp_docs:search_model_context_protocol"]);
    assert_eq!(parsed.servers(Some("example")).unwrap()["server"]["enabled"], false);
    assert!(parsed.inspect_cached("example:search_items").is_err());
    assert_eq!(parsed.search_cached("items", None, 10).unwrap()["count"], 0);
    let fingerprint = parsed.server_sha256("example").unwrap().unwrap();
    assert_eq!(parsed.auth_status("example", None).unwrap().unwrap()["local_control"], "no_local_decision");

    let with = |control: ServerControl| Registry::parse(&raw).unwrap()
        .with_controls(&BTreeMap::from([("example".to_owned(), control)])).unwrap();
    let stale = with(ServerControl { enabled: true, config_sha256: "f".repeat(64) });
    assert!(!stale.list().contains(&"example:search_items".to_owned()));
    let off = with(ServerControl { enabled: false, config_sha256: fingerprint.clone() });
    assert!(!off.list().contains(&"example:search_items".to_owned()));
    let on = with(ServerControl { enabled: true, config_sha256: fingerprint.clone() });
    assert_eq!(on.list(), ["example:search_items", "mcp_docs:search_model_context_protocol"]);
    assert_eq!(on.servers(Some("example")).unwrap()["server"]["enabled"], true);
    assert!(on.inspect_cached("example:search_items").is_ok());
    // Any change to the launch, even one argument, needs a new decision.
    let mut changed = server(Path::new(EXE), &"a".repeat(64));
    changed["stdio"]["args"] = json!(["stdio", "--write"]);
    let changed_raw = bytes_of(json!({"example": changed}));
    let moved = Registry::parse(&changed_raw).unwrap()
        .with_controls(&BTreeMap::from([("example".to_owned(), ServerControl { enabled: true, config_sha256: fingerprint })]))
        .unwrap();
    assert!(moved.list().is_empty());
}

#[test]
fn stdio_tool_grants_keep_data_and_schema_gates() {
    let grant = |name: &str, descriptor: Value, sha: Option<String>, parameters: Value| {
        let sha = sha.unwrap_or_else(|| hash(&descriptor));
        bytes_of(json!({"example": {"stdio": {"executable": EXE, "executable_sha256": "a".repeat(64)},
            "tools": {name: {"descriptor_sha256": sha, "descriptor": descriptor, "parameters": parameters}}}}))
    };
    let query = json!({"query": {"type": "search_terms"}});
    // The executable pin replaces the adapter allowlist, nothing else.
    assert!(Registry::parse(&grant("search_items", descriptor(), None, query.clone())).is_ok());
    let named = |name: &str| json!({"name": name, "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}});
    for name in ["run_command", "execute_shell", "call_tool", "proxy_request", "browser_evaluate"] {
        assert!(Registry::parse(&grant(name, named(name), None, query.clone())).is_err(), "{name}");
    }
    // Tools that are not named data operations can be granted, but only a
    // profile above read-only may call them.
    for name in ["list_files", "browser_search", "firecrawl_scrape"] {
        let registry = Registry::parse(&grant(name, named(name), None, query.clone())).unwrap();
        let args = json!({"query": "alpha"}).as_object().unwrap().clone();
        let refused = registry.call(&format!("example:{name}"), &args, ToolScope::DataOperations).unwrap_err();
        assert!(refused.to_string().contains("only named data operations"), "{name}: {refused}");
        // A higher profile passes the name gate and stops only at the
        // disabled server, before any launch.
        let stopped = registry.call(&format!("example:{name}"), &args, ToolScope::AnyGranted).unwrap_err();
        assert!(stopped.to_string().contains("disabled"), "{name}: {stopped}");
    }
    let opaque = json!({"name": "search_items", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}},
        "oneOf": [{"required": ["query"]}]}});
    assert!(Registry::parse(&grant("search_items", opaque, None, query.clone())).is_err());
    let object_arg = json!({"name": "search_items", "inputSchema": {"type": "object",
        "properties": {"query": {"type": "object"}}}});
    assert!(Registry::parse(&grant("search_items", object_arg, None, query.clone())).is_err());
    assert!(Registry::parse(&grant("search_items", descriptor(), Some("0".repeat(64)), query.clone())).is_err());
    assert!(Registry::parse(&grant("search_items", descriptor(), Some("A".repeat(64)), query)).is_err());
    assert!(Registry::parse(&grant("search_items", descriptor(), None, json!({"code": {"type": "search_terms"}}))).is_err());

    // Optional properties the operator does not grant are never sent, so
    // they may have any shape; every granted one must match its type.
    let scrape = json!({"name": "firecrawl_scrape", "inputSchema": {"type": "object", "required": ["url"], "properties": {
        "url": {"type": "string"}, "formats": {"type": "array"}, "location": {"type": "object"},
        "waitFor": {"type": "number"}}}});
    let url = json!({"type": "public_https_url"});
    let wait = json!({"type": "number", "minimum": 0.0, "maximum": 30000.0});
    assert!(Registry::parse(&grant("firecrawl_scrape", scrape.clone(), None, json!({"url": url, "waitFor": wait}))).is_ok());
    for widened in [json!({"url": url, "formats": {"type": "search_terms"}}), json!({"url": {"type": "search_terms"}}),
        json!({"url": url, "waitFor": {"type": "integer", "minimum": 0, "maximum": 1}}),
        json!({"url": url, "waitFor": {"type": "number", "minimum": 5.0, "maximum": 1.0}}),
        json!({"url": url, "waitFor": {"type": "number", "minimum": 0.0, "maximum": 1e16}}),
        json!({"link": url})] {
        assert!(Registry::parse(&grant("firecrawl_scrape", scrape.clone(), None, widened.clone())).is_err(), "{widened}");
    }
}

#[test]
fn public_https_url_grants_refuse_local_and_ambiguous_targets() {
    let descriptor = json!({"name": "browser_navigate", "inputSchema": {"type": "object",
        "properties": {"url": {"type": "string"}}}});
    let raw = bytes_of(json!({"example": {"stdio": {"executable": EXE, "executable_sha256": "a".repeat(64)},
        "tools": {"browser_navigate": {"descriptor_sha256": hash(&descriptor), "descriptor": descriptor,
            "parameters": {"url": {"type": "public_https_url"}}}}}}));
    let registry = Registry::parse(&raw).unwrap();
    for url in ["http://example.com/", "https://localhost/", "https://127.0.0.1/", "https://[::1]/",
        "https://user:secret@example.com/", "https://example.com:8443/", "https://printer.local/",
        "https://intranet/", "https://exa mple.com/", "https://10.0.0.1/", "https://example.com/\n",
        "https://127.0.0.0x1/", "https://1.0x7f/", "https://example.com./", "https://a%2ecom.org/",
        "https://printer.localdomain/"] {
        let args = json!({"url": url}).as_object().unwrap().clone();
        let refused = registry.call("example:browser_navigate", &args, ToolScope::AnyGranted).unwrap_err();
        assert!(refused.to_string().contains("operator-approved contract"), "{url}: {refused}");
    }
    // An accepted URL passes the argument gate and stops only at the
    // disabled server, before any launch.
    for url in ["https://example.org/docs?q=1#top", "https://docs.example.org:443/a"] {
        let args = json!({"url": url}).as_object().unwrap().clone();
        let stopped = registry.call("example:browser_navigate", &args, ToolScope::AnyGranted).unwrap_err();
        assert!(stopped.to_string().contains("disabled"), "{url}: {stopped}");
    }
}

#[test]
fn executable_pin_mismatch_script_and_reparse_fail_before_launch() {
    let _serial = serial();
    let dir = scratch("pin");
    let native = native_file(&dir, "example-mcp", true);
    let sha = file_sha256(&native);
    assert_eq!(observe_executable(&native).unwrap(), sha);
    verify_executable(&native, &sha).unwrap();
    assert_eq!(verify_executable(&native, &"0".repeat(64)).unwrap_err().kind(), io::ErrorKind::InvalidData);
    let missing = dir.join(if cfg!(windows) { "missing.exe" } else { "missing" });
    assert_ne!(verify_executable(&missing, &sha).unwrap_err().kind(), io::ErrorKind::InvalidData);

    let script = write_executable(&dir, "script-mcp", b"#!/bin/sh\nexec example\n");
    let gui = native_file(&dir, "window-mcp", false);
    let mut refused = vec![(native.clone(), "0".repeat(64)), (script.clone(), file_sha256(&script))];
    if cfg!(windows) { refused.push((gui.clone(), file_sha256(&gui))); }
    for path in [&script, &gui].into_iter().filter(|p| cfg!(windows) || **p != gui) {
        let error = observe_executable(path).unwrap_err();
        assert_ne!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!error.to_string().contains("mcp"), "{error}");
    }

    // A link to the pinned file, or under a linked directory, is refused.
    let linked = dir.join(if cfg!(windows) { "linked-mcp.exe" } else { "linked-mcp" });
    let linked_dir = dir.join("linked-dir");
    let mut links = vec![linked_dir.join(native.file_name().unwrap())];
    #[cfg(unix)] {
        std::os::unix::fs::symlink(&dir, &linked_dir).unwrap();
        std::os::unix::fs::symlink(&native, &linked).unwrap();
        links.push(linked.clone());
    }
    #[cfg(windows)] {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        // A directory junction needs no privilege; a file symbolic link may.
        let junction = Command::new("cmd.exe").args(["/D", "/C", "mklink", "/J"]).arg(&linked_dir).arg(&dir)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .creation_flags(0x0800_0000).status().unwrap();
        assert!(junction.success(), "cannot create the test junction");
        match std::os::windows::fs::symlink_file(&native, &linked) {
            Ok(()) => links.push(linked.clone()),
            Err(error) => eprintln!("file symbolic link case skipped: {error}"),
        }
    }
    for path in links {
        assert!(observe_executable(&path).is_err(), "{}", path.display());
        refused.push((path, sha.clone()));
    }

    for (path, pin) in refused {
        let fake = Fake::new(Mode::Modern);
        let registry = enabled(&bytes_of(json!({"example": server(&path, &pin)}))).with_stdio_launcher(fake.clone());
        assert!(registry.call("example:search_items", &query("alpha"), ToolScope::DataOperations).is_err(), "{}", path.display());
        assert!(registry.refresh_stdio("example").is_err());
        assert_eq!(fake.state().launches, 0, "{}", path.display());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn approved_result_policy_filters_completed_upstream_reply_before_it_leaves_registry() {
    let _serial = serial();
    let dir = scratch("result-filter");
    let image = native_file(&dir, "filter-example", true);
    let mut entry = server(&image, &file_sha256(&image));
    entry["tools"]["search_items"]["result_filter"] = json!({"allow":["/public"],"max_bytes":160});
    let fake = Fake::new(Mode::Modern);
    fake.state().result_override = Some(json!({"resultType":"complete","content":[{"type":"text","text":"unfiltered"}],
        "structuredContent":{"public":{"label":"visible","credential":"unfiltered"},"hidden":"unfiltered"}}));
    let registry = enabled(&bytes_of(json!({"example":entry}))).with_stdio_launcher(fake.clone());
    let result = registry.call("example:search_items", &query("alpha"), ToolScope::DataOperations).unwrap();
    assert_eq!(result["structuredContent"]["public"]["label"], "visible");
    assert_eq!(result["structuredContent"]["public"]["credential"], "[REDACTED]");
    assert!(!result.to_string().contains("unfiltered"));
    assert_eq!(fake.state().methods.iter().filter(|method| *method == "tools/call").count(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stdio_session_modern_and_legacy_fallback_over_fake_child() {
    let _serial = serial();
    let dir = scratch("session");
    let native = native_file(&dir, "example-mcp", true);
    let mut entry = server(&native, &file_sha256(&native));
    entry["stdio"]["env"] = json!({"EXAMPLE_TOKEN": "AGENT_BRIDGE_EXTENSION_STDIO_TEST_TOKEN"});
    std::env::set_var("AGENT_BRIDGE_EXTENSION_STDIO_TEST_TOKEN", "fixture-only-value");
    let raw = bytes_of(json!({"example": entry}));
    for (mode, expected) in [
        (Mode::Modern, &["server/discover", "tools/list", "tools/call"][..]),
        (Mode::Legacy, &["server/discover", "initialize", "notifications/initialized", "tools/list", "tools/call"][..]),
    ] {
        let fake = Fake::new(mode);
        let registry = enabled(&raw).with_stdio_launcher(fake.clone());
        let result = registry.call("example:search_items", &query("alpha"), ToolScope::DataOperations).unwrap();
        assert_eq!(result["content"][0]["text"], "fixture");
        let state = fake.state();
        assert_eq!(state.launches, 1);
        assert_eq!(state.methods, expected);
        assert_eq!(state.arguments[0], ["stdio"]);
        // The environment is exact: the safe set, a fixed PATH and the reference.
        let environment = &state.environments[0];
        let allowed: &[&str] = if cfg!(windows) {
            &["SystemRoot", "SystemDrive", "windir", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
                "ProgramData", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS", "PATH", "EXAMPLE_TOKEN"]
        } else { &["HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "PATH", "EXAMPLE_TOKEN"] };
        assert!(environment.keys().all(|key| allowed.iter().any(|name| key == *name)), "{environment:?}");
        assert_eq!(environment[&OsString::from("EXAMPLE_TOKEN")], "fixture-only-value");
        assert!(!environment.contains_key(&OsString::from("AGENT_BRIDGE_EXTENSION_STDIO_TEST_TOKEN")));
        let path = environment[&OsString::from("PATH")].to_str().unwrap().to_owned();
        assert!(path.starts_with(dir.to_str().unwrap()), "{path}");
    }

    // The local refresh check lists the catalog without a tool call.
    let fake = Fake::new(Mode::Modern);
    let registry = enabled(&raw).with_stdio_launcher(fake.clone());
    let report = registry.refresh_stdio("example").unwrap();
    assert_eq!(report["transport"], "stdio");
    assert_eq!(report["executable_sha256"], file_sha256(&native));
    assert!(report.get("endpoint").is_none());
    assert!(report["stderr_bytes"].as_u64().unwrap() > 0);
    assert_eq!(report["approved_tools"][0]["status"], "unchanged");
    assert_eq!(report["tool_invoked"], false);
    assert!(!report.to_string().contains("fixture diagnostics") && !report.to_string().contains("fixture-only-value"));
    assert_eq!(fake.state().methods, ["server/discover", "tools/list"]);
    let described = registry.describe_for_operator("example", "search_items").unwrap();
    assert_eq!(described["descriptor_sha256"], hash(&descriptor()));
    std::env::remove_var("AGENT_BRIDGE_EXTENSION_STDIO_TEST_TOKEN");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stdio_session_drop_closes_stdin_then_terminates_tree() {
    let _serial = serial();
    let dir = scratch("drop");
    let native = native_file(&dir, "example-mcp", true);
    let fake = Fake::new(Mode::Modern);
    let registry = enabled(&bytes_of(json!({"example": server(&native, &file_sha256(&native))})))
        .with_stdio_launcher(fake.clone());
    registry.call("example:search_items", &query("alpha"), ToolScope::DataOperations).unwrap();
    // The call returns only after the session and its child are shut down.
    assert_eq!(fake.state().events, ["close_stdin", "terminate"]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stdio_ambiguous_call_failure_not_replayed() {
    let _serial = serial();
    let dir = scratch("ambiguous");
    let native = native_file(&dir, "example-mcp", true);
    let fake = Fake::new(Mode::LoseCall);
    let registry = enabled(&bytes_of(json!({"example": server(&native, &file_sha256(&native))})))
        .with_stdio_launcher(fake.clone());
    let error = registry.call("example:search_items", &query("alpha"), ToolScope::DataOperations).unwrap_err();
    assert!(error.to_string().contains("do not replay"), "{error}");
    let state = fake.state();
    assert_eq!(state.launches, 1);
    assert_eq!(state.methods.iter().filter(|m| *m == "tools/call").count(), 1);
    assert_eq!(state.events.last(), Some(&"terminate"));
    drop(state);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stdio_call_without_launcher_or_when_disabled_never_launches() {
    let _serial = serial();
    let dir = scratch("gates");
    let native = native_file(&dir, "example-mcp", true);
    let raw = bytes_of(json!({"example": server(&native, &file_sha256(&native))}));

    let error = enabled(&raw).call("example:search_items", &query("alpha"), ToolScope::DataOperations).unwrap_err();
    assert!(error.to_string().contains("unavailable in this context"), "{error}");
    assert!(enabled(&raw).refresh_stdio("example").is_err());
    assert!(enabled(&raw).describe_for_operator("example", "search_items").is_err());

    let fake = Fake::new(Mode::Modern);
    let undecided = Registry::parse(&raw).unwrap().with_stdio_launcher(fake.clone());
    assert!(undecided.call("example:search_items", &query("alpha"), ToolScope::DataOperations).is_err());
    assert!(undecided.refresh_stdio("example").is_err());
    assert!(undecided.describe_for_operator("example", "search_items").is_err());
    let fingerprint = undecided.server_sha256("example").unwrap().unwrap();
    let off = Registry::parse(&raw).unwrap()
        .with_controls(&BTreeMap::from([("example".to_owned(), ServerControl { enabled: false, config_sha256: fingerprint })]))
        .unwrap().with_stdio_launcher(fake.clone());
    assert!(off.call("example:search_items", &query("alpha"), ToolScope::DataOperations).is_err());
    // Arguments outside the grant are refused before any launch.
    let on = enabled(&raw).with_stdio_launcher(fake.clone());
    assert!(on.call("example:search_items", &query("a;b"), ToolScope::DataOperations).is_err());
    assert!(on.call("example:search_items", &json!({"other": "x"}).as_object().unwrap().clone(), ToolScope::DataOperations).is_err());

    // A missing environment reference fails before launch, without its name.
    let mut entry = server(&native, &file_sha256(&native));
    entry["stdio"]["env"] = json!({"EXAMPLE_TOKEN": "AGENT_BRIDGE_EXTENSION_STDIO_TEST_UNSET"});
    std::env::remove_var("AGENT_BRIDGE_EXTENSION_STDIO_TEST_UNSET");
    let missing = enabled(&bytes_of(json!({"example": entry}))).with_stdio_launcher(fake.clone());
    let error = missing.call("example:search_items", &query("alpha"), ToolScope::DataOperations).unwrap_err();
    assert!(!error.to_string().contains("STDIO_TEST_UNSET") && !error.to_string().contains("EXAMPLE_TOKEN"), "{error}");
    assert_eq!(fake.state().launches, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stdio_concurrency_limit_refuses_fifth_session() {
    let _serial = serial();
    let dir = scratch("limit");
    let native = native_file(&dir, "example-mcp", true);
    let fake = Fake::new(Mode::Stall);
    let registry = enabled(&bytes_of(json!({"example": server(&native, &file_sha256(&native))})))
        .with_stdio_launcher(fake.clone());
    std::thread::scope(|scope| {
        let running: Vec<_> = (0..4).map(|_| scope.spawn(|| registry.call("example:search_items", &query("alpha"), ToolScope::DataOperations)))
            .collect();
        let deadline = Instant::now() + Duration::from_secs(10);
        while fake.state().stalled < 4 {
            assert!(Instant::now() < deadline, "four sessions did not reach their tool call");
            std::thread::sleep(Duration::from_millis(10));
        }
        // The fifth session is refused at once, never queued or launched.
        let started = Instant::now();
        let error = registry.call("example:search_items", &query("alpha"), ToolScope::DataOperations).unwrap_err();
        assert!(error.to_string().contains("Too many"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(fake.state().launches, 4);
        fake.state().release = true;
        for call in running {
            assert_eq!(call.join().unwrap().unwrap()["content"][0]["text"], "fixture");
        }
    });
    // Every slot is released after the sessions end.
    fake.state().release = true;
    registry.call("example:search_items", &query("alpha"), ToolScope::DataOperations).unwrap();
    assert_eq!(fake.state().launches, 5);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The registry with the named servers enabled for their exact fingerprints.
fn enabled_servers(raw: &[u8], names: &[&str]) -> Registry {
    let parsed = Registry::parse(raw).unwrap();
    let controls: BTreeMap<_, _> = names.iter().map(|name| {
        let sha = parsed.server_sha256(name).unwrap().unwrap();
        (name.to_string(), ServerControl { enabled: true, config_sha256: sha })
    }).collect();
    Registry::parse(raw).unwrap().with_controls(&controls).unwrap()
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn pooled_stdio_sessions_are_reused_then_closed_when_idle_changed_or_failed() {
    let _serial = serial();
    let dir = scratch("pool");
    let native = native_file(&dir, "example-mcp", true);
    let raw = bytes_of(json!({"example": server(&native, &file_sha256(&native))}));
    let call = |registry: &Registry| registry.call("example:search_items", &query("alpha"), ToolScope::DataOperations);

    // Two calls share one child and one handshake; the descriptor is still
    // checked before each call. The idle child is closed by the reaper.
    let pool = SessionPool::with_idle(Duration::from_secs(1));
    let fake = Fake::new(Mode::Modern);
    let registry = enabled(&raw).with_stdio_launcher(fake.clone()).with_session_pool(pool.clone());
    for _ in 0..2 { assert_eq!(call(&registry).unwrap()["content"][0]["text"], "fixture"); }
    assert_eq!(fake.state().launches, 1);
    assert_eq!(fake.state().methods, ["server/discover", "tools/list", "tools/call", "tools/list", "tools/call"]);
    assert!(fake.state().events.is_empty());
    assert_eq!(pool.idle_sessions(), 1);
    wait_for("the idle child was not closed", || fake.state().events == ["close_stdin", "terminate"]);
    assert_eq!(pool.idle_sessions(), 0);

    // A changed server entry never reuses the previous child.
    let fake = Fake::new(Mode::Modern);
    let registry = enabled(&raw).with_stdio_launcher(fake.clone()).with_session_pool(pool.clone());
    call(&registry).unwrap();
    let mut entry = server(&native, &file_sha256(&native));
    entry["stdio"]["args"] = json!(["stdio", "--changed"]);
    let changed = enabled(&bytes_of(json!({"example": entry}))).with_stdio_launcher(fake.clone()).with_session_pool(pool.clone());
    call(&changed).unwrap();
    assert_eq!(fake.state().launches, 2);
    assert_eq!(fake.state().events, ["close_stdin", "terminate"]);
    assert_eq!(fake.state().arguments[1], ["stdio", "--changed"]);
    pool.close_all();

    // A reused child that fails before the call is replaced once; the tool
    // call itself is sent exactly once.
    let fake = Fake::new(Mode::Modern);
    let registry = enabled(&raw).with_stdio_launcher(fake.clone()).with_session_pool(pool.clone());
    call(&registry).unwrap();
    fake.state().crash_launch = Some(1);
    call(&registry).unwrap();
    assert_eq!(fake.state().launches, 2);
    assert_eq!(fake.state().methods.iter().filter(|m| *m == "tools/call").count(), 2);
    pool.close_all();

    // A call without a confirmed reply drops its session and is not replayed.
    let fake = Fake::new(Mode::LoseCall);
    let registry = enabled(&raw).with_stdio_launcher(fake.clone()).with_session_pool(pool.clone());
    assert!(call(&registry).unwrap_err().to_string().contains("do not replay"));
    assert_eq!(pool.idle_sessions(), 0);
    assert_eq!(fake.state().events.last(), Some(&"terminate"));

    // A refused call to a disabled server still closes its idle child.
    let fake = Fake::new(Mode::Modern);
    let registry = enabled(&raw).with_stdio_launcher(fake.clone()).with_session_pool(pool.clone());
    call(&registry).unwrap();
    let fingerprint = registry.server_sha256("example").unwrap().unwrap();
    let off = Registry::parse(&raw).unwrap()
        .with_controls(&BTreeMap::from([("example".to_owned(), ServerControl { enabled: false, config_sha256: fingerprint })]))
        .unwrap().with_stdio_launcher(fake.clone()).with_session_pool(pool.clone());
    assert!(call(&off).unwrap_err().to_string().contains("disabled"));
    assert_eq!(pool.idle_sessions(), 0);
    assert_eq!(fake.state().events, ["close_stdin", "terminate"]);

    // Without a launcher, a pooled child is not reused either.
    let fake = Fake::new(Mode::Modern);
    call(&enabled(&raw).with_stdio_launcher(fake.clone()).with_session_pool(pool.clone())).unwrap();
    let bare = enabled(&raw).with_session_pool(pool.clone());
    assert!(call(&bare).unwrap_err().to_string().contains("unavailable in this context"));
    assert_eq!(fake.state().methods.iter().filter(|m| *m == "tools/call").count(), 1);
    pool.close_all();

    // Dropping the last owner of a pool closes its idle children.
    let last = SessionPool::new();
    let fake = Fake::new(Mode::Modern);
    let registry = enabled(&raw).with_stdio_launcher(fake.clone()).with_session_pool(last.clone());
    call(&registry).unwrap();
    assert!(fake.state().events.is_empty());
    drop(registry);
    drop(last);
    assert_eq!(fake.state().events, ["close_stdin", "terminate"]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pooled_idle_stdio_session_yields_its_slot_to_a_new_server() {
    let _serial = serial();
    let dir = scratch("pool-slots");
    let native = native_file(&dir, "example-mcp", true);
    let names = ["one", "two", "three", "four", "five"];
    let servers: Map<String, Value> = names.iter()
        .map(|name| (name.to_string(), server(&native, &file_sha256(&native)))).collect();
    let raw = bytes_of(Value::Object(servers));
    let pool = SessionPool::new();
    let fake = Fake::new(Mode::Modern);
    let registry = enabled_servers(&raw, &names).with_stdio_launcher(fake.clone()).with_session_pool(pool.clone());
    let terminated = || fake.state().events.iter().filter(|event| **event == "terminate").count();
    let call = |registry: &Registry, name: &str| {
        let result = registry.call(&format!("{name}:search_items"), &query("alpha"), ToolScope::DataOperations).unwrap();
        assert_eq!(result["content"][0]["text"], "fixture");
    };
    for name in &names[..4] { call(&registry, name); }
    assert_eq!(pool.idle_sessions(), 4);

    // A broken reused child closes before its replacement starts, so no
    // other idle child loses its slot.
    fake.state().crash_launch = Some(1);
    call(&registry, "one");
    assert_eq!(fake.state().launches, 5);
    assert_eq!(pool.idle_sessions(), 4);
    assert_eq!(terminated(), 1);

    // A fifth server closes the longest idle child, even for a caller
    // without a pool.
    let unpooled = enabled_servers(&raw, &names).with_stdio_launcher(fake.clone());
    call(&unpooled, "five");
    assert_eq!(fake.state().launches, 6);
    assert_eq!(pool.idle_sessions(), 3);
    assert_eq!(terminated(), 3);
    drop(registry);
    drop(pool);
    assert_eq!(terminated(), 6);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stdio_connection_test_covers_success_handshake_drift_and_unapproved_refusal() {
    let _serial = serial();
    let dir = scratch("conn-test");
    let native = native_file(&dir, "example-mcp", true);
    let sha = file_sha256(&native);
    let raw = bytes_of(json!({"example": server(&native, &sha)}));

    // 1. Unapproved / undecided / disabled server refuses with zero launches.
    let fake_unapproved = Fake::new(Mode::Modern);
    let undecided = Registry::parse(&raw).unwrap().with_stdio_launcher(fake_unapproved.clone());
    assert!(undecided.test_connection("example").is_err());
    assert!(undecided.test_connection("missing_srv").is_err());
    assert_eq!(fake_unapproved.state().launches, 0);

    // 2. Approved modern and legacy servers succeed without invoking any tool.
    for mode in [Mode::Modern, Mode::Legacy] {
        let fake = Fake::new(mode);
        let reg = enabled(&raw).with_stdio_launcher(fake.clone());
        let report = reg.test_connection("example").unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["status"], "ok");
        assert!(report["error_class"].is_null());
        assert_eq!(report["transport"], "stdio");
        assert_eq!(report["tool_invoked"], false);
        assert_eq!(report["approved_grants_changed"], false);
        assert_eq!(report["registry_changed"], false);
        assert!(report["latency_ms"].as_u64().is_some());
        assert!(!fake.state().methods.iter().any(|m| m == "tools/call"));
    }

    // 3. Handshake failure (crashing child on first write) returns structured error_class.
    let fake_crash = Fake::new(Mode::Modern);
    fake_crash.state().crash_launch = Some(1);
    let crash_reg = enabled(&raw).with_stdio_launcher(fake_crash.clone());
    let crash_report = crash_reg.test_connection("example").unwrap();
    assert_eq!(crash_report["ok"], false);
    assert_eq!(crash_report["status"], "error");
    assert_eq!(crash_report["error_class"], "handshake_failed");
    assert_eq!(crash_report["tool_invoked"], false);
    assert!(crash_report["latency_ms"].as_u64().is_some());

    // 4. Descriptor hash drift returns descriptor_hash_drift without granting anything.
    let drifted_descriptor = json!({
        "name": "search_items",
        "description": "Drifted description",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}
    });
    let drifted_raw = bytes_of(json!({
        "example": {
            "stdio": {"executable": native.to_str().unwrap(), "executable_sha256": sha, "args": ["stdio"]},
            "tools": {
                "search_items": {
                    "descriptor_sha256": hash(&drifted_descriptor),
                    "descriptor": drifted_descriptor,
                    "parameters": {"query": {"type": "search_terms"}}
                }
            }
        }
    }));
    let fake_drift = Fake::new(Mode::Modern);
    let drift_reg = enabled(&drifted_raw).with_stdio_launcher(fake_drift);
    let drift_report = drift_reg.test_connection("example").unwrap();
    assert_eq!(drift_report["ok"], false);
    assert_eq!(drift_report["status"], "descriptor_drift");
    assert_eq!(drift_report["error_class"], "descriptor_hash_drift");
    assert_eq!(drift_report["catalog_changes_detected"], true);
    assert_eq!(drift_report["approved_tools"][0]["status"], "descriptor_changed");
    assert_eq!(drift_report["approved_grants_changed"], false);
    assert_eq!(drift_report["tool_invoked"], false);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stdio_status_tracker_observes_transitions_pool_and_redacts_secrets() {
    let _serial = serial();
    let dir = scratch("status-tracker");
    let native = native_file(&dir, "example-mcp", true);
    let sha = file_sha256(&native);
    let raw = bytes_of(json!({"example": server(&native, &sha)}));

    let fake = Fake::new(Mode::Modern);
    let pool = SessionPool::new();
    let tracker = agent_bridge_extensions::StatusTracker::with_slow_threshold(std::time::Duration::from_millis(5));
    let reg = enabled(&raw)
        .with_stdio_launcher(fake.clone())
        .with_session_pool(pool.clone())
        .with_status_tracker(tracker.clone());

    let names = reg.server_names();
    let initial = tracker.snapshot(&names, Some(&pool));
    assert_eq!(initial["servers"][0]["server"], "example");
    assert_eq!(initial["servers"][0]["state"], "idle");
    assert_eq!(initial["servers"][0]["pool_idle_sessions"], 0);

    // Hold a starting guard while snapshotting to observe starting transition.
    {
        let _guard = tracker.begin_starting("example");
        let during = tracker.snapshot(&names, Some(&pool));
        assert_eq!(during["servers"][0]["state"], "starting");
    }

    // Successful call puts session into pool and transitions state to ready or slow.
    let secret_arg = "SECRET_ARG_SHOULD_NOT_APPEAR";
    let res = reg.call(
        "example:search_items",
        json!({"query": secret_arg}).as_object().unwrap(),
        ToolScope::DataOperations,
    );
    assert!(res.is_ok(), "call failed: {res:?}");
    let after_call = tracker.snapshot(&names, Some(&pool));
    assert_eq!(after_call["servers"][0]["pool_idle_sessions"], 1);
    assert!(matches!(
        after_call["servers"][0]["state"].as_str(),
        Some("ready" | "slow")
    ));
    assert!(after_call["servers"][0]["last_latency_ms"].as_u64().is_some());

    // Force a slow completion explicitly and verify slow transition.
    tracker.mark_ready("example", 15);
    let slow = tracker.snapshot(&names, Some(&pool));
    assert_eq!(slow["servers"][0]["state"], "slow");
    assert_eq!(slow["slow_threshold_ms"], 5);

    // Crashing next launch transitions to error with bounded error class, then recovers.
    let next_launch = fake.state().launches + 1;
    fake.state().crash_launch = Some(next_launch);
    pool.close_all();
    let err = reg.call(
        "example:search_items",
        json!({"query": "retry"}).as_object().unwrap(),
        ToolScope::DataOperations,
    );
    assert!(err.is_err());
    let errored = tracker.snapshot(&names, Some(&pool));
    assert_eq!(errored["servers"][0]["state"], "error");
    assert!(errored["servers"][0]["last_error_class"].as_str().is_some());
    assert!(errored["servers"][0]["last_error_unix_ms"].as_u64().is_some());

    fake.state().crash_launch = None;
    let recovered = reg.call(
        "example:search_items",
        json!({"query": "ok"}).as_object().unwrap(),
        ToolScope::DataOperations,
    );
    assert!(recovered.is_ok());
    let final_snap = tracker.snapshot(&names, Some(&pool));
    assert!(matches!(
        final_snap["servers"][0]["state"].as_str(),
        Some("ready" | "slow")
    ));
    assert_eq!(final_snap["servers"][0]["pool_idle_sessions"], 1);

    let serialized = serde_json::to_string(&final_snap).unwrap();
    assert!(!serialized.contains(secret_arg));
    assert!(!serialized.contains("fixture"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stdio_live_reload_validates_atomically_revokes_and_cancels_in_flight() {
    let _serial = serial();
    let dir = scratch("live-reload");
    let native = native_file(&dir, "example-mcp", true);
    let sha = file_sha256(&native);
    let base_entry = server(&native, &sha);
    let raw = bytes_of(json!({
        "example": base_entry,
        "keep": base_entry
    }));

    let fake = Fake::new(Mode::Modern);
    let pool = SessionPool::new();
    let tracker = agent_bridge_extensions::StatusTracker::new();
    let initial = enabled_servers(&raw, &["example", "keep"]).with_stdio_launcher(fake.clone());
    let live = agent_bridge_extensions::LiveExtensionRegistry::new(initial, pool.clone(), tracker.clone());

    // Warm pooled idle sessions for both servers.
    let res = live.call("example:search_items", &query("alpha"), ToolScope::DataOperations).unwrap();
    assert_eq!(res["content"][0]["text"], "fixture");
    let res_keep = live.call("keep:search_items", &query("beta"), ToolScope::DataOperations).unwrap();
    assert_eq!(res_keep["content"][0]["text"], "fixture");
    assert_eq!(pool.idle_sessions(), 2);

    // 1. Invalid reload is refused and keeps previous active registry running.
    let invalid = Registry::parse(b"{not-json");
    assert!(live.reload(invalid, agent_bridge_extensions::ReloadMode::OperatorApproved).is_err());
    assert_eq!(live.generation(), 1);
    assert_eq!(pool.idle_sessions(), 2);
    assert_eq!(
        live.call("example:search_items", &query("alpha"), ToolScope::DataOperations).unwrap()["content"][0]["text"],
        "fixture"
    );

    // 2. StrictNoWidening refuses widening parameters, adding enabled server, or adding a tool.
    let widened_raw = bytes_of(json!({
        "example": base_entry,
        "keep": base_entry,
        "extra": base_entry
    }));
    let widened_reg = enabled_servers(&widened_raw, &["example", "keep", "extra"]).with_stdio_launcher(fake.clone());
    let wide_err = live.reload(Ok(widened_reg), agent_bridge_extensions::ReloadMode::StrictNoWidening).unwrap_err();
    assert!(wide_err.to_string().contains("widen"), "{wide_err}");
    assert_eq!(live.generation(), 1);

    // 3. Valid narrowing/disabling reload swaps atomically and closes removed server's pooled session.
    let narrowed = bytes_of(json!({ "example": base_entry }));
    let next_reg = enabled(&narrowed).with_stdio_launcher(fake.clone());
    let audit = live.reload(Ok(next_reg), agent_bridge_extensions::ReloadMode::StrictNoWidening).unwrap();
    assert!(audit.ok);
    assert_eq!(audit.generation, 2);
    assert_eq!(audit.removed_or_disabled, 1);
    assert_eq!(audit.closed_idle_sessions, 1);
    assert_eq!(pool.idle_sessions(), 1);
    assert!(live.call("keep:search_items", &query("beta"), ToolScope::DataOperations).is_err());

    // 4. Stalled in-flight call cancels immediately on live revocation.
    pool.close_all();
    let stall_fake = Fake::new(Mode::Stall);
    let stall_raw = bytes_of(json!({ "staller": server(&native, &sha) }));
    let stall_pool = SessionPool::new();
    let stall_tracker = agent_bridge_extensions::StatusTracker::new();
    let stall_init = enabled_servers(&stall_raw, &["staller"]).with_stdio_launcher(stall_fake.clone());
    let stall_live = agent_bridge_extensions::LiveExtensionRegistry::new(
        stall_init,
        stall_pool.clone(),
        stall_tracker.clone(),
    );

    let call_started = Instant::now();
    let handle = std::thread::scope(|s| {
        let h = s.spawn(|| {
            stall_live.call("staller:search_items", &query("alpha"), ToolScope::DataOperations)
        });
        wait_for("staller did not reach tools/call", || stall_fake.state().stalled >= 1);
        let revoked = stall_live.revoke_server("staller").unwrap();
        assert_eq!(revoked.cancelled_in_flight, 1);
        assert_eq!(revoked.removed_or_disabled, 1);
        let call_result = h.join().unwrap();
        (call_result, call_started.elapsed())
    });
    let (call_result, elapsed) = handle;
    let err = call_result.unwrap_err();
    assert!(err.to_string().contains("cancelled due to revocation"), "{err}");
    assert!(elapsed < Duration::from_secs(3), "cancellation took too long: {elapsed:?}");

    let snap = stall_live.audit_snapshot();
    assert_eq!(snap["generation"], 2);
    assert_eq!(snap["records"][0]["ok"], true);
    assert_eq!(snap["records"][0]["cancelled_in_flight"], 1);
    assert_eq!(snap["in_flight"], 0);

    let _ = std::fs::remove_dir_all(&dir);
}


#[test]
fn stdio_live_admission_cannot_cross_revocation_and_same_fingerprint_reenable() {
    let _serial = serial();
    let dir = scratch("admission-revocation");
    let native = native_file(&dir, "example-mcp", true);
    let raw = bytes_of(json!({"example":server(&native,&file_sha256(&native))}));
    let fake = Fake::new(Mode::Modern);
    let pool = SessionPool::new();
    let initial = enabled(&raw).with_stdio_launcher(fake.clone());
    let live = agent_bridge_extensions::LiveExtensionRegistry::new(
        initial.clone(), pool.clone(), agent_bridge_extensions::StatusTracker::new());
    // Deliberately pause after admission but before the old snapshot can
    // touch the transport. No scheduler/sleep race is needed.
    let old = live.admit("example:search_items", ToolScope::DataOperations, |_| Ok(())).unwrap();
    assert_eq!(live.in_flight().active_count(),1);
    let prepared = live.prepare_reload(Ok(initial.clone()),
        agent_bridge_extensions::ReloadMode::OperatorApproved).unwrap();
    let revoked = live.revoke_server("example").unwrap();
    assert_eq!(revoked.cancelled_in_flight,1);
    assert!(live.commit_reload(prepared).is_err(), "old validation cannot undo a revoke");
    assert!(live.admit("example:search_items",ToolScope::DataOperations, |_| Ok(())).is_err());
    live.reload(Ok(initial),agent_bridge_extensions::ReloadMode::OperatorApproved).unwrap();
    // Re-enabling the same bytes is a new generation; qualification did
    // discovery/list only. The old receipt may not take the new idle child.
    assert!(!fake.state().methods.iter().any(|method|method=="tools/call"));
    live.call("example:search_items",&query("new"),ToolScope::DataOperations).unwrap();
    assert_eq!(pool.idle_sessions(),1);
    let before=fake.state().methods.clone();
    assert!(old.execute(&query("old")).is_err());
    assert_eq!(fake.state().methods,before);
    assert_eq!(pool.idle_sessions(),1);
    assert_eq!(live.in_flight().active_count(),0);
    pool.close_all();
    let _=std::fs::remove_dir_all(dir);
}

#[test]
fn stdio_reload_probes_real_pins_and_descriptors_before_swap_without_tool_calls() {
    let _serial = serial();
    let dir=scratch("reload-pins");
    let native=native_file(&dir,"example-mcp",true);
    let sha=file_sha256(&native);
    let original=server(&native,&sha);
    let raw=bytes_of(json!({"example":original.clone()}));
    let fake=Fake::new(Mode::Modern);
    let pool=SessionPool::new();
    let live=agent_bridge_extensions::LiveExtensionRegistry::new(
        enabled(&raw).with_stdio_launcher(fake.clone()),pool.clone(),
        agent_bridge_extensions::StatusTracker::new());
    let mut wrong=original.clone();
    wrong["stdio"]["executable_sha256"]=json!("0".repeat(64));
    let candidate=enabled(&bytes_of(json!({"example":wrong}))).with_stdio_launcher(fake.clone());
    assert!(live.reload(Ok(candidate),agent_bridge_extensions::ReloadMode::OperatorApproved).is_err());
    assert_eq!(fake.state().launches,0);
    assert_eq!(live.generation(),1);
    let mut drift=original.clone();
    let mut changed=descriptor();
    changed["description"]=json!("Different approved descriptor");
    drift["tools"]["search_items"]["descriptor_sha256"]=json!(hash(&changed));
    drift["tools"]["search_items"]["descriptor"]=changed;
    let candidate=enabled(&bytes_of(json!({"example":drift}))).with_stdio_launcher(fake.clone());
    assert!(live.reload(Ok(candidate),agent_bridge_extensions::ReloadMode::OperatorApproved).is_err());
    assert_eq!(live.generation(),1);
    assert!(fake.state().methods.iter().any(|method|method=="tools/list"));
    assert!(!fake.state().methods.iter().any(|method|method=="tools/call"));
    live.call("example:search_items",&query("old"),ToolScope::DataOperations).unwrap();
    assert_eq!(pool.idle_sessions(),1);
    let audit=live.audit_snapshot();
    assert_eq!(audit["records"].as_array().unwrap().len(),2);
    assert!(audit["records"].as_array().unwrap().iter().all(|record|record["ok"]==false));
    pool.close_all();
    let _=std::fs::remove_dir_all(dir);
}

fn cache_server(executable:&Path)->Value{
    let mut entry=server(executable,&file_sha256(executable));
    let mut pinned=descriptor();
    pinned["annotations"]=json!({"readOnlyHint":true,"destructiveHint":false});
    let grant=&mut entry["tools"]["search_items"];
    grant["descriptor_sha256"]=json!(hash(&pinned));
    grant["descriptor"]=pinned;
    grant["result_cache"]=json!({"read_only":true,"ttl_seconds":60});
    grant["result_filter"]=json!({"allow":["/visible"]});
    entry
}

fn tool_calls(fake:&Fake)->usize{
    fake.state().methods.iter().filter(|method|*method=="tools/call").count()
}
fn cached_call(
    live:&agent_bridge_extensions::LiveExtensionRegistry, token:u8, profile:u8, params:&Map<String,Value>,
)->io::Result<Value>{
    let request=live.cache_request([token;32],profile).unwrap();
    live.admit_with_cache("example:search_items",ToolScope::AnyGranted,
        Some(&request),profile, |_|Ok(()))?.execute(params)
}

#[test]
fn result_cache_normal_admission_checks_pins_filters_and_exact_grant_partitions(){
    let _serial=serial();
    let dir=scratch("result-cache-admission");
    let native=native_file(&dir,"example-mcp",true);
    let entry=cache_server(&native);
    let raw=bytes_of(json!({"example":entry}));
    let fake=Fake::new(Mode::Modern);
    fake.state().cache_fixture=true;
    let pool=SessionPool::new();
    let initial=enabled(&raw).with_stdio_launcher(fake.clone());
    let live=agent_bridge_extensions::LiveExtensionRegistry::new(initial.clone(),pool.clone(),
        agent_bridge_extensions::StatusTracker::new());

    let params=query("alpha");
    let first=cached_call(&live,1,2,&params).unwrap();
    assert_eq!(first["structuredContent"],json!({"visible":"filtered result"}));
    assert_eq!(first["content"],json!([]));
    assert!(!first.to_string().contains("RAW_FIXTURE_PRIVATE"));
    assert_eq!(cached_call(&live,1,2,&params).unwrap(),first);
    assert_eq!(tool_calls(&fake),1,"one miss then one hit");
    assert!(fake.state().methods.iter().filter(|m|*m=="tools/list").count()>=2,
        "a cache hit still revalidates the live descriptor");

    // Two access tokens for the same client must not share cached results.
    cached_call(&live,2,2,&params).unwrap();
    cached_call(&live,1,3,&params).unwrap();
    cached_call(&live,1,2,&query("beta")).unwrap();
    assert_eq!(tool_calls(&fake),4);
    // Neither a local call nor a scope with a mismatched effective profile
    // can borrow a cache partition.
    live.call("example:search_items",&params,ToolScope::AnyGranted).unwrap();
    live.call("example:search_items",&params,ToolScope::AnyGranted).unwrap();
    let wrong=live.cache_request([1;32],3).unwrap();
    live.admit_with_cache("example:search_items",ToolScope::AnyGranted,Some(&wrong),2,|_|Ok(()))
        .unwrap().execute(&params).unwrap();
    assert_eq!(tool_calls(&fake),7);
    let request=live.cache_request([1;32],2).unwrap();
    assert!(live.admit_with_cache("example:search_items",ToolScope::AnyGranted,Some(&request),2,
        |_|Err(io::Error::other("private journal refused"))).is_err());
    for key in ["_meta","caller_id","profile","token_hash"] {
        let mut forged=params.clone();
        forged.insert(key.into(),json!("spoofed"));
        assert!(cached_call(&live,1,2,&forged).is_err());
    }
    assert_eq!(tool_calls(&fake),7);
    fake.state().descriptor_drift=true;
    assert!(cached_call(&live,1,2,&params).is_err());
    assert_eq!(tool_calls(&fake),7);
    fake.state().descriptor_drift=false;

    // The normal reload path must fence even identical fingerprints.
    live.reload(Ok(initial.clone()),agent_bridge_extensions::ReloadMode::OperatorApproved).unwrap();
    cached_call(&live,1,2,&params).unwrap();
    assert_eq!(tool_calls(&fake),8);
    // An actual error is never retained.
    fake.state().tool_error=true;
    let err_params=query("error-case");
    assert_eq!(cached_call(&live,1,2,&err_params).unwrap()["isError"],true);
    assert_eq!(cached_call(&live,1,2,&err_params).unwrap()["isError"],true);
    assert_eq!(tool_calls(&fake),10);
    fake.state().tool_error=false;

    live.revoke_server("example").unwrap();
    assert!(cached_call(&live,1,2,&params).is_err());
    live.reload(Ok(initial),agent_bridge_extensions::ReloadMode::OperatorApproved).unwrap();
    cached_call(&live,1,2,&params).unwrap();
    assert_eq!(tool_calls(&fake),11);
    pool.close_all();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn result_cache_old_inflight_cannot_publish_after_invalidation(){
    let _serial=serial();
    let dir=scratch("result-cache-inflight");
    let native=native_file(&dir,"example-mcp",true);
    let raw=bytes_of(json!({"example":cache_server(&native)}));
    let fake=Fake::new(Mode::Stall);
    fake.state().cache_fixture=true;
    let pool=SessionPool::new();
    let live=agent_bridge_extensions::LiveExtensionRegistry::new(
        enabled(&raw).with_stdio_launcher(fake.clone()),pool.clone(),agent_bridge_extensions::StatusTracker::new());
    std::thread::scope(|scope|{
        let old=scope.spawn(||cached_call(&live,9,2,&query("alpha")));
        wait_for("cache miss reached actual tools/call",||fake.state().stalled==1);
        // Model the profile/revoke fence without cancelling an already
        // admitted read. The late successful reply must not repopulate.
        live.invalidate_results();
        fake.state().release=true;
        assert!(old.join().unwrap().is_ok());
    });
    assert_eq!(tool_calls(&fake),1);
    cached_call(&live,9,2,&query("alpha")).unwrap();
    assert_eq!(tool_calls(&fake),2,"late old result was fenced");
    cached_call(&live,9,2,&query("alpha")).unwrap();
    assert_eq!(tool_calls(&fake),2);
    pool.close_all();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn result_cache_local_opt_in_and_descriptor_are_required(){
    let dir=scratch("result-cache-policy");
    let native=native_file(&dir,"example-mcp",true);
    let good=cache_server(&native);
    let parse=|entry:Value|Registry::parse(&bytes_of(json!({"example":entry})));
    assert!(parse(good.clone()).is_ok());
    for annotations in [json!({}),json!({"readOnlyHint":false}),
        json!({"readOnlyHint":true,"destructiveHint":true})]{
        let mut bad=good.clone();
        let grant=&mut bad["tools"]["search_items"];
        grant["descriptor"]["annotations"]=annotations;
        let sha=hash(&grant["descriptor"]);
        grant["descriptor_sha256"]=json!(sha);
        assert!(parse(bad).is_err());
    }
    for policy in [json!({"read_only":false,"ttl_seconds":60}),
        json!({"read_only":true,"ttl_seconds":0}),json!({"read_only":true,"ttl_seconds":301})]{
        let mut bad=good.clone();
        bad["tools"]["search_items"]["result_cache"]=policy;
        assert!(parse(bad).is_err());
    }
    let mut bad=good.clone();
    bad["tools"]["search_items"]["descriptor_sha256"]=json!("0".repeat(64));
    assert!(parse(bad).is_err());
    let mut bad=good.clone();
    bad["tools"]["search_items"].as_object_mut().unwrap().remove("descriptor");
    assert!(parse(bad).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn stdio_probe_honors_revocation_and_status_transitions_ready_disabled_and_replaced() {
    let _serial = serial();
    let dir = scratch("probe-revoke-status");
    let native = native_file(&dir, "example-mcp", true);
    let sha = file_sha256(&native);
    let orig = server(&native, &sha);
    let raw = bytes_of(json!({ "example": orig }));

    let fake = Fake::new(Mode::Modern);
    let pool = SessionPool::new();
    let status = agent_bridge_extensions::StatusTracker::new();
    let initial = enabled(&raw).with_stdio_launcher(fake.clone());
    let live = agent_bridge_extensions::LiveExtensionRegistry::new(
        initial.clone(),
        pool.clone(),
        status.clone(),
    );

    // 1. Admitted probe transitions idle -> ready.
    let report = live.test_connection("example").unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["tool_invoked"], false);
    assert_eq!(report["approved_grants_changed"], false);
    assert_eq!(report["generation"], 1);
    let ready_snap = status.snapshot_for_registry(&live.current(), Some(&pool), Some(live.generation()));
    assert_eq!(ready_snap["servers"][0]["state"], "ready");
    assert!(ready_snap["servers"][0]["last_latency_ms"].as_u64().is_some());

    // 2. Paused admitted probe cancelled on revocation & stays refused even after same-fingerprint re-enable.
    let old_probe = live.admit_probe("example").unwrap();
    let rev = live.revoke_server("example").unwrap();
    assert_eq!(rev.removed_or_disabled, 1);
    assert_eq!(rev.cancelled_in_flight, 1);

    let disabled_snap = status.snapshot_for_registry(&live.current(), Some(&pool), Some(live.generation()));
    assert_eq!(disabled_snap["servers"][0]["enabled"], false);
    assert_eq!(disabled_snap["servers"][0]["state"], "disabled");
    assert!(disabled_snap["servers"][0]["last_latency_ms"].is_null());
    assert!(live.admit_probe("example").is_err());

    live.reload(Ok(initial), agent_bridge_extensions::ReloadMode::OperatorApproved).unwrap();
    assert_eq!(
        status.snapshot_for_registry(&live.current(), Some(&pool), Some(live.generation()))["servers"][0]["state"],
        "idle"
    );
    let launches_before = fake.state().launches;
    let old_err = old_probe.execute().unwrap_err();
    assert!(old_err.to_string().contains("cancelled due to revocation"), "{old_err}");
    assert_eq!(fake.state().launches, launches_before);
    assert_eq!(
        status.snapshot_for_registry(&live.current(), Some(&pool), Some(live.generation()))["servers"][0]["state"],
        "idle"
    );

    // 3. Successful probe then config replacement (same name, changed args) clears ready -> idle.
    live.test_connection("example").unwrap();
    assert_eq!(
        status.snapshot_for_registry(&live.current(), Some(&pool), Some(live.generation()))["servers"][0]["state"],
        "ready"
    );
    let mut replaced = server(&native, &sha);
    replaced["stdio"]["args"] = json!(["stdio", "v2"]);
    let replaced_raw = bytes_of(json!({ "example": replaced }));
    let replaced_reg = enabled(&replaced_raw).with_stdio_launcher(fake.clone());
    live.reload(Ok(replaced_reg.clone()), agent_bridge_extensions::ReloadMode::OperatorApproved).unwrap();
    let replaced_snap = status.snapshot_for_registry(&live.current(), Some(&pool), Some(live.generation()));
    assert_eq!(replaced_snap["servers"][0]["state"], "idle");
    assert!(replaced_snap["servers"][0]["last_latency_ms"].is_null());
    assert_eq!(
        replaced_snap["servers"][0]["config_sha256"],
        replaced_reg.server_sha256("example").unwrap().unwrap()
    );

    // 4. In-flight stalled stdio probe (tools/list) cancels immediately upon revocation.
    fake.state().stall_list = true;
    let admitted_stall = live.admit_probe("example").unwrap();
    let started = Instant::now();
    let stall_err = std::thread::scope(|scope| {
        let h = scope.spawn(|| admitted_stall.execute());
        wait_for("stdio probe did not stall on tools/list", || fake.state().stalled >= 1);
        let rev = live.revoke_server("example").unwrap();
        assert_eq!(rev.cancelled_in_flight, 1);
        h.join().unwrap().unwrap_err()
    });
    assert!(started.elapsed() < Duration::from_secs(3), "stdio probe cancellation took {:?}", started.elapsed());
    assert!(stall_err.to_string().contains("cancelled due to revocation"), "{stall_err}");
    assert!(!fake.state().methods.iter().any(|m| m == "tools/call"));
    assert_eq!(
        status.snapshot_for_registry(&live.current(), Some(&pool), Some(live.generation()))["servers"][0]["state"],
        "disabled"
    );
    pool.close_all();
    let _ = std::fs::remove_dir_all(&dir);
}
