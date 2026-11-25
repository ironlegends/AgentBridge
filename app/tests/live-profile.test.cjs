"use strict";

const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");
const vm = require("node:vm");

const html = readFileSync(path.join(__dirname, "..", "ui", "index.html"), "utf8");
const script = readFileSync(path.join(__dirname, "..", "ui", "app.js"), "utf8");
const profiles = ["read-only", "workspace-write", "full-control", "fully-unlocked"];

class Element {
  constructor(attributes = {}) {
    this.attributes = attributes;
    this.className = attributes.class || "";
    this.value = attributes.value || "";
    this.textContent = "";
    this.innerHTML = "";
    this.id = attributes.id || "";
    this.checked = "checked" in attributes;
    this.disabled = "disabled" in attributes;
    this.style = {};
    this.listeners = new Map();
    this.classList = {
      contains: (name) => this.className.split(/\s+/).includes(name),
      add: (...names) => names.forEach((name) => this.classList.toggle(name, true)),
      remove: (...names) => names.forEach((name) => this.classList.toggle(name, false)),
      toggle: (name, force) => {
        const classes = new Set(this.className.split(/\s+/).filter(Boolean));
        const enabled = force === undefined ? !classes.has(name) : force;
        if (enabled) classes.add(name);
        else classes.delete(name);
        this.className = [...classes].join(" ");
        return enabled;
      },
    };
  }
  getAttribute(name) { return this.attributes[name] ?? null; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  removeAttribute(name) { delete this.attributes[name]; }
  addEventListener(name, handler) {
    const list = this.listeners.get(name) || [];
    list.push(handler);
    this.listeners.set(name, list);
  }
  set innerHTML(value) {
    this._innerHTML = value;
    this.children = parseElements(value);
  }
  get innerHTML() { return this._innerHTML; }
  querySelectorAll(selector) { return this.children.filter((el) => matches(el, selector)); }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  async fire(name) {
    if (name === "click" && this.disabled) return;
    await Promise.all((this.listeners.get(name) || []).map((fn) => fn({ target: this, currentTarget: this })));
  }
}

function parseElements(source) {
  const result = [];
  for (const tag of source.matchAll(/<[a-z][\w-]*\b([^<>]*)>/gi)) {
    const attributes = {};
    for (const attribute of tag[1].matchAll(/([:\w-]+)(?:="([^"]*)")?/g)) {
      attributes[attribute[1]] = attribute[2] ?? "";
    }
    result.push(new Element(attributes));
  }
  return result;
}

function matches(el, selector) {
  if (selector.startsWith(".")) return el.classList.contains(selector.slice(1));
  const attribute = /^\[([-\w]+)(?:="([^"]*)")?\]$/.exec(selector);
  return Boolean(attribute && el.getAttribute(attribute[1]) !== null
    && (attribute[2] === undefined || el.getAttribute(attribute[1]) === attribute[2]));
}

function createUi({ events = true } = {}) {
  const elements = [];
  const byId = new Map();
  for (const tag of html.matchAll(/<[a-z][\w-]*\b([^<>]*)>/gi)) {
    const attributes = {};
    for (const attribute of tag[1].matchAll(/([:\w-]+)(?:="([^"]*)")?/g)) {
      attributes[attribute[1]] = attribute[2] ?? "";
    }
    const el = new Element(attributes);
    elements.push(el);
    if (attributes.id) byId.set(attributes.id, el);
  }
  const all = () => elements.flatMap((el) => [el, ...el.children]);
  const select = (selector) => all().filter((el) => matches(el, selector));
  const document = {
    documentElement: elements[0],
    activeElement: null,
    getElementById: (id) => byId.get(id) || all().find((el) => el.id === id) || null,
    querySelectorAll: select,
  };
  const calls = [];
  let poll;
  let clock = 1000000;
  let nextTimer = 0;
  const timers = new Map();
  const openedUrls = [];
  const eventHandlers = new Map();
  let hiddenWindows = 0;
  const invoke = (command, args) => new Promise((resolve, reject) => {
    calls.push({ command, args, resolve, reject, settled: false });
  });
  vm.runInNewContext(script, {
    document,
    window: { __TAURI__: {
      core: { invoke }, window: { getCurrentWindow: () => ({ hide: async () => { hiddenWindows++; } }) },
      opener: { openUrl: async (url) => { openedUrls.push(url); } },
      event: events ? { listen: async (name, handler) => { eventHandlers.set(name, handler); return () => eventHandlers.delete(name); } } : undefined,
    } },
    navigator: { clipboard: { writeText: async () => {} } },
    setInterval: (fn) => { poll = fn; return 1; },
    setTimeout: (fn, delay) => { const id = ++nextTimer; timers.set(id, { fn, delay }); return id; },
    clearTimeout: (id) => timers.delete(id),
    URL,
    Date: class extends Date { static now() { return clock; } },
    console,
  }, { filename: "app/ui/app.js" });
  return {
    calls,
    openedUrls,
    hiddenWindows: () => hiddenWindows,
    emit: async (name, payload) => {
      assert.ok(eventHandlers.has(name), "Missing event listener " + name);
      await eventHandlers.get(name)({ payload });
    },
    select,
    advance: (ms) => { clock += ms; },
    timer: (delay) => [...timers.values()].find((timer) => timer.delay === delay),
    runTimer: async (delay) => {
      const found = [...timers].find(([, timer]) => timer.delay === delay);
      assert.ok(found, "Expected timer " + delay);
      timers.delete(found[0]);
      await found[1].fn();
    },
    el: (id) => {
      const el = byId.get(id);
      assert.ok(el, "Missing element " + id);
      return el;
    },
    buttons: () => select("[data-profile]"),
    button: (profile) => select("[data-profile]").find((el) => el.getAttribute("data-profile") === profile),
    active: () => select("[data-profile]").filter((el) => el.classList.contains("active")).map((el) => el.getAttribute("data-profile")),
    poll: () => poll(),
    pending: (command) => {
      const call = calls.find((item) => item.command === command && !item.settled);
      assert.ok(call, "Expected pending IPC " + command);
      return call;
    },
    settle: async (call, value, reject = false) => {
      call.settled = true;
      if (reject) call.reject(value);
      else call.resolve(value);
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    },
  };
}

function panel(activeProfile = "read-only", overrides = {}) {
  return {
    version: "2.0.0-test",
    settings: {
      theme: "system",
      profile: "read-only",
      workspace: "C:/project",
      databasePath: "C:/state/tasks.sqlite",
      settingsDir: "C:/state/settings",
      gatewayPort: 18856,
      oauthStateDir: "C:/state/oauth",
      oauthOrigin: "https://example.test",
      oauthAudience: "workstation",
      recentWorkspaces: [],
      onboardingCompleted: true,
    },
    gateway: { live: true, port: 18856, ownedRunning: false, external: true },
    liveProfile: {
      configured: true,
      connected: true,
      activeProfile,
      maxProfile: "fully-unlocked",
      availableProfiles: profiles,
      error: null,
    },
    database: { activeMissions: 0 },
    pendingApprovalsTotal: 0,
    oauth: { configured: true },
    extensions: { configured: false, exists: false, servers: [], requests: [], outboundOauth: {} },
    quickstart: { mcpLoopbackUrl: "http://127.0.0.1:18856/mcp", stdioReadOnly: "agent-bridge stdio", stdioWorkspaceWrite: "agent-bridge stdio --profile workspace-write" },
    ...overrides,
  };
}

async function ready(data = panel(), options) {
  const ui = createUi(options);
  await ui.settle(ui.pending("get_panel_state"), data);
  return ui;
}

test("attached panel renders the runtime profile instead of the saved startup preference", async () => {
  const ui = await ready(panel("fully-unlocked"));
  assert.deepEqual(ui.active(), ["fully-unlocked"]);
});

test("live elevation is one click and leaves the confirmed mode unchanged while pending", async () => {
  const ui = await ready();
  const click = ui.button("fully-unlocked").fire("click");
  const update = ui.pending("set_permission_profile");
  assert.equal(update.args.profile, "fully-unlocked");
  assert.deepEqual(ui.active(), ["read-only"]);
  assert.ok(ui.el("profileModal").classList.contains("hidden"));
  assert.ok(ui.buttons().every((button) => button.disabled));
  await ui.button("workspace-write").fire("click");
  assert.equal(ui.calls.filter((call) => call.command === "set_permission_profile").length, 1);
  await ui.settle(update, panel("fully-unlocked"));
  await click;
  assert.deepEqual(ui.active(), ["fully-unlocked"]);
  assert.equal(ui.button("workspace-write").disabled, false);
});

test("a poll started before a mode change cannot overwrite its confirmed response", async () => {
  const ui = await ready();
  const polling = ui.poll();
  const oldPoll = ui.pending("get_panel_state");
  const click = ui.button("workspace-write").fire("click");
  await ui.settle(ui.pending("set_permission_profile"), panel("workspace-write"));
  await click;
  await ui.settle(oldPoll, panel("read-only"));
  await polling;
  assert.deepEqual(ui.active(), ["workspace-write"]);
});

test("a rejected live change keeps the confirmed mode and permits a retry", async () => {
  const ui = await ready();
  const click = ui.button("workspace-write").fire("click");
  await ui.settle(ui.pending("set_permission_profile"), "Profile change failed", true);
  await ui.settle(ui.pending("get_panel_state"), panel("read-only"));
  await click;
  assert.deepEqual(ui.active(), ["read-only"]);
  assert.equal(ui.button("workspace-write").disabled, false);
  assert.match(ui.el("profileStatus").textContent, /Profile change failed/);
});

test("an attached disconnected session never falls back to the saved startup profile", async () => {
  const data = panel("workspace-write");
  data.liveProfile.connected = false;
  data.liveProfile.error = "Service unavailable";
  const ui = await ready(data);
  assert.deepEqual(ui.active(), []);
  assert.ok(ui.buttons().every((button) => button.disabled));
});

test("modes above the runtime ceiling remain unavailable", async () => {
  const data = panel("workspace-write");
  data.liveProfile.maxProfile = "workspace-write";
  data.liveProfile.availableProfiles = ["read-only", "workspace-write"];
  const ui = await ready(data);
  assert.equal(ui.button("read-only").disabled, false);
  assert.equal(ui.button("full-control").disabled, true);
  assert.equal(ui.button("fully-unlocked").disabled, true);
});

test("attachment disables local lifecycle and configuration without reopening onboarding", async () => {
  const data = panel();
  data.settings.onboardingCompleted = false;
  const ui = await ready(data);
  for (const id of ["powerBtn", "stopBtn", "initStateBtn", "quickWorkspaceBtn", "chooseWorkspaceBtn", "savePathsBtn", "saveOauthBtn"]) {
    assert.equal(ui.el(id).disabled, true, id + " must not control an external session");
  }
  assert.ok(ui.el("onboardingModal").classList.contains("hidden"));
});

test("background polling does not replace an unsaved settings field", async () => {
  const data = panel();
  data.gateway.external = false;
  data.liveProfile = null;
  const ui = await ready(data);
  const input = ui.el("inputDbPath");
  input.value = "C:/my-unsaved-path/tasks.sqlite";
  await input.fire("input");
  const polling = ui.poll();
  await ui.settle(ui.pending("get_panel_state"), data);
  await polling;
  assert.equal(input.value, "C:/my-unsaved-path/tasks.sqlite");
});

test("a failed state refresh marks attached controls unavailable instead of retaining Live", async () => {
  const ui = await ready(panel("fully-unlocked"));
  const polling = ui.poll();
  await ui.settle(ui.pending("get_panel_state"), "IPC disconnected", true);
  await polling;
  assert.ok(ui.buttons().every((button) => button.disabled));
  assert.notEqual(ui.el("liveText").textContent, "Live");
});

test("an older poll cannot overwrite a newer state loaded by the approvals screen", async () => {
  const ui = await ready();
  const polling = ui.poll();
  const oldPoll = ui.pending("get_panel_state");
  await ui.el("approvalsNavBtn").fire("click");
  const newerRead = ui.calls.filter((call) => call.command === "get_panel_state" && !call.settled).at(-1);
  await ui.settle(ui.pending("get_oauth_pending"), { configured: false, origin: "", pending: [] });
  await ui.settle(newerRead, panel("full-control"));
  assert.deepEqual(ui.active(), ["full-control"]);
  await ui.settle(oldPoll, panel("read-only"));
  await polling;
  assert.deepEqual(ui.active(), ["full-control"]);
});

test("unattached mode changes are presented as saved preferences", async () => {
  const data = panel();
  data.gateway.external = false;
  data.liveProfile = null;
  const ui = await ready(data);
  assert.match(ui.el("profileTitle").textContent, /saved/i);
  assert.match(ui.el("profileStatus").textContent, /attach.*workstation/i);
  const click = ui.button("workspace-write").fire("click");
  const updated = { ...data, settings: { ...data.settings, profile: "workspace-write" } };
  await ui.settle(ui.pending("set_permission_profile"), updated);
  await click;
  assert.deepEqual(ui.active(), ["workspace-write"]);
  assert.match(ui.el("toast").textContent, /preference.*saved/i);
});

const extensionId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

function extensionPanel(operation = null, changes = {}) {
  return panel("fully-unlocked", {
    extensions: {
      configured: true, exists: true, canDecide: true,
      servers: [{ id: "fixture", enabled: true, endpoint: "https://mcp.example.invalid/api" }],
      requests: [{
        requestId: extensionId, action: "install", name: "<img src=x onerror=alert(1)>",
        status: "pending", reason: null, revision: 3,
        payload: {
          action: "install", url: "https://mcp.example.invalid/api?q=<script>",
          secret_env: { AUTH_TOKEN: "FIXTURE_ENV" },
        },
      }],
      outboundOauth: {}, oauthOperation: operation, ...changes,
    },
  });
}

async function showApprovals(ui, data, oauth = { configured: true, origin: "https://example.invalid", pending: [] }) {
  await ui.el("approvalsNavBtn").fire("click");
  await ui.settle(ui.pending("get_oauth_pending"), oauth);
  await ui.settle(ui.pending("get_panel_state"), data);
}

function action(ui, name) {
  const button = ui.select('[data-ext-decide="' + name + '"]')[0];
  assert.ok(button, "Missing extension " + name + " action");
  return button;
}

test("extension review escapes untrusted data and approval requires exact proposal review", async () => {
  const data = extensionPanel();
  const ui = await ready(data);
  await showApprovals(ui, data);
  const body = ui.el("approvalsBody").innerHTML;
  assert.match(body, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(body, /&lt;script&gt;/);
  assert.ok(!body.includes("<img src=x"));
  assert.ok(!body.includes("<script>"));
  assert.match(body, /FIXTURE_ENV/);
  const approve = action(ui, "approve");
  assert.equal(approve.disabled, true);
  await approve.fire("click");
  assert.equal(ui.calls.filter((call) => call.command === "decide_extension_request").length, 0);
  const review = ui.select("[data-ext-review]")[0];
  assert.ok(review, "Exact proposal review checkbox");
  review.checked = true;
  await review.fire("change");
  assert.equal(approve.disabled, false);
  const click = approve.fire("click");
  const decision = ui.pending("decide_extension_request");
  assert.equal(decision.args.requestId, extensionId);
  assert.equal(decision.args.approve, true);
  assert.equal(decision.args.reviewed, true);
  await approve.fire("click");
  await action(ui, "refuse").fire("click");
  assert.equal(ui.calls.filter((call) => call.command === "decide_extension_request").length, 1);
  await ui.settle(decision, { decision: "approved", effect_now: true });
  await ui.settle(ui.pending("get_oauth_pending"), { configured: true, pending: [] });
  await ui.settle(ui.pending("get_panel_state"), extensionPanel(null, { requests: [] }));
  await click;
  assert.match(ui.el("toast").textContent, /approved/i);
  assert.equal(ui.select("[data-ext-decide]").length, 0);
});

test("extension refusal needs no approval checkbox and displays a refused receipt", async () => {
  const data = extensionPanel();
  const ui = await ready(data);
  await showApprovals(ui, data);
  const click = action(ui, "refuse").fire("click");
  const decision = ui.pending("decide_extension_request");
  assert.equal(decision.args.requestId, extensionId);
  assert.equal(decision.args.approve, false);
  assert.equal(decision.args.reviewed, false);
  await ui.settle(decision, { decision: "refused", effect_now: false });
  await ui.settle(ui.pending("get_oauth_pending"), { configured: true, pending: [] });
  await ui.settle(ui.pending("get_panel_state"), extensionPanel(null, { requests: [] }));
  await click;
  assert.match(ui.el("toast").textContent, /refused/i);
  assert.ok(!/approved/i.test(ui.el("toast").textContent));
});

test("failed extension decisions refresh instead of claiming success or resubmitting", async () => {
  const data = extensionPanel();
  const ui = await ready(data);
  await showApprovals(ui, data);
  const click = action(ui, "refuse").fire("click");
  await ui.settle(ui.pending("decide_extension_request"), "Decision could not be confirmed", true);
  await ui.settle(ui.pending("get_oauth_pending"), { configured: true, pending: [] });
  await ui.settle(ui.pending("get_panel_state"), data);
  await click;
  assert.match(ui.el("toast").textContent, /could not be confirmed/i);
  assert.equal(ui.calls.filter((call) => call.command === "decide_extension_request").length, 1);
  assert.equal(action(ui, "refuse").disabled, false);
});

test("detached and disconnected panels do not expose actionable extension decisions", async () => {
  for (const mode of ["detached", "disconnected"]) {
    const data = extensionPanel();
    if (mode === "detached") {
      data.gateway.external = false;
      data.liveProfile = null;
      data.extensions.canDecide = false;
    } else {
      data.liveProfile.connected = false;
    }
    const ui = await ready(data);
    await showApprovals(ui, data);
    assert.equal(ui.select("[data-ext-decide]").filter((button) => !button.disabled).length, 0);
    assert.match(ui.el("approvalsBody").innerHTML, /attach|unavailable|connect/i);
  }
});

test("outbound OAuth stays pending, disables new decisions and opens only a clicked safe link", async () => {
  const url = "https://auth.example.invalid/authorize?state=fixture";
  const operation = {
    request_id: extensionId, status: "awaiting_authorization", auth_url: url,
    result: null, error: null, callback_timeout_seconds: 120,
  };
  const data = extensionPanel(operation);
  const ui = await ready(data);
  await showApprovals(ui, data);
  assert.deepEqual(ui.openedUrls, []);
  assert.match(ui.el("approvalsBody").innerHTML, /authorize|authorization/i);
  assert.ok(!/approved and recorded/i.test(ui.el("approvalsBody").innerHTML));
  assert.ok(ui.select("[data-ext-decide]").every((button) => button.disabled));
  const open = ui.select("[data-ext-auth-open]")[0];
  assert.ok(open, "Manual authorization link");
  await open.fire("click");
  assert.deepEqual(ui.openedUrls, [url]);
  assert.ok(ui.timer(1000), "Bounded status poll");
  ui.advance(240001);
  await ui.runTimer(1000);
  assert.equal(ui.calls.filter((call) => call.command === "decide_extension_request").length, 0);
  assert.equal(ui.calls.filter((call) => !call.settled).length, 0);
});

test("unsafe outbound authorization links never reach the OS opener", async () => {
  for (const url of [
    "javascript:alert(1)", "file:///C:/private.txt", "http://example.invalid/authorize",
    "https://user:password@example.invalid/authorize", "http://127.0.0.1.example.invalid/authorize",
    "http://2130706433/authorize",
  ]) {
    const data = extensionPanel({ request_id: extensionId, status: "awaiting_authorization", auth_url: url });
    const ui = await ready(data);
    await showApprovals(ui, data);
    assert.equal(ui.select("[data-ext-auth-open]").length, 0, "Unsafe URL " + url);
    assert.deepEqual(ui.openedUrls, []);
  }
});

test("an asynchronous decision receipt never claims durable approval or opens a browser", async () => {
  const data = extensionPanel();
  const ui = await ready(data);
  await showApprovals(ui, data);
  const review = ui.select("[data-ext-review]")[0];
  assert.ok(review);
  review.checked = true;
  await review.fire("change");
  const click = action(ui, "approve").fire("click");
  const operation = { request_id: extensionId, status: "starting", auth_url: null, result: null };
  await ui.settle(ui.pending("decide_extension_request"), { oauth_operation: operation });
  await ui.settle(ui.pending("get_oauth_pending"), { configured: true, pending: [] });
  await ui.settle(ui.pending("get_panel_state"), extensionPanel(operation));
  await click;
  assert.ok(/started|pending|authorization/i.test(ui.el("toast").textContent));
  assert.ok(!/approved/i.test(ui.el("toast").textContent));
  assert.deepEqual(ui.openedUrls, []);
});

test("a failed old approvals read cannot overwrite a newer confirmed screen", async () => {
  const data = extensionPanel();
  const ui = await ready(data);
  await showApprovals(ui, data);
  const oldRefresh = ui.el("refreshApprovalsBtn").fire("click");
  const oldOauth = ui.pending("get_oauth_pending");
  const oldPanel = ui.pending("get_panel_state");
  await ui.el("approvalsNavBtn").fire("click");
  const newerOauth = ui.calls.filter((call) => call.command === "get_oauth_pending" && !call.settled).at(-1);
  const newerPanel = ui.calls.filter((call) => call.command === "get_panel_state" && !call.settled).at(-1);
  await ui.settle(newerOauth, { configured: true, pending: [] });
  await ui.settle(newerPanel, extensionPanel(null, { requests: [] }));
  const confirmed = ui.el("approvalsBody").innerHTML;
  await ui.settle(oldOauth, "Stale request failed", true);
  await ui.settle(oldPanel, data);
  await oldRefresh;
  assert.equal(ui.el("approvalsBody").innerHTML, confirmed);
});

test("a provider link cannot silently switch to a different operation after a refresh", async () => {
  const original = {
    request_id: extensionId, status: "awaiting_authorization",
    auth_url: "https://auth.example.invalid/authorize?state=original",
  };
  const data = extensionPanel(original);
  const ui = await ready(data);
  await showApprovals(ui, data);
  const open = ui.select("[data-ext-auth-open]")[0];
  assert.ok(open);
  const polling = ui.poll();
  await ui.settle(ui.pending("get_panel_state"), extensionPanel({
    ...original, request_id: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    auth_url: "https://other.example.invalid/authorize?state=replacement",
  }));
  await polling;
  await open.fire("click");
  assert.deepEqual(ui.openedUrls, []);
});

test("literal loopback OAuth pages remain available through an explicit operator click", async () => {
  for (const url of ["http://127.0.0.1:12345/authorize?state=fixture", "http://[::1]:12345/authorize?state=fixture"]) {
    const data = extensionPanel({ request_id: extensionId, status: "awaiting_authorization", auth_url: url });
    const ui = await ready(data);
    await showApprovals(ui, data);
    assert.deepEqual(ui.openedUrls, []);
    const open = ui.select("[data-ext-auth-open]")[0];
    assert.ok(open);
    await open.fire("click");
    assert.deepEqual(ui.openedUrls, [url]);
  }
});

test("extension authorization polling preserves the current OAuth callback draft by request ID", async () => {
  const data = extensionPanel({
    request_id: extensionId, status: "awaiting_authorization",
    auth_url: "https://auth.example.invalid/authorize?state=fixture",
  });
  const oauth = {
    configured: true, origin: "https://example.invalid",
    pending: [{ id: "oauth-fixture", provider: "chatgpt", clientId: "client-fixture", redirectUri: "https://client.example.invalid/callback" }],
  };
  const ui = await ready(data);
  await showApprovals(ui, data, oauth);
  const input = ui.select('[data-oauth-cb="oauth-fixture"]')[0];
  input.value = "https://client.example.invalid/partial";
  const polling = ui.runTimer(1000);
  input.value = "https://client.example.invalid/callback?state=typed-during-poll";
  await ui.settle(ui.pending("get_oauth_pending"), oauth);
  await ui.settle(ui.pending("get_panel_state"), data);
  await polling;
  const restored = ui.select('[data-oauth-cb="oauth-fixture"]')[0];
  assert.equal(restored.value, input.value);
  const approval = ui.select('[data-oauth-approve="oauth-fixture"]')[0].fire("click");
  const call = ui.pending("approve_oauth_request");
  assert.equal(call.args.expectedCallback, input.value);
  await ui.settle(call, { approved: true });
  await ui.settle(ui.pending("get_oauth_pending"), { ...oauth, pending: [] });
  await ui.settle(ui.pending("get_panel_state"), data);
  await approval;
  await showApprovals(ui, data, oauth);
  assert.equal(ui.select('[data-oauth-cb="oauth-fixture"]')[0].value, "");
});

function supervisedPanel({ live = true, phase = null, canStart = !live, canStop = live, canRestart = live, reason = null } = {}) {
  const data = extensionPanel();
  data.gateway = {
    live, port: 18856, external: true, ownedRunning: false,
    controls: { canStart, canStop, canRestart, phase, reason },
  };
  data.liveProfile.connected = live;
  return data;
}

test("attached lifecycle follows explicit capabilities while configuration stays external", async () => {
  const data = supervisedPanel();
  const ui = await ready(data);
  assert.equal(ui.el("powerBtn").disabled, false);
  assert.equal(ui.el("stopBtn").disabled, false);
  assert.ok(!ui.el("gatewayActions").classList.contains("hidden"));
  for (const id of ["initStateBtn", "quickWorkspaceBtn", "chooseWorkspaceBtn", "savePathsBtn", "saveOauthBtn"]) {
    assert.equal(ui.el(id).disabled, true, id);
  }
  assert.match(ui.el("externalGatewayNotice").textContent, /restart.*startup.*profile/i);
  const restart = ui.el("powerBtn").fire("click");
  const call = ui.pending("start_or_restart_gateway");
  assert.equal(call.args?.intent, "restart");
  assert.equal(ui.el("powerBtn").textContent, "Restarting Bridge…");
  assert.match(ui.el("profileStatus").textContent, /restarting/);
  assert.ok(ui.buttons().every((button) => button.disabled));
  await ui.el("powerBtn").fire("click");
  assert.equal(ui.calls.filter((item) => item.command === "start_or_restart_gateway").length, 1);
  await ui.settle(call, supervisedPanel());
  await restart;
  assert.equal(ui.el("powerBtn").disabled, false);
  assert.equal(ui.el("powerBtn").textContent, "Restart Bridge");
  assert.equal(ui.hiddenWindows(), 0);
});

test("attached stop-only sessions stop without closing the desktop window", async () => {
  const data = supervisedPanel({
    canStart: false, canRestart: false, reason: "The external owner must start this service.",
  });
  const ui = await ready(data);
  assert.equal(ui.el("powerBtn").disabled, true);
  assert.equal(ui.el("stopBtn").disabled, false);
  assert.match(ui.el("externalGatewayNotice").textContent, /external owner/i);
  const stopping = ui.el("stopBtn").fire("click");
  const call = ui.pending("stop_gateway");
  assert.equal(ui.el("powerBtn").textContent, "Stopping Bridge…");
  assert.match(ui.el("externalGatewayNotice").textContent, /stopping/);
  assert.equal(ui.el("stopBtn").disabled, true);
  await ui.el("stopBtn").fire("click");
  assert.equal(ui.calls.filter((item) => item.command === "stop_gateway").length, 1);
  await ui.settle(call, supervisedPanel({
    live: false, canStart: false, canStop: false, canRestart: false,
    reason: "The external owner must start this service.",
  }));
  await stopping;
  assert.match(ui.el("toast").textContent, /stopped/i);
  assert.equal(ui.hiddenWindows(), 0);
  assert.equal(ui.calls.some((item) => item.command === "quit_app"), false);
  assert.equal(ui.el("powerBtn").disabled, true);
  assert.equal(ui.el("powerBtn").textContent, "Start Bridge");
});

test("a stopped supervised workstation can be started while its mode remains disconnected", async () => {
  const ui = await ready(supervisedPanel({ live: false }));
  assert.equal(ui.el("powerBtn").disabled, false);
  assert.match(ui.el("powerBtn").textContent, /start/i);
  assert.ok(ui.buttons().every((button) => button.disabled));
  const starting = ui.el("powerBtn").fire("click");
  assert.equal(ui.el("powerBtn").textContent, "Starting Bridge…");
  assert.equal(ui.pending("start_or_restart_gateway").args?.intent, "start");
  await ui.settle(ui.pending("start_or_restart_gateway"), supervisedPanel());
  await starting;
  assert.equal(ui.el("powerBtn").textContent, "Restart Bridge");
  assert.deepEqual(ui.active(), ["fully-unlocked"]);
});

test("a rejected attached lifecycle action clears the pending phase and permits a retry", async () => {
  const ui = await ready(supervisedPanel());
  const stopping = ui.el("stopBtn").fire("click");
  await ui.settle(ui.pending("stop_gateway"), "Cooperative shutdown failed", true);
  assert.equal(ui.el("stopBtn").disabled, true);
  await ui.settle(ui.pending("get_panel_state"), supervisedPanel());
  await stopping;
  assert.equal(ui.el("powerBtn").textContent, "Restart Bridge");
  assert.equal(ui.el("stopBtn").disabled, false);
  assert.match(ui.el("toast").textContent, /Cooperative shutdown failed/);

  const retry = ui.el("stopBtn").fire("click");
  assert.equal(ui.el("powerBtn").textContent, "Stopping Bridge…");
  await ui.settle(ui.pending("stop_gateway"), supervisedPanel({ live: false }));
  await retry;
  assert.equal(ui.el("powerBtn").textContent, "Start Bridge");
});

test("a tray error during Stop reconciles before restoring lifecycle controls", async () => {
  const ui = await ready(supervisedPanel());
  const stopping = ui.el("stopBtn").fire("click");
  await ui.emit("workstation-error", "The tray action could not complete.");
  await ui.settle(ui.pending("stop_gateway"), supervisedPanel({ live: false }));
  assert.equal(ui.el("stopBtn").disabled, true);
  assert.equal(ui.el("powerBtn").disabled, true);
  await ui.el("stopBtn").fire("click");
  assert.equal(ui.calls.filter((call) => call.command === "stop_gateway").length, 1);
  await ui.settle(ui.pending("get_panel_state"), supervisedPanel({ live: false }));
  await stopping;
  assert.equal(ui.el("powerBtn").textContent, "Start Bridge");
  assert.equal(ui.el("powerBtn").disabled, false);
  assert.equal(ui.el("stopBtn").disabled, true);
});

test("a partial Restart failure replaces running controls with a fresh stopped snapshot", async () => {
  const ui = await ready(supervisedPanel());
  const polling = ui.poll();
  const oldRead = ui.pending("get_panel_state");
  const restarting = ui.el("powerBtn").fire("click");
  await ui.settle(ui.pending("start_or_restart_gateway"), "The supervisor was unable to start.", true);
  assert.equal(ui.el("powerBtn").disabled, true);
  assert.equal(ui.el("stopBtn").disabled, true);
  const read = ui.calls.find((call) => call.command === "get_panel_state" && !call.settled && call !== oldRead);
  assert.ok(read, "Expected a reconciliation read even with an older poll outstanding");
  await ui.settle(read, supervisedPanel({ live: false }));
  await restarting;
  await ui.settle(oldRead, supervisedPanel());
  await polling;
  assert.equal(ui.el("powerBtn").textContent, "Start Bridge");
  assert.equal(ui.el("powerBtn").disabled, false);
  assert.equal(ui.el("stopBtn").disabled, true);
  assert.match(ui.el("toast").textContent, /unable to start/);
});

test("a failed lifecycle reconciliation leaves mutations unavailable until a fresh poll", async () => {
  const ui = await ready(supervisedPanel());
  const restarting = ui.el("powerBtn").fire("click");
  await ui.settle(ui.pending("start_or_restart_gateway"), "Restart failed", true);
  await ui.settle(ui.pending("get_panel_state"), "State unavailable", true);
  await restarting;
  assert.equal(ui.el("powerBtn").disabled, true);
  assert.equal(ui.el("stopBtn").disabled, true);
  assert.match(ui.el("profileStatus").textContent, /State unavailable/);

  const polling = ui.poll();
  await ui.settle(ui.pending("get_panel_state"), supervisedPanel({ live: false }));
  await polling;
  assert.equal(ui.el("powerBtn").textContent, "Start Bridge");
  assert.equal(ui.el("powerBtn").disabled, false);
});

test("a tray state update supersedes a pending lifecycle response", async () => {
  const ui = await ready(supervisedPanel());
  const stopping = ui.el("stopBtn").fire("click");
  const pending = ui.pending("stop_gateway");
  await ui.emit("workstation-state", supervisedPanel({ canRestart: false, reason: "Owner changed." }));
  assert.equal(ui.el("powerBtn").textContent, "Stopping Bridge…");
  await ui.settle(pending, supervisedPanel({ live: false }));
  await stopping;
  assert.equal(ui.el("powerBtn").textContent, "Restart Bridge");
  assert.equal(ui.el("powerBtn").disabled, true);
  assert.equal(ui.el("stopBtn").disabled, false);
  assert.match(ui.el("externalGatewayNotice").textContent, /Owner changed/);
  assert.doesNotMatch(ui.el("toast").textContent, /stopped/i);
});

test("a lifecycle phase blocks mode, OAuth and extension mutations", async () => {
  const ui = await ready(supervisedPanel());
  await showApprovals(ui, supervisedPanel(), {
    configured: true, origin: "https://example.invalid",
    pending: [{ id: "phase-oauth", provider: "gemini", clientId: "fixture", redirectUri: "https://client.example.invalid/callback" }],
  });
  const phase = supervisedPanel({ phase: "restarting", canStart: false, canStop: false, canRestart: false });
  const polling = ui.poll();
  await ui.settle(ui.pending("get_panel_state"), phase);
  await polling;
  assert.ok(ui.buttons().every((button) => button.disabled));
  assert.equal(ui.el("powerBtn").disabled, true);
  assert.equal(ui.el("stopBtn").disabled, true);
  assert.equal(action(ui, "refuse").disabled, true);
  assert.equal(ui.select('[data-oauth-approve="phase-oauth"]')[0].disabled, true);
  assert.equal(ui.select('[data-oauth-cb="phase-oauth"]')[0].disabled, true);
  const enroll = ui.select('[id="enrollBtn"]')[0];
  assert.equal(enroll.disabled, true);
  const before = ui.calls.length;
  await action(ui, "refuse").fire("click");
  await ui.button("read-only").fire("click");
  await enroll.fire("click");
  assert.equal(ui.calls.length, before);
  assert.match(ui.el("externalGatewayNotice").textContent, /restarting/i);
});

test("an old poll cannot overwrite a successful attached stop", async () => {
  const ui = await ready(supervisedPanel());
  const polling = ui.poll();
  const oldPoll = ui.pending("get_panel_state");
  const stopping = ui.el("stopBtn").fire("click");
  await ui.settle(ui.pending("stop_gateway"), supervisedPanel({ live: false }));
  await stopping;
  await ui.settle(oldPoll, supervisedPanel());
  await polling;
  assert.match(ui.el("powerBtn").textContent, /start/i);
  assert.equal(ui.el("stopBtn").disabled, true);
});

test("tray state events supersede in-flight polls and mode responses", async () => {
  const ui = await ready(supervisedPanel());
  const polling = ui.poll();
  const oldPoll = ui.pending("get_panel_state");
  await ui.emit("workstation-state", supervisedPanel({ live: false }));
  await ui.settle(oldPoll, supervisedPanel());
  await polling;
  assert.match(ui.el("powerBtn").textContent, /start/i);
  await ui.emit("workstation-state", supervisedPanel());
  const changing = ui.button("read-only").fire("click");
  const profileCall = ui.pending("set_permission_profile");
  await ui.emit("workstation-state", supervisedPanel({ live: false }));
  await ui.settle(profileCall, panel("read-only"));
  await ui.settle(ui.pending("get_panel_state"), supervisedPanel({ live: false }));
  await changing;
  assert.deepEqual(ui.active(), []);
  assert.match(ui.el("powerBtn").textContent, /start/i);
  assert.equal(ui.hiddenWindows(), 0);
});

test("tray errors are visible and event support remains optional", async () => {
  const ui = await ready(supervisedPanel());
  await ui.emit("workstation-error", "Supervisor readiness timed out.");
  assert.equal(ui.el("toast").textContent, "Supervisor readiness timed out.");
  assert.equal(ui.hiddenWindows(), 0);
  const legacy = await ready(panel(), { events: false });
  assert.deepEqual(legacy.active(), ["read-only"]);
});

test("failed extension authorization polling preserves typing completed while waiting", async () => {
  const data = extensionPanel({
    request_id: extensionId, status: "awaiting_authorization",
    auth_url: "https://auth.example.invalid/authorize?state=fixture",
  });
  const oauth = {
    configured: true, origin: "https://example.invalid",
    pending: [{ id: "oauth-error-fixture", provider: "gemini", clientId: "client-fixture", redirectUri: "https://client.example.invalid/callback" }],
  };
  const ui = await ready(data);
  await showApprovals(ui, data, oauth);
  const input = ui.select('[data-oauth-cb="oauth-error-fixture"]')[0];
  input.value = "https://client.example.invalid/partial";
  const polling = ui.runTimer(1000);
  input.value = "https://client.example.invalid/callback?state=latest-before-error";
  await ui.settle(ui.pending("get_panel_state"), data);
  await ui.settle(ui.pending("get_oauth_pending"), "Fixture refresh failed.", true);
  await polling;
  const refresh = ui.el("refreshApprovalsBtn").fire("click");
  await ui.settle(ui.pending("get_oauth_pending"), oauth);
  await ui.settle(ui.pending("get_panel_state"), data);
  await refresh;
  assert.equal(ui.select('[data-oauth-cb="oauth-error-fixture"]')[0].value, input.value);
});

test("extension token badges describe local token state without claiming a provider connection", async () => {
  for (const [status, label, enabled] of [
    [{ token_stored: true, token_expired: false }, "Token stored", true],
    [{ token_stored: true, token_expired: true }, "Token expired", false],
    [{ token_stored: false, token_expired: false }, "No token", true],
    [undefined, "Token status unavailable", false],
    [null, "Token status unavailable", false],
    [{}, "Token status unavailable", true],
    [false, "Token status unavailable", false],
    ["unavailable", "Token status unavailable", true],
    [[], "Token status unavailable", false],
    [{ token_stored: "false", token_expired: false }, "Token status unavailable", true],
    [{ token_stored: 0, token_expired: false }, "Token status unavailable", false],
    [{ token_stored: true, token_expired: null }, "Token status unavailable", true],
    [{ token_stored: true }, "Token status unavailable", false],
  ]) {
    const data = extensionPanel(null, {
      servers: [{ id: "fixture", enabled, endpoint: "https://mcp.example.invalid/api" }],
      requests: [],
      outboundOauth: { fixture: { tokenStatus: status } },
    });
    const ui = await ready(data);
    await showApprovals(ui, data);
    const content = ui.el("approvalsBody").innerHTML;
    assert.ok(content.includes(">" + label + "</span>"), label);
    assert.ok(content.includes(">" + (enabled ? "On" : "Off") + "</span>"));
    assert.doesNotMatch(content, />Connected<|>Disconnected</);
  }
});

test("lost live mode reply reconciles committed Unlock before allowing an immediate return to Read", async () => {
  const ui = await ready();
  const changing = ui.button("fully-unlocked").fire("click");
  await ui.settle(ui.pending("set_permission_profile"), "Reply interrupted", true);
  const read = ui.pending("get_panel_state");
  assert.ok(ui.buttons().every((button) => button.disabled));
  await ui.settle(read, panel("fully-unlocked"));
  await changing;
  assert.deepEqual(ui.active(), ["fully-unlocked"]);
  const restore = ui.button("read-only").fire("click");
  const call = ui.pending("set_permission_profile");
  assert.equal(call.args.profile, "read-only");
  await ui.settle(call, panel("read-only"));
  await restore;
  assert.deepEqual(ui.active(), ["read-only"]);
});

test("failed live mode reconciliation shows unknown until an authoritative refresh", async () => {
  const ui = await ready();
  const changing = ui.button("fully-unlocked").fire("click");
  await ui.settle(ui.pending("set_permission_profile"), "Reply interrupted", true);
  await ui.settle(ui.pending("get_panel_state"), "State unavailable", true);
  await changing;
  assert.deepEqual(ui.active(), []);
  assert.ok(ui.buttons().every((button) => button.disabled));
  const poll = ui.poll();
  await ui.settle(ui.pending("get_panel_state"), panel("fully-unlocked"));
  await poll;
  assert.deepEqual(ui.active(), ["fully-unlocked"]);
});

test("a newer tray snapshot supersedes mode error reconciliation", async () => {
  const ui = await ready();
  const changing = ui.button("fully-unlocked").fire("click");
  await ui.settle(ui.pending("set_permission_profile"), "Reply interrupted", true);
  const read = ui.pending("get_panel_state");
  await ui.emit("workstation-state", panel("workspace-write"));
  await ui.settle(read, panel("fully-unlocked"));
  await changing;
  assert.deepEqual(ui.active(), ["workspace-write"]);
});

test("a tray error preceding a lost mode reply cannot confirm pre-commit Read", async () => {
  const ui = await ready();
  const changing = ui.button("fully-unlocked").fire("click");
  const update = ui.pending("set_permission_profile");
  await ui.emit("workstation-error", "Tray operation failed");
  const earlyRead = ui.calls.find((call) => call.command === "get_panel_state" && !call.settled);
  if (earlyRead) await ui.settle(earlyRead, panel("read-only"));

  await ui.settle(update, "Reply interrupted", true);
  const reconciliation = ui.pending("get_panel_state");
  assert.deepEqual(ui.active(), []);
  assert.ok(ui.buttons().every((button) => button.disabled));
  assert.equal(earlyRead, undefined);
  await ui.settle(reconciliation, panel("fully-unlocked"));
  await changing;
  assert.deepEqual(ui.active(), ["fully-unlocked"]);

  const restoring = ui.button("read-only").fire("click");
  await ui.settle(ui.pending("set_permission_profile"), panel("read-only"));
  await restoring;
  assert.deepEqual(ui.active(), ["read-only"]);
});

test("a tray snapshot before a lost mode reply requires a post-commit read", async () => {
  const ui = await ready();
  const changing = ui.button("fully-unlocked").fire("click");
  await ui.emit("workstation-state", panel("read-only"));
  await ui.settle(ui.pending("set_permission_profile"), "Reply interrupted", true);
  const reconciliation = ui.pending("get_panel_state");
  assert.deepEqual(ui.active(), []);
  assert.ok(ui.buttons().every((button) => button.disabled));
  await ui.settle(reconciliation, "State unavailable", true);
  await changing;
  assert.deepEqual(ui.active(), []);
  assert.ok(ui.buttons().every((button) => button.disabled));
});

test("a tray error during mode reconciliation keeps the guard through a replacement read", async () => {
  const ui = await ready();
  const changing = ui.button("fully-unlocked").fire("click");
  await ui.settle(ui.pending("set_permission_profile"), "Reply interrupted", true);
  const old = ui.pending("get_panel_state");
  await ui.emit("workstation-error", "Tray operation failed");
  await ui.settle(old, panel("read-only"));
  const newer = ui.pending("get_panel_state");
  assert.ok(ui.buttons().every((button) => button.disabled));
  await ui.settle(newer, panel("fully-unlocked"));
  await changing;
  assert.deepEqual(ui.active(), ["fully-unlocked"]);
});

function nativePanel(activeProfile = "read-only", generation = 1, controls = {}) {
  const data = panel(activeProfile);
  data.gateway = {
    live: true, external: false, native: true, ownedRunning: true,
    port: 18856, generation, controls: {
      canStart: false, canStop: true, canRestart: true, phase: null, reason: null, ...controls,
    },
  };
  data.tunnel = { configured: true, childRunning: true, state: "running", remoteReady: null, error: null };
  return data;
}

test("native workstation configuration stays authoritative for runtime paths and initialization", async () => {
  const ui = await ready(nativePanel());
  for (const id of ["initStateBtn", "quickWorkspaceBtn", "savePathsBtn", "saveOauthBtn", "inputGatewayPort"]) {
    assert.equal(ui.el(id).disabled, true, id);
  }
  assert.equal(ui.button("workspace-write").disabled, false);
  assert.equal(ui.el("stopBtn").disabled, false);
});

test("an older native generation cannot replace the current profile or lifecycle controls", async () => {
  const ui = await ready(nativePanel("read-only", 2));
  await ui.emit("workstation-state", nativePanel("fully-unlocked", 1, { canStop: false, canRestart: false }));
  assert.deepEqual(ui.active(), ["read-only"]);
  assert.equal(ui.el("stopBtn").disabled, false);
});

test("native tunnel liveness is displayed without claiming remote connectivity", async () => {
  const ui = await ready(nativePanel());
  assert.equal(ui.el("externalGatewayNotice").classList.contains("hidden"), false);
  assert.match(ui.el("externalGatewayNotice").textContent, /tunnel.*running/i);
  assert.match(ui.el("externalGatewayNotice").textContent, /remote.*(unverified|not verified)/i);
});

test("Quit reports incomplete cleanup and keeps the panel usable for recovery", async () => {
  const ui = await ready(nativePanel());
  let rejection;
  const quitting = ui.el("quitAppBtn").fire("click").catch((error) => { rejection = error; });
  await ui.settle(ui.pending("quit_app"), "Owned cleanup is incomplete", true);
  const refresh = ui.calls.find((call) => call.command === "get_panel_state" && !call.settled);
  if (refresh) await ui.settle(refresh, nativePanel("read-only", 1, {
    canStart: false, canRestart: false, canStop: true, reason: "Owned cleanup is incomplete",
  }));
  await quitting;
  assert.equal(rejection, undefined, "Quit errors must be handled by the panel");
  assert.match(ui.el("toast").textContent, /cleanup is incomplete/i);
  assert.equal(ui.el("powerBtn").disabled, true);
});

test("an older same-generation tunnel notification cannot replace a confirmed native mode", async () => {
  const ui = await ready(nativePanel("read-only", 7));
  const changing = ui.button("workspace-write").fire("click");
  await ui.settle(ui.pending("set_permission_profile"), nativePanel("workspace-write", 7));
  await changing;
  await ui.emit("workstation-state", nativePanel("read-only", 7));
  assert.deepEqual(ui.active(), ["workspace-write"], "notifications must not install their cached profile");
  await ui.settle(ui.pending("get_panel_state"), nativePanel("workspace-write", 7));
  assert.deepEqual(ui.active(), ["workspace-write"]);
});

test("native invalidation during a mutation waits for a post-mutation authority read", async () => {
  const ui = await ready(nativePanel("read-only", 7));
  const changing = ui.button("workspace-write").fire("click");
  await ui.emit("workstation-state", nativePanel("fully-unlocked", 7));
  assert.deepEqual(ui.active(), ["read-only"], "an event payload cannot assert a mode during an in-flight mutation");
  assert.equal(ui.calls.some((call) => call.command === "get_panel_state" && !call.settled), false);
  await ui.settle(ui.pending("set_permission_profile"), nativePanel("workspace-write", 7));
  const confirmedRead = ui.pending("get_panel_state");
  assert.ok(ui.buttons().every((button) => button.disabled));
  await ui.settle(confirmedRead, nativePanel("workspace-write", 7));
  await changing;
  assert.deepEqual(ui.active(), ["workspace-write"]);
});

test("native invalidations discard an older in-flight read before refreshing again", async () => {
  const ui = await ready(nativePanel("workspace-write", 7));
  await ui.emit("workstation-state", nativePanel("read-only", 7));
  const obsolete = ui.pending("get_panel_state");
  await ui.emit("workstation-state", nativePanel("fully-unlocked", 8));
  await ui.settle(obsolete, nativePanel("read-only", 7));
  assert.deepEqual(ui.active(), ["workspace-write"], "a read predating the latest invalidation must be discarded");
  await ui.settle(ui.pending("get_panel_state"), nativePanel("fully-unlocked", 8));
  assert.deepEqual(ui.active(), ["fully-unlocked"]);
});

test("a confirmed native Stop is displayed as stopped without a connection error", async () => {
  const stopped = nativePanel("read-only", 7, { canStart: true, canStop: false, canRestart: false });
  stopped.gateway.live = false;
  stopped.gateway.ownedRunning = false;
  stopped.gateway.stopped = true;
  stopped.liveProfile = { configured: true, connected: false, activeProfile: null,
    maxProfile: null, availableProfiles: [], error: null };
  stopped.tunnel.childRunning = false;
  stopped.tunnel.state = "stopped";
  const ui = await ready(stopped);
  assert.equal(ui.el("liveText").textContent, "Off");
  assert.equal(ui.el("gwStatus").textContent, "Stopped");
  assert.equal(ui.el("profileStatus").classList.contains("error"), false);
  assert.match(ui.el("externalGatewayNotice").textContent, /Bridge is stopped/);
  assert.equal(ui.el("powerBtn").disabled, false);
  assert.ok(ui.buttons().every((button) => button.disabled));
});

function nativeApprovalsPanel(operation = null, activeProfile = "fully-unlocked") {
  const data = extensionPanel(operation);
  const native = nativePanel(activeProfile, 7);
  data.gateway = native.gateway;
  data.tunnel = native.tunnel;
  data.liveProfile = native.liveProfile;
  return data;
}

test("native invalidation replaces both reads of the active Approvals page", async () => {
  const data = nativeApprovalsPanel(null, "workspace-write");
  const ui = await ready(data);
  await ui.el("approvalsNavBtn").fire("click");
  const oldOAuth = ui.pending("get_oauth_pending");
  const oldPanel = ui.pending("get_panel_state");
  await ui.emit("workstation-state", nativePanel("read-only", 7));
  await ui.settle(oldOAuth, { configured: true, pending: [] });
  await ui.settle(oldPanel, data);
  const replacementOAuth = ui.calls.find((call) => call.command === "get_oauth_pending" && !call.settled);
  assert.ok(replacementOAuth, "the invalidated OAuth read needs a replacement together with the panel");
  await ui.settle(replacementOAuth, { configured: true, origin: "https://example.invalid", pending: [] });
  await ui.settle(ui.pending("get_panel_state"), data);
  assert.doesNotMatch(ui.el("approvalsBody").innerHTML, /Checking requests/);
  assert.match(ui.el("approvalsBody").innerHTML, /No pending connection requests/);
  assert.deepEqual(ui.active(), ["workspace-write"]);
  assert.equal(action(ui, "approve").disabled, true, "a refresh cannot grant proposal review consent");
  assert.equal(ui.calls.filter((call) => call.command === "decide_extension_request").length, 0);
});

test("native invalidation renews OAuth polling and preserves typed callback drafts", async () => {
  const operation = { request_id: extensionId, status: "awaiting_authorization",
    auth_url: "https://auth.example.invalid/authorize?state=fixture" };
  const data = nativeApprovalsPanel(operation);
  const oauth = { configured: true, origin: "https://example.invalid",
    pending: [{ id: "oauth-native", provider: "chatgpt", clientId: "native-client",
      redirectUri: "https://client.example.invalid/callback" }] };
  const ui = await ready(data);
  await showApprovals(ui, data, oauth);
  const input = ui.select('[data-oauth-cb="oauth-native"]')[0];
  input.value = "https://client.example.invalid/partial";
  const polling = ui.runTimer(1000);
  const oldOAuth = ui.pending("get_oauth_pending");
  const oldPanel = ui.pending("get_panel_state");
  input.value = "https://client.example.invalid/callback?state=typed-during-poll";
  await ui.emit("workstation-state", nativePanel("read-only", 7));
  await ui.settle(oldOAuth, oauth);
  await ui.settle(oldPanel, data);
  await polling;
  const replacementOAuth = ui.calls.find((call) => call.command === "get_oauth_pending" && !call.settled);
  assert.ok(replacementOAuth, "the invalidated authorization poll must be replaced");
  await ui.settle(replacementOAuth, oauth);
  await ui.settle(ui.pending("get_panel_state"), data);
  assert.equal(ui.select('[data-oauth-cb="oauth-native"]')[0].value, input.value);
  assert.ok(ui.timer(1000), "the current operation must retain a next status poll");
  assert.deepEqual(ui.openedUrls, []);
  assert.equal(ui.calls.filter((call) => ["approve_oauth_request", "decide_extension_request"].includes(call.command)).length, 0);
});

test("native Approvals invalidation during a mode mutation is reconciled after confirmation", async () => {
  const data = nativeApprovalsPanel(null, "read-only");
  const updated = nativeApprovalsPanel(null, "workspace-write");
  const ui = await ready(data);
  await showApprovals(ui, data);
  const changing = ui.button("workspace-write").fire("click");
  await ui.emit("workstation-state", nativePanel("fully-unlocked", 7));
  assert.equal(ui.calls.some((call) => call.command === "get_oauth_pending" && !call.settled), false);
  await ui.settle(ui.pending("set_permission_profile"), updated);
  await ui.settle(ui.pending("get_panel_state"), updated);
  await changing;
  const replacementOAuth = ui.calls.find((call) => call.command === "get_oauth_pending" && !call.settled);
  assert.ok(replacementOAuth, "deferred active-page reconciliation must resume after the mutation");
  await ui.settle(replacementOAuth, { configured: true, pending: [] });
  await ui.settle(ui.pending("get_panel_state"), updated);
  assert.deepEqual(ui.active(), ["workspace-write"]);
  assert.equal(action(ui, "approve").disabled, true);
});


test("open Tasks page refreshes automatically and shows real task progress", async () => {
  const ui = await ready();
  const snapshot = (completed) => ({ configured: true, exists: true, missions: [],
    task_rooms: [{ title: "Local work", status: "active", steps_completed: completed, steps_total: 4 }] });
  await ui.el("missionsNavBtn").fire("click");
  await ui.settle(ui.pending("get_missions_snapshot"), snapshot(1));
  assert.match(ui.el("missionsBody").innerHTML, /value="1"/);
  const refresh = ui.runTimer(3000);
  assert.match(ui.el("missionsBody").innerHTML, /value="1"/);
  await ui.settle(ui.pending("get_missions_snapshot"), snapshot(3));
  await refresh;
  assert.match(ui.el("missionsBody").innerHTML, /value="3"/);
  assert.ok(ui.timer(3000));
});

test("late Tasks refresh cannot replace newer manual results", async () => {
  const ui = await ready();
  const snapshot = (goal) => ({ configured: true, exists: true, missions: [
    { mission_id: "fixture", status: "active", goal }], task_rooms: [] });
  await ui.el("missionsNavBtn").fire("click");
  await ui.settle(ui.pending("get_missions_snapshot"), snapshot("Initial"));
  const passive = ui.runTimer(3000);
  const old = ui.pending("get_missions_snapshot");
  const manual = ui.el("refreshMissionsBtn").fire("click");
  const newer = ui.calls.filter((call) => call.command === "get_missions_snapshot" && !call.settled).at(-1);
  await ui.settle(newer, snapshot("Newest"));
  await manual;
  await ui.settle(old, snapshot("Obsolete"));
  await passive;
  assert.match(ui.el("missionsBody").innerHTML, /Newest/);
  assert.doesNotMatch(ui.el("missionsBody").innerHTML, /Obsolete/);
});

test("Approvals refreshes automatically without granting consent or losing drafts", async () => {
  const data = extensionPanel();
  const oauth = { configured: true, origin: "https://example.invalid", pending: [
    { id: "request-live", provider: "gemini", clientId: "fixture", redirectUri: "https://client.example.invalid/callback" }] };
  const ui = await ready(data);
  await showApprovals(ui, data, oauth);
  const input = ui.select('[data-oauth-cb="request-live"]')[0];
  input.value = "https://client.example.invalid/callback?state=typed";
  const review = ui.select("[data-ext-review]")[0];
  review.checked = true;
  await review.fire("change");
  const unchanged = ui.runTimer(3000);
  await ui.settle(ui.pending("get_oauth_pending"), oauth);
  await ui.settle(ui.pending("get_panel_state"), data);
  await unchanged;
  assert.equal(ui.select("[data-ext-review]")[0], review);
  assert.equal(ui.select('[data-oauth-cb="request-live"]')[0].value, input.value);
  const changed = ui.runTimer(3000);
  const replacement = extensionPanel(null, { requests: [
    { ...data.extensions.requests[0], revision: 4, payload: { url: "https://other.example.invalid/mcp" } }] });
  await ui.settle(ui.pending("get_oauth_pending"), oauth);
  await ui.settle(ui.pending("get_panel_state"), replacement);
  await changed;
  assert.equal(action(ui, "approve").disabled, true);
  assert.equal(ui.select('[data-oauth-cb="request-live"]')[0].value, input.value);
  assert.match(ui.el("approvalsBody").innerHTML, /other.example.invalid/);
  assert.equal(ui.calls.filter((call) => /^(approve_oauth_request|decide_extension_request)$/.test(call.command)).length, 0);
});

test("Settings diagnostics refresh while open and stop polling after leaving", async () => {
  const ui = await ready();
  await ui.el("settingsNavBtn").fire("click");
  await ui.settle(ui.pending("get_diagnostics"), { oauthKeystore: "Protected", mcpBrowserProfiles: [] });
  await ui.settle(ui.pending("get_skills_overview"), { skills: [] });
  const refresh = ui.runTimer(3000);
  await ui.settle(ui.pending("get_diagnostics"), { oauthKeystore: "Protected", mcpBrowserProfiles: [{}] });
  await ui.settle(ui.pending("get_skills_overview"), { skills: [{ name: "fixture-skill" }] });
  await refresh;
  assert.match(ui.el("skillsAndDiagBox").innerHTML, /fixture-skill/);
  await ui.select("[data-back]")[0].fire("click");
  assert.equal(ui.timer(3000), undefined);
});
