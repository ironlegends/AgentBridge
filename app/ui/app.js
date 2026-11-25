(function () {
  "use strict";

  const invoke = window.__TAURI__.core.invoke;
  const currentWindow = window.__TAURI__.window.getCurrentWindow();

  const PROFILES = ["read-only", "workspace-write", "full-control", "fully-unlocked"];
  const PROFILE_META = {
    "read-only": {
      badge: "READ",
      cls: "",
      hint: "Safe: AI can only view files in your folder",
    },
    "workspace-write": {
      badge: "WRITE",
      cls: "",
      hint: "Edit: AI can read and edit files in your folder",
    },
    "full-control": {
      badge: "FULL",
      cls: "warn",
      hint: "Advanced: adds approved commands & window controls",
    },
    "fully-unlocked": {
      badge: "UNLOCK",
      cls: "danger",
      hint: "Unrestricted: full local access for this session",
    },
  };
  const THEMES = ["system", "light", "dark"];

  let state = null;
  let profileChanging = false;
  let panelBusy = false;
  let panelRefreshNeeded = false;
  let nativeApprovalsRefreshNeeded = false;
  let pendingLifecyclePhase = null;
  let stateGeneration = 0;
  let nextStateRead = 0;
  let lastStateRead = 0;
  let refreshInFlight = false;
  let stateError = "";
  let profileError = "";
  const dirtyInputs = new Set();
  const settingInputs = [
    "inputDbPath", "inputSettingsDir", "inputGatewayPort",
    "inputOauthDir", "inputOauthOrigin", "inputOauthAudience",
  ];
  let pendingElevatedProfile = null;
  let onboardingProfile = "read-only";
  let activePage = "pageMain";
  let approvalsRead = 0;
  let extensionDecisionInFlight = false;
  let extensionPollTimer = null;
  let extensionPollRequest = null;
  let extensionPollDeadline = 0;
  const oauthCallbackDrafts = new Map();

  const $ = (id) => document.getElementById(id);

  function escapeHtml(val) {
    return String(val ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function renderCapability(capability) {
    const marker = capability || { kind: "legacy" };
    const title = marker.kind === "unified-v1" ? "Unified tools · policy " + marker.policy_version
      : marker.kind === "legacy" ? "Legacy tools" : "Unknown contract";
    return '<details class="extension-proposal"><summary>Contract: ' + escapeHtml(title) +
      '</summary><pre class="extension-payload">' +
      escapeHtml(JSON.stringify(marker, null, 2)) + '</pre></details>';
  }

  function renderCapabilitySelection(selection, reviewedCapability) {
    if (!selection || !selection.identity) return "";
    if (reviewedCapability) {
      const keys = ["kind", "manifest_sha256", "catalogue_sha256", "policy_version"];
      if (keys.some((key) => reviewedCapability[key] !== selection.identity[key])) return "";
    }
    const scope = selection.filesystem && selection.filesystem.kind;
    const scopeLabels = {
      workspace: "Selected workspace",
      "allowed-roots": "Selected folders",
      "os-user": "Current Windows user; paths outside the workspace require Unlock",
    };
    const count = Number.isInteger(selection.total_tools) ? selection.total_tools : null;
    let html = '<div class="item-meta">';
    if (count !== null) html += '<strong>' + count + ' tools</strong>';
    if (scopeLabels[scope]) html += (count !== null ? " · " : "") + escapeHtml(scopeLabels[scope]);
    html += "</div>";
    if (typeof selection.allow_import === "boolean") {
      html += '<div class="item-meta">Historical Task Room import: ' +
        (selection.allow_import ? "locally authorized" : "disabled") + "</div>";
    }
    return html + '<details class="extension-proposal"><summary>Selected permissions and resources</summary>' +
      '<pre class="extension-payload">' + escapeHtml(JSON.stringify(selection, null, 2)) + "</pre></details>";
  }

  function showToast(msg) {
    const el = $("toast");
    el.textContent = msg;
    el.classList.remove("hidden");
    clearTimeout(el._t);
    el._t = setTimeout(() => el.classList.add("hidden"), 3800);
  }

  function applyTheme(theme) {
    const mode = THEMES.includes(theme) ? theme : "system";
    document.documentElement.setAttribute("data-theme", mode);
    const idx = THEMES.indexOf(mode);
    $("themeIndicator").style.transform = "translateX(" + (idx * 100) + "%)";
    document.querySelectorAll("[data-theme-choice]").forEach((btn) => {
      btn.classList.toggle("active", btn.getAttribute("data-theme-choice") === mode);
    });
  }

  function isNative(data = state) {
    return Boolean(data && data.gateway && data.gateway.native);
  }

  function isNativeStopped(data = state) {
    return isNative(data) && data.gateway.stopped === true
      && !data.gateway.live && !data.gateway.ownedRunning;
  }

  function usesLiveWorkstation(data = state) {
    return isNative(data) || Boolean(data && data.gateway && data.gateway.external);
  }

  function isStaleNativeSnapshot(data) {
    return isNative(data) && isNative(state)
      && Number.isSafeInteger(data.gateway.generation)
      && Number.isSafeInteger(state.gateway.generation)
      && data.gateway.generation < state.gateway.generation;
  }

  function gatewayControls(data = state) {
    const gateway = data && data.gateway || {};
    const controls = gateway.controls;
    const phase = pendingLifecyclePhase || controls?.phase || null;
    if (controls) return {
      canStart: controls.canStart === true,
      canStop: controls.canStop === true,
      canRestart: controls.canRestart === true,
      phase,
      reason: controls.reason || "",
    };
    const managed = Boolean(data && !usesLiveWorkstation(data));
    return {
      canStart: managed && !gateway.live,
      canStop: managed && Boolean(gateway.ownedRunning),
      canRestart: managed && Boolean(gateway.live),
      phase,
      reason: usesLiveWorkstation(data) ? "The external owner controls this service." : "",
    };
  }

  function mutationsBlocked() {
    return !state || panelBusy || profileChanging || extensionDecisionInFlight
      || Boolean(stateError) || Boolean(gatewayControls().phase);
  }

  function operatorMutationsBlocked() {
    return mutationsBlocked() || (hasLiveProfile()
      && (!state.liveProfile || !state.liveProfile.connected));
  }

  function hasLiveProfile(data = state) {
    return usesLiveWorkstation(data) || Boolean(data && data.liveProfile && data.liveProfile.configured);
  }

  function applyProfileVisual(profile) {
    const known = PROFILES.includes(profile);
    const idx = PROFILES.indexOf(profile);
    $("profileIndicator").classList.toggle("hidden", !known);
    if (known) $("profileIndicator").style.transform = "translateX(" + (idx * 100) + "%)";
    document.querySelectorAll("[data-profile]").forEach((btn) => {
      const active = known && btn.getAttribute("data-profile") === profile;
      btn.classList.toggle("active", active);
      btn.setAttribute("aria-pressed", String(active));
    });
    const meta = known ? PROFILE_META[profile] : null;
    $("profileBadge").textContent = meta ? meta.badge : "-";
    $("profileBadge").className = "profile-badge " + (meta ? meta.cls : "");
    $("profileHint").textContent = meta ? meta.hint : "Waiting for the active session";
  }

  function renderProfileControl() {
    const configured = hasLiveProfile();
    const runtime = state && state.liveProfile;
    const connected = configured && !stateError && runtime && runtime.connected
      && PROFILES.includes(runtime.activeProfile) && PROFILES.includes(runtime.maxProfile);
    const active = configured
      ? (connected ? runtime.activeProfile : null)
      : (state && !stateError ? state.settings.profile : null);
    applyProfileVisual(active);
    $("profileTitle").textContent = configured ? "Active mode" : "Saved preference";
    $("profileCeiling").classList.toggle("hidden", !configured);
    $("profileCeiling").textContent = connected
      ? "Session ceiling: " + PROFILE_META[runtime.maxProfile].badge
      : "Session ceiling unavailable";
    const error = stateError || profileError || (runtime && runtime.error);
    const phase = gatewayControls().phase;
    $("profileStatus").textContent = phase
      ? "Bridge is " + phase + ". Mode changes are unavailable."
      : profileChanging ? "Applying mode…"
      : (error || (configured
        ? (connected ? "Changes apply immediately. Your connection stays open."
          : isNativeStopped() ? "Bridge is stopped. Start it to change the active mode." : "Waiting for the running Bridge.")
        : (state ? "Attach a workstation session to apply a mode live." : "Connecting to Agent Bridge…")));
    $("profileStatus").classList.toggle("error", Boolean(error && !profileChanging));
    $("profileSelector").setAttribute("aria-busy", String(profileChanging));
    document.querySelectorAll("[data-profile]").forEach((btn) => {
      const profile = btn.getAttribute("data-profile");
      const allowed = connected && Array.isArray(runtime.availableProfiles)
        && runtime.availableProfiles.includes(profile)
        && PROFILES.indexOf(profile) <= PROFILES.indexOf(runtime.maxProfile);
      btn.disabled = mutationsBlocked() || (configured && !allowed);
      btn.title = configured && !connected
        ? "The running Bridge is unavailable"
        : (configured && !allowed
          ? "Unavailable above this session's ceiling"
          : PROFILE_META[profile].hint);
    });
  }

  function renderControls() {
    const external = usesLiveWorkstation();
    const controls = gatewayControls();
    const busy = mutationsBlocked();
    const live = Boolean(state && state.gateway && state.gateway.live);
    const localControls = [
      "initStateBtn", "quickWorkspaceBtn", "chooseWorkspaceBtn",
      "pickOauthDirBtn", "savePathsBtn", "saveOauthBtn",
      "obPickWorkspaceBtn", "obNext1Btn", "obNext2Btn", "obFinishBtn",
      ...settingInputs,
    ];
    localControls.forEach((id) => { $(id).disabled = busy || external; });
    document.querySelectorAll("[data-theme-choice]").forEach((btn) => { btn.disabled = busy; });
    document.querySelectorAll("[data-recent]").forEach((btn) => { btn.disabled = busy || external; });
    document.querySelectorAll("[data-skill-rb]").forEach((btn) => { btn.disabled = operatorMutationsBlocked(); });
    $("powerBtn").disabled = busy || !(live ? controls.canRestart : controls.canStart);
    $("stopBtn").disabled = busy || !controls.canStop;
    $("powerBtn").textContent = controls.phase
      ? ({ starting: "Starting Bridge…", stopping: "Stopping Bridge…", restarting: "Restarting Bridge…" }[controls.phase] || "Bridge is busy…")
      : (live ? "Restart Bridge" : "Start Bridge");
    $("gatewayActions").classList.toggle("hidden", external
      && !controls.canStart && !controls.canStop && !controls.canRestart && !controls.phase);
    $("stopBtn").classList.toggle("hidden", !controls.canStop
      && controls.phase !== "stopping" && controls.phase !== "restarting");
    $("externalGatewayNotice").classList.toggle("hidden", !external);
    const notice = [];
    if (controls.phase) notice.push("Bridge is " + controls.phase + ". Other changes are unavailable.");
    else if (isNativeStopped() && !stateError) notice.push("Bridge is stopped.");
    else if (!state || !state.liveProfile || !state.liveProfile.connected || stateError) {
      notice.push("The configured session is unavailable.");
    } else notice.push(isNative()
      ? "This application manages the running Bridge."
      : "Attached to the running Bridge. The session stays open independently.");
    if (isNative() && state.tunnel && state.tunnel.configured) {
      if (state.tunnel.error) notice.push("Tunnel unavailable: " + state.tunnel.error);
      else if (state.tunnel.childRunning) notice.push("Tunnel running. Remote connectivity not verified.");
      else notice.push("Tunnel stopped. Remote connectivity unavailable.");
    }
    $("quitAppBtn").textContent = isNative() ? "Quit and stop Bridge" : "Quit";
    if (controls.reason) notice.push(controls.reason);
    if (controls.canStart || controls.canRestart) {
      notice.push("Starting or restarting uses the configured startup profile.");
    }
    $("externalGatewayNotice").textContent = notice.join(" ");
    renderProfileControl();
    renderExtensionControls();
  }

  function setInputValue(id, value) {
    if (!dirtyInputs.has(id)) $(id).value = value;
  }

  async function runPanelAction(command, args, { clearInputs = [], lifecyclePhase = null } = {}) {
    if (mutationsBlocked()) return null;
    panelBusy = true;
    pendingLifecyclePhase = lifecyclePhase;
    const generation = ++stateGeneration;
    approvalsRead++;
    renderControls();
    try {
      const result = await invoke(command, args);
      if (generation !== stateGeneration || isStaleNativeSnapshot(result)) return null;
      clearInputs.forEach((id) => dirtyInputs.delete(id));
      stateError = "";
      renderMain(command === "initialize_local_state" ? result.state : result);
      return result;
    } catch (err) {
      if (generation === stateGeneration) {
        showToast(String(err));
        if (lifecyclePhase) panelRefreshNeeded = true;
      }
      return null;
    } finally {
      while (panelRefreshNeeded) {
        panelRefreshNeeded = false;
        await readPanelState();
      }
      stateGeneration++;
      panelBusy = false;
      pendingLifecyclePhase = null;
      renderControls();
      resumeNativeApprovalsRefresh();
    }
  }

  async function changeProfile(target) {
    if (mutationsBlocked()) return;
    const button = Array.from(document.querySelectorAll("[data-profile]"))
      .find((btn) => btn.getAttribute("data-profile") === target);
    if (!button || button.disabled) return;
    const runtime = state.liveProfile;
    const liveChange = hasLiveProfile();
    const active = liveChange ? runtime && runtime.activeProfile : state.settings.profile;
    if (active === target) return;
    profileChanging = true;
    profileError = "";
    const generation = ++stateGeneration;
    approvalsRead++;
    renderControls();
    try {
      const updated = await invoke("set_permission_profile", { profile: target, confirmed: true });
      if (generation !== stateGeneration || isStaleNativeSnapshot(updated)) {
        if (liveChange) panelRefreshNeeded = true;
        return;
      }
      stateError = "";
      renderMain(updated);
      const confirmed = hasLiveProfile(updated)
        ? updated.liveProfile && updated.liveProfile.connected && updated.liveProfile.activeProfile
        : updated.settings.profile;
      if (confirmed === target) {
        showToast(hasLiveProfile(updated)
          ? "Access switched to " + PROFILE_META[target].badge + "."
          : "Mode preference saved.");
      } else {
        profileError = "The running Bridge has not confirmed this mode.";
      }
    } catch (err) {
      if (!liveChange && generation !== stateGeneration) return;
      profileError = String(err);
      showToast(profileError);
      if (liveChange) panelRefreshNeeded = true;
    } finally {
      // An event received before the profile request settled can predate its commit.
      while (panelRefreshNeeded) {
        panelRefreshNeeded = false;
        stateGeneration++;
        stateError = "Confirming the active mode with the running Bridge.";
        renderMain(state);
        await readPanelState();
      }
      if (generation === stateGeneration) stateGeneration++;
      profileChanging = false;
      renderControls();
      resumeNativeApprovalsRefresh();
    }
  }

  function showPage(pageId) {
    activePage = pageId;
    if (pageId !== "pageApprovals") {
      clearTimeout(extensionPollTimer);
      extensionPollTimer = null;
      approvalsRead++;
      nativeApprovalsRefreshNeeded = false;
    }
    document.querySelectorAll(".page").forEach((el) => {
      el.classList.toggle("active", el.id === pageId);
    });
  }

  async function pickFolder(title) {
    try {
      if (window.__TAURI__.dialog && window.__TAURI__.dialog.open) {
        const selected = await window.__TAURI__.dialog.open({
          directory: true,
          multiple: false,
          title: title || "Choose folder",
        });
        return typeof selected === "string" ? selected : null;
      }
    } catch (err) {
      showToast("Folder picker error: " + err);
    }
    return null;
  }

  async function chooseAndSaveWorkspace() {
    if (usesLiveWorkstation() || panelBusy || profileChanging) return;
    const dir = await pickFolder("Choose Your Folder");
    if (!dir || !state || usesLiveWorkstation()) return;
    const next = Object.assign({}, state.settings, { workspace: dir });
    if (await runPanelAction("save_panel_settings", { settings: next })) {
      showToast("Folder updated.");
    }
  }

  function renderMain(data) {
    if (isStaleNativeSnapshot(data)) return;
    state = data;
    const s = data.settings;
    applyTheme(s.theme);

    const unavailable = Boolean(stateError) || (usesLiveWorkstation(data) && !isNativeStopped(data)
      && (!data.liveProfile || !data.liveProfile.connected));
    const live = !unavailable && Boolean(data.gateway && data.gateway.live);
    $("livePill").className = "live-pill " + (live ? "live" : "standby");
    $("liveDot").className = "dot " + (live ? "ok" : "");
    $("liveText").textContent = unavailable ? "Unavailable" : (live ? "Live" : "Off");

    $("gwDot").className = "dot " + (live ? "ok" : "warn");
    $("gwStatus").textContent = live
      ? "Port " + data.gateway.port
      : (unavailable ? "Unavailable" : "Stopped");

    const activeMissions = data.database && data.database.activeMissions ? data.database.activeMissions : 0;
    const pendingTotal = data.pendingApprovalsTotal || 0;
    $("relDot").className = "dot " + (pendingTotal > 0 ? "warn" : (activeMissions > 0 ? "ok" : ""));
    $("relStatus").textContent = pendingTotal > 0
      ? pendingTotal + " waiting"
      : (activeMissions > 0 ? activeMissions + " active" : "Idle");

    $("scopePath").textContent = s.workspace || "No folder chosen";
    $("scopePill").textContent = data.oauth && data.oauth.configured ? "Web Ready" : "Local";
    $("versionMeta").textContent = "v" + data.version + " | Runs privately on this PC";

    const badge = $("approvalsBadge");
    if (pendingTotal > 0) {
      badge.textContent = String(pendingTotal);
      badge.classList.remove("hidden");
    } else {
      badge.classList.add("hidden");
    }

    // Settings fields
    $("setWorkspacePath").textContent = s.workspace || "Not chosen";
    setInputValue("inputDbPath", s.databasePath || "");
    setInputValue("inputSettingsDir", s.settingsDir || "");
    setInputValue("inputGatewayPort", String(s.gatewayPort || 18855));
    setInputValue("inputOauthDir", s.oauthStateDir || "");
    setInputValue("inputOauthOrigin", s.oauthOrigin || "");
    setInputValue("inputOauthAudience", s.oauthAudience || "workstation");

    $("snipMcpUrl").textContent = data.quickstart.mcpLoopbackUrl;
    $("snipStdio").textContent = s.profile === "read-only"
      ? data.quickstart.stdioReadOnly
      : data.quickstart.stdioWorkspaceWrite;

    // Recent folders
    const recents = (s.recentWorkspaces || []).filter((r) => r && r !== s.workspace);
    const wrap = $("recentWorkspacesWrap");
    const list = $("recentWorkspacesList");
    if (recents.length > 0) {
      wrap.classList.remove("hidden");
      list.innerHTML = recents
        .map((r) => '<button class="mini-btn recent-item" data-recent="' + escapeHtml(r) + '" type="button">' + escapeHtml(r) + "</button>")
        .join("");
      list.querySelectorAll("[data-recent]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          if (usesLiveWorkstation()) return;
          const next = Object.assign({}, state.settings, { workspace: btn.getAttribute("data-recent") });
          if (await runPanelAction("save_panel_settings", { settings: next })) {
            showToast("Folder updated.");
          }
        });
      });
    } else {
      wrap.classList.add("hidden");
    }

    if (!s.onboardingCompleted && !usesLiveWorkstation(data)) {
      $("obWorkspacePath").textContent = s.workspace || "Not chosen yet";
      $("onboardingModal").classList.remove("hidden");
    } else {
      $("onboardingModal").classList.add("hidden");
    }
    renderControls();
  }

  async function readPanelState() {
    const generation = stateGeneration;
    const read = ++nextStateRead;
    try {
      const data = await invoke("get_panel_state");
      if (generation !== stateGeneration || read < lastStateRead || isStaleNativeSnapshot(data)) return;
      lastStateRead = read;
      stateError = "";
      renderMain(data);
    } catch (err) {
      if (generation !== stateGeneration || read < lastStateRead) return;
      lastStateRead = read;
      stateError = String(err);
      if (state) renderMain(state);
      else renderControls();
    }
  }

  function resumeNativeApprovalsRefresh() {
    if (!nativeApprovalsRefreshNeeded) return;
    panelRefreshNeeded = true;
    refreshState();
  }

  async function refreshState() {
    if (refreshInFlight || profileChanging || panelBusy || extensionDecisionInFlight) return;
    refreshInFlight = true;
    try {
      do {
        panelRefreshNeeded = false;
        if (nativeApprovalsRefreshNeeded && activePage === "pageApprovals") {
          await loadApprovalsDrawer(true);
        } else {
          await readPanelState();
        }
      } while (panelRefreshNeeded && !profileChanging && !panelBusy && !extensionDecisionInFlight);
    } finally {
      refreshInFlight = false;
    }
  }

  async function loadMissionsDrawer() {
    const body = $("missionsBody");
    body.innerHTML = '<div class="empty-note">Loading tasks...</div>';
    try {
      const data = await invoke("get_missions_snapshot");
      if (!data.configured || !data.exists) {
        body.innerHTML = '<div class="set-card"><div class="set-title">Not initialized yet</div><div class="set-sub">Open Settings &gt; Advanced settings and click Initialize.</div></div>';
        return;
      }
      if (data.needsMigration) {
        body.innerHTML = '<div class="set-card"><div class="set-title">Database update needed</div><div class="set-sub">Open Settings &gt; Advanced settings and click Initialize.</div></div>';
        return;
      }
      const missions = data.missions || [];
      const rooms = data.task_rooms || [];
      let html = "";
      if (missions.length === 0) {
        html += '<div class="set-card"><div class="set-title">No active tasks</div><div class="set-sub">Connect ChatGPT, Gemini, or a local coding tool to see live progress here.</div></div>';
      } else {
        html += missions.map((m) => {
          const pillCls = m.status === "active" || m.status === "completed" ? "ok" : "warn";
          const cps = (m.recent_checkpoints || [])
            .map((cp) => '<div class="cp-line"><strong>#' + escapeHtml(cp.revision) + "</strong> " + escapeHtml(cp.summary) + "</div>")
            .join("");
          return '<div class="set-card">' +
            '<div class="set-row"><span class="set-title">' + escapeHtml(m.mission_id) + '</span><span class="pill ' + pillCls + '">' + escapeHtml(m.status) + "</span></div>" +
            '<div class="item-meta">' + escapeHtml(m.goal) + "</div>" +
            cps +
          "</div>";
        }).join("");
      }

      if (rooms.length > 0) {
        html += '<div class="mini-label" style="margin: 6px 2px 2px;">Task Rooms (' + rooms.length + ")</div>";
        html += rooms.map((t) => {
          const pillCls = t.status === "completed" || t.status === "active" ? "ok" : "warn";
          return '<div class="set-card">' +
            '<div class="set-row"><span class="set-title">' + escapeHtml(t.title) + '</span><span class="pill ' + pillCls + '">' + escapeHtml(t.steps_completed) + "/" + escapeHtml(t.steps_total) + "</span></div>" +
            '<div class="item-meta">' + escapeHtml(t.summary || t.goal) + "</div>" +
          "</div>";
        }).join("");
      }
      body.innerHTML = html;
    } catch (err) {
      body.innerHTML = '<div class="set-card"><div class="set-title">Error</div><div class="set-sub">' + escapeHtml(err) + "</div></div>";
    }
  }

  function extensionOperationActive(operation) {
    return Boolean(operation && ["starting", "awaiting_authorization"].includes(operation.status));
  }

  function safeExtensionAuthorizationUrl(value) {
    if (typeof value !== "string" || /[\u0000-\u0020\u007f\\]/.test(value)) return null;
    const authority = /^https?:\/\/([^/?#]+)(?:[/?#]|$)/i.exec(value);
    if (!authority) return null;
    try {
      const url = new URL(value);
      if (url.username || url.password) return null;
      if (url.protocol === "https:" || (url.protocol === "http:"
        && /^(127\.0\.0\.1|\[::1\])(?::[0-9]+)?$/.test(authority[1]))) return url;
    } catch (_) {}
    return null;
  }

  function canDecideExtensions(panel = state) {
    return Boolean(usesLiveWorkstation(panel) && !stateError && !gatewayControls(panel).phase && panel.liveProfile
      && panel.liveProfile.connected && panel.extensions && panel.extensions.canDecide);
  }

  function renderExtensionControls() {
    const body = $("approvalsBody");
    const operation = state && state.extensions && state.extensions.oauthOperation;
    const disabled = !canDecideExtensions() || mutationsBlocked() || extensionOperationActive(operation);
    body.querySelectorAll("[data-ext-auth-open]").forEach((button) => {
      button.disabled = !canDecideExtensions() || mutationsBlocked();
    });
    for (const selector of ["[data-oauth-cb]", "[data-oauth-approve]"]) {
      body.querySelectorAll(selector).forEach((input) => { input.disabled = operatorMutationsBlocked(); });
    }
    const enroll = $("enrollBtn");
    if (enroll) enroll.disabled = operatorMutationsBlocked();
    body.querySelectorAll("[data-ext-review]").forEach((input) => { input.disabled = disabled; });
    body.querySelectorAll("[data-ext-decide]").forEach((button) => {
      const id = button.getAttribute("data-ext-request");
      const review = body.querySelector('[data-ext-review="' + id + '"]');
      button.disabled = disabled || (button.getAttribute("data-ext-decide") === "approve"
        && (!review || !review.checked));
    });
  }

  function renderExtensionOperation(operation) {
    if (!operation) return "";
    const active = extensionOperationActive(operation);
    const result = operation.result || {};
    const approved = operation.status === "completed" && result.decision === "approved";
    let message = active ? "Authorization is pending. No approval has been recorded yet."
      : approved ? "OAuth authorization approved and recorded."
      : (operation.error || "Authorization result: " + (result.reason || result.decision || operation.status));
    let action = "";
    if (active && operation.auth_url) {
      const url = safeExtensionAuthorizationUrl(operation.auth_url);
      if (url) {
        message = "Open the provider page to authorize this request. Waiting for its callback.";
        action = '<div class="item-meta"><code>' + escapeHtml(url.origin + url.pathname) + "</code></div>" +
          '<button class="mini-btn full-w" data-ext-auth-open type="button">Open authorization page</button>';
      } else {
        message = "The authorization address is invalid. Review the extension configuration.";
      }
    }
    return '<div class="set-card"><div class="set-title">Extension authorization</div>' +
      '<div class="set-sub">' + escapeHtml(message) + "</div>" +
      '<div class="item-meta">Request: <code>' + escapeHtml(operation.request_id) + "</code></div>" +
      action + "</div>";
  }

  function scheduleExtensionPoll(operation) {
    clearTimeout(extensionPollTimer);
    extensionPollTimer = null;
    if (!extensionOperationActive(operation)) {
      extensionPollRequest = null;
      return;
    }
    if (extensionPollRequest !== operation.request_id) {
      extensionPollRequest = operation.request_id;
      extensionPollDeadline = Date.now() + 240000;
    }
    if (activePage !== "pageApprovals" || Date.now() >= extensionPollDeadline) return;
    extensionPollTimer = setTimeout(() => {
      extensionPollTimer = null;
      if (activePage !== "pageApprovals" || extensionDecisionInFlight
        || Date.now() >= extensionPollDeadline) return;
      return loadApprovalsDrawer(true);
    }, 1000);
  }

  function extensionReceiptMessage(receipt) {
    const operation = receipt.oauth_operation;
    if (extensionOperationActive(operation)) return "Authorization started. Review its pending status.";
    const result = operation ? operation.result || {} : receipt;
    if (operation && operation.status === "failed") {
      return operation.error || "Authorization could not be confirmed. Refresh its status.";
    }
    if (result.decision === "approved") {
      return "Extension approved. Current effect: " + String(result.effect_now ?? "see status") + ".";
    }
    if (result.decision === "refused") return "Extension refused.";
    return "Decision recorded: " + String(result.reason || result.decision || "review its status") + ".";
  }

  async function decideExtension(button) {
    if (mutationsBlocked() || !canDecideExtensions()
      || extensionOperationActive(state.extensions.oauthOperation)) return;
    const id = button.getAttribute("data-ext-request");
    const approve = button.getAttribute("data-ext-decide") === "approve";
    const review = $("approvalsBody").querySelector('[data-ext-review="' + id + '"]');
    const reviewed = Boolean(review && review.checked);
    if (approve && !reviewed) {
      showToast("Review the exact proposal before approving it.");
      return;
    }
    extensionDecisionInFlight = true;
    approvalsRead++;
    stateGeneration++;
    clearTimeout(extensionPollTimer);
    renderExtensionControls();
    try {
      const receipt = await invoke("decide_extension_request", { requestId: id, approve, reviewed });
      showToast(extensionReceiptMessage(receipt));
    } catch (err) {
      showToast(String(err));
    } finally {
      extensionDecisionInFlight = false;
      stateGeneration++;
      if (activePage === "pageApprovals") await loadApprovalsDrawer();
      else await refreshState();
      renderExtensionControls();
    }
  }

  function rememberOAuthCallbacks() {
    $("approvalsBody").querySelectorAll("[data-oauth-cb]").forEach((input) => {
      const id = input.getAttribute("data-oauth-cb");
      if (input.value) oauthCallbackDrafts.set(id, input.value);
      else oauthCallbackDrafts.delete(id);
    });
  }

  async function loadApprovalsDrawer(polling = false) {
    if (extensionDecisionInFlight) return;
    clearTimeout(extensionPollTimer);
    extensionPollTimer = null;
    const currentRead = ++approvalsRead;
    const body = $("approvalsBody");
    rememberOAuthCallbacks();
    if (!polling) body.innerHTML = '<div class="empty-note">Checking requests...</div>';
    const generation = stateGeneration;
    const read = ++nextStateRead;
    try {
      const [oauth, panel] = await Promise.all([
        invoke("get_oauth_pending"),
        invoke("get_panel_state"),
      ]);
      if (currentRead !== approvalsRead || activePage !== "pageApprovals" || extensionDecisionInFlight
        || generation !== stateGeneration || read < lastStateRead || isStaleNativeSnapshot(panel)) return;
      if (generation === stateGeneration && read >= lastStateRead && !profileChanging && !panelBusy) {
        lastStateRead = read;
        stateError = "";
        renderMain(panel);
      }

      let html = "";
      if (!oauth.configured) {
        html += '<div class="set-card"><div class="set-title">Web Connections</div><div class="set-sub">To approve ChatGPT Web or Gemini Web connectors here, set up Web Relay under Settings &gt; Advanced settings.</div></div>';
      } else {
        html += '<div class="set-card">' +
          '<div class="set-row">' +
            '<div><div class="set-title">Web Connections</div><div class="set-sub">' + escapeHtml(oauth.origin) + "</div></div>" +
            '<button class="mini-btn sm" id="enrollBtn" type="button">Allow New (10m)</button>' +
          "</div>";
        const pending = oauth.pending || [];
        if (pending.length === 0) {
          html += '<div class="item-meta" style="margin-top:8px;">No pending connection requests.</div>';
        } else {
          html += pending.map((req) =>
            '<div style="margin-top:9px;padding-top:9px;border-top:1px solid var(--border);">' +
              '<div class="set-row"><span class="set-title">' + escapeHtml(req.provider.toUpperCase()) + '</span><span class="pill accent">' + escapeHtml(req.clientId) + "</span></div>" +
              '<div class="item-meta">Callback: <code>' + escapeHtml(req.redirectUri) + "</code></div>" +
              '<div class="item-meta">Resource: <code>' + escapeHtml(req.resource) + "</code></div>" +
              renderCapability(req.capability) +
              renderCapabilitySelection(oauth.capabilitySelection, req.capability || { kind: "legacy" }) +
              '<input class="text-input" data-oauth-cb="' + escapeHtml(req.id) + '" type="text" placeholder="Paste callback link to confirm" style="margin-top:6px;">' +
              '<button class="mini-btn full-w" data-oauth-approve="' + escapeHtml(req.id) + '" type="button">Approve Request</button>' +
            "</div>"
          ).join("");
        }
        html += "</div>";
      }

      const ext = panel.extensions || {};
      if (ext.configured && ext.exists) {
        const servers = ext.servers || [];
        const requests = ext.requests || [];
        html += '<div class="set-card"><div class="set-title">Extensions (' + servers.length + ")</div>";
        if (servers.length === 0) {
          html += '<div class="set-sub">No extra extensions connected yet.</div>';
        } else {
          html += servers.map((srv) => {
            const oauthMeta = ext.outboundOauth && ext.outboundOauth[srv.id];
            const tokenStatus = oauthMeta && oauthMeta.tokenStatus;
            const tokenStatusKnown = tokenStatus && typeof tokenStatus === "object"
              && !Array.isArray(tokenStatus) && typeof tokenStatus.token_stored === "boolean"
              && typeof tokenStatus.token_expired === "boolean";
            const tokenStored = tokenStatusKnown && tokenStatus.token_stored === true;
            const tokenExpired = tokenStored && tokenStatus.token_expired === true;
            const tokenLabel = !tokenStatusKnown ? "Token status unavailable"
              : tokenExpired ? "Token expired" : (tokenStored ? "Token stored" : "No token");
            const tokenClass = tokenExpired ? "warn" : (tokenStored ? "ok" : "");
            const badge = '<span><span class="pill">' + (srv.enabled ? "On" : "Off") +
              '</span> <span class="pill ' + tokenClass + '" title="Local OAuth token status">' +
              tokenLabel + "</span></span>";
            return '<div class="set-row" style="margin-top:7px;"><span class="item-meta"><strong>' + escapeHtml(srv.id) + "</strong></span>" + badge + "</div>";
          }).join("");
        }
        if (!canDecideExtensions(panel)) {
          html += '<div class="set-sub">Attach and connect this panel to a running workstation to decide extension requests.</div>';
        }
        if (requests.length > 0) {
          html += '<div class="mini-label" style="margin-top:9px;">Extension requests</div>';
          html += requests.map((r) => {
            const pending = r.status === "pending" && /^[0-9a-fA-F]{64}$/.test(r.requestId);
            const server = servers.find((candidate) => candidate.id === r.name);
            const endpoint = (r.payload && r.payload.url) || (server && server.endpoint) || "Not configured";
            const actions = pending && canDecideExtensions(panel)
              ? '<label class="extension-review-label"><input type="checkbox" data-ext-review="' + escapeHtml(r.requestId) +
                '"> I reviewed this exact endpoint and proposal.</label>' +
                '<div class="extension-actions"><button class="mini-btn" data-ext-decide="approve" data-ext-request="' +
                escapeHtml(r.requestId) + '" type="button" disabled>Approve</button>' +
                '<button class="mini-btn danger" data-ext-decide="refuse" data-ext-request="' + escapeHtml(r.requestId) +
                '" type="button">Refuse</button></div>'
              : '<div class="item-meta">' + escapeHtml(r.reason || r.status) + "</div>";
            return '<details class="extension-proposal"><summary>' + escapeHtml(r.action) +
              " <code>" + escapeHtml(r.name) + "</code> (" + escapeHtml(r.status) + ")</summary>" +
              '<div class="item-meta">Request: <code>' + escapeHtml(r.requestId) + "</code></div>" +
              '<div class="item-meta">Endpoint: <code>' + escapeHtml(endpoint) + "</code></div>" +
              '<pre class="extension-payload">' + escapeHtml(JSON.stringify(r.payload || {}, null, 2)) + "</pre>" +
              '<div class="set-sub">Secret environment entries are references, never their stored values.</div>' +
              actions + "</details>";
          }).join("");
        }
        html += renderExtensionOperation(ext.oauthOperation);
        html += "</div>";
      }

      rememberOAuthCallbacks();
      const pendingOAuthIds = new Set((oauth.pending || []).map((request) => request.id));
      for (const id of oauthCallbackDrafts.keys()) {
        if (!pendingOAuthIds.has(id)) oauthCallbackDrafts.delete(id);
      }
      nativeApprovalsRefreshNeeded = false;
      body.innerHTML = html;
      body.querySelectorAll("[data-oauth-cb]").forEach((input) => {
        input.value = oauthCallbackDrafts.get(input.getAttribute("data-oauth-cb")) || "";
      });
      renderExtensionControls();
      scheduleExtensionPoll(ext.oauthOperation);
      body.querySelectorAll("[data-ext-review]").forEach((input) => {
        input.addEventListener("change", renderExtensionControls);
      });
      body.querySelectorAll("[data-ext-decide]").forEach((button) => {
        button.addEventListener("click", () => decideExtension(button));
      });
      const displayedOperation = ext.oauthOperation;
      const displayedUrl = displayedOperation && safeExtensionAuthorizationUrl(displayedOperation.auth_url);
      body.querySelectorAll("[data-ext-auth-open]").forEach((button) => {
        button.addEventListener("click", async () => {
          const operation = state && state.extensions && state.extensions.oauthOperation;
          const url = extensionOperationActive(operation) && safeExtensionAuthorizationUrl(operation.auth_url);
          if (!url || !displayedUrl || mutationsBlocked() || !canDecideExtensions()
            || operation.request_id !== displayedOperation.request_id || url.href !== displayedUrl.href) {
            showToast("Authorization changed. Refresh the request before opening its page.");
            return;
          }
          try {
            await window.__TAURI__.opener.openUrl(url.href);
          } catch (_) {
            showToast("The authorization page could not be opened. Check the provider and try again.");
          }
        });
      });

      const enrollBtn = $("enrollBtn");
      if (enrollBtn) {
        enrollBtn.addEventListener("click", async () => {
          if (operatorMutationsBlocked()) return;
          try {
            await invoke("enable_oauth_enrollment");
            showToast("New connections allowed for 10 minutes.");
          } catch (err) {
            showToast(String(err));
          }
        });
      }

      body.querySelectorAll("[data-oauth-approve]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          if (operatorMutationsBlocked()) return;
          const id = btn.getAttribute("data-oauth-approve");
          const input = body.querySelector('[data-oauth-cb="' + id + '"]');
          const expectedCallback = input ? input.value.trim() : "";
          if (!expectedCallback) {
            showToast("Paste the exact callback link first.");
            return;
          }
          try {
            const reviewed = (oauth.pending || []).find((request) => request.id === id);
            if (!reviewed) throw new Error("Request changed. Refresh before approving.");
            await invoke("approve_oauth_request", { requestId: id, expectedCallback,
              expectedCapability: reviewed.capability || { kind: "legacy" } });
            oauthCallbackDrafts.delete(id);
            if (input) input.value = "";
            showToast("Connection approved.");
            await loadApprovalsDrawer();
          } catch (err) {
            showToast(String(err));
          }
        });
      });
    } catch (err) {
      if (currentRead !== approvalsRead || activePage !== "pageApprovals" || extensionDecisionInFlight
        || generation !== stateGeneration || read < lastStateRead) return;
      rememberOAuthCallbacks();
      body.innerHTML = '<div class="set-card"><div class="set-title">Error</div><div class="set-sub">' + escapeHtml(err) + "</div></div>";
    }
  }

  async function loadSettingsDiagnostics() {
    const box = $("skillsAndDiagBox");
    try {
      const [diag, skills] = await Promise.all([
        invoke("get_diagnostics"),
        invoke("get_skills_overview"),
      ]);
      const skillList = (skills && skills.skills) || [];
      const profiles = (diag && diag.mcpBrowserProfiles) || [];
      let html = '<div class="item-meta">Token security: <strong>' + escapeHtml(diag.oauthKeystore) + "</strong></div>";
      html += '<div class="item-meta">Skills: <strong>' + skillList.length + "</strong> | Browser profiles: <strong>" + profiles.length + "</strong></div>";
      if (diag.capabilitySelection) {
        html += renderCapability(diag.capabilitySelection.identity);
        html += renderCapabilitySelection(diag.capabilitySelection);
      }
      if (diag.providerCleanup && diag.providerCleanup.pending > 0) {
        html += '<div class="item-meta">Cleanup awaiting confirmation: <strong>' +
          escapeHtml(diag.providerCleanup.pending) + '</strong>. A new runtime waits until cleanup is confirmed.</div>';
      }
      if (skillList.length > 0) {
        html += skillList.map((sk) =>
          '<div class="set-row" style="margin-top:6px;"><code>' + escapeHtml(sk.name || sk.id) +
          '</code><button class="mini-btn sm" data-skill-rb="' + escapeHtml(sk.name || sk.id) + '" type="button">Rollback</button></div>'
        ).join("");
      }
      box.innerHTML = html;
      renderControls();
      box.querySelectorAll("[data-skill-rb]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          if (operatorMutationsBlocked()) return;
          try {
            await invoke("run_skill_action", { action: "rollback", name: btn.getAttribute("data-skill-rb"), version: null });
            showToast("Skill rolled back.");
            await loadSettingsDiagnostics();
          } catch (err) {
            showToast(String(err));
          }
        });
      });
    } catch (err) {
      box.textContent = String(err);
    }
  }

  // WINDOW CONTROLS (minimize & close both hide directly to the system tray)
  $("minBtn").addEventListener("click", () => currentWindow.hide());
  $("hideBtn").addEventListener("click", () => currentWindow.hide());

  // ACCESS LEVEL SWITCHING
  document.querySelectorAll("[data-profile]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!state || btn.disabled) return;
      const target = btn.getAttribute("data-profile");
      const active = hasLiveProfile()
        ? state.liveProfile && state.liveProfile.activeProfile
        : state.settings.profile;
      if (active === target) return;
      if (!hasLiveProfile() && (target === "full-control" || target === "fully-unlocked")) {
        pendingElevatedProfile = target;
        $("modalDangerLabel").textContent = target === "fully-unlocked" ? "UNRESTRICTED ACCESS" : "FULL ACCESS";
        $("modalProfileTitle").textContent = target === "fully-unlocked" ? "Save Unlock preference?" : "Save Full preference?";
        $("modalProfileBody").textContent = "This saves your preferred mode. Attach a workstation session to apply a mode live.";
        $("modalConfirmBtn").textContent = "Save";
        $("profileModal").classList.remove("hidden");
        return;
      }
      await changeProfile(target);
    });
  });

  $("modalCancelBtn").addEventListener("click", () => {
    pendingElevatedProfile = null;
    $("profileModal").classList.add("hidden");
  });

  $("modalConfirmBtn").addEventListener("click", async () => {
    if (!pendingElevatedProfile) return;
    const target = pendingElevatedProfile;
    pendingElevatedProfile = null;
    $("profileModal").classList.add("hidden");
    await changeProfile(target);
  });

  // START / RESTART / STOP BRIDGE
  $("powerBtn").addEventListener("click", async () => {
    if (mutationsBlocked() || $("powerBtn").disabled) return;
    const controls = gatewayControls();
    const live = state.gateway.live;
    if (!(live ? controls.canRestart : controls.canStart)) return;
    const updated = await runPanelAction("start_or_restart_gateway", { intent: live ? "restart" : "start" }, {
      lifecyclePhase: live ? "restarting" : "starting",
    });
    if (updated) showToast("Bridge is running on port " + updated.gateway.port + ".");
  });

  $("stopBtn").addEventListener("click", async () => {
    if (mutationsBlocked() || !gatewayControls().canStop) return;
    if (await runPanelAction("stop_gateway", undefined, { lifecyclePhase: "stopping" })) {
      showToast("Bridge stopped.");
    }
  });

  // QUICK FOLDER PICKER ON MAIN PAGE
  $("quickWorkspaceBtn").addEventListener("click", chooseAndSaveWorkspace);

  // NAVIGATION
  $("missionsNavBtn").addEventListener("click", () => {
    showPage("pageMissions");
    loadMissionsDrawer();
  });
  $("approvalsNavBtn").addEventListener("click", () => {
    showPage("pageApprovals");
    loadApprovalsDrawer();
  });
  $("settingsNavBtn").addEventListener("click", () => {
    showPage("pageSettings");
    loadSettingsDiagnostics();
  });
  document.querySelectorAll("[data-back]").forEach((btn) => {
    btn.addEventListener("click", () => {
      showPage("pageMain");
      refreshState();
    });
  });
  $("refreshMissionsBtn").addEventListener("click", loadMissionsDrawer);
  $("refreshApprovalsBtn").addEventListener("click", loadApprovalsDrawer);
  $("quitAppBtn").addEventListener("click", async () => {
    if (panelBusy || profileChanging || extensionDecisionInFlight) return;
    panelBusy = true;
    pendingLifecyclePhase = "stopping";
    stateGeneration++;
    approvalsRead++;
    renderControls();
    try {
      await invoke("quit_app");
    } catch (error) {
      showToast(String(error));
      await readPanelState();
    } finally {
      panelBusy = false;
      pendingLifecyclePhase = null;
      renderControls();
      resumeNativeApprovalsRefresh();
    }
  });

  // SETTINGS ACTIONS
  document.querySelectorAll("[data-theme-choice]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!state) return;
      const theme = btn.getAttribute("data-theme-choice");
      const next = Object.assign({}, state.settings, { theme });
      await runPanelAction("save_panel_settings", { settings: next });
    });
  });

  settingInputs.forEach((id) => {
    $(id).addEventListener("input", () => dirtyInputs.add(id));
    $(id).addEventListener("change", () => dirtyInputs.add(id));
  });

  $("chooseWorkspaceBtn").addEventListener("click", chooseAndSaveWorkspace);

  $("pickOauthDirBtn").addEventListener("click", async () => {
    if (usesLiveWorkstation()) return;
    const dir = await pickFolder("Select OAuth Folder");
    if (dir) {
      $("inputOauthDir").value = dir;
      dirtyInputs.add("inputOauthDir");
    }
  });

  $("savePathsBtn").addEventListener("click", async () => {
    if (!state || usesLiveWorkstation()) return;
    const port = parseInt($("inputGatewayPort").value, 10) || 18855;
    const next = Object.assign({}, state.settings, {
      databasePath: $("inputDbPath").value.trim(),
      settingsDir: $("inputSettingsDir").value.trim(),
      gatewayPort: port,
    });
    if (await runPanelAction("save_panel_settings", { settings: next }, { clearInputs: ["inputDbPath", "inputSettingsDir", "inputGatewayPort"] })) {
      showToast("Settings saved.");
    }
  });

  $("saveOauthBtn").addEventListener("click", async () => {
    if (!state || usesLiveWorkstation()) return;
    const next = Object.assign({}, state.settings, {
      oauthStateDir: $("inputOauthDir").value.trim(),
      oauthOrigin: $("inputOauthOrigin").value.trim(),
      oauthAudience: $("inputOauthAudience").value,
    });
    if (await runPanelAction("save_panel_settings", { settings: next }, { clearInputs: ["inputOauthDir", "inputOauthOrigin", "inputOauthAudience"] })) {
      showToast("Web Relay settings saved.");
    }
  });

  $("initStateBtn").addEventListener("click", async () => {
    if (usesLiveWorkstation()) return;
    if (await runPanelAction("initialize_local_state")) {
      showToast("Storage initialized.");
      await loadSettingsDiagnostics();
    }
  });

  async function copySnippet(id, message) {
    try {
      await navigator.clipboard.writeText($(id).textContent);
      showToast(message);
    } catch (err) {
      showToast(String(err));
    }
  }
  $("copyMcpBtn").addEventListener("click", () => copySnippet("snipMcpUrl", "Local link copied."));
  $("copyStdioBtn").addEventListener("click", () => copySnippet("snipStdio", "Terminal command copied."));

  $("openWorkspaceBtn").addEventListener("click", async () => {
    if (!state || !state.settings.workspace) {
      showToast("Choose a folder first.");
      return;
    }
    try {
      await window.__TAURI__.opener.openPath(state.settings.workspace);
    } catch (err) {
      showToast(String(err));
    }
  });

  $("openSettingsDirBtn").addEventListener("click", async () => {
    if (!state || !state.settings.settingsDir) return;
    try {
      await window.__TAURI__.opener.openPath(state.settings.settingsDir);
    } catch (err) {
      showToast(String(err));
    }
  });

  // WELCOME SETUP
  function setObStep(step) {
    $("obStepLabel").textContent = step + " / 3";
    $("obStep1").classList.toggle("hidden", step !== 1);
    $("obStep2").classList.toggle("hidden", step !== 2);
    $("obStep3").classList.toggle("hidden", step !== 3);
    $("obTitle").textContent = step === 1
      ? "Pick your folder"
      : (step === 2 ? "Pick a safety level" : "Ready to go!");
  }

  $("obPickWorkspaceBtn").addEventListener("click", async () => {
    if (usesLiveWorkstation()) return;
    const dir = await pickFolder("Pick Your Folder");
    if (!dir || !state) return;
    const next = Object.assign({}, state.settings, { workspace: dir });
    if (await runPanelAction("save_panel_settings", { settings: next })) {
      $("obWorkspacePath").textContent = dir;
    }
  });

  $("obNext1Btn").addEventListener("click", async () => {
    if (usesLiveWorkstation()) return;
    if (await runPanelAction("initialize_local_state")) setObStep(2);
  });

  document.querySelectorAll("[data-ob-profile]").forEach((btn) => {
    btn.addEventListener("click", () => {
      onboardingProfile = btn.getAttribute("data-ob-profile");
      document.querySelectorAll("[data-ob-profile]").forEach((b) => {
        b.classList.toggle("active", b === btn);
      });
    });
  });

  $("obBack2Btn").addEventListener("click", () => setObStep(1));
  $("obNext2Btn").addEventListener("click", async () => {
    if (!state || usesLiveWorkstation()) return;
    const next = Object.assign({}, state.settings, { profile: onboardingProfile });
    if (await runPanelAction("save_panel_settings", { settings: next })) setObStep(3);
  });

  $("obFinishBtn").addEventListener("click", async () => {
    if (!state || usesLiveWorkstation()) return;
    const next = Object.assign({}, state.settings, { onboardingCompleted: true });
    if (await runPanelAction("save_panel_settings", { settings: next })) {
      $("onboardingModal").classList.add("hidden");
      showToast("You're all set.");
    }
  });

  const events = window.__TAURI__.event;
  if (events && typeof events.listen === "function") {
    const listen = (name, handler) => {
      Promise.resolve(events.listen(name, handler)).catch(() => {
        showToast("Service notifications are unavailable. The panel will continue refreshing.");
      });
    };
    listen("workstation-state", ({ payload }) => {
      if (!payload || !payload.gateway || !payload.settings || isStaleNativeSnapshot(payload)) return;
      stateGeneration++;
      approvalsRead++;
      if (isNative(payload)) {
        if (activePage === "pageApprovals") nativeApprovalsRefreshNeeded = true;
        panelRefreshNeeded = true;
        refreshState();
        return;
      }
      stateError = "";
      profileError = "";
      panelRefreshNeeded = false;
      renderMain(payload);
      if (activePage === "pageApprovals" && !mutationsBlocked()) loadApprovalsDrawer(true);
    });
    listen("workstation-error", ({ payload }) => {
      stateGeneration++;
      approvalsRead++;
      showToast(String(payload));
      if (panelBusy || profileChanging) {
        panelRefreshNeeded = true;
      } else {
        stateError = String(payload);
        if (state) renderMain(state);
        else renderControls();
        readPanelState();
      }
    });
  }

  renderControls();
  refreshState();
  setInterval(refreshState, 5000);
})();
