(function () {
  "use strict";

  const invoke = window.__TAURI__.core.invoke;
  const currentWindow = window.__TAURI__.window.getCurrentWindow();

  const PROFILES = ["read-only", "workspace-write", "full-control", "fully-unlocked"];
  const PROFILE_META = {
    "read-only": {
      label: "Read",
      cls: "",
      hint: "AI can view files in the workspace.",
    },
    "workspace-write": {
      label: "Write",
      cls: "",
      hint: "AI can view and edit files in the workspace.",
    },
    "full-control": {
      label: "Full",
      cls: "warn",
      hint: "Adds approved commands and window control.",
    },
    "fully-unlocked": {
      label: "Unlock",
      cls: "danger",
      hint: "Your Windows account's access, and direct commands when enabled.",
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
  let approvalsInFlight = 0;
  let approvalsSnapshotKey = null;
  let missionsRead = 0;
  let missionsInFlight = 0;
  // Sessions are shaped and classified (live, bounds, redaction) by the Rust get_sessions command; the page only renders them.
  let sessionsRequest = null;
  let sessionsSnapshot = null;
  let selectedSessionKey = null;
  let sessionHistoryRead = null;
  let sessionHistory = null;
  let diagnosticsRead = 0;
  let diagnosticsInFlight = 0;
  let diagnosticsMutation = false;
  let pageRefreshTimer = null;
  let pageEpoch = 0;
  let recentFoldersKey = null;
  let extensionDecisionInFlight = false;
  let extensionTestInFlight = false;
  let extensionProbeEpoch = 0;
  let extensionPollTimer = null;
  let extensionPollRequest = null;
  let extensionPollDeadline = 0;
  const extensionTestResults = new Map();
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
    const title = marker.kind === "unified-v1" ? "unified, policy " + marker.policy_version
      : marker.kind === "legacy" ? "legacy" : "unknown";
    return '<details class="extension-proposal"><summary>Tool contract: ' + escapeHtml(title) +
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
      workspace: "workspace only",
      "allowed-roots": "allowed folders",
      "os-user": "your Windows account (outside the workspace needs Unlock)",
    };
    const count = Number.isInteger(selection.total_tools) ? selection.total_tools : null;
    let html = '<div class="item-meta">';
    if (count !== null) html += '<strong>' + count + ' tools</strong>';
    if (scopeLabels[scope]) html += (count !== null ? ", " : "Files: ") + escapeHtml(scopeLabels[scope]);
    html += "</div>";
    if (typeof selection.allow_import === "boolean") {
      html += '<div class="item-meta">Old Task Room import: ' +
        (selection.allow_import ? "allowed on this computer" : "off") + "</div>";
    }
    return html + '<details class="extension-proposal"><summary>Permissions and resources</summary>' +
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
    return !state || panelBusy || profileChanging || extensionDecisionInFlight || extensionTestInFlight
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
    $("profileSelector").className = "seg-shell seg-4 " + (meta ? meta.cls : "");
    $("profileHint").textContent = meta ? meta.hint : "Waiting for Bridge";
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
    $("profileTitle").textContent = configured ? "Access" : "Access (saved preference)";
    // The confirmed session ceiling is always shown, including Unlock, so a missing value is never read as "no limit".
    $("profileCeiling").classList.toggle("hidden", !configured);
    $("profileCeiling").textContent = !configured ? ""
      : connected ? "Up to " + PROFILE_META[runtime.maxProfile].label + " this session"
      : "Session limit unavailable";
    const error = stateError || profileError || (runtime && runtime.error);
    const phase = gatewayControls().phase;
    const status = phase
      ? "Access changes are paused while Bridge is " + phase + "."
      : profileChanging ? "Applying…"
      : (error || (configured
        ? (connected ? ""
          : isNativeStopped() ? "Start Bridge to change access." : "Waiting for Bridge.")
        : (state ? "Attach a workstation to apply it live." : "Connecting to Agent Bridge…")));
    $("profileStatus").textContent = status;
    $("profileStatus").classList.toggle("hidden", !status);
    $("profileStatus").classList.toggle("error", Boolean(error && !profileChanging));
    $("profileSelector").setAttribute("aria-busy", String(profileChanging));
    document.querySelectorAll("[data-profile]").forEach((btn) => {
      const profile = btn.getAttribute("data-profile");
      const allowed = connected && Array.isArray(runtime.availableProfiles)
        && runtime.availableProfiles.includes(profile)
        && PROFILES.indexOf(profile) <= PROFILES.indexOf(runtime.maxProfile);
      btn.disabled = mutationsBlocked() || (configured && !allowed);
      btn.title = configured && !connected
        ? "Bridge is not connected"
        : (configured && !allowed
          ? "Above this session's limit"
          : PROFILE_META[profile].hint);
    });
  }

  function renderStatus(busy) {
    const model = state?.statusCard;
    const card = model?.pending?.[pendingLifecyclePhase] ?? (stateError ? model?.readError : model?.current);
    // Before the first usable IPC reply, keep lifecycle actions unavailable.
    const unavailable = Boolean(state || stateError);
    const tone = card?.tone ?? (unavailable ? "error" : "off");
    $("gwStatus").textContent = card?.title ?? (unavailable ? "Unavailable" : "Checking…");
    $("gwStatus").title = card?.tooltip ?? "";
    $("gwDot").className = "dot " + ({ on: "ok", busy: "warn", error: "danger" }[tone] ?? "");
    $("statusCard").setAttribute("data-tone", tone);
    $("powerBtn").disabled = busy || card?.canPower !== true;
    $("powerBtn").textContent = card?.powerLabel ?? "Start Bridge";
    $("powerBtn").className = card?.powerSecondary ? "ghost-btn" : "action-btn";
    $("stopBtn").disabled = busy || card?.canStop !== true;
    $("stopBtn").classList.toggle("hidden", card?.showStop !== true);
    $("gatewayActions").classList.toggle("hidden", card ? !card.showActions : unavailable);
    $("externalGatewayNotice").classList.toggle("hidden", card?.showNotice !== true);
    $("externalGatewayNotice").textContent = card?.detail ?? "";
    $("quitAppBtn").textContent = card?.quitLabel ?? "Quit";
  }

  function renderControls() {
    const external = usesLiveWorkstation();
    const busy = mutationsBlocked();
    const localControls = [
      "initStateBtn", "quickWorkspaceBtn", "chooseWorkspaceBtn",
      "pickOauthDirBtn", "savePathsBtn", "saveOauthBtn",
      "obPickWorkspaceBtn", "obNext1Btn", "obNext2Btn", "obFinishBtn",
      ...settingInputs,
    ];
    localControls.forEach((id) => { $(id).disabled = busy || external; });
    document.querySelectorAll("[data-theme-choice]").forEach((btn) => { btn.disabled = busy; });
    document.querySelectorAll("[data-recent]").forEach((btn) => { btn.disabled = busy || external; });
    document.querySelectorAll("[data-skill-rb]").forEach((btn) => { btn.disabled = operatorMutationsBlocked() || diagnosticsMutation; });
    renderStatus(busy);
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
          ? "Access set to " + PROFILE_META[target].label + "."
          : "Access preference saved.");
      } else {
        profileError = "Bridge has not confirmed this access level.";
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
        stateError = "Confirming the access level with Bridge.";
        renderMain(state);
        await readPanelState();
      }
      if (generation === stateGeneration) stateGeneration++;
      profileChanging = false;
      renderControls();
      resumeNativeApprovalsRefresh();
    }
  }

  function schedulePageRefresh() {
    clearTimeout(pageRefreshTimer);
    pageRefreshTimer = null;
    if (activePage === "pageMain") return;
    const epoch = pageEpoch;
    pageRefreshTimer = setTimeout(async () => {
      pageRefreshTimer = null;
      if (epoch !== pageEpoch) return;
      try {
        if (!document.hidden && !panelBusy && !profileChanging && !extensionDecisionInFlight) {
          if (activePage === "pageMissions") {
            loadSessions(true);
            if (!missionsInFlight) loadMissionsDrawer(true);
          } else if (activePage === "pageSession") {
            loadSessions(true);
          } else if (activePage === "pageApprovals" && !approvalsInFlight
            && !refreshInFlight && !extensionPollTimer) {
            await loadApprovalsDrawer(true, true);
          } else if (activePage === "pageSettings" && !diagnosticsInFlight && !diagnosticsMutation) {
            await loadSettingsDiagnostics();
          }
        }
      } finally {
        if (epoch === pageEpoch) schedulePageRefresh();
      }
    }, 3000);
  }

  function showPage(pageId) {
    activePage = pageId;
    pageEpoch++;
    missionsRead++;
    diagnosticsRead++;
    schedulePageRefresh();
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
    const dir = await pickFolder("Choose workspace folder");
    if (!dir || !state || usesLiveWorkstation()) return;
    const next = Object.assign({}, state.settings, { workspace: dir });
    if (await runPanelAction("save_panel_settings", { settings: next })) {
      showToast("Folder updated.");
    }
  }

  function renderMain(data) {
    if (isStaleNativeSnapshot(data)) return;
    const changedService = isNative(state) && isNative(data)
      && state.gateway.generation !== data.gateway.generation;
    state = data;
    if (changedService) {
      extensionProbeEpoch++;
      extensionTestResults.clear();
      sessionsRequest = null;
      sessionsSnapshot = null;
      renderSessionsBadge();
      renderSessionsView();
      if (sessionsPageVisible()) loadSessions(true);
    }
    const s = data.settings;
    applyTheme(s.theme);

    const pendingTotal = data.pendingApprovalsTotal || 0;
    const setBadge = (id, count, noun) => {
      $(id).textContent = String(count);
      $(id).classList.toggle("hidden", !(count > 0));
      $(id).setAttribute("aria-label", count + " " + noun + (count === 1 ? "" : "s"));
    };
    setBadge("approvalsBadge", pendingTotal, "pending approval");

    $("scopePath").textContent = s.workspace || "No folder chosen";
    $("scopePath").title = s.workspace || "";
    $("versionMeta").textContent = "Agent Bridge " + data.version;
    const oauthError = data.oauth && typeof data.oauth.error === "string" && data.oauth.error ? data.oauth.error : "";
    $("webRelayState").textContent = oauthError
      ? "Web relay error: " + oauthError
      : data.oauth && data.oauth.configured
        ? "Web relay is set up. Approve new web clients in Approvals."
        : "Web relay not set up. Configure it under Storage and web relay.";
    $("webRelayState").classList.toggle("notice-warn", Boolean(oauthError));

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
    const recentsKey = JSON.stringify(recents);
    if (recents.length > 0) {
      wrap.classList.remove("hidden");
      if (recentsKey !== recentFoldersKey) {
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
      }
    } else {
      wrap.classList.add("hidden");
      list.innerHTML = "";
    }
    recentFoldersKey = recentsKey;

    if (!s.onboardingCompleted && !usesLiveWorkstation(data)) {
      $("obWorkspacePath").textContent = s.workspace || "No folder chosen";
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
    if (activePage === "pageMain" && !document.hidden && !profileChanging && !panelBusy && !extensionDecisionInFlight) {
      loadSessions(true);
    }
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

  async function loadMissionsDrawer(passive = false) {
    const body = $("missionsBody");
    const read = ++missionsRead;
    const epoch = pageEpoch;
    const generation = stateGeneration;
    const current = () => read === missionsRead && epoch === pageEpoch
      && activePage === "pageMissions" && generation === stateGeneration;
    missionsInFlight++;
    if (!passive) body.innerHTML = '<div class="empty-note">Loading tasks…</div>';
    const render = (html, active) => {
      if (body.innerHTML !== html) {
        body.innerHTML = html;
        bindHandoffButtons(body);
      }
      $("tasksHeading").textContent = Number.isSafeInteger(active) && active >= 0 ? "Tasks (" + active + " active)" : "Tasks";
    };
    const initHint = "Open Settings, then Storage and web relay, and select Initialize.";
    try {
      const data = await invoke("get_missions_snapshot");
      if (!current()) return;
      if (!data.configured || !data.exists) {
        render('<div class="empty-state"><div class="set-title">Storage not set up</div><div class="set-sub">' + initHint + "</div></div>");
        return;
      }
      if (data.needsMigration) {
        render('<div class="empty-state"><div class="set-title">Storage needs an update</div><div class="set-sub">' + initHint + "</div></div>");
        return;
      }
      const missions = data.missions || [];
      const rooms = data.task_rooms || [];
      let html = "";
      if (missions.length === 0 && rooms.length === 0) {
        html += '<div class="empty-state"><div class="set-title">No active tasks</div><div class="set-sub">Tasks your AI starts appear here.</div></div>';
      } else {
        html += missions.map((m) => {
          const pillCls = m.status === "active" || m.status === "completed" ? "ok" : "warn";
          const cps = (m.recent_checkpoints || [])
            .map((cp) => '<div class="cp-line"><strong>#' + escapeHtml(cp.revision) + "</strong> " + escapeHtml(cp.summary) + "</div>")
            .join("");
          return '<div class="set-card">' +
            '<div class="set-row"><span class="set-title">' + escapeHtml(m.mission_id) + '</span><span class="pill ' + pillCls + '">' + escapeHtml(m.status) + "</span></div>" +
            '<div class="item-meta">' + escapeHtml(m.goal) + "</div>" +
            cps + handoffButton(m.mission_id, m.revision, m.copy_handoff) +
          "</div>";
        }).join("");
      }

      if (rooms.length > 0) {
        html += '<h3 class="list-heading">Task Rooms</h3>';
        html += rooms.map((t) => {
          const pillCls = t.status === "completed" || t.status === "active" ? "ok" : "warn";
          const total = Number(t.steps_total);
          const completed = Number(t.steps_completed);
          const progress = Number.isFinite(total) && total > 0 && Number.isFinite(completed)
            ? '<progress class="task-progress" aria-label="Task progress" max="' + total
              + '" value="' + Math.max(0, Math.min(completed, total)) + '"></progress>' : "";
          return '<div class="set-card">' +
            '<div class="set-row"><span class="set-title">' + escapeHtml(t.title) + '</span><span class="pill ' + pillCls + '">' + escapeHtml(t.steps_completed) + "/" + escapeHtml(t.steps_total) + "</span></div>" +
            progress + '<div class="item-meta">' + escapeHtml(t.summary || t.goal) + "</div>" +
          "</div>";
        }).join("");
      }
      if (data.attempts_unavailable === true) {
        html += '<div class="item-meta notice-warn">Attempt ledger unavailable. Do not restart uncertain work.</div>';
      } else if (Array.isArray(data.attempts) && data.attempts.length) {
        html += '<h3 class="list-heading">Maintenance attempts</h3>' + data.attempts.map(row => {
          const a = row.attempt || {};
          const evidence = a.evidence;
          const status = row.reconciliation_required === true ? "Reconcile — do not repeat" :
            String(a.state || "unknown").replace(/_/g, " ");
          const lease = row.lease_current === true ? "Lease current (not a live session)" : "No current lease";
          return '<div class="set-card"><div class="set-row"><span class="set-title">Verify local Git HEAD</span>' +
            '<span class="pill ' + (a.state === "reviewed_pass" ? "ok" : "warn") + '">' + escapeHtml(status) + '</span></div>' +
            '<div class="item-meta">' + escapeHtml(a.attempt_id) + ' · ' + escapeHtml(lease) + '</div>' +
            '<div class="item-meta">Subtask ' + escapeHtml(a.plan?.subtask_id) +
            ' · Base ' + escapeHtml(a.plan?.base_commit) + '</div>' +
            (evidence ? '<div class="item-meta">Receipt ' + escapeHtml(evidence.receipt_id) +
              ' · ' + (evidence.verified === true ? "Base matched" : "Base mismatch") + '</div>' : "") +
            '</div>';
        }).join("");
      }
      render(html, data.mission_counts?.active);
    } catch (err) {
      if (current()) render('<div class="empty-state"><div class="set-title">Tasks could not load</div><div class="set-sub">' + escapeHtml(err) + "</div></div>");
    } finally {
      missionsInFlight--;
    }
  }

  const SESSION_PROVIDERS = { chatgpt: "ChatGPT", gemini: "Gemini", local: "Local app" };
  const SESSION_TRANSPORTS = { http: "HTTP", stdio: "Terminal (stdio)" };
  const SESSIONS_LOADING = '<div class="item-meta">Loading sessions…</div>';

  function sessionName(session) {
    return SESSION_PROVIDERS[session.provider] || "AI client";
  }

  function sinceText(iso) {
    const time = Date.parse(iso);
    if (!Number.isFinite(time)) return "-";
    const seconds = Math.max(0, Math.round((Date.now() - time) / 1000));
    if (seconds < 60) return "just now";
    if (seconds < 3600) return Math.round(seconds / 60) + " min ago";
    if (seconds < 86400) return Math.round(seconds / 3600) + " h ago";
    return Math.round(seconds / 86400) + " d ago";
  }

  function listOf(value) {
    return Array.isArray(value) ? value : [];
  }

  function sessionMissions(contexts) {
    return listOf(contexts).reduce((all, ctx) => all.concat(listOf(ctx.missions)), []);
  }

  function sessionRow(key, title, meta, live) {
    return '<button class="session-row" type="button" data-session="' + escapeHtml(key) + '">' +
      '<span class="dot' + (live ? " ok" : "") + '" aria-hidden="true"></span>' +
      '<span class="session-copy"><span class="item-name">' + escapeHtml(title) + "</span>" +
      '<span class="session-meta">' + escapeHtml(meta) + "</span></span>" +
      '<svg class="row-chevron" viewBox="0 0 16 16" width="12" height="12" fill="none" aria-hidden="true"><path d="M6 3.5L10.5 8 6 12.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
    "</button>";
  }

  function countText(count, noun) {
    return count + " " + noun + (count === 1 ? "" : "s");
  }

  function renderSessionsList(data) {
    if (!data) return SESSIONS_LOADING;
    const sessions = listOf(data.sessions);
    const earlier = listOf(data.earlier);
    let html = "";
    if (data.available === false) {
      html += '<div class="item-meta">' + escapeHtml(data.reason || "Sessions appear while Bridge is running.") + "</div>";
    } else if (sessions.length === 0) {
      html += '<div class="empty-state compact"><div class="set-title">No AI connected yet</div>' +
        '<div class="set-sub">Sessions appear when an AI calls Bridge.</div></div>';
    }
    const live = sessions.filter((s) => s.live === true);
    const recent = sessions.filter((s) => s.live !== true);
    const block = (heading, list) => list.length === 0 ? "" :
      '<h3 class="list-heading">' + heading + '</h3><div class="session-list">' + list.map((s) => {
        const parts = [s.live === true ? "Active " + sinceText(s.lastSeen) : "Seen " + sinceText(s.lastSeen),
          countText(sessionMissions(s.contexts).length, "mission"), countText(listOf(s.commands).length, "command")];
        return sessionRow("s:" + s.sessionId, sessionName(s) + (s.clientLabel ? " · " + s.clientLabel : ""), parts.join(" · "), s.live === true);
      }).join("") + "</div>";
    html += block("Live now", live) + block("Connected earlier", recent);
    if (earlier.length > 0) {
      html += '<h3 class="list-heading">Earlier mission contexts</h3><div class="session-list">' + earlier.map((ctx) =>
        sessionRow("c:" + ctx.contextId, (SESSION_PROVIDERS[ctx.actorKind] || ctx.actorKind || "Agent") + " context",
          "Seen " + sinceText(ctx.lastSeen || ctx.attachedAt) + " · " + countText(listOf(ctx.missions).length, "mission"), false)
      ).join("") + "</div>";
    }
    return html;
  }

  function handoffButton(missionId, revision, permitted) {
    if (typeof permitted !== "boolean" || typeof missionId !== "string" || !/^mis_[0-9a-f]{32}$/.test(missionId)
        || !Number.isSafeInteger(revision) || revision < 1) return "";
    if (!permitted) {
      return '<button class="mini-btn sm" type="button" disabled>Copy handoff</button>' +
        '<p class="set-sub">To enable copying, an attached mission member must record the checkpoint ' +
        '<code>handoff: desktop-copy</code> for the current revision. The grant lasts five minutes.</p>';
    }
    return '<button class="mini-btn sm" type="button" data-copy-handoff="' + escapeHtml(missionId)
      + '" data-handoff-revision="' + revision + '">Copy handoff</button>';
  }

  function bindHandoffButtons(body) {
    for (const button of body.querySelectorAll("[data-copy-handoff]")) {
      button.addEventListener("click", async () => {
        const missionId = button.getAttribute("data-copy-handoff");
        const revision = Number(button.getAttribute("data-handoff-revision"));
        const epoch = pageEpoch, generation = stateGeneration;
        const current = () => epoch === pageEpoch && generation === stateGeneration
          && Array.from(body.querySelectorAll("[data-copy-handoff]")).includes(button);
        if (!current()) return;
        button.disabled = true;
        try {
          const result = await invoke("get_mission_handoff", { missionId, revision });
          if (!current()) return;
          if (typeof result?.handoff !== "string" || result.max_bytes !== 4096
              || result.handoff.length > 4096) throw new Error("Invalid handoff");
          await navigator.clipboard.writeText(result.handoff);
          if (current()) showToast(result.truncated ? "Handoff copied (limited)." : "Handoff copied.");
        } catch (_) {
          if (current()) showToast("Copy unavailable. Ask an attached member to approve it again.");
        } finally {
          if (current()) button.disabled = false;
        }
      });
    }
  }

  function missionCard(mission) {
    const subtasks = listOf(mission.subtasks);
    const pillCls = mission.status === "blocked" ? "warn" : "ok";
    return '<div class="mission-block">' +
      '<div class="set-row"><span class="item-name">' + escapeHtml(mission.goal) + '</span><span class="pill ' + pillCls + '">' + escapeHtml(mission.status) + "</span></div>" +
      '<div class="session-meta">' + escapeHtml([mission.role ? "Role " + mission.role : "", "Revision " + mission.revision, "Updated " + sinceText(mission.updatedAt)].filter(Boolean).join(" · ")) + "</div>" +
      (subtasks.length === 0 ? "" : '<ul class="subtask-list">' + subtasks.map((t) =>
        '<li><span class="subtask-title">' + escapeHtml(t.title) + (t.assignedToContext === true ? ' <span class="pill accent">this session</span>' : "") +
        '</span><span class="pill' + (t.status === "completed" ? " ok" : t.status === "blocked" ? " warn" : "") + '">' + escapeHtml(String(t.status).replace(/_/g, " ")) + "</span></li>"
      ).join("") + "</ul>") +
      handoffButton(mission.missionId, mission.revision, mission.copyHandoff) +
    "</div>";
  }

  function selectedAuditSession() {
    const session = selectedSessionKey?.startsWith("s:") ? selectedSessionKey.slice(2) : "";
    const boot = sessionsSnapshot?.bootId;
    if (activePage !== "pageSession" || sessionsSnapshot?.available !== true ||
        !/^[a-f0-9]{32}$/.test(boot || "") || !/^[a-f0-9]{32}$/.test(session) ||
        !listOf(sessionsSnapshot.sessions).some(row => row.sessionId === session)) return null;
    return {bootId: boot, sessionId: session, key: boot + "/" + session};
  }

  async function loadSessionHistory() {
    const selected = selectedAuditSession();
    if (!selected) return;
    const epoch = pageEpoch, generation = stateGeneration;
    if (sessionHistoryRead?.key === selected.key && sessionHistoryRead.epoch === epoch
        && sessionHistoryRead.generation === generation) return;
    const read = {key: selected.key, epoch, generation};
    sessionHistoryRead = read;
    let value;
    try {
      value = await invoke("get_session_history", {bootId: selected.bootId, sessionId: selected.sessionId});
    } catch (_) {
      value = {available: false};
    }
    if (sessionHistoryRead !== read) return;
    sessionHistoryRead = null;
    if (pageEpoch !== epoch || stateGeneration !== generation || selectedAuditSession()?.key !== selected.key) return;
    sessionHistory = {key: selected.key, epoch, generation, value};
    renderSessionsView();
  }

  function renderAuditHistory(history, selected) {
    const title = '<h3 class="set-title">Audit history</h3>';
    const lost = Number.isSafeInteger(history?.lost) && history.lost > 0
      ? '<p class="item-meta notice-warn">' + history.lost + ' audit record' + (history.lost === 1 ? '' : 's') + ' lost across the workstation.</p>' : '';
    if (history?.available !== true || !Array.isArray(history.records)) {
      return title + lost + '<p class="item-meta">Audit history unavailable.</p>';
    }
    const rows = history.records.filter(row => row && (!selected ||
      (row.boot_id === selected.bootId && row.session_id === selected.sessionId))).slice(0, 50);
    if (!rows.length) return title + lost + '<p class="item-meta">No retained audit records.</p>';
    const label = value => typeof value === "string" && /^[a-z0-9_./-]{1,96}$/.test(value) ? value : "";
    return title + lost + '<ol class="audit-list">' + rows.map(row => {
      const when = Number.isSafeInteger(row.timestamp_unix_ms) ? new Date(row.timestamp_unix_ms).toJSON() : null;
      const duration = Number.isSafeInteger(row.duration_ms) && row.duration_ms >= 0 ? row.duration_ms + " ms" : "";
      const source = ["local", "chatgpt", "gemini"].includes(row.provider) ? row.provider : "";
      const context = /^ctx_[0-9a-f]{32}$/.test(row.context_id || "") ? row.context_id : "";
      const mission = /^mis_[0-9a-f]{32}$/.test(row.mission_id || "") ? row.mission_id : "";
      const meta = [when, source, duration, context, mission].filter(Boolean).join(" · ");
      return '<li class="audit-row"><div class="audit-main"><code>' + escapeHtml(label(row.tool_name) || label(row.method) || "other") +
        '</code> <span class="pill' + (row.outcome === "success" ? " ok" : " warn") + '">' +
        escapeHtml(label(row.outcome) || "unknown") + '</span></div><div class="audit-meta">' + escapeHtml(meta) + '</div></li>';
    }).join("") + '</ol>';
  }

  function renderSessionDetail(key) {
    const data = sessionsSnapshot;
    const id = key.slice(2);
    const session = key.startsWith("s:") ? listOf(data && data.sessions).find((s) => s.sessionId === id) : null;
    const context = key.startsWith("c:") ? listOf(data && data.earlier).find((c) => c.contextId === id) : null;
    if (!session && !context) {
      $("sessionTitle").textContent = "Session";
      if (!data) return SESSIONS_LOADING;
      if (data?.available === false) {
        return '<div class="item-meta notice-warn">' + escapeHtml(data.reason || "Sessions unavailable.") + "</div>";
      }
      return '<div class="empty-state"><div class="set-title">Session no longer listed</div><div class="set-sub">Go back to see current sessions.</div></div>';
    }
    if (context) {
      $("sessionTitle").textContent = (SESSION_PROVIDERS[context.actorKind] || "Agent") + " context";
      const missions = listOf(context.missions);
      return '<section class="set-card"><dl class="kv kv-compact"><dt>Context</dt><dd>' + escapeHtml(context.contextId) + "</dd>" +
        "<dt>Attached</dt><dd>" + escapeHtml(context.attachedAt || "-") + "</dd><dt>Last seen</dt><dd>" + escapeHtml(context.lastSeen || "-") + "</dd></dl></section>" +
        '<section class="set-card"><h3 class="set-title">Missions</h3>' +
        (missions.length ? missions.map(missionCard).join("") : '<div class="item-meta">No missions.</div>') + "</section>";
    }
    $("sessionTitle").textContent = sessionName(session);
    const missions = sessionMissions(session.contexts);
    const commands = listOf(session.commands);
    const calls = listOf(session.toolCalls);
    let html = '<section class="set-card">' +
      '<div class="session-status"><span class="dot' + (session.live === true ? " ok" : "") + '" aria-hidden="true"></span>' +
      escapeHtml(session.live === true ? "Live, active " + sinceText(session.lastSeen) : "Not live, seen " + sinceText(session.lastSeen)) + "</div>" +
      '<dl class="kv"><dt>Connection</dt><dd>' + escapeHtml(sessionName(session) + " · " + (SESSION_TRANSPORTS[session.transport] || session.transport || "-")) + "</dd>" +
      (session.clientLabel ? "<dt>Client</dt><dd>" + escapeHtml(session.clientLabel) + "</dd>" : "") +
      "<dt>First seen</dt><dd>" + escapeHtml(session.firstSeen || "-") + "</dd>" +
      "<dt>Requests</dt><dd>" + escapeHtml(session.requestCount) + (Number(session.inFlight) > 0 ? ", " + escapeHtml(session.inFlight) + " in progress" : "") + "</dd></dl></section>";
    html += '<section class="set-card"><h3 class="set-title">Missions</h3>' +
      (missions.length ? missions.map(missionCard).join("") : '<div class="item-meta">No missions in this session.</div>') + "</section>";
    html += '<section class="set-card"><h3 class="set-title">Commands</h3>' +
      (commands.length ? '<ol class="audit-list">' + commands.map((c) =>
        '<li class="audit-row"><div class="audit-main"><code>' + escapeHtml(c.program) + '</code> <span class="pill' + (c.state === "running" ? " accent" : c.exitCode === 0 ? " ok" : " warn") + '">' +
        escapeHtml(c.state === "running" ? "running" : "exit " + (c.exitCode === null || c.exitCode === undefined ? "-" : c.exitCode)) + "</span></div>" +
        '<div class="audit-meta">' + escapeHtml("Started " + sinceText(c.startedAt) + (c.endedAt ? " · ended " + sinceText(c.endedAt) : "")) + "</div></li>"
      ).join("") + "</ol>" : '<div class="item-meta">No commands run.</div>') + "</section>";
    html += '<section class="set-card"><h3 class="set-title">Recent tool calls</h3>' +
      (calls.length ? '<ol class="audit-list">' + calls.map((t) =>
        '<li class="audit-row"><div class="audit-main"><code>' + escapeHtml(t.toolName) + '</code> <span class="pill' + (t.outcome === "success" ? " ok" : " warn") + '">' + escapeHtml(t.outcome || "-") + "</span></div>" +
        '<div class="audit-meta">' + escapeHtml(t.time || "-") + "</div></li>"
      ).join("") + "</ol>" : '<div class="item-meta">No tool calls yet.</div>') + "</section>";
    const selected = selectedAuditSession();
    if (selected) {
      const current = sessionHistory?.key === selected.key && sessionHistory.epoch === pageEpoch
        && sessionHistory.generation === stateGeneration;
      html += '<section class="set-card">' + (current ? renderAuditHistory(sessionHistory.value, selected)
        : '<h3 class="set-title">Audit history</h3><p class="item-meta">Loading audit history…</p>') + '</section>';
    }
    return html;
  }

  function sessionsPageVisible() {
    return activePage === "pageMain" || activePage === "pageMissions" || activePage === "pageSession";
  }

  function renderSessionsBadge() {
    const count = sessionsSnapshot?.available === true ? sessionsSnapshot.totals?.live : null;
    const visible = Number.isSafeInteger(count) && count > 0;
    const badge = $("sessionsBadge");
    badge.classList.toggle("hidden", !visible);
    badge.textContent = visible ? String(count) : "";
    if (visible) badge.setAttribute("aria-label", count + " live sessions");
    else badge.removeAttribute("aria-label");
  }

  function renderSessionsView() {
    if (activePage === "pageMissions") {
      const html = renderSessionsList(sessionsSnapshot);
      const body = $("sessionsBody");
      if (body.innerHTML === html) return;
      const focused = document.activeElement?.getAttribute("data-session");
      body.innerHTML = html;
      if (focused) {
        const row = Array.from(body.querySelectorAll("[data-session]")).find(el => el.getAttribute("data-session") === focused);
        (row ?? $("refreshMissionsBtn")).focus({ preventScroll: true });
      }
    } else if (activePage === "pageSession" && selectedSessionKey) {
      const html = renderSessionDetail(selectedSessionKey);
      const body = $("sessionBody");
      if (body.innerHTML !== html) {
        body.innerHTML = html;
        bindHandoffButtons(body);
      }
    }
  }

  async function loadSessions(passive = false) {
    if (!passive) renderSessionsView();
    if (sessionsRequest?.generation === stateGeneration) return;
    const request = { generation: stateGeneration };
    sessionsRequest = request;
    const current = () => sessionsRequest === request && request.generation === stateGeneration;
    try {
      const data = await invoke("get_sessions");
      if (!current()) return;
      sessionsSnapshot = data && typeof data === "object" ? data : { available: false, reason: "Sessions unavailable." };
    } catch (err) {
      if (!current()) return;
      sessionsSnapshot = { available: false, reason: "Sessions could not load: " + String(err) };
    } finally {
      if (sessionsRequest === request) sessionsRequest = null;
    }
    renderSessionsBadge();
    renderSessionsView();
    loadSessionHistory();
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
    body.querySelectorAll("[data-ext-test]").forEach((button) => {
      button.disabled = !canDecideExtensions() || mutationsBlocked()
        || button.getAttribute("data-ext-enabled") !== "true";
    });
    body.querySelectorAll("[data-ext-reload]").forEach((button) => {
      button.disabled = !canDecideExtensions() || mutationsBlocked();
    });
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

  function extensionServerAuthorityKey(panel, srv) {
    if (!srv || srv.enabled !== true) return null;
    const fp = (typeof srv.config_sha256 === "string" && srv.config_sha256) ? srv.config_sha256
      : (typeof srv.configSha256 === "string" && srv.configSha256) ? srv.configSha256
      : JSON.stringify([srv.transport || null, srv.endpoint || null, srv.executable || null, srv.executable_sha256 || null]);
    return JSON.stringify([
      Number(panel?.gateway?.generation ?? 0),
      panel?.extensions?.generation ?? null,
      srv.id,
      fp,
    ]);
  }

  function pruneExtensionTestResults(panel) {
    const servers = new Map(((panel && panel.extensions && panel.extensions.servers) || []).map((srv) => [srv.id, srv]));
    let changed = false;
    for (const [id, entry] of extensionTestResults.entries()) {
      const currentKey = extensionServerAuthorityKey(panel, servers.get(id));
      if (!currentKey || !entry || entry.authorityKey !== currentKey) {
        extensionTestResults.delete(id);
        changed = true;
      }
    }
    return changed;
  }

  async function testExtensionConnection(button) {
    if (mutationsBlocked() || !canDecideExtensions()
      || button.getAttribute("data-ext-enabled") !== "true") return;
    const server = button.getAttribute("data-ext-test");
    if (!server) return;
    const startSrv = (state?.extensions?.servers || []).find((srv) => srv.id === server);
    const startKey = extensionServerAuthorityKey(state, startSrv);
    if (!startKey) return;
    const startEpoch = extensionProbeEpoch;
    const startGatewayGen = Number(state?.gateway?.generation ?? 0);
    const startExtGen = state?.extensions?.generation ?? null;
    const stillMatchesAuthority = (report) => {
      if (startEpoch !== extensionProbeEpoch) return false;
      if (Number(state?.gateway?.generation ?? 0) !== startGatewayGen) return false;
      if ((state?.extensions?.generation ?? null) !== startExtGen) return false;
      const currentSrv = (state?.extensions?.servers || []).find((srv) => srv.id === server);
      const currentKey = extensionServerAuthorityKey(state, currentSrv);
      if (!currentKey || currentKey !== startKey) return false;
      if (report && typeof report.config_sha256 === "string" && typeof currentSrv?.config_sha256 === "string"
        && report.config_sha256 !== currentSrv.config_sha256) {
        return false;
      }
      if (report && Number.isFinite(report.generation) && Number.isFinite(state?.extensions?.generation)
        && report.generation !== state.extensions.generation) {
        return false;
      }
      return true;
    };
    extensionTestInFlight = true;
    approvalsRead++;
    renderExtensionControls();
    try {
      const report = await invoke("test_extension_connection", { server });
      if (!stillMatchesAuthority(report)) return;
      extensionTestResults.set(server, { authorityKey: startKey, report });
      const latency = Number.isFinite(report?.latency_ms) ? " (" + report.latency_ms + " ms)" : "";
      if (report?.ok === true) {
        showToast("Extension " + server + " connected" + latency + ".");
      } else {
        showToast("Extension " + server + " check failed: " + String(report?.error_class || report?.status || "error") + latency + ".");
      }
    } catch (err) {
      if (!stillMatchesAuthority(null)) return;
      extensionTestResults.set(server, { authorityKey: startKey, report: { ok: false, status: "error", error_class: String(err) } });
      showToast(String(err));
    } finally {
      extensionTestInFlight = false;
      approvalsSnapshotKey = null;
      if (activePage === "pageApprovals") await loadApprovalsDrawer();
      renderExtensionControls();
    }
  }

  async function reloadExtensions() {
    if (mutationsBlocked() || !canDecideExtensions()) return;
    extensionTestInFlight = true;
    extensionProbeEpoch++;
    extensionTestResults.clear();
    approvalsRead++;
    renderExtensionControls();
    try {
      const receipt = await invoke("reload_extensions");
      extensionProbeEpoch++;
      extensionTestResults.clear();
      const count = Number.isFinite(receipt?.server_count) ? receipt.server_count : 0;
      const gen = Number.isFinite(receipt?.generation) ? " · gen " + receipt.generation : "";
      showToast("Extensions reloaded (" + count + " server(s)" + gen + ").");
    } catch (err) {
      showToast("Extension reload failed: " + String(err));
    } finally {
      extensionTestInFlight = false;
      approvalsSnapshotKey = null;
      if (activePage === "pageApprovals") await loadApprovalsDrawer();
      renderExtensionControls();
    }
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
    extensionProbeEpoch++;
    approvalsRead++;
    stateGeneration++;
    clearTimeout(extensionPollTimer);
    renderExtensionControls();
    try {
      const receipt = await invoke("decide_extension_request", { requestId: id, approve, reviewed });
      extensionProbeEpoch++;
      extensionTestResults.clear();
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

  async function loadApprovalsDrawer(polling = false, passive = false) {
    if (extensionDecisionInFlight) return;
    approvalsInFlight++;
    clearTimeout(extensionPollTimer);
    extensionPollTimer = null;
    const currentRead = ++approvalsRead;
    const body = $("approvalsBody");
    rememberOAuthCallbacks();
    if (!polling) {
      approvalsSnapshotKey = null;
      body.innerHTML = '<div class="empty-note">Checking requests…</div>';
    }
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

      const providerNames = { chatgpt: "ChatGPT", gemini: "Gemini" };
      let html = "";
      if (!oauth.configured) {
        html += '<div class="set-card"><div class="set-title">Web connections</div>' +
          '<div class="set-sub">Set up the web relay in Settings to connect ChatGPT or Gemini web.</div></div>';
      } else {
        html += '<div class="set-card">' +
          '<div class="set-row">' +
            '<div class="set-col-grow"><div class="set-title">Web connections</div><div class="set-sub origin-full">' + escapeHtml(oauth.origin) + "</div></div>" +
            '<button class="mini-btn sm" id="enrollBtn" type="button" title="Let a new ChatGPT or Gemini client ask for access during the next 10 minutes">Allow new (10 min)</button>' +
          "</div>";
        const pending = oauth.pending || [];
        if (pending.length === 0) {
          html += '<div class="item-meta">No pending connection requests.</div>';
        } else {
          html += pending.map((req) => {
            const provider = String(req.provider || "");
            return '<div class="request-block">' +
              '<div class="set-row"><span class="set-title">' + escapeHtml(providerNames[provider.toLowerCase()] || provider) +
                '</span><span class="pill accent" title="Client ID">' + escapeHtml(req.clientId) + "</span></div>" +
              '<dl class="kv"><dt>Callback</dt><dd><code>' + escapeHtml(req.redirectUri) + "</code></dd>" +
              "<dt>Resource</dt><dd><code>" + escapeHtml(req.resource) + "</code></dd></dl>" +
              renderCapabilitySelection(oauth.capabilitySelection, req.capability || { kind: "legacy" }) +
              renderCapability(req.capability) +
              '<label class="field"><span class="field-label">To approve, paste the callback link shown by the client</span>' +
              '<input class="text-input" data-oauth-cb="' + escapeHtml(req.id) + '" type="text" placeholder="https://…"></label>' +
              '<button class="action-btn full-w" data-oauth-approve="' + escapeHtml(req.id) + '" type="button">Approve connection</button>' +
            "</div>";
          }).join("");
        }
        html += "</div>";
      }

      const ext = panel.extensions || {};
      if (pruneExtensionTestResults(panel)) {
        approvalsSnapshotKey = null;
      }
      const probeKey = Array.from(extensionTestResults.entries()).map(([id, entry]) => [
        id, entry.authorityKey, entry.report?.ok, entry.report?.status, entry.report?.latency_ms, entry.report?.error_class,
      ]);
      const snapshotKey = JSON.stringify([oauth, ext, canDecideExtensions(panel), probeKey]);
      if (passive && !nativeApprovalsRefreshNeeded && snapshotKey === approvalsSnapshotKey) {
        scheduleExtensionPoll(ext.oauthOperation);
        return;
      }
      if (ext.configured && ext.exists) {
        const servers = ext.servers || [];
        const requests = ext.requests || [];
        html += '<div class="set-card"><div class="set-row"><span class="set-title">Extensions</span>' +
          '<button class="mini-btn xs" data-ext-reload type="button">Reload</button></div>';
        if (servers.length === 0) {
          html += '<div class="set-sub">No extensions added.</div>';
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
            const badge = '<span class="pill-group"><span class="pill" title="Extension enabled">' + (srv.enabled ? "On" : "Off") +
              '</span><span class="pill ' + tokenClass + '" title="Local OAuth token status">' +
              tokenLabel + '</span><button class="mini-btn xs" data-ext-test="' + escapeHtml(srv.id) +
              '" data-ext-enabled="' + (srv.enabled ? "true" : "false") + '" type="button">Test</button></span>';
            const currentKey = extensionServerAuthorityKey(panel, srv);
            const probeEntry = extensionTestResults.get(srv.id);
            const probe = currentKey && probeEntry && probeEntry.authorityKey === currentKey ? probeEntry.report : null;
            const probeLine = probe
              ? '<div class="item-meta">' + escapeHtml(
                (probe.ok === true ? "Check OK" : "Check failed: " + (probe.error_class || probe.status || "error"))
                + (Number.isFinite(probe.latency_ms) ? " · " + probe.latency_ms + " ms" : "")
                + (probe.protocol_version ? " · " + probe.protocol_version : "")
              ) + "</div>"
              : "";
            return '<div class="set-row list-row"><span class="item-name">' + escapeHtml(srv.id) + "</span>" + badge + "</div>" + probeLine;
          }).join("");
        }
        if (!canDecideExtensions(panel)) {
          html += '<div class="set-sub">Connect Bridge to review requests.</div>';
        }
        if (requests.length > 0) {
          html += '<h3 class="list-heading">Requests</h3>';
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
            return '<details class="extension-proposal"' + (pending ? " open" : "") + "><summary>" + escapeHtml(r.action) +
              " <code>" + escapeHtml(r.name) + '</code> <span class="pill' + (pending ? " warn" : "") + '">' +
              escapeHtml(r.status) + "</span></summary>" +
              '<dl class="kv"><dt>Endpoint</dt><dd><code>' + escapeHtml(endpoint) + "</code></dd>" +
              "<dt>Request</dt><dd><code>" + escapeHtml(r.requestId) + "</code></dd></dl>" +
              '<pre class="extension-payload">' + escapeHtml(JSON.stringify(r.payload || {}, null, 2)) + "</pre>" +
              '<div class="set-sub">Secrets appear as references only.</div>' +
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
      approvalsSnapshotKey = snapshotKey;
      const focused = document.activeElement;
      const focusedId = focused && focused.getAttribute("data-oauth-cb");
      const selectionStart = focusedId ? focused.selectionStart : null;
      const selectionEnd = focusedId ? focused.selectionEnd : null;
      body.innerHTML = html;
      body.querySelectorAll("[data-oauth-cb]").forEach((input) => {
        input.value = oauthCallbackDrafts.get(input.getAttribute("data-oauth-cb")) || "";
        if (focusedId && input.getAttribute("data-oauth-cb") === focusedId) {
          input.focus?.();
          if (selectionStart != null && selectionEnd != null) input.setSelectionRange?.(selectionStart, selectionEnd);
        }
      });
      renderExtensionControls();
      scheduleExtensionPoll(ext.oauthOperation);
      body.querySelectorAll("[data-ext-review]").forEach((input) => {
        input.addEventListener("change", renderExtensionControls);
      });
      body.querySelectorAll("[data-ext-decide]").forEach((button) => {
        button.addEventListener("click", () => decideExtension(button));
      });
      body.querySelectorAll("[data-ext-test]").forEach((button) => {
        button.addEventListener("click", () => testExtensionConnection(button));
      });
      body.querySelectorAll("[data-ext-reload]").forEach((button) => {
        button.addEventListener("click", reloadExtensions);
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
      approvalsSnapshotKey = null;
      body.innerHTML = '<div class="empty-state"><div class="set-title">Requests could not load</div><div class="set-sub">' + escapeHtml(err) + "</div></div>";
    } finally {
      approvalsInFlight--;
    }
  }

  function renderRequestAudit(audit) {
    const heading = '<h3 class="list-heading">MCP request log</h3>';
    const empty = heading + '<div class="item-meta">No requests recorded</div>';
    if (!audit || typeof audit !== "object") return empty;
    const text = (value) => (typeof value === "string" && value ? value : "-");
    const count = (value) => (Number.isFinite(value) ? String(value) : "-");
    try {
      const records = Array.isArray(audit.records)
        ? audit.records.filter((record) => record && typeof record === "object")
        : [];
      const summary = heading + '<dl class="kv kv-compact">' +
        "<dt>Boot ID</dt><dd>" + escapeHtml(text(audit.boot_id).slice(0, 8)) + "</dd>" +
        "<dt>Records kept</dt><dd>" + escapeHtml(records.length) + "</dd>" +
        "<dt>In flight</dt><dd>" + escapeHtml(count(audit.in_flight)) + "</dd>" +
        "<dt>Evicted</dt><dd>" + escapeHtml(count(audit.evicted_verified)) + " verified, " +
          escapeHtml(count(audit.evicted_unverified)) + " unverified</dd></dl>";
      if (!records.length) return summary + '<div class="item-meta">No requests recorded</div>';

      // Snapshots list records in ascending completion sequence.
      return summary + '<ol class="audit-list">' + records.slice(-20).reverse().map((record) => {
        const date = new Date(Number(record.timestamp_unix_ms));
        const time = Number.isFinite(date.getTime()) ? date.toISOString() : "-";
        const provider = typeof record.provider === "string" && record.provider ? record.provider : "Unverified";
        const outcome = text(record.outcome);
        const tone = outcome === "success" ? " ok" : (outcome === "-" ? "" : " warn");
        const error = Number.isFinite(record.error_code) ? String(record.error_code)
          : (typeof record.error_code === "string" && record.error_code ? record.error_code : null);
        const client = typeof record.client_id_sha256 === "string" && record.client_id_sha256
          ? record.client_id_sha256.slice(0, 8) : null;
        const details = [
          time,
          "HTTP " + count(record.http_status),
          error === null ? null : "error " + error,
          Number.isFinite(record.duration_ms) ? record.duration_ms + " ms" : null,
          provider,
          client === null ? null : "client " + client,
        ].filter((part) => part !== null);
        return '<li class="audit-row"><div class="audit-main"><strong>' + escapeHtml(text(record.method)) + "</strong>" +
          (typeof record.tool_name === "string" && record.tool_name ? " <code>" + escapeHtml(record.tool_name) + "</code>" : "") +
          ' <span class="pill' + tone + '">' + escapeHtml(outcome) + "</span></div>" +
          '<div class="audit-meta">' + escapeHtml(details.join(" · ")) + "</div></li>";
      }).join("") + "</ol>";
    } catch (_) {
      return heading + '<div class="item-meta">The request log snapshot is unreadable.</div>';
    }
  }
  function renderExtensionStatus(ext) {
    if (!ext || typeof ext !== "object") return "";
    const servers = Array.isArray(ext.servers) ? ext.servers : [];
    const heading = '<h3 class="list-heading">Extension servers</h3>';
    if (!servers.length) {
      return heading + '<div class="item-meta">No extension servers configured.</div>';
    }
    const items = servers.map((srv) => {
      const state = srv.enabled === false || srv.state === "disabled" ? "disabled"
        : (typeof srv.state === "string" ? srv.state : "idle");
      const tone = state === "ready" ? " pill-ok"
        : state === "error" ? " pill-warn"
        : state === "slow" ? " pill-warn"
        : "";
      const parts = [];
      if (state !== "disabled") {
        if (Number.isFinite(srv.last_latency_ms)) parts.push(srv.last_latency_ms + " ms");
        if (typeof srv.last_error_class === "string" && srv.last_error_class) parts.push("error " + srv.last_error_class);
        if (Number.isFinite(srv.pool_idle_sessions)) parts.push("pool " + srv.pool_idle_sessions + " idle");
      }
      return '<li class="audit-row"><div class="audit-main"><code>' + escapeHtml(String(srv.server || "")) + "</code> " +
        '<span class="pill' + tone + '">' + escapeHtml(state) + "</span></div>" +
        (parts.length ? '<div class="audit-meta">' + escapeHtml(parts.join(" · ")) + "</div>" : "") + "</li>";
    }).join("");
    return heading + '<ol class="audit-list">' + items + "</ol>";
  }
  async function loadSettingsDiagnostics() {
    const box = $("skillsAndDiagBox");
    const read = ++diagnosticsRead;
    const epoch = pageEpoch;
    const generation = stateGeneration;
    const gatewayGen = Number(state?.gateway?.generation ?? 0);
    const current = () => read === diagnosticsRead && epoch === pageEpoch
      && activePage === "pageSettings" && generation === stateGeneration
      && Number(state?.gateway?.generation ?? 0) === gatewayGen;
    diagnosticsInFlight++;
    try {
      const [diag, skills] = await Promise.all([
        invoke("get_diagnostics"),
        invoke("get_skills_overview"),
      ]);
      if (!current()) return;
      const skillList = (skills && skills.skills) || [];
      const profiles = diag && Array.isArray(diag.mcpBrowserProfiles) ? diag.mcpBrowserProfiles : [];
      let html = '<dl class="kv kv-compact"><dt>Token storage</dt><dd>' + escapeHtml(diag.oauthKeystore) + "</dd>" +
        "<dt>Browser profiles</dt><dd>" + String(profiles.length) + "</dd></dl>";
      if (diag.capabilitySelection) {
        html += renderCapabilitySelection(diag.capabilitySelection);
        html += renderCapability(diag.capabilitySelection.identity);
      }
      if (diag.providerCleanup && diag.providerCleanup.pending > 0) {
        html += '<div class="item-meta notice-warn">' + escapeHtml(diag.providerCleanup.pending) +
          " cleanup step(s) await confirmation. A new runtime waits until cleanup is confirmed.</div>";
      }
      html += '<h3 class="list-heading">Skills</h3>';
      html += skillList.length > 0
        ? skillList.map((sk) =>
          '<div class="set-row list-row"><code>' + escapeHtml(sk.name || sk.id) +
          '</code><button class="mini-btn xs" data-skill-rb="' + escapeHtml(sk.name || sk.id) + '" type="button" title="Roll back this skill">Roll back</button></div>'
        ).join("")
        : '<div class="item-meta">No skills installed.</div>';
      html += renderExtensionStatus(diag.extensionStatus);
      html += renderRequestAudit(diag.mcpRequestAudit);
      html += '<section>' + renderAuditHistory(diag.auditHistory) + '</section>';
      if (box.innerHTML === html) return;
      box.innerHTML = html;
      renderControls();
      box.querySelectorAll("[data-skill-rb]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          if (operatorMutationsBlocked() || diagnosticsMutation) return;
          diagnosticsMutation = true;
          diagnosticsRead++;
          btn.disabled = true;
          try {
            await invoke("run_skill_action", { action: "rollback", name: btn.getAttribute("data-skill-rb"), version: null });
            showToast("Skill rolled back.");
            if (activePage === "pageSettings") await loadSettingsDiagnostics();
          } catch (err) {
            showToast(String(err));
          } finally {
            diagnosticsMutation = false;
            renderControls();
          }
        });
      });
    } catch (err) {
      if (current()) box.textContent = String(err);
    } finally {
      diagnosticsInFlight--;
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
        $("modalProfileTitle").textContent = "Save " + PROFILE_META[target].label + " as your preference?";
        $("modalDangerLabel").textContent = PROFILE_META[target].hint;
        $("modalProfileBody").textContent = "Nothing changes until a running Bridge applies it.";
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
    loadSessions();
    loadMissionsDrawer();
  });
  $("sessionsBody").addEventListener("click", (event) => {
    const row = event.target && event.target.closest ? event.target.closest("[data-session]") : null;
    if (!row) return;
    selectedSessionKey = row.getAttribute("data-session");
    showPage("pageSession");
    renderSessionsView();
    loadSessionHistory();
    loadSessions(true);
  });
  $("sessionBackBtn").addEventListener("click", () => {
    selectedSessionKey = null;
    showPage("pageMissions");
    renderSessionsView();
    loadSessions(true);
    loadMissionsDrawer(true);
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
  $("refreshMissionsBtn").addEventListener("click", () => {
    loadSessions();
    loadMissionsDrawer();
  });
  $("refreshApprovalsBtn").addEventListener("click", () => loadApprovalsDrawer());
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
    const dir = await pickFolder("Choose OAuth folder");
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
      showToast("Web relay saved.");
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
  $("copyMcpBtn").addEventListener("click", () => copySnippet("snipMcpUrl", "MCP link copied."));
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
    $("obStepLabel").textContent = step + " of 3";
    $("obStep1").classList.toggle("hidden", step !== 1);
    $("obStep2").classList.toggle("hidden", step !== 2);
    $("obStep3").classList.toggle("hidden", step !== 3);
    $("obTitle").textContent = step === 1
      ? "Choose a workspace"
      : (step === 2 ? "Choose starting access" : "You're ready");
  }

  $("obPickWorkspaceBtn").addEventListener("click", async () => {
    if (usesLiveWorkstation()) return;
    const dir = await pickFolder("Choose workspace folder");
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
      extensionProbeEpoch++;
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
