import { chromium } from 'playwright-core';
import { createHash, randomUUID } from 'node:crypto';
import { lstat, realpath, mkdir, mkdtemp, open, rm, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { OwnedPlaywrightDriver } from './driver.mjs';
import { BrowserError, validateActions, validateSnapshot, validateStart, httpUrl, boolean, string, timeout, keys } from './validation.mjs';

const OBSERVATION_TTL = 30_000;
const RESERVATION_TTL = 30_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const IDLE_TTL = 30 * 60_000;
const MAX_OBSERVATIONS = 1024;
const DOWNLOAD_LIMIT = 64 * 1024 * 1024;
const WAIT_TYPES = new Set(['wait', 'wait_selector', 'wait_url', 'wait_text']);

export async function physicalDirectory(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value)) throw new BrowserError('PRIVATE_PATH_INVALID', 'An absolute private directory is required');
  const metadata = await lstat(value);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new BrowserError('PRIVATE_PATH_INVALID', 'Private directory is not a physical directory');
  return realpath(value);
}
function inside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative !== '' && !relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative);
}
function safeSuggestedName(name) {
  const clean = String(name ?? '').replaceAll('\\', '/').split('/').pop().replace(/[\u0000-\u001f<>:"|?*]/gu, '_').replace(/[. ]+$/u, '').slice(0, 180);
  return clean && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu.test(clean) ? clean : 'download.bin';
}

export class BrowserSession {
  static async launch(config) {
    const options = validateStart(config);
    const sessionDir = await physicalDirectory(config.session_dir);
    const profileDir = await physicalDirectory(config.profile_dir);
    if (!path.isAbsolute(config.executable_path ?? '')) throw new BrowserError('EXECUTABLE_INVALID', 'An operator-pinned browser executable is required');
    const uploads = path.join(sessionDir, 'uploads'), downloads = path.join(sessionDir, 'downloads'), rawDownloads = path.join(sessionDir, 'raw-downloads');
    for (const dir of [uploads, downloads, rawDownloads]) {
      await mkdir(dir, { recursive: true });
      if (!inside(sessionDir, await physicalDirectory(dir))) throw new BrowserError('PRIVATE_PATH_INVALID', 'Private child directory escaped its session');
    }
    // Chromium and its Crashpad helper must not write debug.log beside the
    // manifest-pinned executable. Allocate a fresh private session directory.
    const logDir = await physicalDirectory(await mkdtemp(path.join(sessionDir, 'chromium-log-')));
    if (!inside(sessionDir, logDir)) throw new BrowserError('PRIVATE_PATH_INVALID', 'Private log directory escaped its session');
    const logFile = path.join(logDir, 'debug.log');
    const environment = Object.fromEntries(Object.entries(process.env)
      .filter(([name]) => name.toUpperCase() !== 'CHROME_LOG_FILE'));
    environment.CHROME_LOG_FILE = logFile;
    const context = await chromium.launchPersistentContext(profileDir, {
      executablePath: config.executable_path,
      env: environment,
      args: ['--log-file=' + logFile],
      headless: options.headless,
      viewport: options.viewport ?? { width: 1280, height: 720 },
      deviceScaleFactor: 1,
      acceptDownloads: true,
      downloadsPath: rawDownloads,
      timeout: options.timeout_ms,
      handleSIGINT: false,
      handleSIGTERM: false,
      handleSIGHUP: false,
    });
    try {
      return new BrowserSession(context, { ...config, ...options, session_dir: sessionDir, profile_dir: profileDir, uploads, downloads, rawDownloads });
    } catch (error) {
      await context.close().catch(() => undefined);
      throw error;
    }
  }

  constructor(context, config) {
    this.context = context;
    this.config = config;
    this.id = config.session_id ?? randomUUID();
    this.instance = randomUUID();
    this.driver = new OwnedPlaywrightDriver(context);
    this.observations = new Map();
    this.reservation = undefined;
    this.lastReceipt = undefined;
    this.generations = new WeakMap();
    this.lastActivity = Date.now();
    this.closed = false;
    this.closing = false;
    this.closePromise = undefined;
    this.downloadExpected = false;
    this.pendingDownloads = new Set();
    const register = page => {
      this.generations.set(page, 0);
      page.on('framenavigated', () => { this.generations.set(page, (this.generations.get(page) ?? 0) + 1); this.invalidate(); });
      page.on('dialog', () => this.invalidate());
      page.on('close', () => this.invalidate());
      page.on('download', download => {
        if (!this.downloadExpected || this.pendingDownloads.size) {
          void download.cancel().catch(() => undefined);
          return;
        }
        this.pendingDownloads.add(download);
      });
    };
    for (const page of context.pages()) register(page);
    context.on('page', register);
    context.once('close', () => { this.closed = true; this.invalidate(); });
  }

  usable() { return !this.closed && !this.closing && !this.driver.closed; }
  invalidate() { this.observations.clear(); this.reservation = undefined; }
  beginReceipt(operation, phase = operation) {
    this.lastReceipt = { operation, session_id: this.id, phase, completed_actions: 0, failed_action_index: null,
      effect_uncertain: false, session_usable: this.usable(), upload_effect_started: false };
    return this.lastReceipt;
  }
  finishReceipt() { this.lastReceipt.session_usable = this.usable(); return structuredClone(this.lastReceipt); }
  receiptError(error) {
    const receipt = this.finishReceipt();
    const { download, ...details } = receipt;
    const failure = this.domainError(error, details);
    failure.receipt = receipt;
    return failure;
  }

  idleExpired() { return Date.now() - this.lastActivity >= IDLE_TTL; }
  async touch() {
    if (this.closed || this.closing || this.driver.closed) throw new BrowserError('SESSION_CLOSED', 'Owned browser session is closed', { session_usable: false });
    if (this.idleExpired()) {
      await this.close();
      throw new BrowserError('SESSION_IDLE_EXPIRED', 'Browser session expired after 30 minutes idle', { session_usable: false });
    }
    this.lastActivity = Date.now();
  }
  async start(url) {
    this.beginReceipt('start');
    try {
      await this.touch();
      if (url !== undefined) {
        this.lastReceipt.effect_uncertain = true;
        await this.driver.act(1, undefined, [{ type: 'goto', url: httpUrl(url) }], this.config.timeout_ms);
        this.lastReceipt.completed_actions = 1; this.lastReceipt.effect_uncertain = false;
      }
      const result = await this.summary();
      this.lastReceipt.page_id = result.page_id;
      this.lastReceipt.phase = 'complete';
      return result;
    } catch (error) { throw this.receiptError(error); }
  }
  async summary(pageId) {
    const pages = await this.driver.listPages(1);
    const page = pages.find(p => p.page_id === pageId) ?? pages.find(p => p.active) ?? pages[0];
    return { session_id: this.id, headless: this.config.headless, active: !this.closed, pages, ...(page ? { page_id: page.page_id, url: page.url, title: page.title } : {}) };
  }

  async session(args) {
    this.beginReceipt('session', args.action);
    try {
      await this.touch();
      const limit = timeout(args.timeout_ms);
      let selected = args.page_id;
      if (selected !== undefined) { string(selected, 'page_id', 1, 512); this.lastReceipt.page_id = selected; }
      switch (args.action) {
        case 'list': return this.summary();
        case 'new_page':
          if (args.url !== undefined) httpUrl(args.url);
          this.invalidate();
          this.lastReceipt.effect_uncertain = true;
          selected = await this.driver.createPage(1, args.url, limit, created => {
            this.lastReceipt.created_page_id = created;
            this.lastReceipt.page_id = created;
            this.lastReceipt.completed_actions = 1;
            this.lastReceipt.phase = 'navigate_new_page';
          });
          break;
        case 'select_page':
          string(selected, 'page_id', 1, 512); this.invalidate();
          this.lastReceipt.effect_uncertain = true;
          await this.driver.selectPage(1, selected, limit);
          break;
        case 'close_page':
          string(selected, 'page_id', 1, 512); this.invalidate();
          this.lastReceipt.effect_uncertain = true;
          await this.driver.closePage(1, selected, limit); selected = undefined;
          break;
        case 'handle_dialog':
          string(selected, 'page_id', 1, 512);
          boolean(args.accept, 'accept');
          if (args.prompt_text !== undefined) string(args.prompt_text, 'prompt_text', 0, 4096);
          this.invalidate();
          this.lastReceipt.effect_uncertain = true;
          await this.driver.handleDialog(1, selected, args.accept, args.prompt_text, limit);
          break;
        case 'close': await this.close(); return { session_id: this.id, closed: true };
        default: throw new BrowserError('INVALID_ARGUMENT', 'Unsupported per-session operation');
      }
      this.lastReceipt.completed_actions = 1; this.lastReceipt.effect_uncertain = false;
      this.lastReceipt.phase = 'observe_after';
      const result = await this.summary(selected);
      this.lastReceipt.phase = 'complete';
      return result;
    } catch (error) { throw this.receiptError(error); }
  }

  async issue(snapshot) {
    const state = await this.driver.state();
    const page = state.pages.get(snapshot.page_id);
    const now = Date.now();
    for (const [id, value] of this.observations) if (now - value.issued >= OBSERVATION_TTL) this.observations.delete(id);
    while (this.observations.size >= MAX_OBSERVATIONS) this.observations.delete(this.observations.keys().next().value);
    const id = randomUUID();
    this.observations.set(id, { instance: this.instance, session: this.id, page: snapshot.page_id, generation: this.generations.get(page) ?? 0, token: snapshot.state_token, issued: now });
    const { state_token, png, ...view } = snapshot;
    return { ...view, session_id: this.id, browser_observation_id: id, ...(png ? { _screenshot_png_base64: Buffer.from(png).toString('base64') } : {}) };
  }
  async snapshot(args = {}) {
    this.beginReceipt('snapshot');
    try { return await this.capture(args); }
    catch (error) { throw this.receiptError(error); }
  }
  async capture(args) {
    await this.touch();
    const options = validateSnapshot(args);
    const result = options.mode === 'find'
      ? await this.driver.find(1, args.page_id, { query: options.find_query, case_sensitive: options.find_case_sensitive, max_results: options.max_find_results, timeout_ms: options.timeout_ms })
      : await this.driver.snapshot(1, args.page_id, options);
    const view = await this.issue(result);
    this.lastReceipt.observation_page_id = view.page_id;
    this.lastReceipt.browser_observation_id = view.browser_observation_id;
    if (!this.lastReceipt.page_id) this.lastReceipt.page_id = view.page_id;
    return view;
  }
  async consume(args, limit) {
    const observation = this.observations.get(args.browser_observation_id);
    this.observations.delete(args.browser_observation_id);
    if (!observation || observation.instance !== this.instance || observation.session !== this.id || Date.now() - observation.issued >= OBSERVATION_TTL) {
      throw new BrowserError('OBSERVATION_INVALID', 'Unknown, expired or already consumed browser observation');
    }
    if (args.page_id !== undefined && args.page_id !== observation.page) throw new BrowserError('OBSERVATION_INVALID', 'Browser observation belongs to another page');
    const state = await this.driver.state();
    const page = state.pages.get(observation.page);
    if (!page || page.isClosed() || (this.generations.get(page) ?? 0) !== observation.generation) throw new BrowserError('OBSERVATION_STALE', 'Browser observation is stale after navigation');
    if (await this.driver.stateToken(1, observation.page, limit) !== observation.token) throw new BrowserError('OBSERVATION_STALE', 'Browser observation is stale after a page state change');
    return { ...observation, pageObject: page };
  }
  async bindingCurrent(binding) {
    const state = await this.driver.state();
    if (state.pages.get(binding.page) !== binding.pageObject || binding.pageObject.isClosed()
        || (this.generations.get(binding.pageObject) ?? 0) !== binding.generation) {
      throw new BrowserError('OBSERVATION_STALE', 'Reserved page changed before the browser mutation');
    }
  }
  async reserveAct(args) {
    this.beginReceipt('reserve_act');
    try {
      await this.touch();
      const actions = validateActions(args.actions), options = validateSnapshot(args);
      if (this.reservation && Date.now() >= this.reservation.expires) this.reservation = undefined;
      if (this.reservation) throw new BrowserError('RESERVATION_BUSY', 'One browser action reservation is already pending');
      const binding = await this.consume(args, options.timeout_ms);
      const id = randomUUID();
      this.reservation = { id, binding, actions, options, expires: Date.now() + RESERVATION_TTL };
      this.lastReceipt.page_id = binding.page; this.lastReceipt.reservation_id = id;
      this.lastReceipt.phase = 'reserved';
      return { session_id: this.id, page_id: binding.page, reservation_id: id, action_count: actions.length,
        upload_file_count: actions.find(action => action.type === 'set_files')?.files.length ?? 0 };
    } catch (error) { throw this.receiptError(error); }
  }
  async cancelAct(args) {
    this.beginReceipt('cancel_act');
    keys(args, ['reservation_id'], 'cancel_act');
    const id = string(args.reservation_id, 'reservation_id', 36, 36);
    if (!UUID.test(id)) throw new BrowserError('RESERVATION_INVALID', 'Invalid browser action reservation');
    const cancelled = this.reservation?.id === id;
    if (cancelled) this.reservation = undefined;
    this.lastReceipt.reservation_id = id;
    return { session_id: this.id, reservation_id: id, cancelled };
  }
  async stagedActions(reservation, staged) {
    const actions = structuredClone(reservation.actions);
    const upload = actions.find(action => action.type === 'set_files');
    if (!upload) {
      if (staged !== undefined) throw new BrowserError('UPLOAD_REFUSED', 'This reservation has no upload');
      return actions;
    }
    if (!Array.isArray(staged) || staged.length !== upload.files.length) throw new BrowserError('UPLOAD_REFUSED', 'Staged upload count does not match the reservation');
    const root = await physicalDirectory(path.join(this.config.uploads, reservation.id));
    if (!inside(this.config.uploads, root)) throw new BrowserError('UPLOAD_REFUSED', 'Upload reservation escaped its private directory');
    for (const file of staged) {
      string(file, 'staged_file', 1, 4096);
      const metadata = await lstat(file);
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > DOWNLOAD_LIMIT || !inside(root, await realpath(file))) {
        throw new BrowserError('UPLOAD_REFUSED', 'Upload must use a bounded physical file in this private reservation');
      }
    }
    upload.files = staged.slice();
    return actions;
  }

  async download(pageId, action, limit) {
    this.downloadExpected = true;
    const target = path.join(this.config.downloads, randomUUID() + '.bin');
    let download, file, monitor, exceeded = false, monitorBusy = false;
    try {
      ({ download } = await this.driver.beginDownload(pageId, action.selector, action.ref, limit));
      monitor = setInterval(async () => {
        if (monitorBusy) return;
        monitorBusy = true;
        try {
          let bytes = 0;
          for (const name of await readdir(this.config.rawDownloads)) bytes += (await stat(path.join(this.config.rawDownloads, name))).size;
          if (bytes > DOWNLOAD_LIMIT) { exceeded = true; await download.cancel(); }
        } catch { /* Completion and cancellation may remove the raw file concurrently. */ }
        finally { monitorBusy = false; }
      }, 50);
      monitor.unref();
      const stream = await download.createReadStream();
      if (exceeded) throw new BrowserError('DOWNLOAD_LIMIT', 'Download exceeds the 64 MiB limit');
      if (!stream) throw new BrowserError('DOWNLOAD_FAILED', 'Browser did not provide a download stream');
      file = await open(target, 'wx', 0o600);
      const digest = createHash('sha256'); let bytes = 0;
      for await (const chunk of stream) {
        bytes += chunk.length;
        if (bytes > DOWNLOAD_LIMIT) {
          exceeded = true; stream.destroy(); await download.cancel().catch(() => undefined);
          throw new BrowserError('DOWNLOAD_LIMIT', 'Download exceeds the 64 MiB limit');
        }
        digest.update(chunk);
        let offset = 0;
        while (offset < chunk.length) {
          const wrote = await file.write(chunk, offset, chunk.length - offset);
          if (!wrote.bytesWritten) throw new BrowserError('DOWNLOAD_FAILED', 'Download write did not progress');
          offset += wrote.bytesWritten;
        }
      }
      await file.sync(); await file.close(); file = undefined;
      const failure = await download.failure();
      if (failure) throw new BrowserError('DOWNLOAD_FAILED', 'Browser reported an incomplete download');
      return { path: target, suggested_filename: safeSuggestedName(download.suggestedFilename()), bytes, sha256: digest.digest('hex') };
    } catch (error) {
      if (file) await file.close().catch(() => undefined);
      await rm(target, { force: true }).catch(() => undefined);
      if (exceeded) throw new BrowserError('DOWNLOAD_LIMIT', 'Download exceeds the 64 MiB limit');
      throw error;
    } finally {
      if (monitor) clearInterval(monitor);
      this.downloadExpected = false;
      if (download) {
        this.pendingDownloads.delete(download);
        await download.delete().catch(() => undefined);
      }
    }
  }

  domainError(error, details) {
    if (error instanceof BrowserError) return new BrowserError(error.code, error.message, { ...error.details, ...details });
    const timedOut = error?.name === 'TimeoutError' || /Timeout .* exceeded/i.test(error?.message ?? '');
    const networkCode = /net::(ERR_[A-Z0-9_]+)\b/u.exec(error?.message ?? '')?.[1];
    const knownNetworkCodes = new Set([
      'ERR_ABORTED', 'ERR_ADDRESS_UNREACHABLE', 'ERR_BLOCKED_BY_CLIENT', 'ERR_CERT_AUTHORITY_INVALID',
      'ERR_CONNECTION_CLOSED', 'ERR_CONNECTION_REFUSED', 'ERR_CONNECTION_RESET', 'ERR_CONNECTION_TIMED_OUT',
      'ERR_CONTENT_LENGTH_MISMATCH', 'ERR_EMPTY_RESPONSE', 'ERR_FAILED', 'ERR_INTERNET_DISCONNECTED',
      'ERR_INVALID_HTTP_RESPONSE', 'ERR_NAME_NOT_RESOLVED', 'ERR_NETWORK_CHANGED',
      'ERR_PROXY_CONNECTION_FAILED', 'ERR_TIMED_OUT', 'ERR_TUNNEL_CONNECTION_FAILED',
    ]);
    const diagnostic = knownNetworkCodes.has(networkCode) ? networkCode : String(error?.name ?? 'Error').slice(0, 80);
    return new BrowserError(timedOut ? 'PLAYWRIGHT_TIMEOUT' : 'PLAYWRIGHT_FAILED', timedOut ? 'Playwright operation timed out' : 'Playwright operation failed', { ...details, diagnostic_type: diagnostic });
  }
  async act(args) {
    this.beginReceipt('act', 'validate_reservation');
    try {
      await this.touch();
      const id = string(args.reservation_id, 'reservation_id', 36, 36);
      const reservation = this.reservation;
      // A continuation has authority once. Every admitted attempt destroys it,
      // including malformed staged files and subsequent Playwright failures.
      if (reservation?.id === id) this.reservation = undefined;
      keys(args, ['reservation_id', 'staged_files'], 'act');
      if (!UUID.test(id) || !reservation || reservation.id !== id || Date.now() >= reservation.expires) {
        throw new BrowserError('RESERVATION_INVALID', 'Unknown, expired or already consumed browser action reservation');
      }
      this.lastReceipt.reservation_id = id; this.lastReceipt.page_id = reservation.binding.page;
      await this.bindingCurrent(reservation.binding);
      const actions = await this.stagedActions(reservation, args.staged_files);
      const { options } = reservation, pageId = reservation.binding.page;
      for (let index = 0; index < actions.length; index++) {
        const action = actions[index];
        this.lastReceipt.failed_action_index = index; this.lastReceipt.phase = 'action';
        // Waits never replace the target with an active popup. A generation change
        // during a completed wait invalidates the deferred mutation's authority.
        if (!WAIT_TYPES.has(action.type)) await this.bindingCurrent(reservation.binding);
        this.lastReceipt.effect_uncertain = !WAIT_TYPES.has(action.type);
        if (action.type === 'set_files') this.lastReceipt.upload_effect_started = true;
        if (action.type === 'download') this.lastReceipt.download = await this.download(pageId, action, options.timeout_ms);
        else await this.driver.act(1, pageId, [action], options.timeout_ms);
        this.lastReceipt.completed_actions++;
        this.lastReceipt.effect_uncertain = false;
      }
      this.observations.clear();
      this.lastReceipt.failed_action_index = null; this.lastReceipt.phase = 'observe_after';
      // The next observation may describe a popup, independently of the effect target.
      const state = await this.driver.state();
      const result = await this.capture({ ...options, page_id: state.activePageId ?? pageId });
      this.lastReceipt.phase = 'complete';
      return { ...result, completed_actions: this.lastReceipt.completed_actions };
    } catch (error) {
      this.observations.clear();
      throw this.receiptError(error);
    }
  }
  async close() {
    this.closing = true;
    this.invalidate();
    if (this.closed) return;
    if (!this.closePromise) this.closePromise = (async () => {
      for (const download of this.pendingDownloads) await download.cancel().catch(() => undefined);
      await this.context.close();
      this.closed = true;
    })();
    try { await this.closePromise; }
    catch (error) { this.closePromise = undefined; throw error; }
  }
}
