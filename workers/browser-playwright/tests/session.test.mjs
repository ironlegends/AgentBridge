import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, mkdir, readFile, writeFile, copyFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const api = await import('../session.mjs');
let server, base;
const main = `<!doctype html><html><head><title>Browser parity</title></head><body>
<label>Name <input id="name"></label><label>Secret <input id="secret" type="password" value="private-password"></label>
<label>Consent <input id="consent" type="checkbox"></label>
<label>Pick <select id="pick"><option value="a">Alpha</option><option value="b">Beta</option></select></label>
<button id="count" onclick="document.querySelector('#result').textContent='counted'">Count</button><p id="result">ready</p>
<button id="popup" onclick="window.open('/next')">Open popup</button>
<button id="dialog" onclick="alert('bounded dialog')">Open dialog</button>
<button id="events" onclick="console.log('Authorization: should-not-leak'); fetch('/api?q=secret-query').then(()=>document.querySelector('#result').textContent='fetched')">Events</button>
<div id="hover" style="width:120px;height:40px" onmouseenter="this.textContent='hovered'">Hover target</div>
<div id="drag" draggable="true" ondragstart="event.dataTransfer.setData('text/plain','dragged')" style="width:100px;height:40px">Drag source</div>
<div id="drop" ondragover="event.preventDefault()" ondrop="event.preventDefault();this.textContent=event.dataTransfer.getData('text/plain')" style="width:100px;height:50px">Drop target</div>
<label>Files <input type="file" id="files" multiple onchange="document.querySelector('#result').textContent=Array.from(this.files).map(f=>f.name).join(',')"></label>
<a id="download" href="/download">Download text</a><a id="large" href="/large">Download large</a>
<iframe title="Inner frame" src="/frame"></iframe><p id="case">École école</p>
<a href="/next">Next page</a><div style="height:1600px">Tall content</div><p>Page end</p>
</body></html>`;

before(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://fixture');
    if (url.pathname === '/abort') { res.destroy(); return; }
    if (url.pathname === '/download') {
      res.writeHead(200, { 'content-type': 'text/plain', 'content-disposition': 'attachment; filename="witness.txt"' });
      return res.end('download witness\n');
    }
    if (url.pathname === '/large') {
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-disposition': 'attachment; filename="large.bin"', 'content-length': 64 * 1024 * 1024 + 1 });
      const chunk = Buffer.alloc(1024 * 1024, 120); let sent = 0;
      const pump = () => {
        while (sent < 64) { sent++; if (!res.write(chunk)) return res.once('drain', pump); }
        res.end('x');
      };
      return pump();
    }
    res.setHeader('content-type', 'text/html; charset=utf-8');
    if (url.pathname === '/frame') return res.end('<button id="frame-button" onclick="this.textContent=\'Frame clicked\'">Frame button</button>');
    if (url.pathname === '/set-cookie') { res.setHeader('set-cookie', 'owned_session=retained; Max-Age=3600; Path=/'); return res.end('<p>Owned cookie set</p>'); }
    if (url.pathname === '/cookie') return res.end('<p>' + (req.headers.cookie?.includes('owned_session=retained') ? 'Owned cookie retained' : 'Owned cookie absent') + '</p>');
    if (url.pathname === '/next') return res.end('<title>Next page</title><h1>Next destination</h1>');
    if (url.pathname === '/replacement') return res.end('<title>Replacement</title><button id="count" onclick="this.textContent=\'wrong generation clicked\'">Replacement target</button>');
    if (url.pathname === '/popup-target') return res.end('<title>Popup target</title><button id="count" onclick="this.textContent=\'wrong popup clicked\'">Popup untouched</button>');
    if (url.pathname === '/download-observe-failure') return res.end('<title>Download receipt</title><a id="download" href="/download" onclick="document.body.style.height=\'100000px\'">Download then exceed image budget</a>');
    if (url.pathname === '/timing') return res.end('<title>Waiting</title><div id="soon" hidden>arrived</div><script>setTimeout(()=>document.querySelector("#soon").hidden=false,200)</script>');
    if (url.pathname === '/api') return res.end('api done');
    res.end(main);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { if (server) await new Promise(resolve => server.close(resolve)); });

async function launch(t, options = {}) {
  assert.equal(typeof api.BrowserSession?.launch, 'function', 'BrowserSession.launch is not implemented');
  const root = await mkdtemp(path.join(os.tmpdir(), 'agent-bridge-browser-test-'));
  const sessionDir = path.join(root, 'session'), profileDir = path.join(root, 'profile');
  await mkdir(sessionDir); await mkdir(profileDir);
  let session;
  t.after(async () => {
    try { if (session) await session.close(); }
    finally { await rm(root, { recursive: true, force: true, maxRetries: 20, retryDelay: 50 }); }
  });
  session = await api.BrowserSession.launch({
    executable_path: process.env.AGENT_BRIDGE_TEST_CHROME ?? 'C:/Program Files/Google/Chrome/Application/chrome.exe',
    session_dir: sessionDir, profile_dir: profileDir, headless: true, timeout_ms: 15000,
    ...options,
  });
  await session.start(base);
  return { session, sessionDir, profileDir, root };
}
async function execute(session, args) {
  const reserved = await session.reserveAct(args);
  const upload = args.actions.find(action => action.type === 'set_files');
  let staged;
  if (upload) {
    const directory = path.join(session.config.uploads, reserved.reservation_id);
    await mkdir(directory);
    staged = await Promise.all(upload.files.map(async file => {
      if (path.dirname(file) !== session.config.uploads) return file;
      const target = path.join(directory, path.basename(file)); await copyFile(file, target); return target;
    }));
  }
  return session.act({ reservation_id: reserved.reservation_id, ...(staged ? { staged_files: staged } : {}) });
}
async function act(session, action, extra = {}) {
  const snap = await session.snapshot({ screenshot: false });
  return execute(session, { browser_observation_id: snap.browser_observation_id, actions: [action], screenshot: false, ...extra });
}

test('real AX snapshot carries iframe refs, find case sensitivity, masked secrets and a genuine PNG', async t => {
  const { session } = await launch(t);
  const snap = await session.snapshot({ full_page: true });
  assert.match(snap.text, /Count/);
  assert.ok(snap.interactive_elements.some(e => /Frame button/.test(e.aria_name ?? e.text ?? '') && /^f\d+e\d+$/.test(e.ref)));
  assert.equal(JSON.stringify(snap).includes('private-password'), false);
  const png = Buffer.from(snap._screenshot_png_base64, 'base64');
  assert.deepEqual([...png.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);
  assert.ok(png.readUInt32BE(20) > 1200);
  const found = await session.snapshot({ mode: 'find', find_query: 'École', find_case_sensitive: true, max_find_results: 50, screenshot: false });
  assert.ok(found.matches.length > 0);
  assert.ok(found.matches.every(m => m.snippet.includes('École')));
  const frame = snap.interactive_elements.find(e => /Frame button/.test(e.aria_name ?? e.text ?? ''));
  const fresh = await session.snapshot({ screenshot: false });
  const result = await execute(session, { browser_observation_id: fresh.browser_observation_id, actions: [{ type: 'click', ref: frame.ref }], screenshot: false });
  assert.match(JSON.stringify(result.interactive_elements), /Frame clicked/);
});

test('real page actions preserve text, checked/select/press, pointer, drag and scroll semantics', async t => {
  const { session } = await launch(t);
  await act(session, { type: 'fill', selector: '#name', value: 'first' });
  const typed = await act(session, { type: 'type_text', selector: '#name', text: ' second', delay_ms: 1 });
  assert.ok(JSON.stringify(typed).includes('first second'));
  await act(session, { type: 'press', selector: '#name', key: 'ControlOrMeta+A' });
  const replaced = await act(session, { type: 'type_text', selector: '#name', text: 'replaced' });
  assert.ok(JSON.stringify(replaced).includes('replaced'));
  const checked = await act(session, { type: 'set_checked', selector: '#consent', checked: true });
  assert.ok(checked.interactive_elements.some(e => e.role === 'checkbox' && e.checked === true));
  const selected = await act(session, { type: 'select', selector: '#pick', value: 'b' });
  assert.ok(JSON.stringify(selected).includes('Beta'));
  assert.match((await act(session, { type: 'hover', selector: '#hover' })).text, /hovered/);
  assert.match((await act(session, { type: 'drag', source_selector: '#drag', target_selector: '#drop' })).text, /dragged/);
  await act(session, { type: 'scroll', delta_y: 700, delta_x: 0 });
  assert.match((await act(session, { type: 'click', selector: '#count' })).text, /counted/);
});

test('one-use observations reject reuse and page changes before an action can fire', async t => {
  const { session } = await launch(t);
  const old = await session.snapshot({ screenshot: false });
  await execute(session, { browser_observation_id: old.browser_observation_id, actions: [{ type: 'click', selector: '#count' }], screenshot: false });
  await assert.rejects(execute(session, { browser_observation_id: old.browser_observation_id, actions: [{ type: 'click', selector: '#count' }], screenshot: false }), /observation/i);
  const beforeNav = await session.snapshot({ screenshot: false });
  await act(session, { type: 'goto', url: base + '/next', wait_until: 'load' });
  await assert.rejects(execute(session, { browser_observation_id: beforeNav.browser_observation_id, actions: [{ type: 'click', selector: 'h1' }], screenshot: false }), /observation|stale/i);
});

test('real waits report their completed prefix on timeout and keep a usable session', async t => {
  const { session } = await launch(t);
  await act(session, { type: 'goto', url: base + '/timing' });
  const arrived = await act(session, { type: 'wait_selector', selector: '#soon', state: 'visible', timeout_ms: 2000 });
  assert.match(arrived.text, /arrived/);
  await act(session, { type: 'wait_text', text: 'arrived', exact: true, state: 'visible', timeout_ms: 1000 });
  await act(session, { type: 'wait_url', url: base + '/timing', timeout_ms: 1000 });
  const snap = await session.snapshot({ screenshot: false });
  let failure;
  try {
    await execute(session, { browser_observation_id: snap.browser_observation_id, actions: [{ type: 'wait', duration_ms: 1 }, { type: 'wait_text', text: 'never appears', timeout_ms: 1000 }], screenshot: false });
  } catch (e) { failure = e; }
  assert.equal(failure?.code, 'PLAYWRIGHT_TIMEOUT');
  assert.equal(failure.details.completed_actions, 1);
  assert.equal(failure.details.failed_action_index, 1);
  assert.equal(failure.details.session_usable, true);
  assert.match((await session.snapshot({ screenshot: false })).title, /Waiting/);
  await assert.rejects(execute(session, { browser_observation_id: snap.browser_observation_id, actions: [{ type: 'wait', duration_ms: 0 }], screenshot: false }), /observation/i);
  await act(session, { type: 'navigation', direction: 'back', timeout_ms: 1000 });
  await act(session, { type: 'navigation', direction: 'forward', timeout_ms: 1000 });
  await act(session, { type: 'navigation', direction: 'reload', timeout_ms: 1000 });
});

test('pages and dialogs are explicit recovery operations and invalidate old observations', async t => {
  const { session } = await launch(t);
  const first = await session.snapshot({ screenshot: false });
  const opened = await session.session({ action: 'new_page', url: base + '/next' });
  assert.equal(opened.pages.length, 2);
  await session.session({ action: 'select_page', page_id: first.page_id });
  await session.session({ action: 'close_page', page_id: opened.page_id });
  assert.equal((await session.session({ action: 'list' })).pages.length, 1);
  let dialog;
  try { await act(session, { type: 'click', selector: '#dialog' }); } catch (e) { dialog = e; }
  assert.equal(dialog?.code, 'DIALOG_PENDING');
  let timer;
  const listed = await Promise.race([session.session({ action: 'list' }), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('listing hung behind a pending dialog')), 1500); })]).finally(() => clearTimeout(timer));
  assert.equal(listed.pages[0].dialog_pending, true);
  await assert.rejects(session.session({ action: 'handle_dialog', accept: true }), /page_id/i);
  await session.session({ action: 'handle_dialog', page_id: first.page_id, accept: true });
  assert.match((await session.snapshot({ screenshot: false })).title, /Browser parity/);
  const popup = await act(session, { type: 'click', selector: '#popup' });
  assert.equal(popup.pages.length, 2);
  assert.match(popup.title, /Next page/);
});

test('console and network collection is opt-in, bounded and redacts credentials and query strings', async t => {
  const { session } = await launch(t);
  const before = await session.snapshot({ screenshot: false, include_console: true, include_network: true });
  const result = await execute(session, { browser_observation_id: before.browser_observation_id, actions: [{ type: 'click', selector: '#events' }, { type: 'wait_text', text: 'fetched', exact: true, timeout_ms: 2000 }], screenshot: false, include_console: true, include_network: true });
  assert.ok(result.console_messages.length > 0);
  assert.ok(result.network_events.some(e => e.url.endsWith('/api')));
  assert.equal(JSON.stringify(result).includes('secret-query'), false);
  assert.equal(JSON.stringify(result).includes('should-not-leak'), false);
  const disabled = await session.snapshot({ screenshot: false });
  assert.equal(disabled.console_messages, undefined);
  assert.equal(disabled.network_events, undefined);
});

test('uploads use only staged private files and downloads produce a bounded verified private file', async t => {
  const { session, sessionDir, root } = await launch(t);
  const staged = path.join(sessionDir, 'uploads'); await mkdir(staged, { recursive: true });
  const input = path.join(staged, 'upload.txt'); await writeFile(input, 'upload witness');
  assert.match((await act(session, { type: 'set_files', selector: '#files', files: [input] })).text, /upload.txt/);
  const outside = path.join(root, 'outside.txt'); await writeFile(outside, 'must not be uploaded');
  await assert.rejects(act(session, { type: 'set_files', selector: '#files', files: [outside] }), /private|staged|upload/i);
  const result = await act(session, { type: 'download', selector: '#download' });
  assert.equal(session.lastReceipt.download.bytes, 17);
  assert.equal(await readFile(session.lastReceipt.download.path, 'utf8'), 'download witness\n');
  assert.equal(path.dirname(session.lastReceipt.download.path), path.join(sessionDir, 'downloads'));
  assert.match(session.lastReceipt.download.sha256, /^[0-9a-f]{64}$/);
  await assert.rejects(act(session, { type: 'download', selector: '#large' }), /limit|64 MiB|too large/i);
});

test('persistent profile reuse preserves owned cookies and simultaneous use is refused', async t => {
  const { session, sessionDir, profileDir } = await launch(t);
  await act(session, { type: 'goto', url: base + '/set-cookie' });
  await assert.rejects(api.BrowserSession.launch({ executable_path: process.env.AGENT_BRIDGE_TEST_CHROME ?? 'C:/Program Files/Google/Chrome/Application/chrome.exe', session_dir: sessionDir, profile_dir: profileDir, headless: true, timeout_ms: 1000 }), /profile|browser|launch|closed|Target/i);
  await session.close();
  const again = await api.BrowserSession.launch({ executable_path: process.env.AGENT_BRIDGE_TEST_CHROME ?? 'C:/Program Files/Google/Chrome/Application/chrome.exe', session_dir: sessionDir, profile_dir: profileDir, headless: true, timeout_ms: 15000 });
  try { await again.start(base + '/cookie'); assert.match((await again.snapshot({ screenshot: false })).text, /Owned cookie retained/); }
  finally { await again.close(); }
});

test('review: a popup during a wait cannot become the target of the deferred mutation', async t => {
  const { session } = await launch(t);
  const before = await session.snapshot({ screenshot: false });
  const originalPage = session.context.pages()[0], realWait = originalPage.waitForTimeout.bind(originalPage);
  originalPage.waitForTimeout = async duration => {
    const popup = await session.context.newPage(); await popup.goto(base + '/popup-target');
    return realWait(duration);
  };
  await execute(session, { browser_observation_id: before.browser_observation_id, actions: [{ type: 'wait', duration_ms: 10 }, { type: 'click', selector: '#count' }], screenshot: false });
  assert.match((await session.snapshot({ page_id: before.page_id, screenshot: false })).text, /counted/);
  const popup = (await session.summary()).pages.find(page => page.page_id !== before.page_id);
  assert.match((await session.snapshot({ page_id: popup.page_id, screenshot: false })).text, /Popup untouched/);
});

test('review: navigation during a wait revokes the deferred mutation and keeps its completed prefix', async t => {
  const { session } = await launch(t);
  const before = await session.snapshot({ screenshot: false });
  const originalPage = session.context.pages()[0], realAct = session.driver.act.bind(session.driver);
  let injected = false;
  session.driver.act = async (port, pageId, actions, limit) => {
    if (!injected && actions[0].type === 'wait') { injected = true; await originalPage.goto(base + '/replacement'); }
    return realAct(port, pageId, actions, limit);
  };
  await assert.rejects(execute(session, { browser_observation_id: before.browser_observation_id, actions: [{ type: 'wait', duration_ms: 10 }, { type: 'click', selector: '#count' }], screenshot: false }), error => {
    assert.equal(error.code, 'OBSERVATION_STALE');
    assert.equal(error.details.completed_actions, 1);
    return true;
  });
  assert.match((await session.snapshot({ screenshot: false })).text, /Replacement target/);
});

test('review: a completed download retains a compact private receipt when its screenshot fails', async t => {
  const { session } = await launch(t);
  await act(session, { type: 'goto', url: base + '/download-observe-failure' });
  const before = await session.snapshot({ screenshot: false });
  let failure;
  try { await execute(session, { browser_observation_id: before.browser_observation_id, actions: [{ type: 'download', selector: '#download' }], screenshot: true, full_page: true }); }
  catch (error) { failure = error; }
  assert.ok(failure, 'oversized after-action screenshot must fail');
  assert.equal(failure.details.completed_actions, 1);
  assert.equal(failure.receipt?.phase, 'observe_after');
  assert.equal(failure.receipt?.download?.bytes, 17);
  assert.equal(await readFile(failure.receipt.download.path, 'utf8'), 'download witness\n');
});

test('review: navigation failure after new_page creation retains the new page identity', async t => {
  const { session } = await launch(t);
  let failure;
  try { await session.session({ action: 'new_page', url: base + '/abort', timeout_ms: 1000 }); }
  catch (error) { failure = error; }
  assert.ok(failure, 'navigation to the closed response must fail');
  assert.equal(failure.receipt?.phase, 'navigate_new_page');
  assert.equal(typeof failure.receipt?.created_page_id, 'string');
  const state = await session.summary();
  assert.equal(state.pages.length, 2);
  assert.ok(state.pages.some(page => page.page_id === failure.receipt.created_page_id));
});


test('review: action reservation consumes authority before staging and cannot be replayed or retargeted', async t => {
  const { session } = await launch(t);
  assert.equal(typeof session.reserveAct, 'function');
  await assert.rejects(session.reserveAct({ browser_observation_id: 'unknown', actions: [{ type: 'set_files', selector: '#files', files: ['source.txt'] }], screenshot: false }), /observation/i);
  const before = await session.snapshot({ screenshot: false });
  const args = { browser_observation_id: before.browser_observation_id, actions: [{ type: 'click', selector: '#count' }], screenshot: false };
  const reserved = await session.reserveAct(args);
  assert.equal(reserved.page_id, before.page_id);
  assert.match(reserved.reservation_id, /^[a-f0-9-]{36}$/);
  await session.cancelAct({ reservation_id: reserved.reservation_id });
  await assert.rejects(session.act({ reservation_id: reserved.reservation_id }), /reservation/i);
  await assert.rejects(session.reserveAct(args), /observation/i);
  const next = await session.snapshot({ screenshot: false });
  const stale = await session.reserveAct({ ...args, browser_observation_id: next.browser_observation_id });
  await session.context.pages()[0].goto(base + '/replacement');
  await assert.rejects(session.act({ reservation_id: stale.reservation_id }), /reservation|stale/i);
  assert.match((await session.snapshot({ screenshot: false })).text, /Replacement target/);
});


test('review: reservations are bounded, expire, and cannot substitute actions at commit', async t => {
  const { session } = await launch(t);
  const first = await session.snapshot({ screenshot: false });
  const second = await session.snapshot({ screenshot: false });
  const options = { actions: [{ type: 'click', selector: '#count' }], screenshot: false };
  const pending = await session.reserveAct({ ...options, browser_observation_id: first.browser_observation_id });
  await assert.rejects(session.reserveAct({ ...options, browser_observation_id: second.browser_observation_id }), /pending/i);
  await session.cancelAct({ reservation_id: pending.reservation_id });
  const expiring = await session.reserveAct({ ...options, browser_observation_id: second.browser_observation_id });
  session.reservation.expires = Date.now() - 1;
  await assert.rejects(session.act({ reservation_id: expiring.reservation_id }), /expired/i);
  const third = await session.snapshot({ screenshot: false });
  const next = await session.reserveAct({ ...options, browser_observation_id: third.browser_observation_id });
  await assert.rejects(session.act({ reservation_id: next.reservation_id, actions: [{ type: 'click', selector: '#dialog' }] }), /supported/i);
  await assert.rejects(session.act({ reservation_id: next.reservation_id }), /reservation/i);
  assert.match((await session.snapshot({ screenshot: false })).text, /ready/);
});
