import { createRequire } from 'node:module';
import { BrowserSession, physicalDirectory } from './session.mjs';
import { BrowserError, keys } from './validation.mjs';
import { readFrames, validateEnvelope, writeReply, PROTOCOL_VERSION } from './protocol.mjs';

const version = createRequire(import.meta.url)('playwright-core/package.json').version;
let session, closing = false, sequence = 0, idleTimer;

function diagnostic(code, details = {}) {
  process.stderr.write(JSON.stringify({ component: 'browser-worker', code, ...details }) + '\n');
}
async function revoke() {
  closing = true;
  if (session) await session.close();
}
function privateError(error) {
  if (error instanceof BrowserError) return { code: error.code, message: error.message, details: error.details };
  return { code: 'PLAYWRIGHT_FAILED', message: 'Owned browser operation failed', details: { diagnostic_type: String(error?.name ?? 'Error').slice(0, 80), session_usable: session ? !session.closed : false } };
}
async function dispatch(method, params) {
  if (closing) throw new BrowserError('SESSION_CLOSED', 'Browser worker admission is closed', { session_usable: false });
  if (method === 'init') {
    if (session) throw new BrowserError('ALREADY_INITIALIZED', 'A worker owns exactly one browser session');
    keys(params, ['session_id', 'executable_path', 'session_dir', 'profile_dir', 'headless', 'viewport', 'timeout_ms'], 'init');
    process.chdir(await physicalDirectory(params.session_dir));
    session = await BrowserSession.launch(params);
    return { protocol_version: PROTOCOL_VERSION, playwright_version: version, node_version: process.versions.node, worker_pid: process.pid, session_usable: true, ...await session.summary() };
  }
  if (!session) throw new BrowserError('NOT_INITIALIZED', 'Browser worker has no initialized session', { session_usable: false });
  switch (method) {
    case 'start': keys(params, ['url'], 'start'); return session.start(params.url);
    case 'session': return session.session(params);
    case 'snapshot': return session.snapshot(params);
    case 'reserve_act': return session.reserveAct(params);
    case 'cancel_act': return session.cancelAct(params);
    case 'act': return session.act(params);
    case 'close': await revoke(); return { session_id: session.id, closed: true };
    default: throw new BrowserError('PROTOCOL_METHOD', 'Unsupported private method');
  }
}

async function main() {
  if (version !== '1.63.0' || !process.versions.node.startsWith('24.')) throw new BrowserError('DEPENDENCY_MISMATCH', 'Pinned Playwright and Node24 runtime are required');
  process.stdin.once('end', () => { void revoke().catch(error => diagnostic('EOF_CLEANUP_FAILED', { type: error?.name ?? 'Error' })); });
  process.stdin.once('error', () => { void revoke().catch(() => undefined); });
  process.stdout.once('error', () => { void revoke().catch(() => undefined); });
  idleTimer = setInterval(() => {
    if (!session || closing || !session.idleExpired()) return;
    void revoke().then(() => { diagnostic('IDLE_EXPIRED'); process.stdin.destroy(); }).catch(() => { diagnostic('IDLE_CLEANUP_FAILED'); process.stdin.destroy(); });
  }, 1000);
  idleTimer.unref();
  for await (const raw of readFrames(process.stdin)) {
    const request = validateEnvelope(raw);
    const next = BigInt(request.id.slice(1));
    if (next <= sequence) throw new BrowserError('PROTOCOL_REPLAY', 'Private request correlation identifier was replayed');
    sequence = next;
    let reply;
    const fallbackReceipt = { operation: request.method, session_id: session?.id ?? request.params.session_id,
      phase: request.method, completed_actions: 0, failed_action_index: null, effect_uncertain: false,
      session_usable: session?.usable() ?? false, upload_effect_started: false };
    if (session) session.beginReceipt(request.method);
    try {
      const result = await dispatch(request.method, request.params);
      const receipt = session?.lastReceipt ? session.finishReceipt() : { ...fallbackReceipt, session_usable: session?.usable() ?? false };
      if (request.method === 'init') { receipt.session_id = session.id; receipt.session_usable = true; }
      reply = { v: PROTOCOL_VERSION, id: request.id, ok: true, result, receipt };
    } catch (error) {
      const failure = privateError(error);
      const receipt = error.receipt ?? (session?.lastReceipt ? session.finishReceipt() : fallbackReceipt);
      failure.details = { ...failure.details, session_usable: receipt.session_usable };
      diagnostic(failure.code, { request_id: request.id, method: request.method, session_usable: receipt.session_usable });
      reply = { v: PROTOCOL_VERSION, id: request.id, ok: false, error: failure, receipt };
    }
    // Encode before writing any frame bytes. Pipe failures are fatal, never a second
    // response that could erase an earlier successful effect or corrupt framing.
    await writeReply(process.stdout, reply);
    if (closing) break;
  }
}

try { await main(); }
catch (error) { diagnostic(error instanceof BrowserError ? error.code : 'WORKER_FATAL', { type: error?.name ?? 'Error' }); process.exitCode = 70; }
finally {
  if (idleTimer) clearInterval(idleTimer);
  try { await revoke(); }
  catch { diagnostic('FINAL_CLEANUP_FAILED'); process.exitCode = 71; }
  process.stdin.destroy();
}
