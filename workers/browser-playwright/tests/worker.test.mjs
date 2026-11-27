import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { readFrames, writeFrame, RESPONSE_LIMIT } from '../protocol.mjs';

const entry = fileURLToPath(new URL('../worker.mjs', import.meta.url));
async function peer(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'agent-bridge-ipc-test-'));
  await mkdir(path.join(root, 'session')); await mkdir(path.join(root, 'profile'));
  const child = spawn(process.execPath, [entry], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = ''; child.stderr.on('data', data => { stderr = (stderr + data.toString()).slice(-32768); });
  const exited = once(child, 'exit');
  const frames = readFrames(child.stdout, RESPONSE_LIMIT)[Symbol.asyncIterator]();
  let sequence = 0;
  const call = async (method, params = {}) => {
    const id = `r${++sequence}`;
    await writeFrame(child.stdin, { v: 2, id, method, params });
    const pending = frames.next();
    let timer;
    const result = await Promise.race([pending, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('test IPC deadline: ' + stderr)), 20000); })]).finally(() => clearTimeout(timer));
    assert.equal(result.done, false, stderr);
    assert.equal(result.value.id, id);
    assert.equal(result.value.v, 2);
    return result.value;
  };
  t.after(async () => {
    if (child.exitCode === null) child.stdin.end();
    let timer;
    await Promise.race([exited, new Promise(resolve => { timer = setTimeout(() => { child.kill(); resolve(); }, 5000); })]).finally(() => clearTimeout(timer));
    await rm(root, { recursive: true, force: true, maxRetries: 20, retryDelay: 50 });
  });
  return { child, call, exited, stderr: () => stderr, init: { executable_path: process.env.AGENT_BRIDGE_TEST_CHROME ?? 'C:/Program Files/Google/Chrome/Application/chrome.exe', session_dir: path.join(root, 'session'), profile_dir: path.join(root, 'profile'), headless: true } };
}

test('real worker pipe dispatch controls only its own context and answers matching IDs', async t => {
  const server = http.createServer((req, res) => res.end('<title>IPC witness</title><button onclick="this.textContent=\'done\'">Go</button>'));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const worker = await peer(t);
  const initialized = await worker.call('init', worker.init);
  assert.equal(initialized.ok, true);
  assert.equal(initialized.result.playwright_version, '1.65.1');
  assert.equal(initialized.result.worker_pid, worker.child.pid);
  assert.equal((await worker.call('start', { url: `http://127.0.0.1:${server.address().port}` })).ok, true);
  const snapshot = await worker.call('snapshot', { screenshot: false });
  assert.equal(snapshot.ok, true);
  assert.equal(snapshot.result.title, 'IPC witness');
  const preflight = await worker.call('reserve_act', { browser_observation_id: snapshot.result.browser_observation_id, actions: [{ type: 'click', selector: 'button' }, { type: 'fill', selector: 'input', value: 'invalid second mutation' }], screenshot: false });
  assert.equal(preflight.ok, false);
  assert.equal(preflight.error.code, 'INVALID_ARGUMENT');
  const reserved = await worker.call('reserve_act', { browser_observation_id: snapshot.result.browser_observation_id, actions: [{ type: 'click', selector: 'button' }], screenshot: false });
  assert.equal(reserved.ok, true);
  const clicked = await worker.call('act', { reservation_id: reserved.result.reservation_id });
  assert.equal(clicked.ok, true);
  assert.equal(clicked.receipt.completed_actions, 1);
  assert.match(clicked.result.text, /done/);
  const replay = await worker.call('act', { reservation_id: reserved.result.reservation_id });
  assert.equal(replay.ok, false);
  const reused = await worker.call('reserve_act', { browser_observation_id: snapshot.result.browser_observation_id, actions: [{ type: 'click', selector: 'button' }], screenshot: false });
  assert.equal(reused.ok, false);
  assert.equal(reused.error.code, 'OBSERVATION_INVALID');
  assert.equal((await worker.call('close')).ok, true);
  assert.deepEqual(await worker.exited, [0, null]);
});

test('malformed input after browser launch closes the worker instead of becoming an action', async t => {
  const worker = await peer(t);
  assert.equal((await worker.call('init', worker.init)).ok, true);
  const oversized = Buffer.alloc(4); oversized.writeUInt32LE(1024 * 1024 + 1);
  worker.child.stdin.write(oversized);
  assert.deepEqual(await worker.exited, [70, null]);
  assert.match(worker.stderr(), /PROTOCOL_LIMIT/);
});
