import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, lstat, rm, realpath } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import os from 'node:os';

const workerRoot = process.env.AGENT_BRIDGE_TEST_WORKER_ROOT ??
  fileURLToPath(new URL('..', import.meta.url));
const { chromium } = createRequire(path.join(workerRoot, 'session.mjs'))('playwright-core');
const { BrowserSession } = await import(pathToFileURL(path.join(workerRoot, 'session.mjs')).href);

test('Chromium diagnostic log is explicitly isolated inside the owned session', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ab-browser-log-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const sessionDir = path.join(root, 'session'), profileDir = path.join(root, 'profile');
  await mkdir(sessionDir); await mkdir(profileDir);
  const sentinel = new Error('launch intercepted');
  let options;
  t.mock.method(chromium, 'launchPersistentContext', async (_, supplied) => {
    options = supplied;
    throw sentinel;
  });
  const previous = process.env.CHROME_LOG_FILE;
  process.env.CHROME_LOG_FILE = path.join(root, 'outside.log');
  try {
    await assert.rejects(BrowserSession.launch({
      executable_path: path.join(root, 'chromium.exe'),
      session_dir: sessionDir, profile_dir: profileDir, headless: true,
      timeout_ms: 1000,
    }), error => error === sentinel);
  } finally {
    if (previous === undefined) delete process.env.CHROME_LOG_FILE;
    else process.env.CHROME_LOG_FILE = previous;
  }
  assert.ok(options?.env?.CHROME_LOG_FILE, 'launch must set an explicit log destination');
  const log = options.env.CHROME_LOG_FILE;
  const parent = path.dirname(log);
  const relative = path.relative(await realpath(sessionDir), await realpath(parent));
  assert.match(relative, /^chromium-log-[^\\/]+$/);
  assert.equal(path.basename(log), 'debug.log');
  assert.ok((await lstat(parent)).isDirectory());
  assert.ok(options.args.includes('--log-file=' + log));
  assert.notEqual(log, path.join(root, 'outside.log'));
});


test('network diagnostic preserves a bounded error code without leaking URLs or values', () => {
  const failure = BrowserSession.prototype.domainError(
    new Error('page.goto: net::ERR_CONNECTION_RESET at http://127.0.0.1:12345/?token=fixture-secret'),
    { phase: 'start' },
  );
  assert.equal(failure.code, 'PLAYWRIGHT_FAILED');
  assert.equal(failure.details.diagnostic_type, 'ERR_CONNECTION_RESET');
  assert.equal(failure.details.phase, 'start');
  assert.doesNotMatch(JSON.stringify(failure), /fixture-secret|127\.0\.0\.1/);
});


test('unknown network-like text is not copied into the diagnostic', () => {
  const failure = BrowserSession.prototype.domainError(new Error('net::ERR_PRIVATE_FIXTURE_VALUE'), {});
  assert.equal(failure.details.diagnostic_type, 'Error');
  assert.doesNotMatch(JSON.stringify(failure), /PRIVATE_FIXTURE_VALUE/);
});
