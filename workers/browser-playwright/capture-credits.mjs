// Build-time legal-notice capture; not an MCP action or a production entry point.
import { chromium } from 'playwright-core';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
const [executable, destination, temporaryRoot] = process.argv.slice(2);
if (!executable || !destination || !temporaryRoot) throw new Error('Expected dedicated Chromium executable, output HTML and temporary root');
const profile = await mkdtemp(path.join(temporaryRoot, 'credits-'));
let context;
try {
  context = await chromium.launchPersistentContext(profile, { executablePath: executable, headless: true });
  if (context.browser().version() !== '153.0.8010.12') throw new Error('Credits must come from the pinned Chromium distribution');
  const page = context.pages()[0];
  await page.goto('chrome://credits');
  const html = await page.content();
  if (html.length < 100_000 || !html.includes('Copyright') || !html.includes('Chromium')) throw new Error('Incomplete Chromium credits');
  await writeFile(destination, html, { encoding: 'utf8', flag: 'wx' });
  process.stdout.write(JSON.stringify({ version: context.browser().version(), credits_bytes: Buffer.byteLength(html) }) + '\n');
} finally {
  if (context) await context.close();
  await rm(profile, { recursive: true, force: true });
}
