// Agent Bridge browser contract. DeskMCP 0.9.17 validation provenance: NOTICE.
export class BrowserError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'BrowserError';
    this.code = code;
    this.details = details;
  }
}

export const fail = (field, message = 'is invalid') => {
  throw new BrowserError('INVALID_ARGUMENT', `${field} ${message}`);
};
export function object(value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(field, 'must be an object');
  return value;
}
export function string(value, field, min, max) {
  if (typeof value !== 'string' || value.length < min || value.length > max) fail(field, `must contain ${min}..${max} characters`);
  return value;
}
export function integer(value, field, min, max) {
  if (!Number.isInteger(value) || value < min || value > max) fail(field, `must be an integer in ${min}..${max}`);
  return value;
}
export function boolean(value, field) {
  if (typeof value !== 'boolean') fail(field, 'must be boolean');
  return value;
}
export function choice(value, field, choices) {
  if (!choices.includes(value)) fail(field, 'has an unsupported value');
  return value;
}
export function keys(value, allowed, field) {
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`${field}.${key}`, 'is not supported');
}
export function httpUrl(value, field = 'url') {
  string(value, field, 1, 8192);
  if (Buffer.byteLength(value) > 8192) fail(field, 'exceeds 8192 bytes');
  let parsed;
  try { parsed = new URL(value); } catch { fail(field, 'must be an HTTP(S) URL'); }
  if (!['http:', 'https:'].includes(parsed.protocol)) fail(field, 'must be an HTTP(S) URL');
  return parsed.href;
}
export function timeout(value, fallback = 15000) {
  return value === undefined ? fallback : integer(value, 'timeout_ms', 1000, 60000);
}

const REF = /^(?:f[1-9][0-9]{0,6})*e[1-9][0-9]{0,6}$/u;
export const ACTION_TYPES = Object.freeze(['goto', 'click', 'hover', 'drag', 'fill', 'type_text', 'set_checked', 'press', 'wait', 'wait_selector', 'wait_url', 'wait_text', 'select', 'set_files', 'download', 'scroll', 'navigation']);
const WAIT_TYPES = new Set(['wait', 'wait_selector', 'wait_url', 'wait_text']);
const ACTION_KEYS = ['type', 'selector', 'ref', 'source_selector', 'source_ref', 'target_selector', 'target_ref', 'url', 'wait_until', 'timeout_ms', 'value', 'text', 'delay_ms', 'checked', 'key', 'duration_ms', 'state', 'exact', 'files', 'delta_x', 'delta_y', 'direction'];
function target(action, prefix = '', optional = false) {
  const selector = action[`${prefix}selector`];
  const ref = action[`${prefix}ref`];
  if (selector !== undefined) string(selector, `${prefix}selector`, 1, 4096);
  if (ref !== undefined && (typeof ref !== 'string' || !REF.test(ref))) fail(`${prefix}ref`);
  if (optional && selector === undefined && ref === undefined) return;
  if ((selector !== undefined) === (ref !== undefined)) fail('target', `requires exactly one of ${prefix}selector or ${prefix}ref`);
}

export function validateActions(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 20) fail('actions', 'must contain 1..20 actions');
  let mutations = 0;
  const normalized = value.map((raw) => {
    const a = object(raw, 'action');
    choice(a.type, 'type', ACTION_TYPES);
    keys(a, ACTION_KEYS, 'action');
    for (const field of ['value', 'text']) if (a[field] !== undefined) string(a[field], field, 0, 65536);
    for (const field of ['checked', 'exact']) if (a[field] !== undefined) boolean(a[field], field);
    if (a.timeout_ms !== undefined) timeout(a.timeout_ms);
    if (a.url !== undefined) httpUrl(a.url);
    if (a.wait_until !== undefined) choice(a.wait_until, 'wait_until', ['domcontentloaded', 'load']);
    if (a.state !== undefined) choice(a.state, 'state', ['visible', 'hidden', 'attached', 'detached']);
    if (a.direction !== undefined) choice(a.direction, 'direction', ['back', 'forward', 'reload']);
    if (a.delay_ms !== undefined) integer(a.delay_ms, 'delay_ms', 0, 250);
    if (a.duration_ms !== undefined) integer(a.duration_ms, 'duration_ms', 0, 30000);
    for (const field of ['delta_x', 'delta_y']) if (a[field] !== undefined) integer(a[field], field, -100000, 100000);
    switch (a.type) {
      case 'goto': case 'wait_url': httpUrl(a.url); break;
      case 'click': case 'hover': case 'download': case 'wait_selector': target(a); break;
      case 'drag': target(a, 'source_'); target(a, 'target_'); break;
      case 'fill': target(a); string(a.value, 'value', 1, 65536); break;
      case 'type_text': target(a); string(a.text, 'text', 0, 65536); break;
      case 'set_checked': target(a); boolean(a.checked, 'checked'); break;
      case 'press': target(a, '', true); string(a.key, 'key', 1, 64); break;
      case 'wait': integer(a.duration_ms, 'duration_ms', 0, 30000); break;
      case 'wait_text':
        string(a.text, 'text', 1, 4096);
        if (a.state !== undefined) choice(a.state, 'state', ['visible', 'hidden']);
        break;
      case 'select': target(a); string(a.value, 'value', 1, 4096); break;
      case 'set_files':
        target(a);
        if (!Array.isArray(a.files) || a.files.length < 1 || a.files.length > 10) fail('files', 'must contain 1..10 paths');
        for (const file of a.files) string(file, 'files', 1, 4096);
        break;
      case 'navigation': choice(a.direction, 'direction', ['back', 'forward', 'reload']); break;
    }
    if (!WAIT_TYPES.has(a.type)) mutations++;
    return structuredClone(a);
  });
  if (normalized.some(a => a.type === 'download') && normalized.length !== 1) fail('download', 'must be the only action');
  if (mutations > 1) fail('actions', 'permit at most one state mutation per observation');
  return normalized;
}

export function validateSnapshot(input) {
  const a = object(input, 'snapshot');
  const result = {
    mode: a.mode ?? 'full',
    full_page: a.full_page ?? false,
    screenshot: a.screenshot ?? true,
    max_text_chars: a.max_text_chars ?? 8000,
    max_interactive_elements: a.max_interactive_elements ?? 100,
    include_console: a.include_console ?? false,
    max_console_messages: a.max_console_messages ?? 50,
    include_network: a.include_network ?? false,
    max_network_events: a.max_network_events ?? 100,
    timeout_ms: timeout(a.timeout_ms),
  };
  choice(result.mode, 'mode', ['full', 'find']);
  for (const key of ['full_page', 'screenshot', 'include_console', 'include_network']) boolean(result[key], key);
  integer(result.max_text_chars, 'max_text_chars', 1, 50000);
  integer(result.max_interactive_elements, 'max_interactive_elements', 1, 500);
  integer(result.max_console_messages, 'max_console_messages', 1, 200);
  integer(result.max_network_events, 'max_network_events', 1, 500);
  if (result.mode === 'find') {
    result.find_query = string(a.find_query, 'find_query', 1, 1024);
    result.find_case_sensitive = boolean(a.find_case_sensitive ?? false, 'find_case_sensitive');
    result.max_find_results = integer(a.max_find_results ?? 20, 'max_find_results', 1, 50);
  } else {
    if (a.find_query !== undefined) fail('mode', 'must be find when find_query is supplied');
    if (a.find_case_sensitive !== undefined) boolean(a.find_case_sensitive, 'find_case_sensitive');
    if (a.max_find_results !== undefined) integer(a.max_find_results, 'max_find_results', 1, 50);
  }
  return result;
}

export function validateStart(input) {
  const a = object(input, 'start');
  const result = { headless: a.headless ?? true, timeout_ms: timeout(a.timeout_ms) };
  boolean(result.headless, 'headless');
  if (a.url !== undefined) result.url = httpUrl(a.url);
  if (a.viewport !== undefined) {
    object(a.viewport, 'viewport');
    keys(a.viewport, ['width', 'height'], 'viewport');
    result.viewport = { width: integer(a.viewport.width, 'viewport.width', 320, 7680), height: integer(a.viewport.height, 'viewport.height', 240, 4320) };
  }
  if (a.profile_id !== undefined) {
    string(a.profile_id, 'profile_id', 1, 64);
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(a.profile_id) || ['.', '..'].includes(a.profile_id)) fail('profile_id');
    result.profile_id = a.profile_id;
  }
  return result;
}
