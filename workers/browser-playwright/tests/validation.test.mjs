import test from 'node:test';
import assert from 'node:assert/strict';

const api = await import('../validation.mjs').catch(() => ({}));
const validate = (...args) => {
  assert.equal(typeof api.validateActions, 'function', 'validateActions is not implemented');
  return api.validateActions(...args);
};

test('ambiguous targets and an invalid later action reject the whole batch before effects', () => {
  assert.throws(() => validate([{ type: 'click', selector: '#save', ref: 'e2' }]), /exactly one/i);
  assert.throws(() => validate([
    { type: 'wait', duration_ms: 1 },
    { type: 'type_text', ref: 'e2', value: 'wrong field' },
  ]), /text/i);
});

test('a single observation permits waits around one mutation but rejects two mutations', () => {
  assert.deepEqual(validate([
    { type: 'wait', duration_ms: 0 },
    { type: 'fill', ref: 'f1e2', value: 'bonjour' },
    { type: 'wait_text', text: 'saved', exact: true, state: 'visible', timeout_ms: 1000 },
  ]), [
    { type: 'wait', duration_ms: 0 },
    { type: 'fill', ref: 'f1e2', value: 'bonjour' },
    { type: 'wait_text', text: 'saved', exact: true, state: 'visible', timeout_ms: 1000 },
  ]);
  assert.throws(() => validate([
    { type: 'fill', selector: 'input', value: 'new' },
    { type: 'click', selector: 'button' },
  ]), /one.*mutat/i);
});

test('DeskMCP scroll deltas, duration, text and iframe refs remain usable at their boundaries', () => {
  assert.deepEqual(validate([{ type: 'scroll', delta_x: -100000, delta_y: 100000 }]), [{ type: 'scroll', delta_x: -100000, delta_y: 100000 }]);
  assert.deepEqual(validate([{ type: 'type_text', ref: 'f1f22e333', text: 'é'.repeat(1000), delay_ms: 250 }])[0].text, 'é'.repeat(1000));
  assert.throws(() => validate([{ type: 'wait', duration_ms: 30001 }]), /duration_ms/i);
  assert.throws(() => validate([{ type: 'scroll', direction: 'down' }]), /direction/i);
  assert.throws(() => validate([{ type: 'download', ref: 'e2' }, { type: 'wait', duration_ms: 0 }]), /only action/i);
});

test('snapshot options default to image output and preserve full/find bounds', () => {
  assert.equal(typeof api.validateSnapshot, 'function', 'validateSnapshot is not implemented');
  assert.equal(api.validateSnapshot({}).screenshot, true);
  const got = api.validateSnapshot({ mode: 'find', find_query: 'École', find_case_sensitive: true, max_find_results: 50, max_interactive_elements: 500 });
  assert.equal(got.find_case_sensitive, true);
  assert.equal(got.max_find_results, 50);
  assert.throws(() => api.validateSnapshot({ mode: 'find', find_query: 'a'.repeat(1025) }), /find_query/i);
  assert.throws(() => api.validateSnapshot({ max_interactive_elements: 501 }), /max_interactive_elements/i);
});

test('review: full snapshots accept valid serialized find defaults without a query', () => {
  const got = api.validateSnapshot({ mode: 'full', find_case_sensitive: false, max_find_results: 20 });
  assert.equal(got.mode, 'full');
  assert.equal(got.find_query, undefined);
  assert.throws(() => api.validateSnapshot({ mode: 'full', find_query: 'unexpected' }), /mode|find/i);
  assert.throws(() => api.validateSnapshot({ mode: 'full', max_find_results: 0 }), /max_find_results/i);
  assert.throws(() => api.validateSnapshot({ mode: 'full', find_case_sensitive: 'false' }), /find_case_sensitive/i);
});
