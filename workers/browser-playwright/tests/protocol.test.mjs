import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';

const api = await import('../protocol.mjs').catch(() => ({}));
function frame(value) {
  const body = Buffer.from(JSON.stringify(value)), prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(body.length);
  return Buffer.concat([prefix, body]);
}
async function collect(stream) { const chunks = []; for await (const chunk of stream) chunks.push(chunk); return Buffer.concat(chunks); }

test('fragmented private messages retain correlation and one complete request per dispatch', async () => {
  assert.equal(typeof api.readFrames, 'function', 'private frame parser is not implemented');
  const input = new PassThrough();
  const message = { v: 2, id: 'r7', method: 'snapshot', params: { screenshot: false } };
  const bytes = frame(message), observed = [];
  const reading = (async () => { for await (const value of api.readFrames(input, 1024)) observed.push(value); })();
  for (let i = 0; i < bytes.length; i += 3) input.write(bytes.subarray(i, i + 3));
  input.end(); await reading;
  assert.deepEqual(observed, [message]);
});

test('oversized length and truncated EOF fail before any request is admitted', async () => {
  assert.equal(typeof api.readFrames, 'function', 'private frame parser is not implemented');
  for (const bytes of [Buffer.from([1, 0, 16, 0]), frame({ v: 2, id: 'r', method: 'snapshot', params: {} }).subarray(0, 10)]) {
    const input = new PassThrough(); input.end(bytes);
    let admitted = 0;
    await assert.rejects(async () => { for await (const ignored of api.readFrames(input, 1024)) admitted++; }, /limit|truncated/i);
    assert.equal(admitted, 0);
  }
});

test('response writer preserves a real byte budget and never emits an oversized success', async () => {
  assert.equal(typeof api.writeFrame, 'function', 'private frame writer is not implemented');
  const output = new PassThrough(); const result = collect(output);
  await assert.rejects(api.writeFrame(output, { data: 'x'.repeat(1025) }, 1024), /limit/i);
  await api.writeFrame(output, { v: 2, id: 'r1', ok: true, result: { value: 7 } }, 1024);
  output.end();
  const bytes = await result;
  assert.equal(bytes.readUInt32LE(0), bytes.length - 4);
  assert.deepEqual(JSON.parse(bytes.subarray(4).toString('utf8')), { v: 2, id: 'r1', ok: true, result: { value: 7 } });
});

test('protocol version downgrade and unexpected envelope keys are refused', () => {
  assert.equal(typeof api.validateEnvelope, 'function', 'private envelope validator is not implemented');
  assert.throws(() => api.validateEnvelope({ v: 0, id: 'r1', method: 'snapshot', params: {} }), /version/i);
  assert.throws(() => api.validateEnvelope({ v: 2, id: 'r1', method: 'snapshot', params: {}, javascript: 'untrusted' }), /javascript/i);
  assert.throws(() => api.validateEnvelope({ v: 2, id: 'r1', method: 'eval', params: {} }), /method/i);
});


test('review: reply size and serialization failures retain an independent compact effect receipt', () => {
  assert.equal(typeof api.encodeReply, 'function');
  const receipt = { operation: 'act', session_id: 's1', page_id: 'p1', phase: 'complete', completed_actions: 1, failed_action_index: null, session_usable: true, effect_uncertain: false, upload_effect_started: false };
  for (const result of [{ text: 'x'.repeat(2048) }, { value: 1n }]) {
    const bytes = api.encodeReply({ v: 2, id: 'r8', ok: true, result, receipt }, 1024);
    const fallback = JSON.parse(bytes.toString('utf8'));
    assert.equal(fallback.ok, false);
    assert.equal(fallback.receipt.completed_actions, 1);
    assert.equal(fallback.receipt.session_id, 's1');
    assert.equal(fallback.receipt.phase, 'serialize_response');
    assert.equal(fallback.error.details.session_usable, true);
    assert.ok(bytes.length <= 1024);
  }
});
