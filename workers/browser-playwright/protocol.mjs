import { BrowserError, object, keys } from './validation.mjs';

export const PROTOCOL_VERSION = 2;
export const RECEIPT_LIMIT = 16 * 1024;
export const REQUEST_LIMIT = 1024 * 1024;
export const RESPONSE_LIMIT = 48 * 1024 * 1024;
const utf8 = new TextDecoder('utf-8', { fatal: true });

export function validateEnvelope(value) {
  object(value, 'envelope');
  keys(value, ['v', 'id', 'method', 'params'], 'envelope');
  if (value.v !== PROTOCOL_VERSION) throw new BrowserError('PROTOCOL_VERSION', 'Unsupported private protocol version');
  if (typeof value.id !== 'string' || !/^r[1-9][0-9]{0,15}$/u.test(value.id)) throw new BrowserError('PROTOCOL_ID', 'Invalid private correlation identifier');
  if (!['init', 'start', 'session', 'snapshot', 'reserve_act', 'cancel_act', 'act', 'close'].includes(value.method)) throw new BrowserError('PROTOCOL_METHOD', 'Unsupported private method');
  object(value.params, 'params');
  return value;
}

export async function* readFrames(input, limit = REQUEST_LIMIT) {
  const header = Buffer.alloc(4);
  let headerLength = 0, body, bodyLength = 0;
  for await (const incoming of input) {
    const chunk = Buffer.isBuffer(incoming) ? incoming : Buffer.from(incoming);
    let offset = 0;
    while (offset < chunk.length) {
      if (!body) {
        const count = Math.min(4 - headerLength, chunk.length - offset);
        chunk.copy(header, headerLength, offset, offset + count);
        headerLength += count; offset += count;
        if (headerLength !== 4) continue;
        const size = header.readUInt32LE(0);
        if (size === 0 || size > limit) throw new BrowserError('PROTOCOL_LIMIT', 'Private request frame exceeds its byte limit');
        body = Buffer.allocUnsafe(size); bodyLength = 0;
      }
      const count = Math.min(body.length - bodyLength, chunk.length - offset);
      chunk.copy(body, bodyLength, offset, offset + count);
      bodyLength += count; offset += count;
      if (bodyLength === body.length) {
        let message;
        try { message = JSON.parse(utf8.decode(body)); }
        catch { throw new BrowserError('PROTOCOL_JSON', 'Invalid private UTF-8 JSON frame'); }
        body = undefined; bodyLength = 0; headerLength = 0;
        yield message;
      }
    }
  }
  if (headerLength || body) throw new BrowserError('PROTOCOL_TRUNCATED', 'Private frame was truncated at EOF');
}

function write(output, bytes) {
  return new Promise((resolve, reject) => output.write(bytes, error => error ? reject(error) : resolve()));
}
export async function writeFrame(output, value, limit = RESPONSE_LIMIT) {
  const text = JSON.stringify(value), bytes = Buffer.byteLength(text, 'utf8');
  if (!bytes || bytes > limit) throw new BrowserError('PROTOCOL_LIMIT', 'Private response exceeds its byte limit');
  const header = Buffer.alloc(4); header.writeUInt32LE(bytes);
  await write(output, header);
  await write(output, Buffer.from(text, 'utf8'));
}


// Build the effect receipt independently before touching the potentially large view.
// The fallback is still a valid domain reply: no effect is retried to obtain it.
export function encodeReply(reply, limit = RESPONSE_LIMIT) {
  const receiptText = JSON.stringify(reply.receipt);
  if (!receiptText || Buffer.byteLength(receiptText) > RECEIPT_LIMIT) throw new BrowserError('RECEIPT_INVALID', 'Private execution receipt exceeds its independent limit');
  const receipt = JSON.parse(receiptText);
  let code = 'RESPONSE_SERIALIZATION_FAILED';
  try {
    const bytes = Buffer.from(JSON.stringify({ ...reply, receipt }), 'utf8');
    if (bytes.length <= limit) return bytes;
    code = 'RESPONSE_LIMIT';
  } catch { /* A completed effect is described by the separately serialized receipt. */ }
  receipt.previous_phase = receipt.phase;
  receipt.phase = 'serialize_response';
  const failure = { v: PROTOCOL_VERSION, id: reply.id, ok: false, receipt,
    error: { code, message: 'Browser response could not be serialized within its byte budget',
      details: { session_usable: receipt.session_usable, completed_actions: receipt.completed_actions, phase: receipt.phase } } };
  const bytes = Buffer.from(JSON.stringify(failure), 'utf8');
  if (bytes.length > limit) throw new BrowserError('RECEIPT_INVALID', 'Private fallback receipt exceeds its byte limit');
  return bytes;
}
export async function writeReply(output, reply) {
  const bytes = encodeReply(reply), header = Buffer.alloc(4);
  header.writeUInt32LE(bytes.length);
  await write(output, header); await write(output, bytes);
}
