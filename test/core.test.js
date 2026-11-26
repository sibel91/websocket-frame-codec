import test from 'node:test';
import assert from 'node:assert/strict';

import {
  OPCODE_CONTINUATION,
  OPCODE_TEXT,
  OPCODE_BINARY,
  OPCODE_CLOSE,
  OPCODE_PING,
  OPCODE_PONG,
  MAX_PAYLOAD_LENGTH,
  ProtocolError,
  encodeFrame,
  decodeFrame,
  FrameDecoder,
  encodeMessage,
  decodeMessage,
} from '../src/index.js';

/**
 * Build a deterministic payload so tests never depend on randomness.
 * @param {number} length
 * @returns {Uint8Array}
 */
function pattern(length) {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    out[i] = (i * 7 + 3) & 0xff;
  }
  return out;
}

/**
 * Hand-build a frame with an arbitrary length code so we can test the decoder
 * against non-minimal encodings the encoder would never produce.
 * @param {object} spec
 * @returns {Uint8Array}
 */
function rawFrame({ fin = true, opcode, lengthCode, lengthBytes = [], masked = false, maskKey = [0, 0, 0, 0], payload = new Uint8Array(0) }) {
  const parts = [];
  parts.push((fin ? 0x80 : 0x00) | opcode);
  parts.push((masked ? 0x80 : 0x00) | lengthCode);
  for (const b of lengthBytes) {
    parts.push(b);
  }
  if (masked) {
    for (const b of maskKey) {
      parts.push(b);
    }
  }
  for (const b of payload) {
    parts.push(b);
  }
  return Uint8Array.from(parts);
}

test('round-trips a small unmasked text frame', () => {
  const payload = new TextEncoder().encode('hello');
  const encoded = encodeFrame({ opcode: OPCODE_TEXT, payload });
  assert.equal(encoded.length, 2 + payload.length);
  assert.equal(encoded[0], 0x81);
  assert.equal(encoded[1], 5);

  const { frame, bytesConsumed } = decodeFrame(encoded);
  assert.equal(bytesConsumed, encoded.length);
  assert.equal(frame.fin, true);
  assert.equal(frame.opcode, OPCODE_TEXT);
  assert.equal(frame.masked, false);
  assert.deepEqual(Array.from(frame.payload), Array.from(payload));
});

test('round-trips a masked binary frame and reports masked=true', () => {
  const payload = pattern(300);
  const encoded = encodeFrame({ opcode: OPCODE_BINARY, payload, mask: true });
  assert.equal(encoded[1] & 0x80, 0x80);
  assert.equal(encoded[1] & 0x7f, 126);

  const { frame, bytesConsumed } = decodeFrame(encoded);
  assert.equal(bytesConsumed, encoded.length);
  assert.equal(frame.masked, true);
  assert.equal(frame.opcode, OPCODE_BINARY);
  assert.deepEqual(Array.from(frame.payload), Array.from(payload));
});

test('uses the 64-bit length form above 65535 bytes', () => {
  const payload = pattern(70000);
  const encoded = encodeFrame({ opcode: OPCODE_BINARY, payload });
  assert.equal(encoded[1] & 0x7f, 127);

  const { frame, bytesConsumed } = decodeFrame(encoded);
  assert.equal(bytesConsumed, encoded.length);
  assert.equal(frame.payload.length, 70000);
  assert.deepEqual(Array.from(frame.payload), Array.from(payload));
});

test('round-trips the boundary lengths 125 and 126', () => {
  for (const size of [125, 126]) {
    const payload = pattern(size);
    const encoded = encodeFrame({ opcode: OPCODE_BINARY, payload });
    if (size === 125) {
      assert.equal(encoded[1] & 0x7f, 125);
    } else {
      assert.equal(encoded[1] & 0x7f, 126);
    }
    const { frame } = decodeFrame(encoded);
    assert.deepEqual(Array.from(frame.payload), Array.from(payload));
  }
});

test('round-trips the boundary lengths 65535 and 65536', () => {
  for (const size of [65535, 65536]) {
    const payload = pattern(size);
    const encoded = encodeFrame({ opcode: OPCODE_BINARY, payload });
    if (size === 65535) {
      assert.equal(encoded[1] & 0x7f, 126);
    } else {
      assert.equal(encoded[1] & 0x7f, 127);
    }
    const { frame } = decodeFrame(encoded);
    assert.equal(frame.payload.length, size);
    assert.deepEqual(Array.from(frame.payload), Array.from(payload));
  }
});

test('rejects a non-minimal 16-bit length field', () => {
  const frame = rawFrame({ opcode: OPCODE_TEXT, lengthCode: 126, lengthBytes: [0, 5], payload: new Uint8Array(5) });
  assert.throws(() => decodeFrame(frame), (err) => err instanceof ProtocolError && /not minimal/.test(err.message));
});

test('rejects a non-minimal 64-bit length field', () => {
  const lengthBytes = [0, 0, 0, 0, 0, 0, 0, 5];
  const frame = rawFrame({ opcode: OPCODE_TEXT, lengthCode: 127, lengthBytes, payload: new Uint8Array(5) });
  assert.throws(() => decodeFrame(frame), (err) => err instanceof ProtocolError && /not minimal/.test(err.message));
});

test('rejects a 64-bit length with the high bit set', () => {
  const lengthBytes = [0x80, 0, 0, 0, 0, 0, 0, 0];
  const frame = rawFrame({ opcode: OPCODE_TEXT, lengthCode: 127, lengthBytes });
  assert.throws(() => decodeFrame(frame), (err) => err instanceof ProtocolError && /high bit/.test(err.message));
});

test('rejects unknown opcodes and reserved bits', () => {
  assert.throws(
    () => decodeFrame(rawFrame({ opcode: 0x3, lengthCode: 0 })),
    (err) => err instanceof ProtocolError && /unknown opcode/.test(err.message),
  );
  const withReserved = rawFrame({ opcode: OPCODE_TEXT, lengthCode: 0 });
  withReserved[0] |= 0x40;
  assert.throws(
    () => decodeFrame(withReserved),
    (err) => err instanceof ProtocolError && /reserved bits/.test(err.message),
  );
});

test('enforces control-frame constraints on encode and decode', () => {
  assert.throws(
    () => encodeFrame({ opcode: OPCODE_PING, payload: new Uint8Array(126) }),
    (err) => err instanceof ProtocolError && /125 bytes/.test(err.message),
  );
  assert.throws(
    () => encodeFrame({ opcode: OPCODE_PING, fin: false }),
    (err) => err instanceof ProtocolError && /fragmented/.test(err.message),
  );

  const fragmentedPing = rawFrame({ fin: false, opcode: OPCODE_PING, lengthCode: 0 });
  assert.throws(
    () => decodeFrame(fragmentedPing),
    (err) => err instanceof ProtocolError && /fragmented/.test(err.message),
  );

  const bigPong = rawFrame({ opcode: OPCODE_PONG, lengthCode: 126, lengthBytes: [0, 126], payload: new Uint8Array(126) });
  assert.throws(
    () => decodeFrame(bigPong),
    (err) => err instanceof ProtocolError && /125 bytes/.test(err.message),
  );
});

test('rejects a negative payload length', () => {
  assert.throws(
    () => encodeFrame({ opcode: OPCODE_BINARY, payload: { length: -1 } }),
    (err) => err instanceof TypeError,
  );
  assert.equal(MAX_PAYLOAD_LENGTH, 0x7fffffffffffffffn);
});

test('decodeFrame reports truncation distinctly', () => {
  const encoded = encodeFrame({ opcode: OPCODE_TEXT, payload: pattern(50) });
  assert.throws(
    () => decodeFrame(encoded.subarray(0, 10)),
    (err) => err instanceof ProtocolError && /truncated payload/.test(err.message),
  );
  assert.throws(
    () => decodeFrame(new Uint8Array([0x81])),
    (err) => err instanceof ProtocolError && /2-byte minimum/.test(err.message),
  );
});

test('FrameDecoder buffers partial frames and yields them in order', () => {
  const first = encodeFrame({ opcode: OPCODE_TEXT, payload: new TextEncoder().encode('one') });
  const second = encodeFrame({ opcode: OPCODE_BINARY, payload: pattern(200) });
  const stream = new Uint8Array(first.length + second.length);
  stream.set(first, 0);
  stream.set(second, first.length);

  const decoder = new FrameDecoder();
  const seen = [];

  // Feed one byte at a time: the decoder must never emit a partial frame.
  for (let i = 0; i < stream.length; i += 1) {
    decoder.push(stream.subarray(i, i + 1));
    let frame = decoder.next();
    while (frame !== null) {
      seen.push(frame);
      frame = decoder.next();
    }
  }

  assert.equal(seen.length, 2);
  assert.equal(seen[0].opcode, OPCODE_TEXT);
  assert.equal(new TextDecoder().decode(seen[0].payload), 'one');
  assert.equal(seen[1].opcode, OPCODE_BINARY);
  assert.equal(seen[1].payload.length, 200);
  assert.deepEqual(Array.from(seen[1].payload), Array.from(pattern(200)));
});

test('FrameDecoder surfaces protocol errors instead of buffering forever', () => {
  const decoder = new FrameDecoder();
  decoder.push(rawFrame({ opcode: 0x3, lengthCode: 0 }));
  assert.throws(() => decoder.next(), (err) => err instanceof ProtocolError && /unknown opcode/.test(err.message));
});

test('encodeMessage fragments and decodeMessage reassembles', () => {
  const payload = pattern(250);
  const frames = encodeMessage({ opcode: OPCODE_BINARY, payload, fragmentSize: 100 });
  assert.equal(frames.length, 3);

  const decodedFrames = frames.map((bytes) => decodeFrame(bytes).frame);
  assert.equal(decodedFrames[0].opcode, OPCODE_BINARY);
  assert.equal(decodedFrames[0].fin, false);
  assert.equal(decodedFrames[1].opcode, OPCODE_CONTINUATION);
  assert.equal(decodedFrames[1].fin, false);
  assert.equal(decodedFrames[2].opcode, OPCODE_CONTINUATION);
  assert.equal(decodedFrames[2].fin, true);

  const message = decodeMessage(decodedFrames);
  assert.equal(message.opcode, OPCODE_BINARY);
  assert.deepEqual(Array.from(message.payload), Array.from(payload));
  assert.equal(message.control.length, 0);
});

test('encodeMessage emits a single frame when fragmentSize is null', () => {
  const payload = pattern(10);
  const frames = encodeMessage({ opcode: OPCODE_TEXT, payload });
  assert.equal(frames.length, 1);
  const { frame } = decodeFrame(frames[0]);
  assert.equal(frame.fin, true);
  assert.equal(frame.opcode, OPCODE_TEXT);
});

test('decodeMessage separates interleaved control frames', () => {
  const first = encodeFrame({ opcode: OPCODE_TEXT, payload: new TextEncoder().encode('a'), fin: false });
  const ping = encodeFrame({ opcode: OPCODE_PING, payload: new Uint8Array(0) });
  const last = encodeFrame({ opcode: OPCODE_CONTINUATION, payload: new TextEncoder().encode('b'), fin: true });

  const frames = [first, ping, last].map((bytes) => decodeFrame(bytes).frame);
  const message = decodeMessage(frames);
  assert.equal(message.opcode, OPCODE_TEXT);
  assert.equal(new TextDecoder().decode(message.payload), 'ab');
  assert.equal(message.control.length, 1);
  assert.equal(message.control[0].opcode, OPCODE_PING);
});

test('decodeMessage rejects a continuation with no start frame', () => {
  const cont = decodeFrame(encodeFrame({ opcode: OPCODE_CONTINUATION, payload: new Uint8Array(0) })).frame;
  assert.throws(
    () => decodeMessage([cont]),
    (err) => err instanceof ProtocolError && /without a preceding/.test(err.message),
  );
});

test('decodeMessage rejects a new data frame mid-message', () => {
  const first = decodeFrame(encodeFrame({ opcode: OPCODE_TEXT, payload: new Uint8Array(1), fin: false })).frame;
  const second = decodeFrame(encodeFrame({ opcode: OPCODE_TEXT, payload: new Uint8Array(1), fin: true })).frame;
  assert.throws(
    () => decodeMessage([first, second]),
    (err) => err instanceof ProtocolError && /in progress/.test(err.message),
  );
});

test('decodeMessage rejects an incomplete fragmented message', () => {
  const first = decodeFrame(encodeFrame({ opcode: OPCODE_TEXT, payload: new Uint8Array(1), fin: false })).frame;
  assert.throws(
    () => decodeMessage([first]),
    (err) => err instanceof ProtocolError && /incomplete/.test(err.message),
  );
});

test('masks are not reused across frames', () => {
  const a = encodeFrame({ opcode: OPCODE_TEXT, payload: pattern(8), mask: true });
  const b = encodeFrame({ opcode: OPCODE_TEXT, payload: pattern(8), mask: true });
  // The mask key lives in the four bytes before the payload.
  const keyA = Array.from(a.subarray(2, 6));
  const keyB = Array.from(b.subarray(2, 6));
  assert.notDeepEqual(keyA, keyB);
});

import { TextEncoder, TextDecoder } from 'node:util';
