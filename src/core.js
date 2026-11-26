// WebSocket frame codec (RFC 6455 section 5).
//
// The encoder always emits the final form of a frame: the shortest payload
// length representation that can hold the payload, and (when masking is asked
// for) a fresh 4-byte mask key. The decoder is deliberately strict: it rejects
// frames whose length field is non-minimal, whose reserved bits are set, whose
// opcode is unknown, or whose control-frame constraints are violated. Strictness
// is the trade-off here: a lenient decoder would silently accept malformed input
// that a peer could use to smuggle data past intermediaries.

/**
 * Opcode for a continuation frame. Carries the next slice of a fragmented
 * message and never appears on its own as the first frame of a message.
 * @type {number}
 */
export const OPCODE_CONTINUATION = 0x0;

/** Opcode for a text frame. Payload must be valid UTF-8. @type {number} */
export const OPCODE_TEXT = 0x1;

/** Opcode for a binary frame. @type {number} */
export const OPCODE_BINARY = 0x2;

/**
 * Opcode for a close frame. A close frame may carry a 2-byte status code and a
 * UTF-8 reason; with no body it means "no status supplied".
 * @type {number}
 */
export const OPCODE_CLOSE = 0x8;

/** Opcode for a ping frame. @type {number} */
export const OPCODE_PING = 0x9;

/** Opcode for a pong frame. @type {number} */
export const OPCODE_PONG = 0xa;

/**
 * The set of opcodes this codec recognises. Anything else is a protocol error
 * at decode time; the encoder refuses to emit them.
 * @type {Set<number>}
 */
export const OPCODES = new Set([
  OPCODE_CONTINUATION,
  OPCODE_TEXT,
  OPCODE_BINARY,
  OPCODE_CLOSE,
  OPCODE_PING,
  OPCODE_PONG,
]);

/**
 * Largest payload length we can represent: 2^63 - 1. The high bit of a 64-bit
 * length field must be zero per RFC 6455, so we cap at the signed maximum.
 * @type {number}
 */
export const MAX_PAYLOAD_LENGTH = 0x7fffffffffffffffn;

const CONTROL_OPCODES = new Set([OPCODE_CLOSE, OPCODE_PING, OPCODE_PONG]);

/**
 * Error thrown for any malformed frame or message. A single error type keeps
 * callers from having to guess which of a dozen subclasses to catch; the
 * `message` carries the detail.
 */
export class ProtocolError extends Error {
  /**
   * @param {string} message
   */
  constructor(message) {
    super(message);
    this.name = 'ProtocolError';
  }
}

/**
 * @param {number} opcode
 * @returns {boolean}
 */
function isControlOpcode(opcode) {
  return CONTROL_OPCODES.has(opcode);
}

/**
 * @param {number} opcode
 * @returns {boolean}
 */
function isKnownOpcode(opcode) {
  return OPCODES.has(opcode);
}

/**
 * Validate a payload length against the representable range.
 * @param {number} length
 * @param {string} what
 */
function checkLength(length, what) {
  if (!Number.isInteger(length) || length < 0) {
    throw new ProtocolError(`${what} length must be a non-negative integer`);
  }
  if (length > MAX_PAYLOAD_LENGTH) {
    throw new ProtocolError(`${what} length exceeds 2^63 - 1`);
  }
}

/**
 * Convert a Buffer/Uint8Array/ArrayBuffer into a Uint8Array without copying when
 * possible. Accepting all three keeps callers from having to normalise input.
 * @param {Uint8Array|ArrayBuffer} value
 * @param {string} what
 * @returns {Uint8Array}
 */
function toBytes(value, what) {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  throw new TypeError(`${what} must be a Uint8Array or ArrayBuffer`);
}

/**
 * Generate a fresh 4-byte mask key. Masking is mandatory for client-to-server
 * frames and the key must not be reused across frames, so we never accept one
 * from the caller.
 * @returns {Uint8Array}
 */
function randomMaskKey() {
  const key = new Uint8Array(4);
  // globalThis.crypto is available in Node >= 19 and in browsers. Fall back to
  // Math.random only if it is missing; the mask is not a security boundary, it
  // exists to defeat cache-poisoning proxies.
  const cryptoObj = globalThis.crypto;
  if (cryptoObj && typeof cryptoObj.getRandomValues === 'function') {
    cryptoObj.getRandomValues(key);
    return key;
  }
  for (let i = 0; i < key.length; i += 1) {
    key[i] = Math.floor(Math.random() * 256);
  }
  return key;
}

/**
 * Apply the WebSocket masking transform. XOR is its own inverse, so the same
 * function both masks and unmasks.
 * @param {Uint8Array} payload
 * @param {Uint8Array} maskKey
 * @returns {Uint8Array}
 */
function applyMask(payload, maskKey) {
  const out = new Uint8Array(payload.length);
  for (let i = 0; i < payload.length; i += 1) {
    out[i] = payload[i] ^ maskKey[i & 3];
  }
  return out;
}

/**
 * Encode a single WebSocket frame.
 *
 * @param {object} options
 * @param {number} options.opcode One of the exported OPCODE_* constants.
 * @param {Uint8Array|ArrayBuffer} [options.payload] Frame payload.
 * @param {boolean} [options.fin] Whether this is the final frame of a message.
 * @param {boolean} [options.mask] Whether to mask the payload. Defaults to false.
 * @returns {Uint8Array} The encoded frame.
 */
export function encodeFrame(options) {
  if (options === null || typeof options !== 'object') {
    throw new TypeError('encodeFrame requires an options object');
  }
  const { opcode } = options;
  const fin = options.fin === undefined ? true : options.fin;
  const mask = options.mask === undefined ? false : options.mask;

  if (!isKnownOpcode(opcode)) {
    throw new ProtocolError(`unknown opcode 0x${Number(opcode).toString(16)}`);
  }
  if (typeof fin !== 'boolean') {
    throw new TypeError('fin must be a boolean');
  }
  if (typeof mask !== 'boolean') {
    throw new TypeError('mask must be a boolean');
  }

  const payload = options.payload === undefined ? new Uint8Array(0) : toBytes(options.payload, 'payload');
  checkLength(payload.length, 'payload');

  if (isControlOpcode(opcode)) {
    if (!fin) {
      throw new ProtocolError('control frames must not be fragmented');
    }
    if (payload.length > 125) {
      throw new ProtocolError('control frame payload must not exceed 125 bytes');
    }
  }

  const length = payload.length;
  let headerLength = 2;
  if (length > 65535) {
    headerLength += 8;
  } else if (length > 125) {
    headerLength += 2;
  }
  if (mask) {
    headerLength += 4;
  }

  const frame = new Uint8Array(headerLength + length);
  frame[0] = (fin ? 0x80 : 0x00) | opcode;

  const maskBit = mask ? 0x80 : 0x00;
  let offset = 2;
  if (length > 65535) {
    frame[1] = maskBit | 127;
    // Write the 64-bit length big-endian. JS numbers are exact up to 2^53, and
    // we have already rejected anything above 2^63 - 1, so splitting into two
    // 32-bit halves is exact for all lengths we accept.
    const high = Math.floor(length / 0x100000000);
    const low = length % 0x100000000;
    frame[offset] = (high >>> 24) & 0xff;
    frame[offset + 1] = (high >>> 16) & 0xff;
    frame[offset + 2] = (high >>> 8) & 0xff;
    frame[offset + 3] = high & 0xff;
    frame[offset + 4] = (low >>> 24) & 0xff;
    frame[offset + 5] = (low >>> 16) & 0xff;
    frame[offset + 6] = (low >>> 8) & 0xff;
    frame[offset + 7] = low & 0xff;
    offset += 8;
  } else if (length > 125) {
    frame[1] = maskBit | 126;
    frame[offset] = (length >>> 8) & 0xff;
    frame[offset + 1] = length & 0xff;
    offset += 2;
  } else {
    frame[1] = maskBit | length;
  }

  if (mask) {
    const key = randomMaskKey();
    frame.set(key, offset);
    offset += 4;
    frame.set(applyMask(payload, key), offset);
  } else {
    frame.set(payload, offset);
  }

  return frame;
}

/**
 * Decode exactly one frame from the front of `data`.
 *
 * @param {Uint8Array|ArrayBuffer} data
 * @returns {{frame: object, bytesConsumed: number}}
 */
export function decodeFrame(data) {
  const bytes = toBytes(data, 'data');
  if (bytes.length < 2) {
    throw new ProtocolError('frame is shorter than the 2-byte minimum header');
  }

  const b0 = bytes[0];
  const b1 = bytes[1];

  if ((b0 & 0x70) !== 0) {
    throw new ProtocolError('reserved bits must be zero');
  }

  const fin = (b0 & 0x80) !== 0;
  const opcode = b0 & 0x0f;
  if (!isKnownOpcode(opcode)) {
    throw new ProtocolError(`unknown opcode 0x${opcode.toString(16)}`);
  }

  const masked = (b1 & 0x80) !== 0;
  const lengthCode = b1 & 0x7f;

  let offset = 2;
  let payloadLength;
  if (lengthCode === 126) {
    if (bytes.length < offset + 2) {
      throw new ProtocolError('truncated 16-bit length field');
    }
    payloadLength = (bytes[offset] << 8) | bytes[offset + 1];
    offset += 2;
    if (payloadLength <= 125) {
      throw new ProtocolError('length field is not minimal');
    }
  } else if (lengthCode === 127) {
    if (bytes.length < offset + 8) {
      throw new ProtocolError('truncated 64-bit length field');
    }
    const high = (bytes[offset] * 0x1000000) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3];
    const low = (bytes[offset + 4] * 0x1000000) + (bytes[offset + 5] << 16) + (bytes[offset + 6] << 8) + bytes[offset + 7];
    if ((high & 0x80000000) !== 0) {
      throw new ProtocolError('64-bit length field must have its high bit clear');
    }
    payloadLength = high * 0x100000000 + low;
    offset += 8;
    if (payloadLength <= 65535) {
      throw new ProtocolError('length field is not minimal');
    }
  } else {
    payloadLength = lengthCode;
  }

  if (isControlOpcode(opcode)) {
    if (!fin) {
      throw new ProtocolError('control frames must not be fragmented');
    }
    if (payloadLength > 125) {
      throw new ProtocolError('control frame payload must not exceed 125 bytes');
    }
  }

  let maskKey = null;
  if (masked) {
    if (bytes.length < offset + 4) {
      throw new ProtocolError('truncated mask key');
    }
    maskKey = bytes.slice(offset, offset + 4);
    offset += 4;
  }

  if (bytes.length < offset + payloadLength) {
    throw new ProtocolError('truncated payload');
  }

  let payload;
  if (masked) {
    payload = applyMask(bytes.subarray(offset, offset + payloadLength), maskKey);
  } else {
    // Copy so the returned frame does not alias the caller's buffer.
    payload = bytes.slice(offset, offset + payloadLength);
  }

  const frame = {
    fin,
    opcode,
    masked,
    payload,
  };

  return { frame, bytesConsumed: offset + payloadLength };
}

/**
 * Incremental decoder for a stream of frames.
 *
 * Feed it arbitrary chunks; it buffers until a whole frame is available and
 * then returns it. This is the shape a real socket needs, where a single
 * `data` event may contain half a frame or three frames.
 */
export class FrameDecoder {
  constructor() {
    /** @type {Uint8Array} */
    this.buffer = new Uint8Array(0);
  }

  /**
   * Append bytes to the internal buffer.
   * @param {Uint8Array|ArrayBuffer} chunk
   */
  push(chunk) {
    const bytes = toBytes(chunk, 'chunk');
    if (bytes.length === 0) {
      return;
    }
    const merged = new Uint8Array(this.buffer.length + bytes.length);
    merged.set(this.buffer, 0);
    merged.set(bytes, this.buffer.length);
    this.buffer = merged;
  }

  /**
   * Try to decode one frame from the buffer.
   * @returns {object|null} The frame, or null if more bytes are needed.
   */
  next() {
    try {
      const { frame, bytesConsumed } = decodeFrame(this.buffer);
      this.buffer = this.buffer.slice(bytesConsumed);
      return frame;
    } catch (err) {
      if (err instanceof ProtocolError && isTruncationError(err.message)) {
        return null;
      }
      throw err;
    }
  }
}

/**
 * Distinguish "need more bytes" from "this is malformed". The decoder throws a
 * ProtocolError for both; only the truncation variants are recoverable by
 * waiting for more input.
 * @param {string} message
 * @returns {boolean}
 */
function isTruncationError(message) {
  return (
    message === 'frame is shorter than the 2-byte minimum header' ||
    message === 'truncated 16-bit length field' ||
    message === 'truncated 64-bit length field' ||
    message === 'truncated mask key' ||
    message === 'truncated payload'
  );
}

/**
 * Encode a whole message, fragmenting it if requested.
 *
 * Fragmentation is expressed explicitly rather than derived from a maximum
 * frame size: the caller knows its own framing policy, and guessing here would
 * produce surprises. When `fragmentSize` is null the message is a single frame.
 *
 * @param {object} options
 * @param {number} options.opcode OPCODE_TEXT or OPCODE_BINARY.
 * @param {Uint8Array|ArrayBuffer} [options.payload]
 * @param {boolean} [options.mask]
 * @param {number|null} [options.fragmentSize] Max payload per frame.
 * @returns {Uint8Array[]} The frames, in order.
 */
export function encodeMessage(options) {
  if (options === null || typeof options !== 'object') {
    throw new TypeError('encodeMessage requires an options object');
  }
  const { opcode } = options;
  if (opcode !== OPCODE_TEXT && opcode !== OPCODE_BINARY) {
    throw new ProtocolError('message opcode must be TEXT or BINARY');
  }
  const mask = options.mask === undefined ? false : options.mask;
  const payload = options.payload === undefined ? new Uint8Array(0) : toBytes(options.payload, 'payload');
  const fragmentSize = options.fragmentSize === undefined ? null : options.fragmentSize;

  if (fragmentSize === null) {
    return [encodeFrame({ opcode, payload, fin: true, mask })];
  }
  if (!Number.isInteger(fragmentSize) || fragmentSize <= 0) {
    throw new ProtocolError('fragmentSize must be a positive integer');
  }

  if (payload.length === 0) {
    return [encodeFrame({ opcode, payload, fin: true, mask })];
  }

  const frames = [];
  let offset = 0;
  let first = true;
  while (offset < payload.length) {
    const end = Math.min(offset + fragmentSize, payload.length);
    const slice = payload.subarray(offset, end);
    const fin = end === payload.length;
    frames.push(
      encodeFrame({
        opcode: first ? opcode : OPCODE_CONTINUATION,
        payload: slice,
        fin,
        mask,
      }),
    );
    first = false;
    offset = end;
  }
  return frames;
}

/**
 * Reassemble a message from a sequence of frames.
 *
 * Interleaved control frames are returned separately because a real peer must
 * be able to answer a ping in the middle of a fragmented message. The function
 * takes an array rather than a live socket so it stays pure and testable.
 *
 * @param {object[]} frames
 * @returns {{opcode: number, payload: Uint8Array, control: object[]}}
 */
export function decodeMessage(frames) {
  if (!Array.isArray(frames)) {
    throw new TypeError('decodeMessage requires an array of frames');
  }

  let messageOpcode = null;
  let fragments = [];
  let totalLength = 0;
  const control = [];

  for (const frame of frames) {
    if (frame === null || typeof frame !== 'object') {
      throw new TypeError('each frame must be an object');
    }
    const { opcode, fin, payload } = frame;
    if (!isKnownOpcode(opcode)) {
      throw new ProtocolError(`unknown opcode 0x${Number(opcode).toString(16)}`);
    }
    if (!(payload instanceof Uint8Array)) {
      throw new TypeError('frame payload must be a Uint8Array');
    }

    if (isControlOpcode(opcode)) {
      if (!fin) {
        throw new ProtocolError('control frames must not be fragmented');
      }
      if (payload.length > 125) {
        throw new ProtocolError('control frame payload must not exceed 125 bytes');
      }
      control.push(frame);
      continue;
    }

    if (opcode === OPCODE_CONTINUATION) {
      if (messageOpcode === null) {
        throw new ProtocolError('continuation frame without a preceding data frame');
      }
      fragments.push(payload);
      totalLength += payload.length;
      if (fin) {
        const merged = new Uint8Array(totalLength);
        let at = 0;
        for (const part of fragments) {
          merged.set(part, at);
          at += part.length;
        }
        return { opcode: messageOpcode, payload: merged, control };
      }
    } else {
      if (messageOpcode !== null) {
        throw new ProtocolError('new data frame while a fragmented message is in progress');
      }
      messageOpcode = opcode;
      fragments = [payload];
      totalLength = payload.length;
      if (fin) {
        return { opcode: messageOpcode, payload: payload.slice(), control };
      }
    }
  }

  throw new ProtocolError('incomplete fragmented message');
}
