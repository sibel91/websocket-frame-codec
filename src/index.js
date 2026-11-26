// Public entry point for websocket-frame-codec.
//
// Everything that callers are expected to touch is re-exported from here so that
// the internal module layout (core.js) stays an implementation detail.
export {
  OPCODE_CONTINUATION,
  OPCODE_TEXT,
  OPCODE_BINARY,
  OPCODE_CLOSE,
  OPCODE_PING,
  OPCODE_PONG,
  OPCODES,
  MAX_PAYLOAD_LENGTH,
  ProtocolError,
  encodeFrame,
  decodeFrame,
  FrameDecoder,
  encodeMessage,
  decodeMessage,
} from './core.js';
