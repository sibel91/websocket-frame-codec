# websocket-frame-codec

Encode and decode RFC 6455 WebSocket data frames, including masking, fragmentation, and the 16- and 64-bit payload length extensions.

```js
import {
  OPCODE_TEXT,
  OPCODE_BINARY,
  OPCODE_PING,
  encodeFrame,
  decodeFrame,
  FrameDecoder,
  encodeMessage,
  decodeMessage,
} from 'websocket-frame-codec';

// Encode a single text frame (server-to-client, so no mask).
const frame = encodeFrame({
  opcode: OPCODE_TEXT,
  payload: new TextEncoder().encode('hello'),
});

// Decode it back. decodeFrame consumes exactly one frame.
const { frame: decoded, bytesConsumed } = decodeFrame(frame);
console.log(decoded.opcode, bytesConsumed); // 1 7

// Client-to-server frames must be masked; the mask key is generated for you.
const masked = encodeFrame({
  opcode: OPCODE_BINARY,
  payload: new Uint8Array([1, 2, 3]),
  mask: true,
});

// For a socket, feed chunks of arbitrary size into a FrameDecoder.
const decoder = new FrameDecoder();
decoder.push(masked.subarray(0, 3));
console.log(decoder.next()); // null: not enough bytes yet
decoder.push(masked.subarray(3));
console.log(decoder.next().opcode); // 2

// Fragment a large message and reassemble it, keeping control frames aside.
const frames = encodeMessage({
  opcode: OPCODE_BINARY,
  payload: new Uint8Array(250),
  fragmentSize: 100,
});
const message = decodeMessage(frames.map((f) => decodeFrame(f).frame));
console.log(message.payload.length); // 250
```

## Why this exists

Most WebSocket code lives inside a socket library that also handles the handshake, TLS, and framing policy. When you need just the framing layer — to implement a proxy, a fuzzer, or a test double — pulling in a full client is the wrong shape. This library is the wire format and nothing else: it takes bytes in and gives frames out, with no sockets, no timers, and no I/O.

The trade-off is strictness. The decoder rejects frames that a permissive implementation would accept: non-minimal length fields, set reserved bits, unknown opcodes, oversized or fragmented control frames, and 64-bit lengths with the high bit set. A lenient decoder lets a peer smuggle data past an intermediary that parses the same bytes differently, so rejecting is the safer default. If you need to accept a known-broken peer, decode the header yourself.

## The awkward edge

`decodeFrame` consumes exactly one frame and throws when the buffer is short. That is correct for a codec but wrong for a socket, where a chunk may hold half a frame or three frames. Use `FrameDecoder` for that: it buffers, returns `null` when more bytes are needed, and only throws for genuine protocol errors. The distinction is by message text on `ProtocolError`; truncation errors are recoverable, everything else is not.

Masking is generated internally from the platform CSPRNG and is never accepted from the caller, because reusing a mask key across frames is itself a protocol violation. This means `encodeFrame` with `mask: true` is not deterministic; the decoded payload is.

## API

Exports: `OPCODE_CONTINUATION`, `OPCODE_TEXT`, `OPCODE_BINARY`, `OPCODE_CLOSE`, `OPCODE_PING`, `OPCODE_PONG`, `OPCODES`, `MAX_PAYLOAD_LENGTH`, `ProtocolError`, `encodeFrame`, `decodeFrame`, `FrameDecoder`, `encodeMessage`, `decodeMessage`.

- `encodeFrame({ opcode, payload?, fin?, mask? })` returns a `Uint8Array`.
- `decodeFrame(bytes)` returns `{ frame, bytesConsumed }`, where `frame` is `{ fin, opcode, masked, payload }`.
- `new FrameDecoder()` has `push(bytes)` and `next()`; `next()` returns a frame or `null`.
- `encodeMessage({ opcode, payload?, mask?, fragmentSize? })` returns an array of encoded frames. `fragmentSize: null` (the default) means one frame.
- `decodeMessage(frames)` returns `{ opcode, payload, control }`, where `control` holds any interleaved ping/pong/close frames.
