import { InvalidPadding, PayloadTooLarge } from './errors.js';

const MAGIC = Buffer.from('ZKLG', 'ascii');
const HEADER_LEN = 8;

/**
 * Pad plaintext payload to an exact target length.
 *
 * Format:
 * - 4 bytes: magic "ZKLG"
 * - 4 bytes: u32 payload length (little endian)
 * - N bytes: payload
 * - remaining: filler
 *
 * This mirrors the Rust/Python SDK padding format for interoperability.
 */
export function padPayload(payload: Uint8Array, targetLen: number): Uint8Array {
  if (targetLen < HEADER_LEN) throw new InvalidPadding('target length too small');
  const maxPayload = targetLen - HEADER_LEN;
  if (payload.length > maxPayload) throw new PayloadTooLarge(payload.length, maxPayload);

  const out = Buffer.alloc(targetLen);
  MAGIC.copy(out, 0);
  out.writeUInt32LE(payload.length, 4);
  Buffer.from(payload).copy(out, 8);

  // Low-entropy filler (inside encrypted payload).
  const filler = Buffer.from(' \n', 'ascii');
  let i = 8 + payload.length;
  let j = 0;
  while (i < targetLen) {
    out[i] = filler[j % filler.length]!;
    i += 1;
    j += 1;
  }

  return out;
}

/** Remove padding applied by `padPayload`. */
export function unpadPayload(padded: Uint8Array): Uint8Array {
  if (padded.length < HEADER_LEN) throw new InvalidPadding('padded payload too small');
  const buf = Buffer.from(padded);
  if (!buf.subarray(0, 4).equals(MAGIC)) throw new InvalidPadding('bad magic');
  const length = buf.readUInt32LE(4);
  if (length > padded.length - HEADER_LEN) throw new InvalidPadding('invalid length');
  return buf.subarray(8, 8 + length);
}
