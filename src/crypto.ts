import * as crypto from 'node:crypto';

import { CryptoError, InvalidGatewayPublicKey, ProtocolError } from './errors.js';
import { padPayload, unpadPayload } from './padding.js';
import { parseTokenClass, requestPaddedLen, TokenClass } from './tokenClass.js';

export interface Envelope {
  /** protocol version */
  v: number;
  token_class: TokenClass;
  eph_pubkey_b64: string;
  nonce_b64: string;
  ciphertext_b64: string;
}

export class GatewayPublicKey {
  private constructor(public readonly raw: Uint8Array) {
    if (raw.length !== 32) throw new InvalidGatewayPublicKey('gateway public key must be 32 bytes');
  }

  static fromBase64(b64: string): GatewayPublicKey {
    const raw = Buffer.from(b64.trim(), 'base64');
    if (raw.length !== 32) throw new InvalidGatewayPublicKey('gateway public key must decode to 32 bytes');
    return new GatewayPublicKey(raw);
  }

  toBase64(): string {
    return Buffer.from(this.raw).toString('base64');
  }
}

export interface SealState {
  tokenClass: TokenClass;
  ephPubkey: Uint8Array; // 32 bytes
  key: Uint8Array; // 32 bytes
}

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

function x25519SpkiFromRaw(raw32: Uint8Array): Buffer {
  if (raw32.length !== 32) throw new CryptoError('x25519 public key must be 32 bytes');
  return Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(raw32)]);
}

function x25519RawFromSpki(spkiDer: Buffer): Uint8Array {
  if (spkiDer.length !== X25519_SPKI_PREFIX.length + 32) {
    throw new CryptoError('unexpected x25519 spki length');
  }
  const prefix = spkiDer.subarray(0, X25519_SPKI_PREFIX.length);
  if (!prefix.equals(X25519_SPKI_PREFIX)) {
    throw new CryptoError('unexpected x25519 spki prefix');
  }
  return spkiDer.subarray(X25519_SPKI_PREFIX.length);
}

/**
 * Deterministic AAD:
 * [v] + token_class_ascii + '|' + eph_pubkey (32 bytes)
 */
export function makeAad(v: number, tokenClass: TokenClass, ephPubkey: Uint8Array): Uint8Array {
  const tc = Buffer.from(tokenClass, 'ascii');
  const out = Buffer.concat([Buffer.from([v & 0xff]), tc, Buffer.from('|', 'ascii'), Buffer.from(ephPubkey)]);
  return out;
}

function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len: number): Uint8Array {
  // HKDF-Extract
  const prk = crypto.createHmac('sha256', Buffer.from(salt)).update(Buffer.from(ikm)).digest();

  // HKDF-Expand
  const blocks: Buffer[] = [];
  let prev = Buffer.alloc(0);
  let counter = 1;
  while (Buffer.concat(blocks).length < len) {
    const h = crypto.createHmac('sha256', prk);
    h.update(prev);
    h.update(Buffer.from(info));
    h.update(Buffer.from([counter]));
    prev = h.digest();
    blocks.push(prev);
    counter += 1;
  }
  return Buffer.concat(blocks).subarray(0, len);
}

function deriveKey(sharedSecret: Uint8Array, v: number, tokenClass: TokenClass): Uint8Array {
  const info = Buffer.from(`zk-llm-gateway|v${v}|${tokenClass}`, 'ascii');
  const salt = Buffer.alloc(32, 0); // match Rust/Python HKDF(None, ...)
  return hkdfSha256(sharedSecret, salt, info, 32);
}

function chacha20poly1305Encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Uint8Array {
  try {
    const cipher = crypto.createCipheriv('chacha20-poly1305', Buffer.from(key), Buffer.from(nonce), {
      authTagLength: 16,
    });
    if (aad) cipher.setAAD(Buffer.from(aad), { plaintextLength: plaintext.length });
    const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([ct, tag]);
  } catch (e) {
    throw new CryptoError(`encrypt failed: ${(e as Error).message}`);
  }
}

function chacha20poly1305Decrypt(key: Uint8Array, nonce: Uint8Array, ciphertextAndTag: Uint8Array, aad?: Uint8Array): Uint8Array {
  try {
    const buf = Buffer.from(ciphertextAndTag);
    if (buf.length < 16) throw new CryptoError('ciphertext too short');
    const ct = buf.subarray(0, buf.length - 16);
    const tag = buf.subarray(buf.length - 16);

    const decipher = crypto.createDecipheriv('chacha20-poly1305', Buffer.from(key), Buffer.from(nonce), {
      authTagLength: 16,
    });
    if (aad) decipher.setAAD(Buffer.from(aad), { plaintextLength: ct.length });
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return pt;
  } catch (e) {
    throw new CryptoError(`decrypt failed: ${(e as Error).message}`);
  }
}

/**
 * Encrypt + pad a JSON payload into an Envelope.
 *
 * Returns (envelope, sealState). Keep sealState to decrypt the response.
 */
export function sealJson(
  gatewayPk: GatewayPublicKey,
  tokenClass: TokenClass,
  payload: unknown,
): { envelope: Envelope; state: SealState } {
  const v = 1;

  const raw = Buffer.from(JSON.stringify(payload), 'utf8');
  const padded = padPayload(raw, requestPaddedLen(tokenClass));

  // Ephemeral X25519
  const { publicKey: ephPublicKey, privateKey: ephPrivateKey } = crypto.generateKeyPairSync('x25519');
  const ephSpki = ephPublicKey.export({ format: 'der', type: 'spki' }) as Buffer;
  const ephPubRaw = x25519RawFromSpki(ephSpki);

  const gwSpki = x25519SpkiFromRaw(gatewayPk.raw);
  const gwPublicKey = crypto.createPublicKey({ key: gwSpki, format: 'der', type: 'spki' });

  const shared = crypto.diffieHellman({ privateKey: ephPrivateKey, publicKey: gwPublicKey });
  if (shared.length !== 32) throw new CryptoError('unexpected x25519 shared secret length');

  const key = deriveKey(shared, v, tokenClass);
  const nonce = crypto.randomBytes(12);
  const aad = makeAad(v, tokenClass, ephPubRaw);
  const ct = chacha20poly1305Encrypt(key, nonce, padded, aad);

  const envelope: Envelope = {
    v,
    token_class: tokenClass,
    eph_pubkey_b64: Buffer.from(ephPubRaw).toString('base64'),
    nonce_b64: Buffer.from(nonce).toString('base64'),
    ciphertext_b64: Buffer.from(ct).toString('base64'),
  };

  const state: SealState = {
    tokenClass,
    ephPubkey: ephPubRaw,
    key,
  };

  return { envelope, state };
}

/** Decrypt an Envelope using the SealState from the request. */
export function openJson(envelope: Envelope, state: SealState): unknown {
  if (envelope.v !== 1) throw new CryptoError('unsupported envelope version');

  // Normalize token class (string) to enum
  const envTc = parseTokenClass(String(envelope.token_class));
  if (envTc !== state.tokenClass) throw new CryptoError('token_class mismatch');

  const ephPub = Buffer.from(String(envelope.eph_pubkey_b64).trim(), 'base64');
  const nonce = Buffer.from(String(envelope.nonce_b64).trim(), 'base64');
  const ct = Buffer.from(String(envelope.ciphertext_b64).trim(), 'base64');

  if (ephPub.length !== 32 || nonce.length !== 12) throw new CryptoError('invalid envelope fields');

  // Expect gateway to echo the eph_pubkey from request.
  if (!Buffer.from(state.ephPubkey).equals(ephPub)) throw new CryptoError('unexpected eph_pubkey in response');

  const aad = makeAad(envelope.v, envTc, ephPub);
  const padded = chacha20poly1305Decrypt(state.key, nonce, ct, aad);
  const raw = unpadPayload(padded);

  try {
    return JSON.parse(Buffer.from(raw).toString('utf8'));
  } catch (e) {
    throw new ProtocolError(`invalid decrypted JSON: ${(e as Error).message}`);
  }
}
